"""Defensive multimodal hidden-instruction analysis for skill packages.

The pipeline models the runtime path explicitly:

    raw bytes -> parse/decode -> symbol recovery -> instruction reconstruction
    -> guarded tool-call projection

It never executes recovered instructions.  The final stage projects the tool
calls that an agent could make and marks them as blocked/review-only evidence.
The implementation intentionally uses the Python standard library so media
inspection remains available in minimal scanner deployments.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import io
import math
import re
import struct
import urllib.parse
import wave
import zipfile
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from .cross_media_evidence_graph import build_cross_media_evidence_graph
from .media_adapters import analyze_raster_symbols


PIPELINE_VERSION = "0.6.0"

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"}
AUDIO_EXTENSIONS = {".wav", ".wave", ".mp3", ".flac", ".ogg", ".oga", ".m4a", ".aac"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".mkv", ".webm", ".avi", ".m4v"}
SUBTITLE_EXTENSIONS = {".srt", ".vtt", ".ass", ".ssa"}
DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".pptx", ".xlsx"}
MULTIMODAL_EXTENSIONS = (
    IMAGE_EXTENSIONS | AUDIO_EXTENSIONS | VIDEO_EXTENSIONS
    | SUBTITLE_EXTENSIONS | DOCUMENT_EXTENSIONS
)

MAGIC_TYPES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"RIFF", "container/riff"),
    (b"ID3", "audio/mpeg"),
    (b"fLaC", "audio/flac"),
    (b"OggS", "audio/ogg"),
    (b"%PDF-", "document/pdf"),
    (b"\x1aE\xdf\xa3", "video/matroska"),
)

ARCHIVE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
)

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TEXT_CANDIDATES = 160
MAX_CANDIDATE_CHARS = 4096
MAX_DECODE_DEPTH = 3
MAX_PNG_PIXELS = 4_000_000
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024
MAX_RASTER_ADAPTER_FILES = 24


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_media_bytes(path: Path) -> tuple[bytes, bool]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    return data[:MAX_FILE_BYTES], size > MAX_FILE_BYTES


def _magic_type(data: bytes) -> str | None:
    for magic, media_type in MAGIC_TYPES:
        if data.startswith(magic):
            if media_type == "container/riff" and data[8:12] == b"WAVE":
                return "audio/wav"
            if media_type == "container/riff" and data[8:12] == b"WEBP":
                return "image/webp"
            if media_type == "container/riff" and data[8:12] == b"AVI ":
                return "video/avi"
            return media_type
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "container/mp4"
    if data.lstrip().startswith(b"<svg") or b"<svg" in data[:512].lower():
        return "image/svg+xml"
    if data.startswith(b"\xff\xfb") or data.startswith(b"\xff\xf3") or data.startswith(b"\xff\xf2"):
        return "audio/mpeg"
    return None


def _extension_media_type(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        mapped = {".jpg": "jpeg", ".jpeg": "jpeg", ".svg": "svg+xml"}
        return f"image/{mapped.get(suffix, suffix[1:])}"
    if suffix in AUDIO_EXTENSIONS:
        mapped = {".wave": "wav", ".mp3": "mpeg", ".oga": "ogg", ".m4a": "mp4"}
        return f"audio/{mapped.get(suffix, suffix[1:])}"
    if suffix in VIDEO_EXTENSIONS:
        mapped = {".mov": "quicktime", ".m4v": "mp4", ".mkv": "matroska"}
        return f"video/{mapped.get(suffix, suffix[1:])}"
    if suffix in SUBTITLE_EXTENSIONS:
        return f"subtitle/{suffix[1:]}"
    if suffix in DOCUMENT_EXTENSIONS:
        mapped = {
            ".pdf": "pdf",
            ".docx": "wordprocessingml",
            ".pptx": "presentationml",
            ".xlsx": "spreadsheetml",
        }
        return f"document/{mapped[suffix]}"
    return None


def _media_kind(path: Path, data: bytes) -> tuple[str | None, str | None, str | None]:
    extension_type = _extension_media_type(path)
    detected_type = _magic_type(data)
    if detected_type == "container/mp4" and extension_type:
        media_type = extension_type
    elif detected_type == "container/mp4":
        media_type = "video/mp4"
    else:
        media_type = detected_type or extension_type
    if not media_type:
        return None, extension_type, detected_type
    kind = media_type.split("/", 1)[0]
    if kind == "subtitle":
        kind = "video"
    return kind, extension_type, detected_type


def _preview(text: str, limit: int = 320) -> str:
    text = " ".join(text.replace("\x00", " ").split())
    return text[:limit]


def _is_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(sample) >= 0.72


def _extract_printable_runs(data: bytes, minimum: int = 6, limit: int = 80) -> list[str]:
    found: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        found.append(match.group(0).decode("ascii", errors="ignore"))
        if len(found) >= limit:
            return found
    # UTF-16LE strings are common in metadata and RIFF chunks.
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % minimum
    for match in re.finditer(pattern, data):
        found.append(match.group(0).decode("utf-16le", errors="ignore"))
        if len(found) >= limit:
            break
    return found


def _candidate(
    file: str,
    text: str,
    source: str,
    chain: Iterable[str] = (),
    confidence: float = 0.7,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    normalized = text.replace("\x00", " ").strip()
    if len(normalized) < 4:
        return None
    result: dict[str, Any] = {
        "file": file,
        "text": normalized[:MAX_CANDIDATE_CHARS],
        "preview": _preview(normalized),
        "source": source,
        "transform_chain": list(chain),
        "confidence": round(float(confidence), 3),
    }
    if metadata:
        for key in (
            "adapter", "backend", "kind", "frame_index", "region",
            "regions", "polygon", "association_mode", "fragment_files",
            "fragment_sources", "fragment_count",
        ):
            if key in metadata and metadata[key] is not None:
                result[key] = metadata[key]
    return result


def _safe_zlib_decompress(data: bytes, max_output: int = 4 * 1024 * 1024) -> bytes:
    inflater = zlib.decompressobj()
    output = inflater.decompress(data, max_output + 1)
    if len(output) > max_output or inflater.unconsumed_tail:
        raise ValueError("decompressed data exceeds safety limit")
    output += inflater.flush(max_output + 1 - len(output))
    if len(output) > max_output:
        raise ValueError("decompressed data exceeds safety limit")
    return output


def _safe_xml_root(payload: bytes) -> ET.Element:
    upper = payload[:65536].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ET.ParseError("DTD/entity declarations are not allowed")
    return ET.fromstring(payload)


def _parse_png(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"parser": "png", "chunks": [], "logical_end": None}
    candidates: list[dict[str, Any]] = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return result, candidates
    cursor = 8
    while cursor + 12 <= len(data):
        length = struct.unpack(">I", data[cursor:cursor + 4])[0]
        chunk_type = data[cursor + 4:cursor + 8]
        end = cursor + 12 + length
        if length > MAX_FILE_BYTES or end > len(data):
            result["parse_error"] = "invalid or truncated chunk"
            break
        payload = data[cursor + 8:cursor + 8 + length]
        name = chunk_type.decode("ascii", errors="replace")
        result["chunks"].append({"type": name, "length": length})
        try:
            text: str | None = None
            if chunk_type == b"tEXt" and b"\x00" in payload:
                key, value = payload.split(b"\x00", 1)
                text = f"{key.decode('latin1', errors='replace')}={value.decode('latin1', errors='replace')}"
            elif chunk_type == b"zTXt" and b"\x00" in payload:
                key, rest = payload.split(b"\x00", 1)
                if len(rest) > 1 and rest[0] == 0:
                    value = _safe_zlib_decompress(rest[1:], 256 * 1024)
                    text = f"{key.decode('latin1', errors='replace')}={value.decode('utf-8', errors='replace')}"
            elif chunk_type == b"iTXt":
                fields = payload.split(b"\x00", 5)
                if len(fields) == 6:
                    key, compressed, method, language, translated, value = fields
                    if compressed == b"\x01" and method == b"\x00":
                        value = _safe_zlib_decompress(value, 256 * 1024)
                    text = f"{key.decode('utf-8', errors='replace')}={value.decode('utf-8', errors='replace')}"
            if text:
                item = _candidate(rel, text, f"png:{name}", ("container-metadata",), 0.95)
                if item:
                    candidates.append(item)
        except (ValueError, zlib.error):
            result.setdefault("warnings", []).append(f"could not safely decode {name}")
        cursor = end
        if chunk_type == b"IEND":
            result["logical_end"] = end
            break
    return result, candidates


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _png_pixel_bytes(data: bytes) -> tuple[bytes, int] | None:
    """Decode non-interlaced 8-bit grayscale/RGB/RGBA PNG scanlines."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    cursor = 8
    ihdr: tuple[int, int, int, int, int, int, int] | None = None
    idat: list[bytes] = []
    while cursor + 12 <= len(data):
        length = struct.unpack(">I", data[cursor:cursor + 4])[0]
        end = cursor + 12 + length
        if end > len(data) or length > MAX_FILE_BYTES:
            return None
        chunk_type = data[cursor + 4:cursor + 8]
        payload = data[cursor + 8:cursor + 8 + length]
        if chunk_type == b"IHDR" and len(payload) == 13:
            ihdr = struct.unpack(">IIBBBBB", payload)
        elif chunk_type == b"IDAT":
            idat.append(payload)
        elif chunk_type == b"IEND":
            break
        cursor = end
    if not ihdr or not idat:
        return None
    width, height, bit_depth, color_type, compression, filtering, interlace = ihdr
    channels_by_type = {0: 1, 2: 3, 6: 4}
    channels = channels_by_type.get(color_type)
    if (
        not channels
        or bit_depth != 8
        or compression != 0
        or filtering != 0
        or interlace != 0
        or width * height > MAX_PNG_PIXELS
    ):
        return None
    stride = width * channels
    expected = height * (stride + 1)
    try:
        raw = _safe_zlib_decompress(b"".join(idat), expected)
    except (ValueError, zlib.error):
        return None
    if len(raw) != expected:
        return None
    rows: list[bytearray] = []
    pos = 0
    prior = bytearray(stride)
    for _ in range(height):
        filter_type = raw[pos]
        pos += 1
        scanline = bytearray(raw[pos:pos + stride])
        pos += stride
        if filter_type > 4:
            return None
        for index, value in enumerate(scanline):
            left = scanline[index - channels] if index >= channels else 0
            up = prior[index]
            up_left = prior[index - channels] if index >= channels else 0
            if filter_type == 1:
                scanline[index] = (value + left) & 0xFF
            elif filter_type == 2:
                scanline[index] = (value + up) & 0xFF
            elif filter_type == 3:
                scanline[index] = (value + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                scanline[index] = (value + _paeth(left, up, up_left)) & 0xFF
        rows.append(scanline)
        prior = scanline
    return b"".join(rows), channels


def _pack_bits(bits: Iterable[int], *, least_significant_first: bool = False) -> bytes:
    output = bytearray()
    value = 0
    count = 0
    for bit in bits:
        if least_significant_first:
            value |= (bit & 1) << count
        else:
            value = (value << 1) | (bit & 1)
        count += 1
        if count == 8:
            output.append(value)
            value = 0
            count = 0
    return bytes(output)


def _lsb_candidates(
    rel: str,
    sample_bytes: bytes,
    channels: int,
    source_prefix: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    streams: list[tuple[str, bytes]] = [("all", sample_bytes)]
    if channels > 1:
        channel_names = ("r", "g", "b", "a") if source_prefix == "png-pixels" else tuple(f"ch{i}" for i in range(channels))
        for index in range(min(channels, len(channel_names))):
            streams.append((channel_names[index], sample_bytes[index::channels]))
    for stream_name, stream in streams:
        if len(stream) < 48:
            continue
        bits = (value & 1 for value in stream)
        packed = _pack_bits(bits)
        for text in _extract_printable_runs(packed, minimum=6, limit=12):
            item = _candidate(
                rel,
                text,
                f"{source_prefix}:lsb:{stream_name}",
                ("least-significant-bit", "bits-to-bytes"),
                0.82,
            )
            if item:
                candidates.append(item)
        bits_little = (value & 1 for value in stream)
        packed_little = _pack_bits(bits_little, least_significant_first=True)
        for text in _extract_printable_runs(packed_little, minimum=6, limit=8):
            item = _candidate(
                rel,
                text,
                f"{source_prefix}:lsb-little:{stream_name}",
                ("least-significant-bit", "bits-to-bytes-little-endian"),
                0.72,
            )
            if item:
                candidates.append(item)
    return candidates


def _parse_jpeg(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"parser": "jpeg", "segments": [], "logical_end": None}
    candidates: list[dict[str, Any]] = []
    if not data.startswith(b"\xff\xd8"):
        return result, candidates
    eoi = data.rfind(b"\xff\xd9")
    if eoi >= 0:
        result["logical_end"] = eoi + 2
    cursor = 2
    while cursor + 4 <= len(data):
        if data[cursor] != 0xFF:
            cursor += 1
            continue
        marker = data[cursor + 1]
        if marker in (0xD9, 0xDA):
            break
        if marker in range(0xD0, 0xD8) or marker == 0x01:
            cursor += 2
            continue
        length = struct.unpack(">H", data[cursor + 2:cursor + 4])[0]
        if length < 2 or cursor + 2 + length > len(data):
            break
        payload = data[cursor + 4:cursor + 2 + length]
        marker_name = f"APP{marker - 0xE0}" if 0xE0 <= marker <= 0xEF else f"0x{marker:02x}"
        result["segments"].append({"marker": marker_name, "length": length})
        if marker == 0xFE or marker in (0xE1, 0xED):
            for text in _extract_printable_runs(payload, minimum=5, limit=20):
                item = _candidate(rel, text, f"jpeg:{marker_name}", ("container-metadata",), 0.82)
                if item:
                    candidates.append(item)
        cursor += 2 + length
    return result, candidates


def _parse_gif(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"parser": "gif", "logical_end": None}
    candidates: list[dict[str, Any]] = []
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return result, candidates
    trailer = data.rfind(b"\x3b")
    if trailer >= 0:
        result["logical_end"] = trailer + 1
    cursor = 0
    while True:
        index = data.find(b"\x21\xfe", cursor)
        if index < 0:
            break
        pos = index + 2
        pieces: list[bytes] = []
        while pos < len(data):
            length = data[pos]
            pos += 1
            if length == 0:
                break
            if pos + length > len(data):
                break
            pieces.append(data[pos:pos + length])
            pos += length
        text = b"".join(pieces).decode("latin1", errors="replace")
        item = _candidate(rel, text, "gif:comment", ("container-metadata",), 0.9)
        if item:
            candidates.append(item)
        cursor = max(pos, index + 2)
    return result, candidates


def _decode_id3_text(payload: bytes) -> str:
    if not payload:
        return ""
    encoding = payload[0]
    body = payload[1:]
    codec = {0: "latin1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(encoding, "latin1")
    return body.decode(codec, errors="replace").replace("\x00", " ")


def _parse_id3(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"parser": "id3", "frames": []}
    candidates: list[dict[str, Any]] = []
    if not data.startswith(b"ID3") or len(data) < 10:
        return result, candidates
    version = data[3]
    tag_size = sum((data[6 + i] & 0x7F) << (7 * (3 - i)) for i in range(4))
    result.update({"version": version, "tag_size": tag_size})
    cursor = 10
    end = min(len(data), 10 + tag_size)
    while cursor + 10 <= end:
        frame_id = data[cursor:cursor + 4].decode("ascii", errors="ignore")
        if not frame_id.strip("\x00"):
            break
        if version == 4:
            frame_size = sum((data[cursor + 4 + i] & 0x7F) << (7 * (3 - i)) for i in range(4))
        else:
            frame_size = int.from_bytes(data[cursor + 4:cursor + 8], "big")
        if frame_size <= 0 or cursor + 10 + frame_size > end:
            break
        payload = data[cursor + 10:cursor + 10 + frame_size]
        result["frames"].append({"id": frame_id, "length": frame_size})
        if frame_id.startswith("T") or frame_id in {"COMM", "USLT"}:
            text = _decode_id3_text(payload)
            item = _candidate(rel, text, f"id3:{frame_id}", ("container-metadata",), 0.9)
            if item:
                candidates.append(item)
        cursor += 10 + frame_size
    return result, candidates


def _parse_svg(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {
        "parser": "svg-xml",
        "text_nodes": 0,
        "hidden_text_nodes": 0,
        "external_references": [],
        "risk_flags": [],
    }
    candidates: list[dict[str, Any]] = []
    try:
        root = _safe_xml_root(data)
    except ET.ParseError:
        result["parse_error"] = "malformed SVG XML"
        return result, candidates
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else "unknown"
        style = str(element.attrib.get("style", "")).lower()
        hidden = (
            str(element.attrib.get("display", "")).lower() == "none"
            or str(element.attrib.get("visibility", "")).lower() == "hidden"
            or str(element.attrib.get("opacity", "")) in {"0", "0.0"}
            or "display:none" in style.replace(" ", "")
            or "visibility:hidden" in style.replace(" ", "")
            or "opacity:0" in style.replace(" ", "")
        )
        texts: list[tuple[str, str]] = []
        if element.text and element.text.strip():
            texts.append((f"svg:{tag}", html.unescape(element.text.strip())))
        for attr_name, attr_value in element.attrib.items():
            local_attr = attr_name.rsplit("}", 1)[-1].lower()
            if local_attr in {"aria-label", "title", "desc", "alt", "data-text"}:
                texts.append((f"svg:attribute:{local_attr}", html.unescape(str(attr_value))))
            if local_attr == "href":
                href = str(attr_value)
                if href.startswith(("http://", "https://", "file://")):
                    result["external_references"].append(href[:300])
                    texts.append(("svg:external-reference", href))
        for source, text in texts:
            result["text_nodes"] += 1
            if hidden:
                result["hidden_text_nodes"] += 1
                source = "svg:hidden-" + source.removeprefix("svg:")
            item = _candidate(
                rel,
                text,
                source,
                ("xml-parse", "hidden-presentation" if hidden else "visible-content"),
                0.94 if hidden else 0.78,
            )
            if item:
                candidates.append(item)
        if tag == "script" and element.text and element.text.strip():
            result["risk_flags"].append("script_element")
    if result["external_references"]:
        result["risk_flags"].append("external_reference")
    if result["hidden_text_nodes"]:
        result["risk_flags"].append("hidden_text")
    result["risk_flags"] = sorted(set(result["risk_flags"]))
    return result, candidates


def _decode_pdf_literal(raw: bytes) -> str:
    body = raw[1:-1]

    def replace_escape(match: re.Match[bytes]) -> bytes:
        token = match.group(1)
        escapes = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}
        if token in escapes:
            return escapes[token]
        if token[:1] in b"01234567":
            try:
                return bytes([int(token[:3], 8) & 0xFF])
            except ValueError:
                return token
        return token[-1:]

    body = re.sub(rb"\\([0-7]{1,3}|.)", replace_escape, body, flags=re.DOTALL)
    if body.startswith((b"\xfe\xff", b"\xff\xfe")):
        codec = "utf-16-be" if body.startswith(b"\xfe\xff") else "utf-16-le"
        return body[2:].decode(codec, errors="replace")
    return body.decode("latin1", errors="replace")


PDF_LITERAL = rb"\((?:\\.|[^\\()])*\)"


def _pdf_candidates_from_blob(
    blob: bytes,
    rel: str,
    source: str,
) -> tuple[list[dict[str, Any]], int]:
    candidates: list[dict[str, Any]] = []
    hidden_count = 0
    patterns = (
        re.compile(PDF_LITERAL + rb"\s*Tj"),
        re.compile(rb"\[(.{1,32768}?)\]\s*TJ", re.DOTALL),
        re.compile(rb"/(?:Title|Subject|Keywords|Contents)\s*(" + PDF_LITERAL + rb")"),
    )
    for pattern_index, pattern in enumerate(patterns):
        for match in pattern.finditer(blob):
            region = match.group(0)
            literals = re.findall(PDF_LITERAL, region)
            if not literals:
                continue
            text = "".join(_decode_pdf_literal(value) for value in literals)
            nearby = blob[max(0, match.start() - 96):match.start()]
            hidden = bool(re.search(rb"(?:^|\s)3\s+Tr(?:\s|$)", nearby))
            if hidden:
                hidden_count += 1
            item = _candidate(
                rel,
                text,
                f"{source}:{'hidden-text' if hidden else 'text'}",
                ("pdf-object-parse", "hidden-render-mode" if hidden else "text-operator"),
                0.94 if hidden else (0.86 if pattern_index < 2 else 0.82),
            )
            if item:
                candidates.append(item)
    for match in re.finditer(rb"<([0-9A-Fa-f]{12,})>\s*Tj", blob):
        try:
            raw = bytes.fromhex(match.group(1).decode("ascii"))
        except ValueError:
            continue
        text = raw[2:].decode("utf-16-be", errors="replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin1", errors="replace")
        item = _candidate(rel, text, f"{source}:hex-text", ("pdf-hex-string",), 0.84)
        if item:
            candidates.append(item)
    return candidates, hidden_count


def _parse_pdf(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {
        "parser": "pdf-objects",
        "decompressed_streams": 0,
        "hidden_text_objects": 0,
        "risk_flags": [],
    }
    candidates, hidden = _pdf_candidates_from_blob(data, rel, "pdf:raw")
    result["hidden_text_objects"] += hidden
    stream_header = re.compile(rb"<<(.*?)>>\s*stream\r?\n", re.DOTALL)
    for match in stream_header.finditer(data):
        if len(match.group(1)) > 8192:
            continue
        end = data.find(b"endstream", match.end())
        if end < 0 or end - match.end() > 4 * 1024 * 1024:
            continue
        payload = data[match.end():end].rstrip(b"\r\n")
        if b"/FlateDecode" not in match.group(1):
            continue
        try:
            decoded = _safe_zlib_decompress(payload, 4 * 1024 * 1024)
        except (ValueError, zlib.error):
            continue
        result["decompressed_streams"] += 1
        stream_candidates, stream_hidden = _pdf_candidates_from_blob(decoded, rel, "pdf:flate-stream")
        candidates.extend(stream_candidates)
        result["hidden_text_objects"] += stream_hidden
    flag_tokens = {
        b"/EmbeddedFiles": "embedded_files",
        b"/JavaScript": "javascript_action",
        b"/OpenAction": "open_action",
        b"/Launch": "launch_action",
        b"/RichMedia": "rich_media",
    }
    result["risk_flags"] = [label for token, label in flag_tokens.items() if token in data]
    if result["hidden_text_objects"]:
        result["risk_flags"].append("hidden_text")
    return result, candidates


def _ooxml_part_priority(media_type: str, name: str) -> tuple[bool, str, float]:
    lower = name.lower()
    if not (lower.endswith(".xml") or lower.endswith(".rels")):
        return False, "", 0.0
    if "presentationml" in media_type:
        if "notesslides/" in lower:
            return True, "pptx:presenter-notes", 0.95
        if "comments/" in lower:
            return True, "pptx:comments", 0.93
        if "slides/" in lower:
            return True, "pptx:slide", 0.76
    elif "wordprocessingml" in media_type:
        if any(part in lower for part in ("comments", "footnotes", "endnotes")):
            return True, "docx:annotation", 0.93
        if lower.startswith("word/"):
            return True, "docx:document", 0.76
    elif "spreadsheetml" in media_type:
        if "comments" in lower:
            return True, "xlsx:comments", 0.93
        if any(part in lower for part in ("sharedstrings", "worksheets/")):
            return True, "xlsx:cells", 0.74
    if lower.startswith("docprops/"):
        return True, "ooxml:properties", 0.86
    if lower.endswith(".rels"):
        return True, "ooxml:relationships", 0.88
    return False, "", 0.0


def _parse_ooxml(
    data: bytes,
    rel: str,
    media_type: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {
        "parser": "ooxml-zip-xml",
        "parts": [],
        "external_relationships": [],
        "risk_flags": [],
    }
    candidates: list[dict[str, Any]] = []
    total = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result["parse_error"] = "malformed OOXML ZIP"
        return result, candidates
    with archive:
        for info in archive.infolist()[:300]:
            include, source, confidence = _ooxml_part_priority(media_type, info.filename)
            if not include or info.is_dir() or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                continue
            if info.compress_size and info.file_size / info.compress_size > 100:
                continue
            if total + info.file_size > MAX_ARCHIVE_TOTAL_BYTES:
                result["truncated"] = True
                break
            try:
                payload = archive.read(info)
            except (RuntimeError, OSError, zipfile.BadZipFile):
                continue
            total += len(payload)
            try:
                root = _safe_xml_root(payload)
            except ET.ParseError:
                continue
            texts: list[str] = []
            for element in root.iter():
                if element.text and element.text.strip():
                    texts.append(element.text.strip())
                for attr_name, attr_value in element.attrib.items():
                    local = attr_name.rsplit("}", 1)[-1].lower()
                    value = str(attr_value)
                    if local in {"descr", "title", "name", "alt", "tooltip"} and value.strip():
                        texts.append(value)
                    if local == "target" and value.startswith(("http://", "https://", "file://")):
                        result["external_relationships"].append(value[:300])
                        texts.append(value)
            joined = "\n".join(texts)
            item = _candidate(
                rel,
                joined,
                f"{source}:{info.filename}",
                ("zip-container", "xml-parse"),
                confidence,
            )
            if item:
                candidates.append(item)
                result["parts"].append({"name": info.filename, "source": source, "chars": len(joined)})
    if result["external_relationships"]:
        result["risk_flags"].append("external_relationship")
    return result, candidates


def _parse_subtitle(data: bytes, rel: str, suffix: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"parser": "subtitle-text", "format": suffix.lstrip(".")}
    candidates: list[dict[str, Any]] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="replace")
    else:
        text = data.decode("utf-8-sig", errors="replace")
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.isdigit() or stripped.upper() == "WEBVTT":
            continue
        if re.search(r"\d{1,2}:\d{2}(?::\d{2})?[.,]\d{3}\s*-->", stripped):
            continue
        if suffix.lower() in {".ass", ".ssa"} and stripped.lower().startswith("dialogue:"):
            fields = stripped.split(",", 9)
            stripped = fields[-1] if fields else stripped
        stripped = re.sub(r"<[^>]+>|\{[^}]+\}", " ", stripped)
        if stripped.strip():
            lines.append(stripped.strip())
    body = "\n".join(lines)
    result["text_chars"] = len(body)
    item = _candidate(rel, body, f"subtitle:{suffix.lstrip('.')}", ("subtitle-parse",), 0.9)
    if item:
        candidates.append(item)
    return result, candidates


def _parse_mp4(data: bytes, rel: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result: dict[str, Any] = {"parser": "iso-bmff-boxes", "boxes": [], "subtitle_markers": []}
    candidates: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 8 <= len(data) and len(result["boxes"]) < 400:
        size = int.from_bytes(data[cursor:cursor + 4], "big")
        box_type = data[cursor + 4:cursor + 8]
        header = 8
        if size == 1 and cursor + 16 <= len(data):
            size = int.from_bytes(data[cursor + 8:cursor + 16], "big")
            header = 16
        elif size == 0:
            size = len(data) - cursor
        if size < header or cursor + size > len(data):
            break
        name = box_type.decode("latin1", errors="replace")
        result["boxes"].append({"type": name, "offset": cursor, "size": size})
        payload = data[cursor + header:cursor + size]
        if box_type in {b"data", b"desc", b"ldes", b"\xa9nam", b"\xa9cmt", b"\xa9des"}:
            for text in _extract_printable_runs(payload, minimum=4, limit=12):
                item = _candidate(rel, text, f"mp4:{name}", ("iso-bmff-box",), 0.82)
                if item:
                    candidates.append(item)
        cursor += size
    if cursor:
        result["logical_end"] = cursor
    for marker in (b"tx3g", b"wvtt", b"stpp", b"sbtl", b"subt"):
        if marker in data:
            result["subtitle_markers"].append(marker.decode("ascii"))
    # Subtitle and metadata samples often remain printable inside mdat; keep
    # these candidates separate from generic raw strings for provenance.
    for text in _extract_printable_runs(data, minimum=10, limit=30):
        item = _candidate(rel, text, "video-container:printable-sample", ("container-string",), 0.55)
        if item:
            candidates.append(item)
    return result, candidates


def _wav_sample_bytes(data: bytes) -> tuple[dict[str, Any], bytes, int]:
    info: dict[str, Any] = {"parser": "wav"}
    try:
        with wave.open(io.BytesIO(data), "rb") as audio:
            channels = audio.getnchannels()
            sample_width = audio.getsampwidth()
            frame_rate = audio.getframerate()
            frame_count = audio.getnframes()
            max_frames = min(frame_count, max(1, (8 * 1024 * 1024) // max(1, channels * sample_width)))
            frames = audio.readframes(max_frames)
    except (wave.Error, EOFError):
        info["parse_error"] = "unsupported or malformed WAV"
        return info, b"", 0
    info.update(
        {
            "channels": channels,
            "sample_width": sample_width,
            "frame_rate": frame_rate,
            "frame_count": frame_count,
            "sample_data_truncated": max_frames < frame_count,
        }
    )
    sample_stride = channels * sample_width
    low_bytes = bytearray()
    for frame_pos in range(0, len(frames) - sample_stride + 1, sample_stride):
        for channel in range(channels):
            low_bytes.append(frames[frame_pos + channel * sample_width])
    return info, bytes(low_bytes), channels


def _wav_mono_samples(data: bytes, max_seconds: int = 30) -> tuple[list[float], int] | None:
    try:
        with wave.open(io.BytesIO(data), "rb") as audio:
            channels = audio.getnchannels()
            width = audio.getsampwidth()
            rate = audio.getframerate()
            frames = audio.readframes(min(audio.getnframes(), rate * max_seconds))
    except (wave.Error, EOFError):
        return None
    if width not in {1, 2} or channels < 1:
        return None
    values: list[float] = []
    stride = width * channels
    for pos in range(0, len(frames) - stride + 1, stride):
        total = 0.0
        for channel in range(channels):
            offset = pos + channel * width
            if width == 1:
                total += (frames[offset] - 128) / 128.0
            else:
                total += int.from_bytes(frames[offset:offset + 2], "little", signed=True) / 32768.0
        values.append(total / channels)
    return values, rate


def _goertzel(samples: list[float], rate: int, frequency: float) -> float:
    omega = 2.0 * math.pi * frequency / rate
    coeff = 2.0 * math.cos(omega)
    s_prev = 0.0
    s_prev2 = 0.0
    for sample in samples:
        current = sample + coeff * s_prev - s_prev2
        s_prev2, s_prev = s_prev, current
    return s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2


def _detect_dtmf(data: bytes) -> str:
    decoded = _wav_mono_samples(data)
    if not decoded:
        return ""
    samples, rate = decoded
    frame_size = max(160, int(rate * 0.05))
    lows = (697, 770, 852, 941)
    highs = (1209, 1336, 1477, 1633)
    symbols = (
        ("1", "2", "3", "A"),
        ("4", "5", "6", "B"),
        ("7", "8", "9", "C"),
        ("*", "0", "#", "D"),
    )
    raw_symbols: list[str] = []
    for start in range(0, len(samples) - frame_size + 1, frame_size):
        frame = samples[start:start + frame_size]
        rms = math.sqrt(sum(value * value for value in frame) / len(frame))
        if rms < 0.015:
            raw_symbols.append("")
            continue
        low_power = [_goertzel(frame, rate, freq) for freq in lows]
        high_power = [_goertzel(frame, rate, freq) for freq in highs]
        low_sorted = sorted(low_power, reverse=True)
        high_sorted = sorted(high_power, reverse=True)
        if (
            low_sorted[0] < max(1e-9, low_sorted[1]) * 2.5
            or high_sorted[0] < max(1e-9, high_sorted[1]) * 2.5
        ):
            raw_symbols.append("")
            continue
        raw_symbols.append(symbols[low_power.index(low_sorted[0])][high_power.index(high_sorted[0])])
    collapsed: list[str] = []
    previous = ""
    for symbol in raw_symbols:
        if symbol and symbol != previous:
            collapsed.append(symbol)
        previous = symbol
    return "".join(collapsed) if len(collapsed) >= 3 else ""


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9",
}


def _decode_morse(text: str) -> str | None:
    if not re.fullmatch(r"[.\-/\s]+", text.strip()) or len(text.strip()) < 7:
        return None
    words: list[str] = []
    for word in re.split(r"\s*/\s*|\s{2,}", text.strip()):
        letters = [MORSE.get(token) for token in word.split()]
        if not letters or any(letter is None for letter in letters):
            return None
        words.append("".join(letter for letter in letters if letter))
    return " ".join(words)


def _embedded_archives(data: bytes, rel: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    archives: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for signature, archive_type in ARCHIVE_SIGNATURES:
        cursor = 1
        while True:
            offset = data.find(signature, cursor)
            if offset < 0:
                break
            record: dict[str, Any] = {"type": archive_type, "offset": offset}
            archives.append(record)
            if archive_type == "zip":
                total = 0
                try:
                    with zipfile.ZipFile(io.BytesIO(data[offset:])) as archive:
                        names: list[str] = []
                        for info in archive.infolist()[:20]:
                            names.append(info.filename)
                            if info.is_dir() or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                                continue
                            if info.compress_size and info.file_size / info.compress_size > 100:
                                continue
                            if total + info.file_size > MAX_ARCHIVE_TOTAL_BYTES:
                                break
                            payload = archive.read(info)
                            total += len(payload)
                            if _is_textual(payload):
                                text = payload.decode("utf-8", errors="replace")
                                item = _candidate(
                                    rel,
                                    text,
                                    f"embedded-zip:{info.filename}",
                                    ("embedded-archive", "safe-extract-text-member"),
                                    0.96,
                                )
                                if item:
                                    candidates.append(item)
                        record["members"] = names
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    record["parse_error"] = "embedded ZIP could not be safely listed"
            cursor = offset + len(signature)
            if len(archives) >= 8:
                return archives, candidates
    return archives, candidates


def _logical_end(media_type: str | None, data: bytes, parsed: dict[str, Any]) -> int | None:
    if isinstance(parsed.get("logical_end"), int):
        return int(parsed["logical_end"])
    if media_type == "audio/wav" and len(data) >= 8:
        declared = int.from_bytes(data[4:8], "little") + 8
        return declared if 8 <= declared <= len(data) else None
    if media_type == "image/bmp" and len(data) >= 6:
        declared = int.from_bytes(data[2:6], "little")
        return declared if 14 <= declared <= len(data) else None
    if media_type == "document/pdf":
        marker = data.rfind(b"%%EOF")
        return marker + len(b"%%EOF") if marker >= 0 else None
    return None


def _base_decode_variants(text: str) -> list[tuple[str, str]]:
    stripped = "".join(text.split())
    decoded: list[tuple[str, str]] = []
    # Metadata commonly prefixes encoded data (for example ``Comment=...``),
    # and binary CRC bytes may append printable noise.  Decode bounded tokens
    # as well as the whole candidate instead of requiring a perfect full match.
    base_tokens = [stripped]
    base_tokens.extend(
        match.group(0)
        for match in re.finditer(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{12,}={0,2}", text)
    )
    seen_tokens: set[str] = set()
    for token in base_tokens:
        if token in seen_tokens or not (12 <= len(token) <= 8192):
            continue
        seen_tokens.add(token)
        if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", token):
            continue
        for label, decoder in (("base64", base64.b64decode), ("base64url", base64.urlsafe_b64decode)):
            try:
                padded = token + "=" * (-len(token) % 4)
                raw = decoder(padded.encode("ascii"))
                if len(raw) >= 6 and _is_textual(raw):
                    decoded.append((label, raw.decode("utf-8", errors="replace")))
            except (ValueError, binascii.Error):
                pass
    if 12 <= len(stripped) <= 8192 and len(stripped) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", stripped):
        try:
            raw = bytes.fromhex(stripped)
            if len(raw) >= 6 and _is_textual(raw):
                decoded.append(("hex", raw.decode("utf-8", errors="replace")))
        except ValueError:
            pass
    if 16 <= len(stripped) <= 8192 and re.fullmatch(r"[A-Z2-7=]+", stripped.upper()):
        try:
            padded = stripped.upper() + "=" * (-len(stripped) % 8)
            raw = base64.b32decode(padded)
            if len(raw) >= 6 and _is_textual(raw):
                decoded.append(("base32", raw.decode("utf-8", errors="replace")))
        except (ValueError, binascii.Error):
            pass
    if 16 <= len(stripped) <= 32768 and len(stripped) % 8 == 0 and re.fullmatch(r"[01]+", stripped):
        try:
            raw = bytes(int(stripped[i:i + 8], 2) for i in range(0, len(stripped), 8))
            if _is_textual(raw):
                decoded.append(("binary", raw.decode("utf-8", errors="replace")))
        except ValueError:
            pass
    if "%" in text:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text and len(unquoted) >= 6:
            decoded.append(("url-percent", unquoted))
    morse = _decode_morse(text)
    if morse:
        decoded.append(("morse", morse))
    rot13 = codecs.decode(text, "rot_13")
    if _instruction_signal(rot13)[0] > _instruction_signal(text)[0]:
        decoded.append(("rot13", rot13))
    reversed_text = text[::-1]
    if _instruction_signal(reversed_text)[0] > _instruction_signal(text)[0]:
        decoded.append(("reverse", reversed_text))
    return decoded


def _recover_symbols(seed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recovered: list[dict[str, Any]] = []
    queue: list[tuple[dict[str, Any], int]] = [(item, 0) for item in seed]
    # Preserve provenance variants. The same encoded text can appear in raw
    # strings and a higher-confidence metadata/notes extractor.
    seen: set[tuple[str, str, str]] = set()
    while queue and len(recovered) < MAX_TEXT_CANDIDATES:
        item, depth = queue.pop(0)
        key = (item["file"], item["source"], item["text"])
        if key in seen:
            continue
        seen.add(key)
        recovered.append(item)
        if depth >= MAX_DECODE_DEPTH:
            continue
        for transform, decoded_text in _base_decode_variants(item["text"]):
            inherited_metadata = {
                key: item[key]
                for key in (
                    "adapter", "backend", "kind", "frame_index", "region",
                    "regions", "polygon", "association_mode", "fragment_files",
                    "fragment_sources", "fragment_count",
                )
                if key in item
            }
            child = _candidate(
                item["file"],
                decoded_text,
                item["source"],
                tuple(item.get("transform_chain", [])) + (transform,),
                min(0.99, float(item.get("confidence", 0.7)) + 0.04),
                metadata=inherited_metadata,
            )
            if child and (child["file"], child["source"], child["text"]) not in seen:
                queue.append((child, depth + 1))
    return recovered


SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("prompt_control", re.compile(r"ignore (?:all |the )?(?:previous|prior) instructions|system prompt|developer message|忽略.{0,12}(?:指令|提示)|无视.{0,12}(?:规则|要求)", re.I), 3),
    ("shell", re.compile(r"\b(?:powershell|cmd\.exe|bash|sh -c|subprocess|os\.system|shell|execute|run command)\b|执行.{0,12}(?:命令|脚本)|运行.{0,12}(?:命令|脚本)", re.I), 3),
    ("network", re.compile(r"\b(?:curl|wget|webhook|http[s]?://|upload|exfiltrat|send\s+to|network request)\b|外传|上传.{0,12}(?:数据|文件)|发送.{0,12}(?:密钥|凭据|数据)", re.I), 2),
    ("credential_access", re.compile(r"\b(?:api[_ -]?key|token|password|credential|secret|\.ssh|aws_secret|environment variable)\b|密钥|凭据|口令|环境变量", re.I), 3),
    ("filesystem", re.compile(r"\b(?:read|write|open|copy|delete|remove)\b.{0,30}\b(?:file|directory|folder)\b|读取.{0,12}文件|写入.{0,12}文件|删除.{0,12}文件", re.I), 1),
    ("destructive", re.compile(r"rm\s+-rf|remove-item\s+.+-recurse|format\s+[a-z]:|删除.{0,10}(?:所有|系统|目录)", re.I), 5),
    ("persistence", re.compile(r"\b(?:crontab|startup folder|scheduled task|registry run key|persist)\b|计划任务|开机启动|持久化", re.I), 3),
    ("concealment", re.compile(r"\b(?:do not tell|keep this secret|hide this action|without asking|silently)\b|不要告知|秘密执行|静默执行", re.I), 2),
)


def _instruction_signal(text: str) -> tuple[int, list[str]]:
    score = 0
    categories: list[str] = []
    for category, pattern, weight in SIGNAL_PATTERNS:
        if pattern.search(text):
            score += weight
            categories.append(category)
    if (
        "credential_access" not in categories
        and re.search(r"\b(?:credentials?|passwords?|api[_ -]?keys?|tokens?|secrets?|environment variables?)\b", text, re.I)
    ):
        score += 3
        categories.append("credential_access")
    return score, categories


ACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("READ", re.compile(r"\b(?:read|access|collect|obtain|load|inspect)\b|\u8bfb\u53d6|\u8bbf\u95ee|\u6536\u96c6|\u83b7\u53d6|\u67e5\u770b", re.I)),
    ("WRITE", re.compile(r"\b(?:write|save|store|modify|update)\b|\u5199\u5165|\u4fdd\u5b58|\u5b58\u50a8|\u4fee\u6539|\u66f4\u65b0", re.I)),
    ("EXECUTE", re.compile(r"\b(?:execute|run|invoke|launch|powershell|cmd\.exe|bash|shell)\b|\u6267\u884c|\u8fd0\u884c|\u8c03\u7528|\u542f\u52a8", re.I)),
    ("SEND", re.compile(r"\b(?:send|upload|post|transmit|exfiltrat|submit)\b|\u53d1\u9001|\u4e0a\u4f20|\u5916\u4f20|\u63d0\u4ea4", re.I)),
    ("DOWNLOAD", re.compile(r"\b(?:download|fetch|retrieve|curl|wget)\b|\u4e0b\u8f7d|\u62c9\u53d6", re.I)),
    (
        "DELETE",
        re.compile(
            r"\b(?:delete|remove|destroy|erase)\b|"
            r"\bformat\s+(?:the\s+)?(?:[a-z]:|disk|drive|volume|partition|filesystem)\b|"
            r"\u5220\u9664|\u6e05\u7a7a|\u9500\u6bc1|"
            r"\u683c\u5f0f\u5316.{0,8}(?:\u78c1\u76d8|\u786c\u76d8|\u5206\u533a|\u5377|\u6587\u4ef6\u7cfb\u7edf)",
            re.I,
        ),
    ),
    ("INSTALL", re.compile(r"\b(?:install|deploy|enable)\b|\u5b89\u88c5|\u90e8\u7f72|\u542f\u7528", re.I)),
    ("PERSIST", re.compile(r"\b(?:persist|schedule|crontab|startup|registry run)\b|\u6301\u4e45\u5316|\u8ba1\u5212\u4efb\u52a1|\u5f00\u673a\u542f\u52a8", re.I)),
    ("DECODE", re.compile(r"\b(?:decode|decrypt|extract|unpack)\b|\u89e3\u7801|\u89e3\u5bc6|\u63d0\u53d6|\u89e3\u5305", re.I)),
)

OBJECT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CREDENTIAL", re.compile(r"\b(?:credentials?|passwords?|api[_ -]?keys?|tokens?|secrets?|\.ssh|private keys?)\b|\u51ed\u636e|\u5bc6\u7801|\u5bc6\u94a5|\u4ee4\u724c|\u79c1\u94a5", re.I)),
    ("ENVIRONMENT", re.compile(r"\b(?:environment variables?|env vars?|process environment)\b|\u73af\u5883\u53d8\u91cf", re.I)),
    ("FILE", re.compile(r"\b(?:file|directory|folder|document|report)\b|\u6587\u4ef6|\u76ee\u5f55|\u6587\u6863|\u62a5\u544a", re.I)),
    ("USER_DATA", re.compile(r"\b(?:user data|personal data|private data|conversation|history)\b|\u7528\u6237\u6570\u636e|\u4e2a\u4eba\u4fe1\u606f|\u5bf9\u8bdd\u8bb0\u5f55", re.I)),
    ("SYSTEM_CONFIG", re.compile(r"\b(?:system config|configuration|registry|startup file)\b|\u7cfb\u7edf\u914d\u7f6e|\u6ce8\u518c\u8868|\u542f\u52a8\u9879", re.I)),
)

NEGATION_RE = re.compile(
    r"(?:\b(?:do not|don't|never|must not|should not|cannot|can't|without)\b|"
    r"\u4e0d\u8981|\u4e0d\u5f97|\u7981\u6b62|\u5207\u52ff|\u65e0\u9700|\u4e0d\u5141\u8bb8)",
    re.I,
)
REMOTE_RE = re.compile(r"https?://|\b(?:webhook|remote|server|endpoint|third[- ]party)\b|\u8fdc\u7a0b|\u5916\u90e8\u670d\u52a1|\u7b2c\u4e09\u65b9", re.I)
CONDITION_RE = re.compile(r"\b(?:if|when|unless|after|before|on first run|in case)\b|\u5982\u679c|\u5f53|\u4e4b\u540e|\u4e4b\u524d|\u9996\u6b21\u8fd0\u884c", re.I)
EXAMPLE_RE = re.compile(r"\b(?:example|sample|demo|illustration|malicious case|attack example)\b|\u4f8b\u5982|\u793a\u4f8b|\u6848\u4f8b|\u6f14\u793a|\u653b\u51fb\u6837\u4f8b", re.I)
WARNING_RE = re.compile(r"\b(?:warning|risk|danger|malicious|attack|detection rule)\b|\u8b66\u544a|\u98ce\u9669|\u5371\u9669|\u6076\u610f|\u653b\u51fb|\u68c0\u6d4b\u89c4\u5219", re.I)
COMMAND_RE = re.compile(r"\b(?:please|must|shall|immediately|always|first|then)\b|\u8bf7|\u5fc5\u987b|\u7acb\u5373|\u59cb\u7ec8|\u7136\u540e", re.I)
ACTOR_RE = {
    "AGENT": re.compile(r"\b(?:agent|assistant|model|you)\b|\u667a\u80fd\u4f53|\u52a9\u624b|\u6a21\u578b|\u4f60", re.I),
    "USER": re.compile(r"\buser\b|\u7528\u6237", re.I),
    "SCRIPT": re.compile(r"\b(?:script|program|process|command)\b|\u811a\u672c|\u7a0b\u5e8f|\u8fdb\u7a0b|\u547d\u4ee4", re.I),
}

CATEGORY_WEIGHTS = {
    "prompt_control": 3,
    "shell": 3,
    "network": 2,
    "credential_access": 3,
    "filesystem": 1,
    "destructive": 5,
    "persistence": 3,
    "concealment": 2,
}

HIDDEN_SOURCE_MARKERS = (
    "lsb", "hidden", "metadata", "comment", "notes", "trailing",
    "embedded", "attribute", "id3", "exif", "flate-stream", "qr:",
    "cross-media:",
)


def _split_sentences(text: str) -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    pieces = re.split(r"\n+|(?<=[!?\u3002\uff01\uff1f;\uff1b])\s*|(?<=\.)\s+(?=[A-Z0-9\"'])", normalized)
    return [" ".join(piece.split()) for piece in pieces if len(" ".join(piece.split())) >= 4][:80]


def _negated_at(sentence: str, action_start: int) -> bool:
    prefix = sentence[max(0, action_start - 48):action_start]
    matches = list(NEGATION_RE.finditer(prefix))
    if not matches:
        return False
    tail = prefix[matches[-1].end():]
    # A sentence boundary or contrastive conjunction ends the simple local scope.
    return not re.search(r"[.;!?\u3002\uff01\uff1f]|\b(?:but|however|instead)\b|\u4f46\u662f|\u7136\u800c", tail, re.I)


def _source_tags(source: str, transform_chain: list[str]) -> list[str]:
    lowered = source.lower()
    lowered_chain = [str(value).lower() for value in transform_chain]
    tags = ["UNTRUSTED_MULTIMODAL"]
    if (
        any(marker in lowered for marker in HIDDEN_SOURCE_MARKERS)
        or any(any(marker in value for marker in ("metadata", "hidden", "lsb", "archive", "tail")) for value in lowered_chain)
    ):
        tags.append("HIDDEN_OR_AUXILIARY")
    else:
        tags.append("SURFACE_CONTENT")
    semantic_transforms = {
        "base64", "base64url", "base32", "hex", "binary", "morse",
        "rot13", "reverse", "url-percent", "least-significant-bit",
    }
    if semantic_transforms.intersection(transform_chain):
        tags.append("DECODED_CONTENT")
    return tags


def _event_categories(event: dict[str, Any]) -> set[str]:
    action = event["action"]
    objects = set(event["objects"])
    categories: set[str] = set()
    if action == "EXECUTE":
        categories.add("shell")
    if action in {"SEND", "DOWNLOAD"}:
        categories.add("network")
    if action in {"READ", "WRITE", "DELETE"} and "FILE" in objects:
        categories.add("filesystem")
    if action in {"READ", "WRITE", "SEND"} and objects.intersection({"CREDENTIAL", "ENVIRONMENT", "USER_DATA"}):
        categories.add("credential_access")
    if action == "DELETE":
        categories.add("destructive")
    if action == "PERSIST":
        categories.add("persistence")
    return categories


def _task_alignment(events: list[dict[str, Any]], skill_profile: dict[str, Any]) -> str:
    positive = [event for event in events if not event["negated"]]
    if not positive:
        return "NOT_APPLICABLE"
    declared_actions = set(skill_profile.get("declared_actions", []))
    declared_objects = set(skill_profile.get("declared_objects", []))
    sensitive = {"CREDENTIAL", "ENVIRONMENT", "USER_DATA", "SYSTEM_CONFIG"}
    if any(set(event["objects"]).intersection(sensitive - declared_objects) for event in positive):
        return "OUT_OF_SCOPE"
    if declared_actions and all(event["action"] in declared_actions for event in positive):
        return "LIKELY_ALIGNED"
    return "UNKNOWN"


def _tag_sentence(
    sentence: str,
    item: dict[str, Any],
    candidate_id: str,
    sentence_index: int,
    skill_profile: dict[str, Any],
) -> dict[str, Any]:
    objects = [name for name, pattern in OBJECT_PATTERNS if pattern.search(sentence)]
    actors = [name for name, pattern in ACTOR_RE.items() if pattern.search(sentence)] or ["IMPLICIT_AGENT"]
    events: list[dict[str, Any]] = []
    seen_event_types: set[tuple[str, bool]] = set()
    # Do not interpret URL path tokens such as "/collect" as natural-language
    # action verbs. Keep string length stable so event spans remain valid.
    action_text = re.sub(r"https?://[^\s<>\"']+", lambda match: " " * len(match.group(0)), sentence, flags=re.I)
    for action, pattern in ACTION_PATTERNS:
        for match in pattern.finditer(action_text):
            negated = _negated_at(sentence, match.start())
            event_key = (action, negated)
            if event_key in seen_event_types:
                continue
            seen_event_types.add(event_key)
            event = {
                "action": action,
                "actor": actors[0],
                "objects": objects.copy(),
                "destination": "REMOTE" if REMOTE_RE.search(sentence) else "LOCAL_OR_UNSPECIFIED",
                "negated": negated,
                "span": [match.start(), match.end()],
            }
            event["categories"] = sorted(_event_categories(event))
            events.append(event)
    raw_score, raw_categories = _instruction_signal(sentence)
    actionable_categories: set[str] = set()
    for event in events:
        if not event["negated"]:
            actionable_categories.update(event["categories"])
    if "prompt_control" in raw_categories and not NEGATION_RE.search(sentence):
        actionable_categories.add("prompt_control")
    if "concealment" in raw_categories:
        actionable_categories.add("concealment")
    context_role = "INSTRUCTION"
    if EXAMPLE_RE.search(sentence):
        context_role = "EXAMPLE"
    elif WARNING_RE.search(sentence):
        context_role = "WARNING_OR_ANALYSIS"
    elif events and all(event["negated"] for event in events):
        context_role = "PROHIBITION"
    elif not (COMMAND_RE.search(sentence) or events):
        context_role = "DESCRIPTION"
    source_tags = _source_tags(item["source"], list(item.get("transform_chain", [])))
    alignment = _task_alignment(events, skill_profile)
    actionable_score = sum(CATEGORY_WEIGHTS.get(category, 0) for category in actionable_categories)
    adjustment = 0
    reasons: list[str] = []
    hidden = "HIDDEN_OR_AUXILIARY" in source_tags
    if events and all(event["negated"] for event in events):
        adjustment -= 3
        reasons.append("all detected actions are locally negated")
    if context_role in {"EXAMPLE", "WARNING_OR_ANALYSIS"} and not hidden:
        adjustment -= 2
        reasons.append("surface content is marked as example/warning analysis")
    if alignment == "OUT_OF_SCOPE" and actionable_categories:
        adjustment += 1
        reasons.append("action appears outside declared skill capabilities")
    if hidden and actionable_categories:
        adjustment += 1
        reasons.append("actionable instruction originates from hidden/auxiliary content")
    if "DECODED_CONTENT" in source_tags and actionable_categories:
        adjustment += 1
        reasons.append("actionable instruction required semantic decoding")
    hard_floor = bool(
        actionable_categories.intersection({"destructive", "persistence"})
        or {"credential_access", "network"}.issubset(actionable_categories)
        or ("prompt_control" in actionable_categories and actionable_categories.intersection({"shell", "network"}))
    )
    adjusted_score = max(0, actionable_score + adjustment)
    if hard_floor and actionable_score:
        adjusted_score = max(3, adjusted_score)
    decision = "KEEP"
    if not actionable_categories and raw_score:
        decision = "DENOISED_NON_ACTIONABLE"
    elif adjusted_score < 3:
        decision = "DENOISED_CONTEXT"
    elif adjustment < 0:
        decision = "DOWNGRADED"
    return {
        "candidate_id": candidate_id,
        "sentence_index": sentence_index,
        "file": item["file"],
        "source": item["source"],
        "transform_chain": item.get("transform_chain", []),
        "text_preview": _preview(sentence, 500),
        "provenance_tags": source_tags,
        "speech_act": "PROHIBITION" if context_role == "PROHIBITION" else ("COMMAND" if COMMAND_RE.search(sentence) or events else "STATEMENT"),
        "context_role": context_role,
        "polarity": "NEGATED" if events and all(event["negated"] for event in events) else "AFFIRMATIVE_OR_MIXED",
        "modality": (
            "PROHIBITED" if context_role == "PROHIBITION" else
            "REQUIRED" if re.search(r"\b(?:must|shall)\b|\u5fc5\u987b|\u5e94\u5f53", sentence, re.I) else
            "OPTIONAL" if re.search(r"\b(?:may|can|could)\b|\u53ef\u4ee5|\u53ef\u80fd", sentence, re.I) else
            "UNSPECIFIED"
        ),
        "actors": actors,
        "objects": objects,
        "destination": "REMOTE" if REMOTE_RE.search(sentence) else "LOCAL_OR_UNSPECIFIED",
        "condition_present": bool(CONDITION_RE.search(sentence)),
        "concealment": "concealment" in raw_categories,
        "task_alignment": alignment,
        "raw_signal_score": raw_score,
        "raw_categories": raw_categories,
        "actionable_categories": sorted(actionable_categories),
        "context_adjustment": adjustment,
        "adjustment_reasons": reasons,
        "adjusted_signal_score": adjusted_score,
        "hard_risk_floor": hard_floor,
        "context_decision": decision,
        "confidence": item.get("confidence", 0.7),
        "events": events,
    }


REFERENCE_PATTERNS: tuple[tuple[str, re.Pattern[str], set[str]], ...] = (
    ("FILE_REFERENCE", re.compile(r"\b(?:the|this|that|said|above)\s+(?:file|report|document)\b|\u8be5\u6587\u4ef6|\u4e0a\u8ff0\u6587\u4ef6|\u8be5\u62a5\u544a", re.I), {"FILE", "RESULT"}),
    ("RESULT_REFERENCE", re.compile(r"\b(?:the|this|that)\s+(?:result|output|response|content|data)\b|\u8be5\u7ed3\u679c|\u4e0a\u8ff0\u7ed3\u679c|\u8f93\u51fa\u5185\u5bb9|\u8fd9\u4e9b\u5185\u5bb9|\u4e0a\u8ff0\u4fe1\u606f", re.I), {"RESULT", "FILE", "CREDENTIAL", "ENVIRONMENT", "USER_DATA"}),
    ("PRONOUN", re.compile(r"\b(?:it|this|that|them|they)\b|\u5b83|\u5b83\u4eec|\u5176|\u8fd9\u4e9b|\u4e0a\u8ff0\u5185\u5bb9", re.I), {"RESULT", "FILE", "CREDENTIAL", "ENVIRONMENT", "USER_DATA", "SYSTEM_CONFIG"}),
)

FILE_NAME_RE = re.compile(r"(?<![\w.-])(?:[A-Za-z]:\\[^\s<>\"']+|/(?:[^\s/]+/)*[^\s/]+|[\w.-]+\.(?:txt|json|csv|log|md|pdf|docx|zip))(?![\w-])", re.I)
URL_ENTITY_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SENSITIVE_ENTITY_TYPES = {"CREDENTIAL", "ENVIRONMENT", "USER_DATA", "SYSTEM_CONFIG"}


def _sentence_event_ids(events: list[dict[str, Any]], candidate_id: str, sentence_index: int) -> list[str]:
    return [
        event["id"]
        for event in events
        if event["candidate_id"] == candidate_id and event["sentence_index"] == sentence_index
    ]


def _extract_graph_entities(
    sentences: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    for sentence in sentences:
        candidate_id = sentence["candidate_id"]
        sentence_index = sentence["sentence_index"]
        sentence_events = [
            event for event in events
            if event["candidate_id"] == candidate_id and event["sentence_index"] == sentence_index
        ]
        positive_events = [event for event in sentence_events if not event["negated"]]
        producer = next(
            (event for event in positive_events if event["action"] in {"WRITE", "DECODE", "DOWNLOAD"}),
            None,
        )
        reader = next((event for event in positive_events if event["action"] == "READ"), None)
        labels: list[tuple[str, str, str]] = []
        for object_type in sentence["objects"]:
            labels.append((object_type, object_type.lower(), "OUTPUT" if producer and object_type == "FILE" else "MENTION"))
        for match in FILE_NAME_RE.finditer(sentence["text_preview"]):
            labels.append(("FILE", match.group(0), "OUTPUT" if producer else "MENTION"))
        for match in URL_ENTITY_RE.finditer(sentence["text_preview"]):
            labels.append(("REMOTE_DESTINATION", match.group(0), "DESTINATION"))
        if producer and not any(entity_type in {"FILE", "RESULT"} for entity_type, _, _ in labels):
            labels.append(("RESULT", f"result@{sentence_index}", "OUTPUT"))
        seen_labels: set[tuple[str, str]] = set()
        for entity_type, label, role in labels:
            key = (entity_type, label.lower())
            if key in seen_labels:
                continue
            seen_labels.add(key)
            origin_event_ids: list[str] = []
            producer_event_id: str | None = producer["id"] if producer and role == "OUTPUT" else None
            if entity_type in SENSITIVE_ENTITY_TYPES and reader:
                origin_event_ids = [reader["id"]]
                producer_event_id = reader["id"]
            entities.append(
                {
                    "id": f"N{len(entities) + 1}",
                    "candidate_id": candidate_id,
                    "sentence_index": sentence_index,
                    "file": sentence["file"],
                    "source": sentence["source"],
                    "type": entity_type,
                    "label": label[:240],
                    "role": role,
                    "producer_event_id": producer_event_id,
                    "taint_types": [entity_type] if entity_type in SENSITIVE_ENTITY_TYPES else [],
                    "origin_event_ids": origin_event_ids,
                }
            )
    return entities


def _extract_reference_mentions(sentence: dict[str, Any]) -> list[dict[str, Any]]:
    mentions: list[dict[str, Any]] = []
    text = sentence["text_preview"]
    occupied: list[tuple[int, int]] = []
    for reference_type, pattern, expected_types in REFERENCE_PATTERNS:
        for match in pattern.finditer(text):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            occupied.append((match.start(), match.end()))
            mentions.append(
                {
                    "reference_type": reference_type,
                    "text": match.group(0),
                    "span": [match.start(), match.end()],
                    "expected_types": sorted(expected_types),
                }
            )
    return mentions


def _antecedent_score(
    mention: dict[str, Any],
    entity: dict[str, Any],
    sentence_index: int,
) -> float:
    distance = sentence_index - entity["sentence_index"]
    if distance <= 0 or distance > 24:
        return 0.0
    score = max(0.15, 0.92 - 0.055 * distance)
    expected = set(mention["expected_types"])
    if entity["type"] in expected:
        score += 0.18
    else:
        score -= 0.32
    if entity["role"] == "OUTPUT" and mention["reference_type"] in {"RESULT_REFERENCE", "PRONOUN"}:
        score += 0.12
    if mention["reference_type"] == "FILE_REFERENCE" and entity["type"] != "FILE":
        score -= 0.2
    return max(0.0, min(0.99, score))


def _resolve_references(
    sentences: list[dict[str, Any]],
    entities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for sentence in sentences:
        mentions = _extract_reference_mentions(sentence)
        sentence["reference_mentions"] = [mention["text"] for mention in mentions]
        for mention in mentions:
            scored: list[tuple[float, dict[str, Any]]] = []
            for entity in entities:
                if entity["candidate_id"] != sentence["candidate_id"]:
                    continue
                score = _antecedent_score(mention, entity, sentence["sentence_index"])
                if score >= 0.42:
                    scored.append((score, entity))
            scored.sort(key=lambda pair: (-pair[0], -pair[1]["sentence_index"], pair[1]["id"]))
            candidates = [
                {
                    "entity_id": entity["id"],
                    "entity_type": entity["type"],
                    "label": entity["label"],
                    "score": round(score, 3),
                }
                for score, entity in scored[:3]
            ]
            references.append(
                {
                    "id": f"R{len(references) + 1}",
                    "candidate_id": sentence["candidate_id"],
                    "sentence_index": sentence["sentence_index"],
                    "file": sentence["file"],
                    **mention,
                    "candidates": candidates,
                    "resolved_entity_ids": [candidate["entity_id"] for candidate in candidates if candidate["score"] >= 0.55],
                    "ambiguous": len(candidates) > 1 and abs(candidates[0]["score"] - candidates[1]["score"]) < 0.12,
                }
            )
    return references


def _propagate_taint(
    sentences: list[dict[str, Any]],
    events: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    references: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    entity_by_id = {entity["id"]: entity for entity in entities}
    refs_by_sentence: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for reference in references:
        refs_by_sentence.setdefault((reference["candidate_id"], reference["sentence_index"]), []).append(reference)
    entities_by_sentence: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for entity in entities:
        entities_by_sentence.setdefault((entity["candidate_id"], entity["sentence_index"]), []).append(entity)
    events_by_sentence: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for event in events:
        events_by_sentence.setdefault((event["candidate_id"], event["sentence_index"]), []).append(event)

    for sentence in sentences:
        key = (sentence["candidate_id"], sentence["sentence_index"])
        sentence_refs = refs_by_sentence.get(key, [])
        antecedents: list[tuple[dict[str, Any], float]] = []
        for reference in sentence_refs:
            score_by_id = {candidate["entity_id"]: candidate["score"] for candidate in reference["candidates"]}
            for entity_id in reference["resolved_entity_ids"]:
                entity = entity_by_id.get(entity_id)
                if entity:
                    antecedents.append((entity, score_by_id.get(entity_id, 0.55)))
        inherited_taints = sorted({taint for entity, _ in antecedents for taint in entity["taint_types"]})
        inherited_origins = sorted({origin for entity, _ in antecedents for origin in entity["origin_event_ids"]})
        sentence_events = events_by_sentence.get(key, [])
        positive_events = [event for event in sentence_events if not event["negated"]]
        output_entities = [entity for entity in entities_by_sentence.get(key, []) if entity["role"] == "OUTPUT"]
        transform_event = next((event for event in positive_events if event["action"] in {"WRITE", "DECODE", "DOWNLOAD"}), None)
        if transform_event and inherited_taints:
            for entity in output_entities:
                entity["taint_types"] = sorted(set(entity["taint_types"]) | set(inherited_taints))
                entity["origin_event_ids"] = sorted(set(entity["origin_event_ids"]) | set(inherited_origins))
                entity["producer_event_id"] = transform_event["id"]
            for antecedent, confidence in antecedents:
                if not antecedent["taint_types"]:
                    continue
                source_event = antecedent.get("producer_event_id") or (antecedent["origin_event_ids"][0] if antecedent["origin_event_ids"] else None)
                if source_event:
                    edges.append(
                        {
                            "from": source_event,
                            "to": transform_event["id"],
                            "type": "TAINT_PROPAGATION",
                            "entity_id": antecedent["id"],
                            "confidence": round(confidence, 3),
                        }
                    )
        for sink_event in positive_events:
            if sink_event["action"] != "SEND" or sink_event["destination"] != "REMOTE":
                continue
            explicit_taints = set(sink_event["objects"]).intersection(SENSITIVE_ENTITY_TYPES)
            taints = sorted(set(inherited_taints) | explicit_taints)
            origins = inherited_origins.copy()
            if explicit_taints and not origins:
                origins = [sink_event["id"]]
            if not taints:
                continue
            producer_ids = sorted({
                entity["producer_event_id"]
                for entity, _ in antecedents
                if entity.get("producer_event_id")
            })
            event_ids = list(dict.fromkeys(origins + producer_ids + [sink_event["id"]]))
            confidence = min((score for entity, score in antecedents if entity["taint_types"]), default=0.9)
            for producer_id in producer_ids or origins:
                if producer_id != sink_event["id"]:
                    edges.append(
                        {
                            "from": producer_id,
                            "to": sink_event["id"],
                            "type": "COREFERENCE_DATA_FLOW",
                            "confidence": round(confidence, 3),
                        }
                    )
            chains.append(
                {
                    "type": "TAINTED_DATA_TO_REMOTE",
                    "severity": "CRITICAL",
                    "event_ids": event_ids,
                    "taint_types": taints,
                    "categories": ["credential_access", "network"],
                    "confidence": round(confidence, 3),
                    "resolution_mode": "multi_candidate_coreference",
                }
            )
    return chains


def _build_behavior_graph(sentences: list[dict[str, Any]]) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    chains: list[dict[str, Any]] = []
    for sentence in sentences:
        previous_id: str | None = None
        for event in sentence["events"]:
            event_id = f"E{len(events) + 1}"
            node = {
                "id": event_id,
                "candidate_id": sentence["candidate_id"],
                "sentence_index": sentence["sentence_index"],
                "file": sentence["file"],
                "source": sentence["source"],
                **event,
            }
            events.append(node)
            if previous_id:
                edges.append({"from": previous_id, "to": event_id, "type": "SAME_SENTENCE_SEQUENCE"})
            previous_id = event_id
    entities = _extract_graph_entities(sentences, events)
    references = _resolve_references(sentences, entities)
    chains.extend(_propagate_taint(sentences, events, entities, references, edges))

    by_candidate: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_candidate.setdefault(event["candidate_id"], []).append(event)
    seen_chains: set[tuple[str, str, str]] = set()
    for candidate_events in by_candidate.values():
        positive = [event for event in candidate_events if not event["negated"]]
        for source_event in positive:
            if source_event["action"] not in {"READ", "WRITE"}:
                continue
            if not set(source_event["objects"]).intersection(SENSITIVE_ENTITY_TYPES):
                continue
            for sink_event in positive:
                if sink_event["action"] != "SEND" or sink_event["destination"] != "REMOTE":
                    continue
                distance = sink_event["sentence_index"] - source_event["sentence_index"]
                if not 0 <= distance <= 3:
                    continue
                chain_key = (source_event["id"], sink_event["id"], "SENSITIVE_DATA_EXFILTRATION")
                if chain_key in seen_chains:
                    continue
                seen_chains.add(chain_key)
                edges.append({"from": source_event["id"], "to": sink_event["id"], "type": "DATA_FLOW_TO_REMOTE"})
                chains.append(
                    {
                        "type": "SENSITIVE_DATA_EXFILTRATION",
                        "severity": "CRITICAL",
                        "event_ids": [source_event["id"], sink_event["id"]],
                        "categories": ["credential_access", "network"],
                        "confidence": 0.9,
                        "resolution_mode": "bounded_event_window",
                    }
                )
    deduped_chains: list[dict[str, Any]] = []
    seen_chain_signatures: set[tuple[str, tuple[str, ...]]] = set()
    for chain in chains:
        signature = (chain["type"], tuple(chain["event_ids"]))
        if signature in seen_chain_signatures:
            continue
        seen_chain_signatures.add(signature)
        deduped_chains.append(chain)
    return {
        "event_count": len(events),
        "entity_count": len(entities),
        "reference_count": len(references),
        "events": events[:160],
        "entities": entities[:200],
        "references": references[:160],
        "edges": edges[:320],
        "chains": deduped_chains[:60],
    }


def _semantic_analysis(
    candidates: list[dict[str, Any]],
    skill_profile: dict[str, Any],
) -> dict[str, Any]:
    sentences: list[dict[str, Any]] = []
    instructions: list[dict[str, Any]] = []
    seen_sentences: set[tuple[str, str]] = set()
    ordered = sorted(candidates, key=lambda item: float(item.get("confidence", 0.0)), reverse=True)
    for candidate_number, item in enumerate(ordered[:MAX_TEXT_CANDIDATES], start=1):
        candidate_id = f"C{candidate_number}"
        for sentence_index, sentence in enumerate(_split_sentences(item["text"]), start=1):
            key = (item["file"], sentence.lower())
            if key in seen_sentences:
                continue
            seen_sentences.add(key)
            tagged = _tag_sentence(sentence, item, candidate_id, sentence_index, skill_profile)
            sentences.append(tagged)
            if tagged["adjusted_signal_score"] < 3 or not tagged["actionable_categories"]:
                continue
            instructions.append(
                {
                    "file": tagged["file"],
                    "source": tagged["source"],
                    "transform_chain": tagged["transform_chain"],
                    "text_preview": tagged["text_preview"],
                    "signal_score": tagged["adjusted_signal_score"],
                    "raw_signal_score": tagged["raw_signal_score"],
                    "categories": tagged["actionable_categories"],
                    "semantic_tags": {
                        "speech_act": tagged["speech_act"],
                        "context_role": tagged["context_role"],
                        "polarity": tagged["polarity"],
                        "modality": tagged["modality"],
                        "actors": tagged["actors"],
                        "objects": tagged["objects"],
                        "destination": tagged["destination"],
                        "task_alignment": tagged["task_alignment"],
                        "provenance": tagged["provenance_tags"],
                    },
                    "context_decision": tagged["context_decision"],
                    "context_adjustment": tagged["context_adjustment"],
                    "adjustment_reasons": tagged["adjustment_reasons"],
                    "hard_risk_floor": tagged["hard_risk_floor"],
                    "confidence": tagged["confidence"],
                }
            )
            if len(sentences) >= 160:
                break
        if len(sentences) >= 160:
            break
    graph = _build_behavior_graph(sentences)
    event_by_id = {event["id"]: event for event in graph["events"]}
    for chain in graph["chains"]:
        chain_events = [event_by_id[event_id] for event_id in chain["event_ids"] if event_id in event_by_id]
        if not chain_events:
            continue
        instructions.append(
            {
                "file": chain_events[0]["file"],
                "source": chain_events[0]["source"],
                "transform_chain": ["cross-sentence-behavior-graph"],
                "text_preview": " -> ".join(f"{event['action']}({','.join(event['objects']) or 'UNKNOWN'})" for event in chain_events),
                "signal_score": 8,
                "raw_signal_score": 8,
                "categories": chain["categories"],
                "semantic_tags": {
                    "behavior_chain": chain["type"],
                    "event_ids": chain["event_ids"],
                    "taint_types": chain.get("taint_types", []),
                    "resolution_mode": chain.get("resolution_mode", "event_graph"),
                },
                "context_decision": "KEEP_GRAPH_CHAIN",
                "context_adjustment": 0,
                "adjustment_reasons": ["cross-sentence sensitive data flow reached remote sink"],
                "hard_risk_floor": True,
                "confidence": float(chain.get("confidence", 0.94)),
            }
        )
    instructions = sorted(instructions, key=lambda item: (-item["signal_score"], item["file"]))[:40]
    return {
        "sentence_count": len(sentences),
        "sentences": sentences,
        "instructions": instructions,
        "behavior_graph": graph,
        "denoised_sentence_count": sum(tagged["context_decision"].startswith("DENOISED") for tagged in sentences),
    }


TOOL_BY_CATEGORY = {
    "shell": "shell.execute",
    "network": "network.request",
    "credential_access": "credential.read",
    "filesystem": "filesystem.access",
    "destructive": "filesystem.destructive_write",
    "persistence": "system.persistence_change",
}


def _project_tool_calls(instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for instruction in instructions:
        for category in instruction["categories"]:
            tool = TOOL_BY_CATEGORY.get(category)
            if not tool:
                continue
            key = (instruction["file"], tool)
            if key in seen:
                continue
            seen.add(key)
            projected.append(
                {
                    "file": instruction["file"],
                    "tool": tool,
                    "source": instruction["source"],
                    "status": "blocked",
                    "execution_mode": "projection_only",
                    "reason": "untrusted multimodal-derived instruction reached a sensitive tool sink",
                    "instruction_preview": instruction["text_preview"],
                }
            )
    return projected


def _finding(
    rule_id: str,
    severity: str,
    file: str,
    description: str,
    snippet: str,
    *,
    evidence_type: str = "multimodal_hidden_instruction",
    confidence: float = 0.85,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "kill_chain_phase": "execution",
        "file": file,
        "line": 0,
        "pattern": "media_pipeline",
        "matched_text": snippet[:160],
        "description": description,
        "confidence": confidence,
        "context": snippet[:500],
        "original_severity": severity,
        "evidence_type": evidence_type,
        "context_type": "media_resource",
        "snippet": snippet[:220],
        "downgraded": False,
        "downgrade_reason": None,
        "lifecycle_stage": "governance",
    }


def _severity_for_instruction(instruction: dict[str, Any]) -> str:
    categories = set(instruction["categories"])
    if "destructive" in categories:
        return "CRITICAL"
    if {"credential_access", "network"}.issubset(categories):
        return "CRITICAL"
    if "prompt_control" in categories and ({"shell", "network", "persistence"} & categories):
        return "CRITICAL"
    if {"shell", "network", "credential_access", "persistence"} & categories:
        return "HIGH"
    return "MEDIUM"


def _build_skill_profile(skill_root: Path) -> dict[str, Any]:
    skill_md = skill_root / "SKILL.md"
    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")[:16384]
    except OSError:
        text = ""
    declared_actions = sorted({name for name, pattern in ACTION_PATTERNS if pattern.search(text)})
    declared_objects = sorted({name for name, pattern in OBJECT_PATTERNS if pattern.search(text)})
    title = ""
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            title = line.lstrip("# ").strip()[:160]
            break
    return {
        "skill_md_present": skill_md.is_file(),
        "title": title,
        "declared_actions": declared_actions,
        "declared_objects": declared_objects,
        "profile_method": "static_action_object_tags",
    }


def _analyze_media_file(
    path: Path,
    skill_root: Path,
    skill_profile: dict[str, Any],
    *,
    run_raster_adapters: bool = True,
) -> dict[str, Any] | None:
    try:
        data, truncated = _read_media_bytes(path)
        size = path.stat().st_size
        digest = _sha256_file(path)
    except OSError as exc:
        return {
            "file": str(path),
            "kind": "unknown",
            "error": str(exc),
            "findings": [],
            "candidates": [],
            "instructions": [],
            "tool_calls": [],
        }
    kind, extension_type, detected_type = _media_kind(path, data)
    if not kind:
        return None
    rel = path.relative_to(skill_root).as_posix()
    if detected_type == "container/mp4" and extension_type:
        media_type = extension_type
    elif detected_type == "container/mp4":
        media_type = "video/mp4"
    else:
        media_type = detected_type or extension_type
    raw_stage: dict[str, Any] = {
        "size_bytes": size,
        "sha256": digest,
        "extension_type": extension_type,
        "detected_type": detected_type,
        "bytes_truncated": truncated,
    }
    parse_stage: dict[str, Any] = {"media_type": media_type, "extractors": []}
    seed: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    if extension_type and detected_type and extension_type != detected_type:
        # jpg/jpeg and MPEG aliases are normalized before comparison where needed.
        aliases = {
            ("image/jpg", "image/jpeg"),
            ("audio/mp3", "audio/mpeg"),
            ("audio/mp4", "container/mp4"),
            ("video/mp4", "container/mp4"),
            ("video/quicktime", "container/mp4"),
        }
        if (extension_type, detected_type) not in aliases:
            findings.append(
                _finding(
                    "MM-BYTE-001",
                    "MEDIUM",
                    rel,
                    "Media extension and file signature disagree.",
                    f"extension={extension_type}, magic={detected_type}",
                    evidence_type="parser_differential",
                    confidence=0.98,
                )
            )

    for text in _extract_printable_runs(data, minimum=8, limit=50):
        item = _candidate(rel, text, "raw-bytes:strings", ("printable-strings",), 0.45)
        if item:
            seed.append(item)
    parsed: dict[str, Any] = {}
    parsed_candidates: list[dict[str, Any]] = []
    if media_type == "image/png":
        parsed, parsed_candidates = _parse_png(data, rel)
        parse_stage["extractors"].append("png-chunks")
        pixels = _png_pixel_bytes(data)
        if pixels:
            pixel_bytes, channels = pixels
            seed.extend(_lsb_candidates(rel, pixel_bytes, channels, "png-pixels"))
            parse_stage["extractors"].append("png-lsb")
    elif media_type == "image/jpeg":
        parsed, parsed_candidates = _parse_jpeg(data, rel)
        parse_stage["extractors"].append("jpeg-segments")
    elif media_type == "image/gif":
        parsed, parsed_candidates = _parse_gif(data, rel)
        parse_stage["extractors"].append("gif-comments")
    elif media_type == "image/svg+xml":
        parsed, parsed_candidates = _parse_svg(data, rel)
        parse_stage["extractors"].append("svg-xml")
    elif media_type == "audio/wav":
        parsed, low_bytes, channels = _wav_sample_bytes(data)
        parse_stage["extractors"].append("wav-riff-pcm")
        if low_bytes:
            seed.extend(_lsb_candidates(rel, low_bytes, channels, "wav-pcm"))
            parse_stage["extractors"].append("wav-lsb")
        dtmf = _detect_dtmf(data)
        if dtmf:
            item = _candidate(rel, dtmf, "wav:dtmf", ("goertzel-dtmf",), 0.82)
            if item:
                seed.append(item)
            parse_stage["extractors"].append("wav-dtmf")
    elif media_type == "audio/mpeg":
        parsed, parsed_candidates = _parse_id3(data, rel)
        parse_stage["extractors"].append("id3-frames")
    elif media_type == "document/pdf":
        parsed, parsed_candidates = _parse_pdf(data, rel)
        parse_stage["extractors"].append("pdf-objects-and-streams")
    elif media_type and media_type.startswith("document/") and path.suffix.lower() in {".docx", ".pptx", ".xlsx"}:
        parsed, parsed_candidates = _parse_ooxml(data, rel, media_type)
        parse_stage["extractors"].append("ooxml-zip-xml")
    elif extension_type and extension_type.startswith("subtitle/"):
        parsed, parsed_candidates = _parse_subtitle(data, rel, path.suffix)
        parse_stage["extractors"].append("subtitle-text")
    elif kind == "video" and media_type in {"video/mp4", "video/quicktime"}:
        parsed, parsed_candidates = _parse_mp4(data, rel)
        parse_stage["extractors"].append("iso-bmff-boxes")
    else:
        parsed = {"parser": "generic-container-strings"}
        parse_stage["extractors"].append("generic-strings")
    seed.extend(parsed_candidates)

    if kind == "image" and media_type != "image/svg+xml" and run_raster_adapters:
        try:
            adapter_report = analyze_raster_symbols(
                path,
                relative_path=rel,
                media_type=str(media_type),
                data=data,
            )
        except Exception as exc:  # adapters must fail closed without aborting the scan
            adapter_report = {
                "observations": [],
                "capabilities": {
                    "ocr": {"available": False, "attempted": False, "errors": [str(exc)[:1000]]},
                    "qr": {"available": False, "attempted": False, "errors": [str(exc)[:1000]]},
                },
                "execution_policy": "symbol_recovery_only_never_execute",
            }
        parse_stage["symbol_adapters"] = {
            "capabilities": adapter_report.get("capabilities", {}),
            "observation_count": len(adapter_report.get("observations", [])),
            "execution_policy": adapter_report.get("execution_policy"),
        }
        for observation in adapter_report.get("observations", []):
            item = _candidate(
                rel,
                str(observation.get("text", "")),
                str(observation.get("source", "raster-adapter")),
                observation.get("transform_chain", []),
                float(observation.get("confidence", 0.75)),
                metadata=observation,
            )
            if item:
                seed.append(item)
        if adapter_report.get("observations"):
            parse_stage["extractors"].append("raster-symbol-adapters")
    elif kind == "image" and media_type != "image/svg+xml":
        parse_stage["symbol_adapters"] = {
            "capabilities": {
                "ocr": {
                    "available": False,
                    "operational": False,
                    "attempted": False,
                    "errors": ["package raster-adapter file budget exhausted"],
                },
                "qr": {
                    "available": False,
                    "operational": False,
                    "attempted": False,
                    "errors": ["package raster-adapter file budget exhausted"],
                },
            },
            "observation_count": 0,
            "execution_policy": "symbol_recovery_only_never_execute",
        }
    parse_stage["details"] = parsed
    if parsed.get("risk_flags"):
        findings.append(
            _finding(
                "MM-PARSE-002",
                "HIGH",
                rel,
                "Multimodal resource contains hidden, active, or externally referenced content.",
                ", ".join(str(flag) for flag in parsed["risk_flags"]),
                evidence_type="hidden_or_active_content",
                confidence=0.9,
            )
        )

    logical_end = _logical_end(media_type, data, parsed)
    if logical_end is not None and len(data) > logical_end:
        trailing = data[logical_end:]
        if trailing.strip(b"\x00\r\n\t "):
            raw_stage["trailing_bytes"] = len(trailing)
            findings.append(
                _finding(
                    "MM-BYTE-002",
                    "HIGH",
                    rel,
                    "Non-padding bytes exist after the media container's logical end.",
                    f"{len(trailing)} trailing bytes after offset {logical_end}",
                    evidence_type="appended_payload",
                    confidence=0.97,
                )
            )
            for text in _extract_printable_runs(trailing, minimum=5, limit=24):
                item = _candidate(rel, text, "trailing-bytes", ("container-tail",), 0.9)
                if item:
                    seed.append(item)

    archives, archive_candidates = _embedded_archives(data, rel)
    if archives:
        parse_stage["embedded_archives"] = archives
        seed.extend(archive_candidates)
        findings.append(
            _finding(
                "MM-PARSE-001",
                "HIGH",
                rel,
                "Archive signature embedded inside a multimodal resource.",
                ", ".join(f"{item['type']}@{item['offset']}" for item in archives),
                evidence_type="embedded_archive",
                confidence=0.98,
            )
        )

    recovered = _recover_symbols(seed)
    semantic_analysis = _semantic_analysis(recovered, skill_profile)
    instructions = semantic_analysis["instructions"]
    tool_calls = _project_tool_calls(instructions)
    if instructions:
        top = instructions[0]
        severity = _severity_for_instruction(top)
        findings.append(
            _finding(
                "MM-INSTR-001",
                severity,
                rel,
                "Instruction-like content was reconstructed from an untrusted multimodal resource.",
                top["text_preview"],
                confidence=float(top.get("confidence", 0.8)),
            )
        )
    if tool_calls:
        tools = sorted({call["tool"] for call in tool_calls})
        severity = "CRITICAL" if any("destructive" in tool or tool == "credential.read" for tool in tools) else "HIGH"
        findings.append(
            _finding(
                "MM-TOOL-001",
                severity,
                rel,
                "Multimodal-derived instructions project into sensitive agent tool calls; execution was blocked.",
                ", ".join(tools),
                evidence_type="untrusted_media_to_tool_sink",
                confidence=0.93,
            )
        )

    parse_stage["unsupported_but_declared"] = []
    if kind == "image" and media_type != "image/svg+xml":
        capabilities = parse_stage.get("symbol_adapters", {}).get("capabilities", {})
        ocr_status = capabilities.get("ocr", {})
        qr_status = capabilities.get("qr", {})
        if not ocr_status.get("operational"):
            parse_stage["unsupported_but_declared"].append("ocr")
        if not qr_status.get("operational"):
            parse_stage["unsupported_but_declared"].append("qr")
        if media_type == "image/jpeg":
            parse_stage["unsupported_but_declared"].append("jpeg-pixel-lsb")
        if media_type == "image/gif":
            if not ocr_status.get("frames_attempted"):
                parse_stage["unsupported_but_declared"].append("frame-ocr")
            parse_stage["unsupported_but_declared"].append("frame-lsb")
    if kind == "audio":
        parse_stage["unsupported_but_declared"].extend(["spectrogram-ocr", "sstv", "mp3-bitstream-stego"])
    if kind == "video":
        parse_stage["unsupported_but_declared"].extend(["keyframe-ocr", "audio-track-asr", "frame-lsb"])
    if kind == "document" and media_type == "document/pdf":
        parse_stage["unsupported_but_declared"].extend(["scanned-page-ocr", "embedded-file-recursive-scan"])
    missing_live_adapters = [
        capability
        for capability in ("ocr", "qr")
        if capability in parse_stage["unsupported_but_declared"]
    ]
    if missing_live_adapters:
        findings.append(
            _finding(
                "MM-CAP-001",
                "MEDIUM",
                rel,
                "Raster content was not fully inspected because a local symbol-recovery adapter was unavailable or its package budget was exhausted.",
                ", ".join(missing_live_adapters),
                evidence_type="multimodal_capability_gap",
                confidence=0.99,
            )
        )

    return {
        "file": rel,
        "kind": kind,
        "media_type": media_type,
        "raw_bytes": raw_stage,
        "parse_decode": parse_stage,
        "symbol_recovery": {
            "candidate_count": len(recovered),
            "candidates": [
                {key: value for key, value in item.items() if key != "text"}
                for item in recovered[:40]
            ],
        },
        "instruction_reconstruction": {
            "instruction_count": len(instructions),
            "instructions": instructions,
            "semantic_sentence_count": semantic_analysis["sentence_count"],
            "denoised_sentence_count": semantic_analysis["denoised_sentence_count"],
            "semantic_sentences": semantic_analysis["sentences"],
            "behavior_graph": semantic_analysis["behavior_graph"],
        },
        "tool_call": {
            "policy": "never execute media-derived instructions during scanning",
            "projected_count": len(tool_calls),
            "calls": tool_calls,
        },
        "findings": findings,
        "_recovered_candidates": recovered,
    }


def analyze_skill_media(skill_path: str | Path) -> dict[str, Any]:
    """Run the pipeline when a skill contains supported multimodal resources."""
    root = Path(skill_path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Skill path is not a directory: {root}")
    skill_profile = _build_skill_profile(root)
    media_files: list[dict[str, Any]] = []
    package_candidates: list[dict[str, Any]] = []
    raster_adapter_files = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        extension_hint = path.suffix.lower() in MULTIMODAL_EXTENSIONS
        if not extension_hint:
            try:
                with path.open("rb") as handle:
                    extension_hint = _magic_type(handle.read(16)) is not None
            except OSError:
                extension_hint = False
        if not extension_hint:
            continue
        analyzed = _analyze_media_file(
            path,
            root,
            skill_profile,
            run_raster_adapters=raster_adapter_files < MAX_RASTER_ADAPTER_FILES,
        )
        if analyzed:
            if analyzed.get("kind") == "image" and analyzed.get("media_type") != "image/svg+xml":
                raster_adapter_files += 1
            package_candidates.extend(analyzed.pop("_recovered_candidates", []))
            media_files.append(analyzed)

    cross_media_graph = build_cross_media_evidence_graph(root, package_candidates, media_files)
    hypothesis_candidates = cross_media_graph.pop("_hypothesis_candidates", [])
    cross_semantic = _semantic_analysis(hypothesis_candidates, skill_profile)
    cross_instructions = cross_semantic["instructions"]
    cross_tool_calls = _project_tool_calls(cross_instructions)
    cross_findings: list[dict[str, Any]] = []
    if cross_instructions:
        top = cross_instructions[0]
        cross_findings.append(
            _finding(
                "MM-XMEDIA-001",
                _severity_for_instruction(top),
                str(top.get("file", "multiple media resources")),
                "Instruction-like behavior was reconstructed by joining strongly associated media fragments.",
                str(top.get("text_preview", "")),
                evidence_type="cross_media_instruction_reconstruction",
                confidence=float(top.get("confidence", 0.85)),
            )
        )
    if cross_tool_calls:
        tools = sorted({call["tool"] for call in cross_tool_calls})
        cross_findings.append(
            _finding(
                "MM-XMEDIA-TOOL-001",
                "CRITICAL" if "credential.read" in tools and "network.request" in tools else "HIGH",
                str(cross_instructions[0].get("file", "multiple media resources")),
                "Cross-media reconstructed behavior projects into sensitive agent tools; execution was blocked.",
                ", ".join(tools),
                evidence_type="cross_media_to_tool_sink",
                confidence=0.94,
            )
        )
    cross_media_graph["instruction_reconstruction"] = {
        "instruction_count": len(cross_instructions),
        "instructions": cross_instructions,
        "semantic_sentence_count": cross_semantic["sentence_count"],
        "denoised_sentence_count": cross_semantic["denoised_sentence_count"],
        "semantic_sentences": cross_semantic["sentences"],
        "behavior_graph": cross_semantic["behavior_graph"],
    }
    cross_media_graph["tool_call"] = {
        "policy": "never execute cross-media reconstructed instructions during scanning",
        "projected_count": len(cross_tool_calls),
        "calls": cross_tool_calls,
    }
    cross_media_graph["findings"] = cross_findings

    findings = [finding for item in media_files for finding in item.get("findings", [])] + cross_findings
    instruction_count = sum(
        item["instruction_reconstruction"]["instruction_count"]
        for item in media_files
        if "instruction_reconstruction" in item
    ) + len(cross_instructions)
    projected_count = sum(
        item["tool_call"]["projected_count"]
        for item in media_files
        if "tool_call" in item
    ) + len(cross_tool_calls)
    semantic_sentence_count = sum(
        item["instruction_reconstruction"].get("semantic_sentence_count", 0)
        for item in media_files
        if "instruction_reconstruction" in item
    ) + cross_semantic["sentence_count"]
    denoised_sentence_count = sum(
        item["instruction_reconstruction"].get("denoised_sentence_count", 0)
        for item in media_files
        if "instruction_reconstruction" in item
    ) + cross_semantic["denoised_sentence_count"]
    behavior_chain_count = sum(
        len(item["instruction_reconstruction"].get("behavior_graph", {}).get("chains", []))
        for item in media_files
        if "instruction_reconstruction" in item
    ) + len(cross_semantic["behavior_graph"].get("chains", []))
    resolved_reference_count = sum(
        sum(
            bool(reference.get("resolved_entity_ids"))
            for reference in item["instruction_reconstruction"].get("behavior_graph", {}).get("references", [])
        )
        for item in media_files
        if "instruction_reconstruction" in item
    ) + sum(
        bool(reference.get("resolved_entity_ids"))
        for reference in cross_semantic["behavior_graph"].get("references", [])
    )
    ambiguous_reference_count = sum(
        sum(
            bool(reference.get("ambiguous"))
            for reference in item["instruction_reconstruction"].get("behavior_graph", {}).get("references", [])
        )
        for item in media_files
        if "instruction_reconstruction" in item
    ) + sum(
        bool(reference.get("ambiguous"))
        for reference in cross_semantic["behavior_graph"].get("references", [])
    )
    tainted_entity_count = sum(
        sum(
            bool(entity.get("taint_types"))
            for entity in item["instruction_reconstruction"].get("behavior_graph", {}).get("entities", [])
        )
        for item in media_files
        if "instruction_reconstruction" in item
    ) + sum(
        bool(entity.get("taint_types"))
        for entity in cross_semantic["behavior_graph"].get("entities", [])
    )
    return {
        "pipeline_version": PIPELINE_VERSION,
        "triggered": bool(media_files),
        "trigger_reason": "multimodal_resource_present" if media_files else "no_supported_multimodal_resource",
        "execution_policy": "analysis_only_no_recovered_instruction_execution",
        "semantic_method": "sentence_tags_plus_coreference_taint_and_cross_media_evidence_graph",
        "skill_profile": skill_profile,
        "resource_budgets": {
            "max_raster_adapter_files": MAX_RASTER_ADAPTER_FILES,
            "raster_adapter_files_attempted": min(raster_adapter_files, MAX_RASTER_ADAPTER_FILES),
            "raster_files_skipped_by_budget": max(0, raster_adapter_files - MAX_RASTER_ADAPTER_FILES),
        },
        "stage_order": [
            "raw_bytes",
            "parse_decode",
            "symbol_recovery",
            "cross_media_evidence_graph",
            "instruction_reconstruction",
            "tool_call",
        ],
        "media_file_count": len(media_files),
        "image_file_count": sum(item.get("kind") == "image" for item in media_files),
        "audio_file_count": sum(item.get("kind") == "audio" for item in media_files),
        "video_file_count": sum(item.get("kind") == "video" for item in media_files),
        "document_file_count": sum(item.get("kind") == "document" for item in media_files),
        "instruction_count": instruction_count,
        "semantic_sentence_count": semantic_sentence_count,
        "denoised_sentence_count": denoised_sentence_count,
        "behavior_chain_count": behavior_chain_count,
        "resolved_reference_count": resolved_reference_count,
        "ambiguous_reference_count": ambiguous_reference_count,
        "tainted_entity_count": tainted_entity_count,
        "projected_tool_call_count": projected_count,
        "finding_count": len(findings),
        "files": media_files,
        "cross_media_evidence_graph": cross_media_graph,
        "findings": findings,
    }


def merge_findings_into_scan_result(
    scan_result: dict[str, Any], media_result: dict[str, Any]
) -> dict[str, Any]:
    """Merge media evidence into the canonical static result in place."""
    media_findings = list(media_result.get("findings", []) or [])
    if not media_findings:
        scan_result["media_pipeline_triggered"] = bool(media_result.get("triggered"))
        scan_result["media_files_scanned_count"] = int(media_result.get("media_file_count", 0))
        return scan_result
    findings = list(scan_result.get("findings", []) or []) + media_findings
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_pattern: dict[str, int] = {}
    by_phase: dict[str, int] = {}
    by_lifecycle: dict[str, int] = {}
    rule_ids: set[str] = set()
    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        rule_id = str(finding.get("rule_id", "UNKNOWN"))
        phase = str(finding.get("kill_chain_phase", "execution"))
        lifecycle = str(finding.get("lifecycle_stage", "governance"))
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_pattern[rule_id] = by_pattern.get(rule_id, 0) + 1
        by_phase[phase] = by_phase.get(phase, 0) + 1
        by_lifecycle[lifecycle] = by_lifecycle.get(lifecycle, 0) + 1
        rule_ids.add(rule_id)
    scan_result.update(
        {
            "findings": findings,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_pattern": by_pattern,
            "by_kill_chain_phase": by_phase,
            "by_lifecycle_stage": by_lifecycle,
            "rule_ids_hit": sorted(rule_ids),
            "media_pipeline_triggered": bool(media_result.get("triggered")),
            "media_files_scanned_count": int(media_result.get("media_file_count", 0)),
        }
    )
    return scan_result
