"""Bounded local OCR adapters with explicit capability reporting."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


MAX_OCR_FILE_BYTES = 16 * 1024 * 1024
MAX_OCR_PIXELS = 4_000_000
MAX_OCR_FRAMES = 12
MAX_OCR_CHARS = 16_384
OCR_TIMEOUT_SECONDS = 20


def _observation(
    relative_path: str,
    text: str,
    *,
    backend: str,
    confidence: float,
    frame_index: int | None = None,
    lines: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    normalized = " ".join(str(text).replace("\x00", " ").split())
    if len(normalized) < 4:
        return None
    result: dict[str, Any] = {
        "file": relative_path,
        "kind": "ocr_text",
        "text": normalized[:MAX_OCR_CHARS],
        "source": f"ocr:{backend}",
        "confidence": round(confidence, 3),
        "transform_chain": ["raster-ocr"],
        "adapter": "ocr",
        "backend": backend,
    }
    if frame_index is not None:
        result["frame_index"] = frame_index
        result["source"] += f":frame-{frame_index}"
        result["transform_chain"].append("frame-extraction")
    if lines:
        result["regions"] = lines[:80]
    return result


def _run_windows_ocr(image_path: Path) -> dict[str, Any]:
    script = Path(__file__).with_name("windows_ocr.ps1")
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-ImagePath",
            str(image_path.resolve()),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=OCR_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip()[:1000] or "Windows OCR failed")
    output = completed.stdout.strip().lstrip("\ufeff")
    if not output:
        raise RuntimeError("Windows OCR returned no JSON")
    return json.loads(output.splitlines()[-1])


def _run_tesseract(image_path: Path) -> dict[str, Any]:
    executable = shutil.which("tesseract")
    if not executable:
        raise RuntimeError("tesseract executable unavailable")
    completed = subprocess.run(
        [executable, str(image_path.resolve()), "stdout"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=OCR_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip()[:1000] or "Tesseract OCR failed")
    return {"backend": "tesseract-cli", "text": completed.stdout, "lines": []}


def _run_rapidocr(image_path: Path) -> dict[str, Any]:
    try:
        from rapidocr_onnxruntime import RapidOCR
    except ImportError as exc:
        raise RuntimeError("rapidocr_onnxruntime unavailable") from exc
    engine = RapidOCR()
    result, _ = engine(str(image_path.resolve()))
    lines: list[dict[str, Any]] = []
    texts: list[str] = []
    for item in result or []:
        box, text, score = item
        texts.append(str(text))
        lines.append({"text": str(text), "polygon": box, "confidence": float(score)})
    return {"backend": "rapidocr-onnxruntime", "text": " ".join(texts), "lines": lines}


def _choose_backend() -> tuple[str | None, Any | None]:
    if platform.system() == "Windows" and shutil.which("powershell.exe"):
        return "windows-media-ocr", _run_windows_ocr
    try:
        import rapidocr_onnxruntime  # noqa: F401
    except ImportError:
        pass
    else:
        return "rapidocr-onnxruntime", _run_rapidocr
    if shutil.which("tesseract"):
        return "tesseract-cli", _run_tesseract
    return None, None


def _image_info(path: Path) -> tuple[int, int, int]:
    try:
        from PIL import Image
        with Image.open(path) as image:
            return image.width, image.height, int(getattr(image, "n_frames", 1))
    except (ImportError, OSError):
        return 0, 0, 1


def _extract_gif_frames(path: Path, target: Path) -> list[tuple[int, Path]]:
    try:
        from PIL import Image, ImageSequence
    except ImportError:
        return []
    frames: list[tuple[int, Path]] = []
    try:
        with Image.open(path) as image:
            for index, frame in enumerate(ImageSequence.Iterator(image)):
                if index >= MAX_OCR_FRAMES:
                    break
                output = target / f"frame-{index:03d}.png"
                frame.convert("RGB").save(output, format="PNG")
                frames.append((index, output))
    except OSError:
        return []
    return frames


def analyze_ocr(path: Path, *, relative_path: str, media_type: str) -> dict[str, Any]:
    backend_name, backend = _choose_backend()
    status: dict[str, Any] = {
        "available": backend is not None,
        "backend": backend_name,
        "attempted": False,
        "observation_count": 0,
        "errors": [],
        "limits": {
            "max_file_bytes": MAX_OCR_FILE_BYTES,
            "max_pixels": MAX_OCR_PIXELS,
            "max_frames": MAX_OCR_FRAMES,
            "timeout_seconds": OCR_TIMEOUT_SECONDS,
        },
    }
    observations: list[dict[str, Any]] = []
    if backend is None:
        status["errors"].append("no local OCR backend available")
        return {"status": status, "observations": observations}
    try:
        if path.stat().st_size > MAX_OCR_FILE_BYTES:
            status["errors"].append("file exceeds OCR byte limit")
            return {"status": status, "observations": observations}
    except OSError as exc:
        status["errors"].append(str(exc))
        return {"status": status, "observations": observations}
    width, height, frame_count = _image_info(path)
    status.update({"width": width, "height": height, "frame_count": frame_count})
    if width and height and width * height > MAX_OCR_PIXELS:
        status["errors"].append("image exceeds OCR pixel limit")
        return {"status": status, "observations": observations}

    status["attempted"] = True
    views: list[tuple[int | None, Path]] = [(None, path)]
    temp_parent = Path(__file__).resolve().parents[2] / "tmp" / "media-adapters"
    temp_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ocr-", dir=temp_parent) as temporary:
        if media_type == "image/gif" and frame_count > 1:
            views = [(index, frame) for index, frame in _extract_gif_frames(path, Path(temporary))]
            status["frames_attempted"] = len(views)
        for frame_index, view in views:
            try:
                payload = backend(view)
                item = _observation(
                    relative_path,
                    payload.get("text", ""),
                    backend=str(payload.get("backend") or backend_name),
                    confidence=0.84 if backend_name == "windows-media-ocr" else 0.8,
                    frame_index=frame_index,
                    lines=list(payload.get("lines") or []),
                )
                if item:
                    observations.append(item)
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
                status["errors"].append(str(exc)[:1000])
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    for item in observations:
        key = (item["text"].lower(), item.get("frame_index"))
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    status["observation_count"] = len(deduped)
    status["successful"] = bool(deduped)
    status["operational"] = bool(status["attempted"] and not status["errors"])
    return {"status": status, "observations": deduped}
