from __future__ import annotations

import os
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


MAX_FILES = 500
MAX_TOTAL_BYTES = 50 * 1024 * 1024


class SafeExtractError(Exception):
    """Raised when an uploaded archive violates the local UI safety boundary."""


@dataclass(frozen=True)
class ExtractResult:
    extracted_path: str
    file_count: int
    total_bytes: int
    files: list[str]


def _target_path(base_dir: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or normalized.startswith("/"):
        raise SafeExtractError(f"absolute archive path rejected: {member_name}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise SafeExtractError(f"path traversal rejected: {member_name}")
    candidate = base_dir.joinpath(*path.parts)
    try:
        candidate.resolve().relative_to(base_dir.resolve())
    except ValueError as exc:
        raise SafeExtractError(f"path escapes target directory: {member_name}") from exc
    return candidate


def _ensure_within_target(base_dir: Path) -> None:
    base_real = base_dir.resolve()
    for current_root, dirs, files in os.walk(base_dir, followlinks=False):
        root = Path(current_root)
        for name in [*dirs, *files]:
            path = root / name
            if path.is_symlink():
                raise SafeExtractError(f"symlink rejected after extraction: {path}")
            try:
                path.resolve().relative_to(base_real)
            except ValueError as exc:
                raise SafeExtractError(f"extracted path escapes target directory: {path}") from exc


def _check_limits(file_count: int, total_bytes: int) -> None:
    if file_count > MAX_FILES:
        raise SafeExtractError(f"archive file limit exceeded: {file_count} > {MAX_FILES}")
    if total_bytes > MAX_TOTAL_BYTES:
        raise SafeExtractError(f"archive size limit exceeded: {total_bytes} > {MAX_TOTAL_BYTES}")


def _extract_zip(archive_path: Path, target_dir: Path) -> ExtractResult:
    files: list[str] = []
    total_bytes = 0
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        for member in members:
            _target_path(target_dir, member.filename)
            if member.is_dir():
                continue
            file_count = len(files) + 1
            total_bytes += member.file_size
            _check_limits(file_count, total_bytes)
            files.append(member.filename)

        for member in members:
            destination = _target_path(target_dir, member.filename)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, destination.open("wb") as sink:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    sink.write(chunk)

    _ensure_within_target(target_dir)
    return ExtractResult(str(target_dir), len(files), total_bytes, files)


def _extract_tar_gz(archive_path: Path, target_dir: Path) -> ExtractResult:
    files: list[str] = []
    total_bytes = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            _target_path(target_dir, member.name)
            if member.issym() or member.islnk():
                raise SafeExtractError(f"symlink or hardlink rejected: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise SafeExtractError(f"unsupported tar entry rejected: {member.name}")
            file_count = len(files) + 1
            total_bytes += member.size
            _check_limits(file_count, total_bytes)
            files.append(member.name)

        for member in members:
            destination = _target_path(target_dir, member.name)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise SafeExtractError(f"failed to read tar member: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("wb") as sink:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    sink.write(chunk)

    _ensure_within_target(target_dir)
    return ExtractResult(str(target_dir), len(files), total_bytes, files)


def safe_extract_archive(archive_path: str | Path, target_dir: str | Path) -> ExtractResult:
    source = Path(archive_path)
    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)

    name = source.name.lower()
    if name.endswith(".zip"):
        return _extract_zip(source, target)
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return _extract_tar_gz(source, target)
    raise SafeExtractError("only .zip, .tar.gz, and .tgz uploads are supported")
