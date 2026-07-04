"""Optional, analysis-only adapters for raster symbol recovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ocr_adapter import analyze_ocr
from .qr_adapter import analyze_qr


def analyze_raster_symbols(
    path: Path,
    *,
    relative_path: str,
    media_type: str,
    data: bytes,
) -> dict[str, Any]:
    """Run bounded OCR and QR recovery without executing recovered content."""
    ocr = analyze_ocr(path, relative_path=relative_path, media_type=media_type)
    qr = analyze_qr(data, relative_path=relative_path)
    return {
        "observations": [*ocr["observations"], *qr["observations"]],
        "capabilities": {
            "ocr": ocr["status"],
            "qr": qr["status"],
        },
        "execution_policy": "symbol_recovery_only_never_execute",
    }


__all__ = ["analyze_raster_symbols"]
