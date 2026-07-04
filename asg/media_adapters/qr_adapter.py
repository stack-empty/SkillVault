"""Bounded QR recovery using an optional local OpenCV backend."""

from __future__ import annotations

from typing import Any


MAX_QR_BYTES = 16 * 1024 * 1024
MAX_QR_SYMBOLS = 16
MAX_QR_CHARS = 16_384


def _points(value: Any) -> list[list[float]] | None:
    if value is None:
        return None
    try:
        points = value.tolist()
    except AttributeError:
        points = value
    while isinstance(points, list) and len(points) == 1 and isinstance(points[0], list):
        points = points[0]
    try:
        return [[round(float(x), 3), round(float(y), 3)] for x, y in points]
    except (TypeError, ValueError):
        return None


def analyze_qr(data: bytes, *, relative_path: str) -> dict[str, Any]:
    status: dict[str, Any] = {
        "available": False,
        "backend": None,
        "attempted": False,
        "observation_count": 0,
        "errors": [],
        "limits": {"max_file_bytes": MAX_QR_BYTES, "max_symbols": MAX_QR_SYMBOLS},
    }
    observations: list[dict[str, Any]] = []
    if len(data) > MAX_QR_BYTES:
        status["errors"].append("file exceeds QR byte limit")
        return {"status": status, "observations": observations}
    try:
        import cv2
        import numpy as np
    except ImportError:
        status["errors"].append("opencv-python-headless unavailable")
        return {"status": status, "observations": observations}
    status.update({"available": True, "backend": "opencv-qrcode-detector", "attempted": True})
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        status["errors"].append("OpenCV could not decode raster")
        return {"status": status, "observations": observations}
    detector = cv2.QRCodeDetector()
    decoded: list[tuple[str, Any]] = []
    try:
        ok, values, point_sets, _ = detector.detectAndDecodeMulti(image)
        if ok:
            for index, value in enumerate(values[:MAX_QR_SYMBOLS]):
                points = point_sets[index] if point_sets is not None and index < len(point_sets) else None
                decoded.append((str(value), points))
    except (cv2.error, ValueError):
        pass
    if not decoded:
        try:
            value, points, _ = detector.detectAndDecode(image)
            if value:
                decoded.append((str(value), points))
        except cv2.error as exc:
            status["errors"].append(str(exc)[:1000])
    seen: set[str] = set()
    for value, points in decoded:
        normalized = " ".join(value.replace("\x00", " ").split())[:MAX_QR_CHARS]
        if len(normalized) < 4 or normalized in seen:
            continue
        seen.add(normalized)
        observations.append(
            {
                "file": relative_path,
                "kind": "qr_payload",
                "text": normalized,
                "source": "qr:opencv-qrcode-detector",
                "confidence": 0.98,
                "transform_chain": ["qr-decode"],
                "adapter": "qr",
                "backend": "opencv-qrcode-detector",
                "polygon": _points(points),
            }
        )
    status["observation_count"] = len(observations)
    status["successful"] = bool(observations)
    status["operational"] = bool(status["attempted"] and not status["errors"])
    return {"status": status, "observations": observations}
