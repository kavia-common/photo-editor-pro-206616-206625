from __future__ import annotations

import io
from typing import Literal, Tuple

from PIL import Image, ImageEnhance, ImageOps


def _open_image(data: bytes) -> Image.Image:
    im = Image.open(io.BytesIO(data))
    # Ensure consistent mode for ops
    if im.mode not in ("RGB", "RGBA"):
        im = im.convert("RGBA") if "A" in im.getbands() else im.convert("RGB")
    return im


def _to_bytes(im: Image.Image, format_hint: str | None = None) -> Tuple[bytes, str]:
    # Default to PNG for safety; if hint is JPEG prefer JPEG
    fmt = "PNG"
    if format_hint:
        h = format_hint.lower()
        if h in ("jpeg", "jpg"):
            fmt = "JPEG"
        elif h in ("png", "webp", "gif", "bmp", "tiff"):
            fmt = h.upper() if h != "jpg" else "JPEG"

    out = io.BytesIO()
    if fmt == "JPEG":
        im = im.convert("RGB")  # JPEG doesn't support alpha
        im.save(out, format=fmt, quality=92, optimize=True)
        return out.getvalue(), "image/jpeg"
    if fmt == "WEBP":
        im.save(out, format=fmt, quality=92, method=6)
        return out.getvalue(), "image/webp"

    im.save(out, format=fmt)
    return out.getvalue(), "image/png"


# PUBLIC_INTERFACE
def crop_image(data: bytes, x: int, y: int, width: int, height: int, format_hint: str | None = None) -> Tuple[bytes, str, int, int]:
    """Crop image to (x,y,width,height). Returns (bytes, mime, new_w, new_h)."""
    im = _open_image(data)
    cropped = im.crop((x, y, x + width, y + height))
    out, mime = _to_bytes(cropped, format_hint=format_hint)
    return out, mime, cropped.width, cropped.height


# PUBLIC_INTERFACE
def adjust_brightness(data: bytes, value: float, format_hint: str | None = None) -> Tuple[bytes, str, int, int]:
    """Adjust brightness (1.0 = no change)."""
    im = _open_image(data)
    enhancer = ImageEnhance.Brightness(im)
    out_im = enhancer.enhance(value)
    out, mime = _to_bytes(out_im, format_hint=format_hint)
    return out, mime, out_im.width, out_im.height


# PUBLIC_INTERFACE
def adjust_contrast(data: bytes, value: float, format_hint: str | None = None) -> Tuple[bytes, str, int, int]:
    """Adjust contrast (1.0 = no change)."""
    im = _open_image(data)
    enhancer = ImageEnhance.Contrast(im)
    out_im = enhancer.enhance(value)
    out, mime = _to_bytes(out_im, format_hint=format_hint)
    return out, mime, out_im.width, out_im.height


# PUBLIC_INTERFACE
def apply_filter(
    data: bytes,
    name: Literal["grayscale", "sepia", "invert"],
    format_hint: str | None = None,
) -> Tuple[bytes, str, int, int]:
    """Apply a basic filter. Returns (bytes, mime, w, h)."""
    im = _open_image(data)
    if name == "grayscale":
        out_im = ImageOps.grayscale(im).convert("RGB")
    elif name == "invert":
        base = im.convert("RGB")
        out_im = ImageOps.invert(base)
    elif name == "sepia":
        base = ImageOps.grayscale(im).convert("RGB")
        # Simple sepia tone
        sepia = ImageOps.colorize(base, "#704214", "#C0A080")
        out_im = sepia
    else:
        out_im = im

    out, mime = _to_bytes(out_im, format_hint=format_hint)
    return out, mime, out_im.width, out_im.height
