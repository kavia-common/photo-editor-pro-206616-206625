import os
import pathlib
import uuid
from typing import Tuple

from fastapi import UploadFile

STORAGE_DIR_ENV = "IMAGE_STORAGE_DIR"


def _storage_root() -> pathlib.Path:
    root = os.getenv(STORAGE_DIR_ENV, "").strip() or "storage"
    p = pathlib.Path(root).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe_join(root: pathlib.Path, key: str) -> pathlib.Path:
    # Prevent path traversal: resolve and ensure it is within root.
    candidate = (root / key).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError("Invalid storage key")
    return candidate


# PUBLIC_INTERFACE
def save_upload(upload: UploadFile, prefix: str) -> Tuple[str, int]:
    """
    Save an uploaded file into local storage.

    Returns:
      (storage_key, size_bytes)
    """
    root = _storage_root()
    ext = pathlib.Path(upload.filename or "").suffix.lower()
    if ext not in [".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff"]:
        # Still allow unknown; default to .bin
        ext = ext or ".bin"
    storage_key = f"{prefix}/{uuid.uuid4().hex}{ext}"
    target = _safe_join(root, storage_key)
    target.parent.mkdir(parents=True, exist_ok=True)

    size = 0
    with target.open("wb") as f:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            f.write(chunk)
    return storage_key, size


# PUBLIC_INTERFACE
def save_bytes(data: bytes, key: str) -> int:
    """Save bytes to a storage key. Returns size in bytes."""
    root = _storage_root()
    target = _safe_join(root, key)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as f:
        f.write(data)
    return len(data)


# PUBLIC_INTERFACE
def load_bytes(key: str) -> bytes:
    """Load bytes for a storage key."""
    root = _storage_root()
    path = _safe_join(root, key)
    return path.read_bytes()


# PUBLIC_INTERFACE
def resolve_path(key: str) -> str:
    """Resolve storage key to absolute path string (for FileResponse)."""
    root = _storage_root()
    return str(_safe_join(root, key))
