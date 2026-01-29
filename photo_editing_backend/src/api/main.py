from __future__ import annotations

import mimetypes
import os
import uuid
from typing import List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.auth import create_access_token, get_current_user, hash_password, verify_password
from src.api.db import ensure_schema, get_db, new_uuid, utcnow
from src.api.image_processing import (
    adjust_brightness,
    adjust_contrast,
    apply_filter,
    crop_image,
)
from src.api.schemas import (
    AdjustRequest,
    CropRequest,
    FilterRequest,
    HealthResponse,
    ImageCreateResponse,
    ImageListItem,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserPublic,
)
from src.api.storage import load_bytes, resolve_path, save_bytes, save_upload

openapi_tags = [
    {"name": "health", "description": "Service health and diagnostics."},
    {"name": "auth", "description": "User registration and login (JWT bearer tokens)."},
    {"name": "images", "description": "Image upload, listing, metadata retrieval, and file download."},
    {"name": "editing", "description": "Non-destructive editing endpoints that create a new current image version."},
]

app = FastAPI(
    title="Photo Editing Backend",
    description=(
        "Backend for a photo editing app. Provides JWT authentication, image upload/storage, "
        "basic editing operations (crop/filters/brightness/contrast), and PostgreSQL persistence."
    ),
    version="0.3.0",
    openapi_tags=openapi_tags,
)


def _get_cors_origins() -> list[str]:
    """
    Parse CORS allow-origins from env.

    Env:
      - CORS_ALLOW_ORIGINS: comma-separated list of allowed origins, or '*' to allow all.
        Example: 'http://localhost:3000,http://127.0.0.1:3000'
    """
    raw = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
    if not raw or raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_cors_origins(),
    # If allow_origins is ["*"], Starlette will not allow credentials. That's OK for our Bearer auth.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    """
    App startup hook.

    We attempt to ensure the DB schema exists, but the service should still start even if:
      - the database container isn't running yet, or
      - POSTGRES_* env vars are not configured.

    In those cases, DB-backed endpoints will fail when called, but liveness/docs will remain available.
    """
    try:
        # Ensure schema exists (defensive; DB container is expected to have created tables).
        ensure_schema()
    except Exception as exc:
        # Don't prevent the API from starting when the DB is unavailable.
        # This is important in environments where dependencies may start out-of-order.
        print(f"⚠️  Startup DB initialization skipped: {exc}")


def _public_api_base_url() -> str:
    """
    Base URL used to construct absolute URLs returned to the frontend.

    Env:
      - PUBLIC_API_BASE_URL: e.g. 'http://localhost:8000'
    """
    return (os.getenv("PUBLIC_API_BASE_URL", "").strip() or "").rstrip("/")


def _image_file_url(image_id: uuid.UUID) -> str:
    base = _public_api_base_url()
    path = f"/images/{image_id}/file"
    return f"{base}{path}" if base else path


class SaveImageRequest(BaseModel):
    editedDataUrl: str = Field(..., description="Edited image as a data URL (image/png or image/jpeg).")


class SaveImageResponse(BaseModel):
    image: ImageListItem = Field(..., description="Updated image record.")


class ImageMeta(BaseModel):
    id: uuid.UUID = Field(..., description="Image ID")
    title: Optional[str] = Field(None, description="Image title")
    createdAt: Optional[str] = Field(None, description="Created timestamp (ISO8601)")
    updatedAt: Optional[str] = Field(None, description="Updated timestamp (ISO8601)")
    url: str = Field(..., description="URL to download the current image file")


class GetImageResponse(BaseModel):
    image: ImageMeta = Field(..., description="Image metadata payload for the frontend.")


# PUBLIC_INTERFACE
@app.get("/", response_model=HealthResponse, tags=["health"], summary="Health check", description="Basic liveness endpoint.")
def health_check() -> HealthResponse:
    return HealthResponse(message="Healthy")


# PUBLIC_INTERFACE
@app.post(
    "/auth/register",
    response_model=UserPublic,
    tags=["auth"],
    summary="Register",
    description="Register a new user account. Returns the created user (without password).",
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> UserPublic:
    existing = db.execute(text("SELECT id FROM users WHERE email = :email"), {"email": payload.email}).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user_id = new_uuid()
    now = utcnow()
    db.execute(
        text(
            """
            INSERT INTO users (id, email, password_hash, display_name, created_at, updated_at)
            VALUES (:id, :email, :password_hash, :display_name, :created_at, :updated_at)
            """
        ),
        {
            "id": user_id,
            "email": payload.email,
            "password_hash": hash_password(payload.password),
            "display_name": payload.display_name,
            "created_at": now,
            "updated_at": now,
        },
    )
    db.commit()

    row = db.execute(
        text("SELECT id, email, display_name, created_at, updated_at FROM users WHERE id = :id"),
        {"id": user_id},
    ).mappings().first()
    return UserPublic(**dict(row))


# PUBLIC_INTERFACE
@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["auth"],
    summary="Login",
    description="Login with email/password and receive a JWT access token.",
)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.execute(
        text("SELECT id, email, password_hash FROM users WHERE email = :email"),
        {"email": payload.email},
    ).mappings().first()
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(uuid.UUID(str(user["id"])))
    # Frontend expects { token: string, user?: ... } shape; add backward-compatible alias field.
    return TokenResponse(access_token=token, token_type="bearer")


# PUBLIC_INTERFACE
@app.get(
    "/auth/me",
    response_model=UserPublic,
    tags=["auth"],
    summary="Current user",
    description="Get the currently authenticated user.",
)
def me(current_user=Depends(get_current_user)) -> UserPublic:
    return UserPublic(**current_user)


def _get_image_owned(db: Session, user_id: uuid.UUID, image_id: uuid.UUID) -> dict:
    row = db.execute(
        text(
            """
            SELECT *
            FROM images
            WHERE id = :id AND user_id = :user_id
            """
        ),
        {"id": image_id, "user_id": user_id},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found")
    return dict(row)


def _log_edit(db: Session, image_id: uuid.UUID, user_id: uuid.UUID, operation: str, params: dict) -> None:
    db.execute(
        text(
            """
            INSERT INTO edit_history (id, image_id, user_id, operation, params, created_at)
            VALUES (:id, :image_id, :user_id, :operation, :params::jsonb, :created_at)
            """
        ),
        {
            "id": new_uuid(),
            "image_id": image_id,
            "user_id": user_id,
            "operation": operation,
            "params": params,
            "created_at": utcnow(),
        },
    )


# PUBLIC_INTERFACE
@app.post(
    "/images/upload",
    response_model=ImageCreateResponse,
    tags=["images"],
    summary="Upload image",
    description="Upload an image file. Persists metadata and stores bytes in backend local storage.",
)
def upload_image(
    file: UploadFile = File(..., description="Image file to upload"),
    title: Optional[str] = Query(None, description="Optional title for the image"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> ImageCreateResponse:
    user_id = uuid.UUID(str(current_user["id"]))

    storage_key, size_bytes = save_upload(file, prefix="original")

    # Try to detect mime type and dimensions with Pillow
    from PIL import Image as PILImage  # local import to avoid import cost at startup

    data = load_bytes(storage_key)
    width = height = None
    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0]
    try:
        with PILImage.open(resolve_path(storage_key)) as im:
            width, height = im.size
            if not mime:
                mime = PILImage.MIME.get(im.format)  # type: ignore[attr-defined]
    except Exception:
        # Non-fatal: keep metadata minimal.
        pass

    image_id = new_uuid()
    now = utcnow()
    db.execute(
        text(
            """
            INSERT INTO images (
              id, user_id, title,
              original_storage_key, original_mime_type, original_width, original_height, original_size_bytes,
              current_storage_key, current_mime_type, current_width, current_height, current_size_bytes,
              created_at, updated_at
            )
            VALUES (
              :id, :user_id, :title,
              :original_storage_key, :original_mime_type, :original_width, :original_height, :original_size_bytes,
              NULL, NULL, NULL, NULL, NULL,
              :created_at, :updated_at
            )
            """
        ),
        {
            "id": image_id,
            "user_id": user_id,
            "title": title,
            "original_storage_key": storage_key,
            "original_mime_type": mime,
            "original_width": width,
            "original_height": height,
            "original_size_bytes": size_bytes,
            "created_at": now,
            "updated_at": now,
        },
    )
    _log_edit(db, image_id=image_id, user_id=user_id, operation="upload", params={"title": title})
    db.commit()

    return ImageCreateResponse(
        id=image_id,
        title=title,
        original_storage_key=storage_key,
        current_storage_key=None,
        created_at=now,
    )


# PUBLIC_INTERFACE
@app.get(
    "/images",
    response_model=List[ImageListItem],
    tags=["images"],
    summary="List images",
    description="List images owned by the authenticated user.",
)
def list_images(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200, description="Max number of images to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> List[ImageListItem]:
    user_id = uuid.UUID(str(current_user["id"]))
    rows = db.execute(
        text(
            """
            SELECT id, title, original_storage_key, current_storage_key, created_at, updated_at
            FROM images
            WHERE user_id = :user_id
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {"user_id": user_id, "limit": limit, "offset": offset},
    ).mappings().all()
    # Keep schema stable; frontend will derive URL via /images/{id}/file. (We also support absolute URL via PUBLIC_API_BASE_URL.)
    return [ImageListItem(**dict(r)) for r in rows]


# PUBLIC_INTERFACE
@app.get(
    "/images/{image_id}",
    response_model=GetImageResponse,
    tags=["images"],
    summary="Get image metadata",
    description="Fetch a single image metadata record owned by the authenticated user.",
)
def get_image(
    image_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> GetImageResponse:
    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)

    return GetImageResponse(
        image=ImageMeta(
            id=uuid.UUID(str(img["id"])),
            title=img.get("title"),
            createdAt=img["created_at"].isoformat() if img.get("created_at") else None,
            updatedAt=img["updated_at"].isoformat() if img.get("updated_at") else None,
            url=_image_file_url(image_id),
        )
    )


# PUBLIC_INTERFACE
@app.post(
    "/images/{image_id}/save",
    response_model=SaveImageResponse,
    tags=["images"],
    summary="Save edited image",
    description=(
        "Persist an edited image sent as a data URL. Stores bytes as the current version and updates metadata.\n\n"
        "Used by the frontend when running in LIVE API mode."
    ),
)
def save_edited_image(
    image_id: uuid.UUID,
    payload: SaveImageRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> SaveImageResponse:
    import base64

    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)

    data_url = (payload.editedDataUrl or "").strip()
    if not data_url.startswith("data:") or ";base64," not in data_url:
        raise HTTPException(status_code=400, detail="editedDataUrl must be a base64 data URL")

    header, b64 = data_url.split(";base64,", 1)
    mime = header.replace("data:", "").strip() or "image/png"
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 payload")

    # Determine extension + default output name
    ext = ".png"
    if mime in ("image/jpeg", "image/jpg"):
        ext = ".jpg"
    elif mime == "image/webp":
        ext = ".webp"

    new_key = f"current/{uuid.uuid4().hex}{ext}"
    size_bytes = save_bytes(raw, new_key)

    # Try to infer dimensions
    width = height = None
    try:
        from PIL import Image as PILImage

        with PILImage.open(resolve_path(new_key)) as im:
            width, height = im.size
            if not mime:
                mime = PILImage.MIME.get(im.format) or mime  # type: ignore[attr-defined]
    except Exception:
        width = width or 0
        height = height or 0

    _update_current_version(
        db,
        image_id=image_id,
        user_id=user_id,
        new_key=new_key,
        mime=mime,
        width=int(width or 0),
        height=int(height or 0),
        size_bytes=size_bytes,
    )
    _log_edit(db, image_id=image_id, user_id=user_id, operation="save", params={"source": "data_url"})
    db.commit()

    row = db.execute(
        text("SELECT id, title, original_storage_key, current_storage_key, created_at, updated_at FROM images WHERE id=:id"),
        {"id": image_id},
    ).mappings().first()
    return SaveImageResponse(image=ImageListItem(**dict(row)))


# PUBLIC_INTERFACE
@app.get(
    "/images/{image_id}/file",
    tags=["images"],
    summary="Get image file",
    description="Download the current version of an image; falls back to original if not edited yet.",
    responses={
        200: {
            "description": "Binary image response (the image bytes).",
            "content": {
                # We may return different image types depending on upload/edit.
                "image/jpeg": {"schema": {"type": "string", "format": "binary"}},
                "image/png": {"schema": {"type": "string", "format": "binary"}},
                "image/webp": {"schema": {"type": "string", "format": "binary"}},
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}},
            },
        }
    },
)
def get_image_file(
    image_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> FileResponse:
    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)
    key = img.get("current_storage_key") or img.get("original_storage_key")
    if not key:
        raise HTTPException(status_code=404, detail="No file for image")
    path = resolve_path(key)
    media_type = img.get("current_mime_type") or img.get("original_mime_type") or "application/octet-stream"
    return FileResponse(path, media_type=media_type, filename=os.path.basename(path))


def _update_current_version(
    db: Session,
    image_id: uuid.UUID,
    user_id: uuid.UUID,
    new_key: str,
    mime: str,
    width: int,
    height: int,
    size_bytes: int,
) -> None:
    db.execute(
        text(
            """
            UPDATE images
            SET current_storage_key = :key,
                current_mime_type = :mime,
                current_width = :w,
                current_height = :h,
                current_size_bytes = :s,
                updated_at = :updated
            WHERE id = :id AND user_id = :user_id
            """
        ),
        {"key": new_key, "mime": mime, "w": width, "h": height, "s": size_bytes, "updated": utcnow(), "id": image_id, "user_id": user_id},
    )


def _source_bytes_and_hint(img: dict) -> tuple[bytes, str | None]:
    key = img.get("current_storage_key") or img.get("original_storage_key")
    if not key:
        raise HTTPException(status_code=404, detail="Image has no storage key")
    data = load_bytes(key)
    hint = None
    if key.lower().endswith((".jpg", ".jpeg")):
        hint = "jpeg"
    elif key.lower().endswith(".webp"):
        hint = "webp"
    elif key.lower().endswith(".png"):
        hint = "png"
    return data, hint


# PUBLIC_INTERFACE
@app.post(
    "/images/{image_id}/edit/crop",
    response_model=ImageListItem,
    tags=["editing"],
    summary="Crop image",
    description="Crop an image and set the result as the current version.",
)
def edit_crop(
    image_id: uuid.UUID,
    payload: CropRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> ImageListItem:
    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)
    data, hint = _source_bytes_and_hint(img)

    out, mime, w, h = crop_image(data, payload.x, payload.y, payload.width, payload.height, format_hint=hint)
    new_key = f"current/{uuid.uuid4().hex}.png"
    size_bytes = save_bytes(out, new_key)

    _update_current_version(db, image_id=image_id, user_id=user_id, new_key=new_key, mime=mime, width=w, height=h, size_bytes=size_bytes)
    _log_edit(db, image_id=image_id, user_id=user_id, operation="crop", params=payload.model_dump())
    db.commit()

    row = db.execute(
        text("SELECT id, title, original_storage_key, current_storage_key, created_at, updated_at FROM images WHERE id=:id"),
        {"id": image_id},
    ).mappings().first()
    return ImageListItem(**dict(row))


# PUBLIC_INTERFACE
@app.post(
    "/images/{image_id}/edit/brightness",
    response_model=ImageListItem,
    tags=["editing"],
    summary="Adjust brightness",
    description="Adjust brightness and set result as current version. Value typically in [0.0, 2.0].",
)
def edit_brightness(
    image_id: uuid.UUID,
    payload: AdjustRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> ImageListItem:
    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)
    data, hint = _source_bytes_and_hint(img)

    out, mime, w, h = adjust_brightness(data, payload.value, format_hint=hint)
    new_key = f"current/{uuid.uuid4().hex}.png"
    size_bytes = save_bytes(out, new_key)

    _update_current_version(db, image_id=image_id, user_id=user_id, new_key=new_key, mime=mime, width=w, height=h, size_bytes=size_bytes)
    _log_edit(db, image_id=image_id, user_id=user_id, operation="brightness", params=payload.model_dump())
    db.commit()

    row = db.execute(
        text("SELECT id, title, original_storage_key, current_storage_key, created_at, updated_at FROM images WHERE id=:id"),
        {"id": image_id},
    ).mappings().first()
    return ImageListItem(**dict(row))


# PUBLIC_INTERFACE
@app.post(
    "/images/{image_id}/edit/contrast",
    response_model=ImageListItem,
    tags=["editing"],
    summary="Adjust contrast",
    description="Adjust contrast and set result as current version. Value typically in [0.0, 2.0].",
)
def edit_contrast(
    image_id: uuid.UUID,
    payload: AdjustRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> ImageListItem:
    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)
    data, hint = _source_bytes_and_hint(img)

    out, mime, w, h = adjust_contrast(data, payload.value, format_hint=hint)
    new_key = f"current/{uuid.uuid4().hex}.png"
    size_bytes = save_bytes(out, new_key)

    _update_current_version(db, image_id=image_id, user_id=user_id, new_key=new_key, mime=mime, width=w, height=h, size_bytes=size_bytes)
    _log_edit(db, image_id=image_id, user_id=user_id, operation="contrast", params=payload.model_dump())
    db.commit()

    row = db.execute(
        text("SELECT id, title, original_storage_key, current_storage_key, created_at, updated_at FROM images WHERE id=:id"),
        {"id": image_id},
    ).mappings().first()
    return ImageListItem(**dict(row))


# PUBLIC_INTERFACE
@app.post(
    "/images/{image_id}/edit/filter",
    response_model=ImageListItem,
    tags=["editing"],
    summary="Apply filter",
    description="Apply a named filter (grayscale/sepia/invert) and set result as current version.",
)
def edit_filter(
    image_id: uuid.UUID,
    payload: FilterRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> ImageListItem:
    user_id = uuid.UUID(str(current_user["id"]))
    img = _get_image_owned(db, user_id=user_id, image_id=image_id)
    data, hint = _source_bytes_and_hint(img)

    out, mime, w, h = apply_filter(data, payload.name, format_hint=hint)
    new_key = f"current/{uuid.uuid4().hex}.png"
    size_bytes = save_bytes(out, new_key)

    _update_current_version(db, image_id=image_id, user_id=user_id, new_key=new_key, mime=mime, width=w, height=h, size_bytes=size_bytes)
    _log_edit(db, image_id=image_id, user_id=user_id, operation="filter", params=payload.model_dump())
    db.commit()

    row = db.execute(
        text("SELECT id, title, original_storage_key, current_storage_key, created_at, updated_at FROM images WHERE id=:id"),
        {"id": image_id},
    ).mappings().first()
    return ImageListItem(**dict(row))
