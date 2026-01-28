import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class HealthResponse(BaseModel):
    message: str = Field(..., description="Health status message")


class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password (min 6 chars)")
    display_name: Optional[str] = Field(None, description="Optional display name")


class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT bearer token")
    token_type: Literal["bearer"] = Field("bearer", description="Token type")


class UserPublic(BaseModel):
    id: uuid.UUID = Field(..., description="User ID")
    email: str = Field(..., description="Email")
    display_name: Optional[str] = Field(None, description="Display name")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Updated timestamp")


class ImageCreateResponse(BaseModel):
    id: uuid.UUID = Field(..., description="Image ID")
    title: Optional[str] = Field(None, description="Image title")
    original_storage_key: str = Field(..., description="Storage key for the originally uploaded image")
    current_storage_key: Optional[str] = Field(None, description="Storage key for latest edited image")
    created_at: datetime = Field(..., description="Created timestamp")


class ImageListItem(BaseModel):
    id: uuid.UUID = Field(..., description="Image ID")
    title: Optional[str] = Field(None, description="Title")
    original_storage_key: str = Field(..., description="Original storage key")
    current_storage_key: Optional[str] = Field(None, description="Current storage key (edited)")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Updated timestamp")


class EditHistoryItem(BaseModel):
    id: uuid.UUID = Field(..., description="Edit history entry ID")
    image_id: uuid.UUID = Field(..., description="Image ID")
    user_id: uuid.UUID = Field(..., description="User ID")
    operation: str = Field(..., description="Operation type: crop/filter/brightness/contrast/etc")
    params: Dict[str, Any] = Field(default_factory=dict, description="Operation parameters")
    created_at: datetime = Field(..., description="Timestamp")


class CropRequest(BaseModel):
    x: int = Field(..., ge=0, description="Left offset in pixels")
    y: int = Field(..., ge=0, description="Top offset in pixels")
    width: int = Field(..., gt=0, description="Crop width in pixels")
    height: int = Field(..., gt=0, description="Crop height in pixels")


class AdjustRequest(BaseModel):
    value: float = Field(..., description="Adjustment value. brightness/contrast use 0.0-2.0 where 1.0 is no-op.")


class FilterRequest(BaseModel):
    name: Literal["grayscale", "sepia", "invert"] = Field(..., description="Filter name")
