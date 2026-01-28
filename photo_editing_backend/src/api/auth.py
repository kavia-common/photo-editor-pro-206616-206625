import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

JWT_ALG = "HS256"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "").strip()
    if not secret:
        raise RuntimeError(
            "Missing JWT_SECRET environment variable. Ask the orchestrator to set it in backend .env."
        )
    return secret


def _get_access_token_minutes() -> int:
    val = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120").strip()
    try:
        return int(val)
    except ValueError:
        return 120


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against stored hash."""
    return pwd_context.verify(password, password_hash)


# PUBLIC_INTERFACE
def create_access_token(subject_user_id: uuid.UUID) -> str:
    """
    Create a signed JWT access token.

    The `sub` claim is set to the user's UUID string.
    """
    expire = _utcnow() + timedelta(minutes=_get_access_token_minutes())
    payload: Dict[str, Any] = {
        "sub": str(subject_user_id),
        "exp": expire,
        "iat": _utcnow(),
    }
    token = jwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALG)
    return token


def _decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALG])


# PUBLIC_INTERFACE
def get_current_user(db: Session = Depends(get_db), creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Dict[str, Any]:
    """
    FastAPI dependency that returns the current authenticated user row.

    Expects `Authorization: Bearer <token>`.
    """
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = _decode_token(creds.credentials)
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user_id = uuid.UUID(sub)
    except (JWTError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    row = db.execute(
        text(
            """
            SELECT id, email, display_name, created_at, updated_at
            FROM users
            WHERE id = :id
            """
        ),
        {"id": user_id},
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return dict(row)
