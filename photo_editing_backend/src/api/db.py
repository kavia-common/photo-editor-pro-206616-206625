import os
import uuid
from datetime import datetime, timezone
from typing import Generator, Optional
from urllib.parse import urlparse

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _normalize_host(raw_host: str) -> str:
    """
    Normalize POSTGRES_URL value into a host-only string when it contains a URL.

    The DB container sometimes writes POSTGRES_URL as a URL (e.g. "postgresql://localhost:5000/myapp"),
    while other deployments provide just a hostname (e.g. "localhost").
    """
    raw = (raw_host or "").strip()
    if not raw:
        return ""

    if raw.startswith(("postgres://", "postgresql://")):
        parsed = urlparse(raw)
        # urlparse('postgresql://localhost:5000/myapp') -> hostname=localhost
        return parsed.hostname or ""

    # If it's already a host (or host:port), keep it; we'll handle host:port below.
    return raw


def _split_host_port(host_value: str, fallback_port: str) -> tuple[str, str]:
    """
    Split "host[:port]" into (host, port). If no port in host_value, use fallback_port.
    """
    hv = (host_value or "").strip()
    if not hv:
        return "", fallback_port

    if ":" in hv:
        host, port = hv.rsplit(":", 1)
        return host.strip(), (port.strip() or fallback_port)

    return hv, fallback_port


# PUBLIC_INTERFACE
def build_postgres_dsn() -> str:
    """
    Build a PostgreSQL DSN from environment variables provided by the database container.

    Expected env vars (database container conventions):
      - POSTGRES_URL, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_PORT

    Notes:
      - Some environments provide POSTGRES_URL as a full URL (e.g. "postgresql://localhost:5000/myapp").
        In that case, we will extract the hostname, and still rely on POSTGRES_PORT/DB/USER/PASSWORD.
      - SQLAlchemy psycopg3 driver prefix is "postgresql+psycopg://".
    """
    raw_url = os.getenv("POSTGRES_URL", "").strip()
    user = os.getenv("POSTGRES_USER", "").strip()
    password = os.getenv("POSTGRES_PASSWORD", "").strip()
    db = os.getenv("POSTGRES_DB", "").strip()
    port = os.getenv("POSTGRES_PORT", "").strip()

    if not all([raw_url, user, password, db, port]):
        missing = [
            k
            for k in ["POSTGRES_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "POSTGRES_PORT"]
            if not (os.getenv(k) or "").strip()
        ]
        raise RuntimeError(
            f"Missing required database environment variables: {', '.join(missing)}. "
            "Ask the orchestrator to populate them in the backend .env."
        )

    host_norm = _normalize_host(raw_url)
    host, effective_port = _split_host_port(host_norm, port)

    if not host:
        raise RuntimeError(
            "Invalid POSTGRES_URL. Expected hostname (e.g. 'localhost') or URL (e.g. 'postgresql://localhost:5000/myapp')."
        )

    return f"postgresql+psycopg://{user}:{password}@{host}:{effective_port}/{db}"


def get_engine() -> Engine:
    dsn = build_postgres_dsn()
    return create_engine(
        dsn,
        pool_pre_ping=True,
        future=True,
    )


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())


# PUBLIC_INTERFACE
def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a SQLAlchemy session and guarantees close()."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# PUBLIC_INTERFACE
def ensure_schema(engine: Optional[Engine] = None) -> None:
    """
    Ensure required tables exist.

    The database container is expected to be initialized, but this makes the backend robust in dev.
    Creates:
      - users
      - images
      - edit_history
    """
    eng = engine or get_engine()
    ddl_statements = [
        """
        CREATE TABLE IF NOT EXISTS users (
          id uuid PRIMARY KEY,
          email text UNIQUE NOT NULL,
          password_hash text NOT NULL,
          display_name text,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at)",
        """
        CREATE TABLE IF NOT EXISTS images (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title text,
          original_storage_key text NOT NULL,
          original_mime_type text,
          original_width int,
          original_height int,
          original_size_bytes bigint,
          current_storage_key text,
          current_mime_type text,
          current_width int,
          current_height int,
          current_size_bytes bigint,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_images_user_created_at ON images (user_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_images_created_at ON images (created_at DESC)",
        """
        CREATE TABLE IF NOT EXISTS edit_history (
          id uuid PRIMARY KEY,
          image_id uuid NOT NULL REFERENCES images(id) ON DELETE CASCADE,
          user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          operation text NOT NULL,
          params jsonb NOT NULL DEFAULT '{}'::jsonb,
          created_at timestamptz NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_edit_history_image_created_at ON edit_history (image_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_edit_history_user_created_at ON edit_history (user_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_edit_history_params_gin ON edit_history USING GIN (params)",
    ]
    with eng.begin() as conn:
        for stmt in ddl_statements:
            conn.execute(text(stmt))


# PUBLIC_INTERFACE
def new_uuid() -> uuid.UUID:
    """Generate a new UUIDv4."""
    return uuid.uuid4()


# PUBLIC_INTERFACE
def utcnow() -> datetime:
    """Return current UTC timestamp with tzinfo."""
    return _utcnow()
