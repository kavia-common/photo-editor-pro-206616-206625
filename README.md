# photo-editor-pro-206616-206625

## End-to-end integration (frontend ↔ backend ↔ database)

### Frontend → Backend
Set the frontend env var:

- `REACT_APP_API_BASE_URL=http://localhost:<BACKEND_PORT>` (no trailing slash)

The frontend calls:
- `POST /auth/login`
- `POST /auth/register`
- `GET /images`
- `GET /images/{id}`
- `GET /images/{id}/file`
- `POST /images/upload`
- `POST /images/{id}/save`

### Backend CORS
Configure in backend `.env`:
- `CORS_ALLOW_ORIGINS=http://localhost:3000` (comma-separated or `*` for dev)

### Backend → PostgreSQL
Backend expects the database container conventions:
- `POSTGRES_URL, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_PORT`

Note: the DB container may provide `POSTGRES_URL` as either a hostname (`localhost`) or a full URL
(`postgresql://localhost:5000/myapp`). The backend normalizes this.

Task completed: final integration for API base URL usage + configurable CORS + robust Postgres DSN parsing + aligned frontend/backed endpoints for auth/upload/edit/save/gallery.