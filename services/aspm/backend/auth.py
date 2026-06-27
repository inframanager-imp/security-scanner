"""Shared-JWT auth for the ASPM service.

Validates the access token issued by the CSPM (Node) service. Both services share
JWT_ACCESS_SECRET, so the single unified login authorizes /api/aspm/* too.

Token is read from the Authorization: Bearer header, or — for links that can't set
headers (window.open downloads / SSE in some browsers) — from a `token` query param.
"""
import os

import jwt
from fastapi import HTTPException, Request

JWT_ACCESS_SECRET = os.environ.get("JWT_ACCESS_SECRET", "")
# Allow turning auth off for local/dev runs without the gateway (default: on).
AUTH_REQUIRED = os.environ.get("ASPM_AUTH_REQUIRED", "true").lower() != "false"


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.query_params.get("token")


def verify_jwt(request: Request) -> dict:
    """FastAPI dependency. Raises 401 unless a valid CSPM access token is present."""
    if not AUTH_REQUIRED:
        return {"sub": "dev", "role": "ADMIN", "type": "access"}

    if not JWT_ACCESS_SECRET:
        # Misconfiguration: fail closed rather than allow unauthenticated access.
        raise HTTPException(status_code=500, detail="ASPM auth not configured (JWT_ACCESS_SECRET missing)")

    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    try:
        payload = jwt.decode(token, JWT_ACCESS_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    return payload
