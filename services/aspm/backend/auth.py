"""Shared-JWT auth for the ASPM service.

Validates the access token issued by the CSPM (Node) service. Both services share
JWT_ACCESS_SECRET, so the single unified login authorizes /api/aspm/* too.

Token is read from the Authorization: Bearer header, or — for links that can't set
headers (window.open downloads / SSE in some browsers) — from a `token` query param.
"""
import logging
import os
from typing import Optional

import jwt
from fastapi import HTTPException, Request

JWT_ACCESS_SECRET = os.environ.get("JWT_ACCESS_SECRET", "")
# Allow turning auth off for local/dev runs without the gateway (default: on).
# Hard rule: the bypass is refused in production so a stray env var can never
# expose the service. APP_ENV / NODE_ENV = production => auth is always on.
_ENV = (os.environ.get("APP_ENV") or os.environ.get("NODE_ENV") or "development").lower()
_BYPASS_REQUESTED = os.environ.get("ASPM_AUTH_REQUIRED", "true").lower() == "false"
AUTH_REQUIRED = not (_BYPASS_REQUESTED and _ENV != "production")
if _BYPASS_REQUESTED and _ENV == "production":
    logging.getLogger(__name__).error(
        "ASPM_AUTH_REQUIRED=false ignored because APP_ENV/NODE_ENV is production; auth stays enforced"
    )
elif not AUTH_REQUIRED:
    logging.getLogger(__name__).warning(
        "AUTH BYPASS ACTIVE: ASPM_AUTH_REQUIRED=false - every request is treated as ADMIN. Never use outside local dev."
    )


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or request.headers.get("Authorization")
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.query_params.get("token")


def verify_jwt(request: Request) -> dict:
    """FastAPI dependency. Raises 401 unless a valid CSPM access token is present."""
    if request.url.path == "/api/health":
        return {"sub": "healthcheck", "role": "SYSTEM", "type": "access"}

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


def current_tenant(request: Request) -> Optional[str]:
    """FastAPI dependency: the active tenant id for this request.

    Returns the `tid` claim. Returns None only for a platform super admin
    (`sa` == True) operating in system context, which means "no tenant filter".
    A regular user whose token carries no `tid` is rejected with 403.
    Health checks and the local-dev auth bypass behave like system context.
    """
    payload = verify_jwt(request)
    tid = payload.get("tid")
    if tid:
        return str(tid)
    if payload.get("sa") is True:
        return None
    # Health check / dev bypass synthetic payloads carry no tenant: treat as system context.
    if payload.get("sub") in ("healthcheck", "dev") and payload.get("role") in ("SYSTEM", "ADMIN") and "tid" not in payload:
        return None
    raise HTTPException(status_code=403, detail="No active tenant")
