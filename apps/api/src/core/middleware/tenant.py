"""
SATARK Layer 1 — Tenant Middleware (P0-05)
Extracts tenant_id from JWT and makes it available on request.state.
All Neo4j operations use request.state.tenant_id to scope to the right DB.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from jose import JWTError, jwt
from core.config import get_settings

settings = get_settings()

# Routes that do not require tenant context
PUBLIC_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/api/v1/auth/login"}


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.tenant_id = None
        request.state.user_role = None

        if request.url.path not in PUBLIC_PATHS:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                try:
                    payload = jwt.decode(
                        auth[7:], settings.app_secret_key, algorithms=["HS256"]
                    )
                    request.state.tenant_id = payload.get("tenant_id")
                    request.state.user_role = payload.get("role")
                except JWTError:
                    pass  # Auth errors handled by the route dependency

        return await call_next(request)
