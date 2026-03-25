"""API key authentication middleware."""

from fastapi import Request
from fastapi.responses import JSONResponse


class APIKeyMiddleware:
    def __init__(self, api_key: str):
        self._api_key = api_key
        self._protected_paths = ("/analyze", "/analyze/stream")

    async def __call__(self, request: Request, call_next):
        if request.url.path in self._protected_paths:
            key = request.headers.get("X-API-Key", "")
            if key != self._api_key:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                )

        return await call_next(request)
