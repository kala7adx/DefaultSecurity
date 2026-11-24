"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from skyline_api.errors import install_error_handlers
from skyline_api.middleware import (
    BodySizeLimitMiddleware,
    OriginGuardMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from skyline_api.routes import assets, auth, catalog, exceptions, findings, integrations, scans
from skyline_api.services import Services, build_services
from skyline_api.settings import ApiSettings

#: Routes that need no session. Everything else declares a permission (tested).
PUBLIC_ROUTES = frozenset({("GET", "/healthz"), ("GET", "/readyz"), ("POST", "/api/v1/auth/login")})


def create_app(settings: ApiSettings, services: Services | None = None) -> FastAPI:
    """Build the app. Tests pass ``services``; otherwise they're built at start-up."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = services is None
        app.state.services = services or build_services(settings)
        try:
            yield
        finally:
            if owned:
                await app.state.services.engine.dispose()

    docs = settings.is_development
    app = FastAPI(
        title="Skyline API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )
    if services is not None:
        app.state.services = services
    install_error_handlers(app)
    for router in (
        catalog.health,
        auth.router,
        integrations.router,
        scans.router,
        assets.router,
        findings.router,
        exceptions.router,
        catalog.router,
    ):
        app.include_router(router)
    # Starlette runs the last-added middleware first, so this list is innermost-first.
    # Security headers are outermost: every response gets them, including the 500 that
    # RequestContextMiddleware produces for unhandled errors.
    app.add_middleware(OriginGuardMiddleware, allowed_origin=settings.public_origin)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts_enabled)
    return app
