"""FastAPI application entry point for EST Adapter.

Initializes configuration, CA backend, authentication, and routes.
Run with: uvicorn est_adapter.main:app --reload
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from est_adapter.audit.logger import (
    configure_audit_logger,
    log_error,
    log_shutdown,
    log_startup,
)
from est_adapter.auth.handler import CombinedAuthHandler
from est_adapter.ca.backend import create_ca_backend
from est_adapter.config import load_config_from_env
from est_adapter.exceptions import ESTAdapterError
from est_adapter.routes.est import configure_routes, router

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from est_adapter.config import Settings

__version__ = "0.1.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional settings instance. If not provided,
            loads from environment or defaults.

    Returns:
        Configured FastAPI application.
    """
    if settings is None:
        settings = load_config_from_env()

    # Configure audit logging
    configure_audit_logger(settings.audit)

    # Initialize CA backend
    ca_backend = create_ca_backend(settings.ca)

    # Initialize auth handler
    auth_handler = CombinedAuthHandler.from_config(settings.auth)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        """Application lifespan events."""
        log_startup(
            version=__version__,
            host=settings.server.host,
            port=settings.server.port,
        )
        yield
        log_shutdown()

    app = FastAPI(
        title="EST Adapter",
        description="Enrollment over Secure Transport (RFC 7030) adapter for certificate management",
        version=__version__,
        lifespan=lifespan,
    )

    # Configure routes with dependencies
    configure_routes(ca_backend, auth_handler, settings)
    app.include_router(router)

    # Global exception handler for EST Adapter errors
    @app.exception_handler(ESTAdapterError)
    async def est_error_handler(
        _request: Request,
        exc: ESTAdapterError,
    ) -> JSONResponse:
        """Handle EST Adapter errors with appropriate HTTP status."""
        log_error(error=exc, context="request_handling")
        return JSONResponse(
            status_code=exc.http_status.value,
            content={
                "error": exc.__class__.__name__,
                "message": exc.message,
                "details": exc.details,
            },
        )

    # Health check endpoint
    @app.get("/health")
    async def health_check() -> dict[str, str]:
        """Health check endpoint for monitoring."""
        return {"status": "healthy", "version": __version__}

    return app


# Default app instance for uvicorn
app = create_app()


def main() -> None:
    """Run the server using uvicorn."""
    settings = load_config_from_env()

    uvicorn_config: dict[str, str | int | bool | None] = {
        "app": "est_adapter.main:app",
        "host": settings.server.host,
        "port": settings.server.port,
        "reload": False,
    }

    # Add TLS configuration if provided
    if settings.server.tls:
        uvicorn_config["ssl_certfile"] = str(settings.server.tls.cert_file)
        uvicorn_config["ssl_keyfile"] = str(settings.server.tls.key_file)

    uvicorn.run(**uvicorn_config)


if __name__ == "__main__":
    main()
