"""Admin API main application for certificate-orchestrator-proxy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import uvicorn
from fastapi import FastAPI

from est_adapter.admin.api import (
    ca_backends_router,
    enrollment_events_router,
    est_profiles_router,
    status_router,
)
from est_adapter.database import init_database

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

__version__ = "0.1.0"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan events."""
    # Initialize database on startup
    await init_database()
    yield
    # Cleanup on shutdown (if needed)


def create_admin_app() -> FastAPI:
    """Create and configure the admin FastAPI application.

    Returns:
        Configured admin FastAPI application.
    """
    app = FastAPI(
        title="Certificate Orchestrator Proxy Admin API",
        description="Admin API for managing CA backends, EST profiles, and enrollment events",
        version=__version__,
        lifespan=lifespan,
    )

    # Include all admin routers
    app.include_router(ca_backends_router)
    app.include_router(est_profiles_router)
    app.include_router(enrollment_events_router)
    app.include_router(status_router)

    return app


# Default app instance for uvicorn
app = create_admin_app()


def main() -> None:
    """Run the admin server using uvicorn."""
    uvicorn_config: dict[str, str | int | bool | None] = {
        "app": "est_adapter.admin.main:app",
        "host": "0.0.0.0",
        "port": 8000,
        "reload": False,
    }

    uvicorn.run(**uvicorn_config)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
