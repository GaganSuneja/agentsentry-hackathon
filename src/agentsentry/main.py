"""AgentSentry control plane — FastAPI entrypoint.

Run locally:
    uvicorn agentsentry.main:app --reload --port 8080
"""

from __future__ import annotations

import logging

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentsentry import __version__
from agentsentry.api import agents, runtime, scans
from agentsentry.config import get_settings


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=level.upper(), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
    )


_TELEMETRY_CONFIGURED = False


def _configure_telemetry(settings) -> None:
    global _TELEMETRY_CONFIGURED  # noqa: PLW0603
    if _TELEMETRY_CONFIGURED or not settings.applicationinsights_connection_string:
        return
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
        configure_azure_monitor(
            connection_string=settings.applicationinsights_connection_string,
        )
        _TELEMETRY_CONFIGURED = True
        logging.getLogger(__name__).info(
            "Azure Monitor OpenTelemetry configured — telemetry flowing to Application Insights"
        )
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).warning("Azure Monitor setup failed: %s", exc)


def create_app() -> FastAPI:
    settings = get_settings()
    _configure_logging(settings.log_level)
    _configure_telemetry(settings)

    app = FastAPI(
        title="AgentSentry",
        version=__version__,
        description=(
            "Unified Scan + Guard + Audit plane for agent fleets. "
            "Built on PyRIT, Azure AI Content Safety Prompt Shields, and "
            "Microsoft Agent Framework."
        ),
    )

    # Dashboard runs on a different origin — allow cross-origin from anywhere
    # while developing. Tighten before any non-demo deployment.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(agents.router)
    app.include_router(scans.router)
    app.include_router(runtime.router)

    @app.get("/", tags=["health"])
    async def root() -> dict:
        return {
            "service": "agentsentry",
            "version": __version__,
            "env": settings.env,
            "storage": settings.storage_backend,
        }

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
