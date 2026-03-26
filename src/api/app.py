"""FastAPI application factory."""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from src.api.routes import router, set_orchestrator
from src.core.orchestrator import Orchestrator


def create_app(
    **orchestrator_kwargs,
) -> FastAPI:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    app = FastAPI(
        title="Semgrep False-Positive Analyzer",
        version="1.0.0",
        docs_url="/docs",
    )

    # Routes
    app.include_router(router)

    # Orchestrator (lazy — tests can mock it)
    if orchestrator_kwargs:
        orch = Orchestrator(**orchestrator_kwargs)
        set_orchestrator(orch)

    # Static frontend (must come after router so API routes take priority)
    frontend_dir = os.path.join(os.path.dirname(__file__), "../../frontend/dist")
    if os.path.isdir(frontend_dir):
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return app
