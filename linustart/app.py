"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import audit
from .jobs import JobManager
from .routes import build_router
from .sessions import SessionManager
from .settings import Settings
from .terminal import TerminalManager
from .updater import running_version, version_details

STATIC_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings) -> FastAPI:
    version = running_version()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        audit.record("app.start", f"LinuStart {version} started")
        # Changes left unconfirmed when the panel last stopped still revert.
        sessions.resume()
        yield

    app = FastAPI(
        title="LinuStart",
        version=version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    jobs = JobManager()
    sessions = SessionManager()
    terminals = TerminalManager()

    app.state.settings = settings
    app.state.jobs = jobs
    app.state.sessions = sessions
    app.state.terminals = terminals

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(_request: Request, exc: RuntimeError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.get("/api/health")
    async def health() -> dict:
        # 'commit' only appears on a git checkout; a release tarball has no
        # repository to ask, so the declared version is all we can report.
        details = version_details()
        return {
            "status": "ok",
            "version": details["version"],
            "version_source": details["source"],
            "commit": details["commit"],
        }

    app.include_router(build_router(settings, jobs, sessions, terminals), prefix="/api")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def index() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))

    return app
