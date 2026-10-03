"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, audit
from .jobs import JobManager
from .routes import SessionManager, build_router
from .settings import Settings

STATIC_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="LinuStart", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")
    jobs = JobManager()
    sessions = SessionManager()

    app.state.settings = settings
    app.state.jobs = jobs
    app.state.sessions = sessions

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    app.include_router(build_router(settings, jobs, sessions), prefix="/api")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def index() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))

    @app.on_event("startup")
    async def startup() -> None:
        audit.record("app.start", f"LinuStart {__version__} started")

    return app
