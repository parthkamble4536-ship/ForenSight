"""
ForenSight — Advanced Digital Forensics & Evidence Intelligence Platform.

FastAPI application factory, lifespan event handler, and routing assembler.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from forensight.api.routes import api_router
from forensight.core.config import settings
from forensight.crypto.keys import key_manager
from forensight.dashboard.routes import dashboard_router
from forensight.database.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifespan handler.
    Initializes storage directories, SQLite database, and cryptographic keypair.
    """
    settings.ensure_directories()
    init_db()
    key_manager.load_or_create_keypair()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Advanced file-centric digital forensics, deep structural triage, and verifiable reporting.",
    lifespan=lifespan,
)

# Mount static web assets
static_dir = Path(__file__).parent / "dashboard" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Mount API and Web Dashboard routers
app.include_router(api_router)
app.include_router(dashboard_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "forensight.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
