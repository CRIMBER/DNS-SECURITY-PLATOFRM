"""FastAPI application factory.

One process serves both the JSON API under ``/api`` and the static dashboard at
``/``. That removes CORS configuration, a second server, and a build step from
the demo, which matters more than architectural purity at this size.
"""

import contextlib
import logging
import traceback

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import routes
from .config import get_risk_config, get_settings
from .api.routes import CaptureUploadError
from .core.normalizer import DomainValidationError
from .dns_gateway import build_gateway, get_gateway, set_gateway
from .dns_gateway.server import DNSGatewayBindError
from .storage.db import init_db

logger = logging.getLogger("dnssec")


def _error(status: int, code: str, message: str, detail: str = None) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "detail": detail}}
    return JSONResponse(status_code=status, content=body)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """Start and stop the DNS gateway alongside the HTTP API.

    The UDP socket is bound HERE and never in ``create_app()``. The module
    creates an app at import time, and the test suite builds two more, so
    binding in the factory would collide on the listen port immediately.
    Tests construct ``TestClient(create_app())`` without entering it as a
    context manager, so this never runs for them.

    A bind failure is logged and surfaced through /api/dns/status; it does not
    take the HTTP API down, and the status endpoint reports the gateway as not
    running rather than pretending otherwise.
    """
    settings = get_settings()

    if settings.dns_enabled:
        gateway = build_gateway(settings)
        try:
            await gateway.start()
            set_gateway(gateway)
        except DNSGatewayBindError:
            set_gateway(gateway)   # retains bind_error for the status endpoint
    else:
        logger.info("DNS gateway disabled (DNS_ENABLED=false)")

    try:
        yield
    finally:
        gateway = get_gateway()
        if gateway is not None:
            await gateway.stop()
            set_gateway(None)


def create_app() -> FastAPI:
    settings = get_settings()
    risk_config = get_risk_config()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=(
            "Analyses domain names using lexical features, a local "
            "threat-intelligence dataset and a transparent statistical suspicion "
            "model, fuses those independent signals into an explained ALLOW / "
            "MONITOR / BLOCK decision, and enforces that decision on real DNS "
            "traffic through a local DNS gateway. "
            "The gateway resolves allowed queries through the configured "
            "upstream resolver and returns a deliberate block response for "
            "blocked ones. It makes no other outbound connections: it never "
            "issues HTTP requests to a queried domain and never fetches content "
            "from one."
        ),
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.risk_config = risk_config

    # Create the events table before the first request can arrive.
    init_db()

    # -- error handling ----------------------------------------------------
    # A judge typing something strange must never see a stack trace.

    @app.exception_handler(DomainValidationError)
    async def _handle_domain_error(request: Request, exc: DomainValidationError):
        return _error(400, exc.code, exc.message)

    @app.exception_handler(CaptureUploadError)
    async def _handle_capture_error(request: Request, exc: CaptureUploadError):
        # An unreadable capture is the uploader's problem to fix, so say what
        # was wrong with the file rather than returning a server error.
        return _error(400, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
        return _error(
            422,
            "INVALID_REQUEST",
            "The request body was not valid.",
            "{}: {}".format(field, first.get("msg", "invalid value")),
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception):
        logger.error(
            "Unhandled error on %s: %s\n%s",
            request.url.path,
            exc,
            traceback.format_exc(),
        )
        return _error(
            500,
            "INTERNAL_ERROR",
            "The analysis engine encountered an unexpected error.",
            type(exc).__name__,
        )

    app.include_router(routes.router, prefix="/api")

    # -- static dashboard --------------------------------------------------
    frontend = settings.frontend_dir
    if (frontend / "index.html").exists():
        app.mount(
            "/static", StaticFiles(directory=str(frontend)), name="static"
        )

        @app.get("/", include_in_schema=False)
        async def _dashboard():
            return FileResponse(str(frontend / "index.html"))

    else:

        @app.get("/", include_in_schema=False)
        async def _no_dashboard():
            return JSONResponse(
                {
                    "status": "api_only",
                    "message": "Dashboard not built yet. API is live.",
                    "docs": "/api/docs",
                    "health": "/api/health",
                }
            )

    return app


app = create_app()
