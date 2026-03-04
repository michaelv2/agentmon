"""FastAPI application factory for the alert review dashboard."""

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agentmon.config import Config

logger = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


def create_app(config: Config) -> FastAPI:
    """Create and configure the FastAPI dashboard application.

    Args:
        config: agentmon Config object.

    Returns:
        Configured FastAPI app.
    """
    app = FastAPI(
        title="agentmon Dashboard",
        description="Alert review and triage dashboard",
        version="0.1.0",
    )

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Set up templates
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Store config and dependencies in app state
    app.state.config = config
    app.state.templates = templates
    app.state.db_path = config.db_path

    # Lazy-init Anthropic client
    app.state.anthropic_client = None
    if config.anthropic_api_key:
        try:
            from agentmon.llm.anthropic_client import AnthropicClient
            app.state.anthropic_client = AnthropicClient(config.anthropic_api_key)
        except Exception as e:
            logger.warning(f"Failed to initialize Anthropic client: {e}")

    # Register routes
    from agentmon.dashboard.routes.alerts import router as alerts_router
    app.include_router(alerts_router)

    return app
