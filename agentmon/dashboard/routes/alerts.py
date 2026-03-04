"""API routes for the alert review dashboard."""

import asyncio
import logging
from functools import partial

import duckdb
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from agentmon.config import append_to_allowlist, find_config_file
from agentmon.storage import EventStore

logger = logging.getLogger(__name__)

router = APIRouter()

LLM_REVIEW_SYSTEM_PROMPT = (
    "You are a network security analyst reviewing a flagged domain from a DNS monitoring system. "
    "Analyze whether this domain is likely benign, suspicious, or malicious. "
    "Consider: domain structure, known services, common false positive patterns, "
    "and the context of which clients queried it.\n\n"
    "Provide a concise assessment (2-3 paragraphs) with:\n"
    "1. Your verdict: benign / suspicious / likely malicious\n"
    "2. Reasoning\n"
    "3. Recommended action (allowlist, investigate, block)"
)


def _get_store(request: Request) -> EventStore:
    """Open a read-write EventStore connection."""
    try:
        store = EventStore(request.app.state.db_path)
        store.connect()
        return store
    except duckdb.IOException as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "Database is locked — another agentmon process (e.g. 'agentmon listen') "
                "may be holding the write lock. Stop it first, then retry. "
                f"Error: {e}"
            ),
        ) from e


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Render the dashboard HTML."""
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "index.html")


@router.get("/api/flagged-domains")
async def flagged_domains(request: Request, min_severity: str | None = None) -> JSONResponse:
    """Get aggregated flagged domains, sorted by severity then count."""
    store = _get_store(request)
    try:
        domains = store.get_flagged_domains_summary(limit=100, min_severity=min_severity)
        # Serialize datetimes
        for d in domains:
            for key in ("first_seen", "last_seen"):
                if d.get(key) is not None:
                    d[key] = str(d[key])
        return JSONResponse(content={"domains": domains})
    finally:
        store.close()


@router.get("/api/domain/{domain:path}/clients")
async def domain_clients(request: Request, domain: str) -> JSONResponse:
    """Get clients that queried a specific domain."""
    store = _get_store(request)
    try:
        clients = store.get_domain_querying_clients(domain)
        for c in clients:
            for key in ("first_query", "last_query"):
                if c.get(key) is not None:
                    c[key] = str(c[key])
        return JSONResponse(content={"domain": domain, "clients": clients})
    finally:
        store.close()


@router.post("/api/domain/{domain:path}/acknowledge")
async def acknowledge_domain(request: Request, domain: str) -> JSONResponse:
    """Acknowledge all alerts for a domain."""
    store = _get_store(request)
    try:
        count = store.acknowledge_domain_alerts(domain)
        return JSONResponse(content={"domain": domain, "acknowledged": count})
    finally:
        store.close()


@router.post("/api/domain/{domain:path}/false-positive")
async def false_positive_domain(request: Request, domain: str) -> JSONResponse:
    """Mark all alerts for a domain as false positives."""
    store = _get_store(request)
    try:
        count = store.mark_domain_false_positive(domain)
        return JSONResponse(content={"domain": domain, "marked_false_positive": count})
    finally:
        store.close()


@router.post("/api/domain/{domain:path}/allowlist")
async def allowlist_domain(request: Request, domain: str) -> JSONResponse:
    """Add a domain to the allowlist in TOML config and in-memory."""
    config = request.app.state.config

    # Add to in-memory allowlist
    config.allowlist.add(domain)

    # Persist to TOML config
    try:
        config_path = find_config_file()
        append_to_allowlist(domain, config_path)
        msg = f"Added '{domain}' to allowlist"
    except Exception as e:
        msg = f"Added to in-memory allowlist but failed to persist: {e}"
        logger.warning(msg)

    # Also mark existing alerts as false positives
    store = _get_store(request)
    try:
        fp_count = store.mark_domain_false_positive(domain)
        ack_count = store.acknowledge_domain_alerts(domain)
    finally:
        store.close()

    return JSONResponse(content={
        "domain": domain,
        "message": msg,
        "false_positives_marked": fp_count,
        "acknowledged": ack_count,
    })


@router.post("/api/domain/{domain:path}/llm-review")
async def llm_review_domain(request: Request, domain: str) -> JSONResponse:
    """Send domain to Claude Sonnet for analysis."""
    anthropic_client = request.app.state.anthropic_client
    if anthropic_client is None or not anthropic_client.available:
        raise HTTPException(
            status_code=503,
            detail=(
                "Anthropic client not available. "
                "Set ANTHROPIC_API_KEY and install: pip install -e '.[cloud-llm]'"
            ),
        )

    # Gather context
    store = _get_store(request)
    try:
        clients = store.get_domain_querying_clients(domain)
    finally:
        store.close()

    # Build user message with context
    client_lines = "\n".join(
        f"  - {c['client']}: {c['query_count']} queries"
        for c in clients[:10]
    ) if clients else "  No query data available"

    user_message = (
        f"Domain: {domain}\n\n"
        f"Clients querying this domain:\n{client_lines}\n\n"
        f"This domain was flagged by the agentmon DNS monitoring system. "
        f"Please analyze it."
    )

    # Run synchronous SDK call in executor to avoid blocking
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        partial(anthropic_client.complete, LLM_REVIEW_SYSTEM_PROMPT, user_message),
    )

    if response is None:
        raise HTTPException(status_code=502, detail="LLM analysis returned no response")

    return JSONResponse(content={"domain": domain, "analysis": response})
