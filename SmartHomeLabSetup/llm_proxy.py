"""
LLM Proxy Service — Transparent Ollama API relay for the A2A Security Lab.

Presents the same REST API as a real Ollama instance so consumers need
zero code changes.  Routing handled by LLM_Manager (flat service list,
healthiest-first).
"""

import asyncio
import logging
from datetime import datetime
from functools import partial

from fastapi import FastAPI, Request, Response
from llm_manager import LLM_Manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="A2A Lab — LLM Proxy")

FAST_PATHS = {"/api/tags", "/api/version"}


# ── Generic relay ───────────────────────────────────────────────────────

async def _relay(request: Request, path: str) -> Response:
    method = request.method
    body = await request.body() if method in ("POST", "PUT", "PATCH") else None

    timeout = (
        15 if path in FAST_PATHS
        else 600 if path == "/api/pull"
        else None
    )

    loop = asyncio.get_event_loop()
    try:
        status, resp_headers, resp_body = await loop.run_in_executor(
            None,
            partial(LLM_Manager.relay_request, method=method, path=path,
                    body=body, timeout_override=timeout),
        )
    except Exception as exc:
        logger.error(f"Relay failed: {method} {path}: {exc}")
        return Response(
            content=f'{{"error": "{exc}"}}',
            status_code=502,
            media_type="application/json",
        )

    ct = resp_headers.get("Content-Type",
                          resp_headers.get("content-type", "application/json"))
    return Response(content=resp_body, status_code=status, media_type=ct)


# ── Ollama-compatible endpoints ─────────────────────────────────────────

@app.api_route("/api/chat", methods=["POST"])
async def relay_chat(request: Request):
    return await _relay(request, "/api/chat")

@app.api_route("/api/generate", methods=["POST"])
async def relay_generate(request: Request):
    return await _relay(request, "/api/generate")

@app.api_route("/api/tags", methods=["GET"])
async def relay_tags(request: Request):
    return await _relay(request, "/api/tags")

@app.api_route("/api/pull", methods=["POST"])
async def relay_pull(request: Request):
    """
    Streaming relay for model pulls.

    Ollama's /api/pull sends progress as newline-delimited JSON chunks.
    We pipe these through in real-time so the dashboard can track download
    progress — unlike the normal buffered relay used for other endpoints.
    """
    import requests as req
    from fastapi.responses import StreamingResponse

    body = await request.body()

    target_url, headers = LLM_Manager.get_target()
    if not target_url:
        return Response(
            content='{"error": "no healthy LLM service available"}',
            status_code=502,
            media_type="application/json",
        )

    url = f"{target_url}/api/pull"

    logger.info(f"🔽 Streaming pull relay to {url}")

    def _stream():
        try:
            with req.post(url, data=body, headers=headers, timeout=1800, stream=True) as resp:
                for chunk in resp.iter_lines():
                    if chunk:
                        yield chunk + b"\n"
        except Exception as exc:
            import json
            logger.error(f"Pull stream error: {exc}")
            yield json.dumps({"status": "error", "error": str(exc)}).encode() + b"\n"

    return StreamingResponse(_stream(), media_type="application/x-ndjson")

@app.api_route("/api/show", methods=["POST"])
async def relay_show(request: Request):
    return await _relay(request, "/api/show")

@app.api_route("/api/embeddings", methods=["POST"])
async def relay_embeddings(request: Request):
    return await _relay(request, "/api/embeddings")

@app.api_route("/api/embed", methods=["POST"])
async def relay_embed(request: Request):
    return await _relay(request, "/api/embed")

@app.api_route("/api/version", methods=["GET"])
async def relay_version(request: Request):
    return await _relay(request, "/api/version")


# ── Proxy health / status ──────────────────────────────────────────────

@app.get("/health")
async def health_check():
    info = LLM_Manager.get_service_status()
    svcs = info.get("services", [])
    any_healthy = any(s.get("healthy") for s in svcs)
    return {
        "status": "healthy" if any_healthy else "degraded",
        "timestamp": datetime.now().isoformat(),
        "service": "llm-proxy",
        "services_total": len(svcs),
        "services_healthy": sum(1 for s in svcs if s.get("healthy")),
    }

@app.get("/health/simple")
async def simple_health():
    return {"status": "healthy", "service": "llm-proxy"}

@app.get("/status")
async def detailed_status():
    return LLM_Manager.get_service_status()


# ── Entry point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=11435)
