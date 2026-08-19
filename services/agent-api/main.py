"""
Agent API — Phase 1 of the LangGraph agentic-AI plan: a SAST/DAST finding
triage agent that replaces the hardcoded ai_analysis/remediation stubs in
services/aspm/backend/scanners.py with real, reference-grounded LLM analysis.

Read-only by design: this service only analyzes findings handed to it and
returns structured JSON. It does not touch cloud accounts, scan targets, or
write directly to the database — the caller (aspm-api) decides what to
persist, same as it does today for the stub values.
"""
import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from auth import verify_jwt
from graph import run_triage, run_blindspot_review

app = FastAPI(
    title="Agent API",
    version="0.1.0",
    docs_url="/api/agent/docs",
    redoc_url="/api/agent/redoc",
    openapi_url="/api/agent/openapi.json",
)


class Finding(BaseModel):
    title: str
    type: Optional[str] = None
    cwe: Optional[str] = None
    asset: Optional[str] = None
    description: Optional[str] = None
    poc: Optional[str] = None
    code_snippet: Optional[str] = None


class BlindspotFile(BaseModel):
    file_path: str
    content: str


def _llm_configured() -> bool:
    provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if provider == "openai":
        return bool(os.environ.get("OPENAI_API_KEY"))
    if provider == "groq":
        return bool(os.environ.get("GROQ_API_KEY"))
    return True  # ollama — local daemon, no API key; reachability is checked at call time


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "provider": os.environ.get("LLM_PROVIDER", "ollama"),
        "model": os.environ.get("AGENT_MODEL", ""),
        "llm_configured": str(_llm_configured()),
    }


@app.post("/triage")
def triage(finding: Finding, _user: dict = Depends(verify_jwt)) -> Dict[str, Any]:
    if not _llm_configured():
        provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
        key_name = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "groq": "GROQ_API_KEY"}.get(provider, "")
        raise HTTPException(status_code=503, detail=f"{key_name or 'LLM'} not configured for provider '{provider}'")
    try:
        return run_triage(finding.model_dump())
    except Exception as exc:  # noqa: BLE001 — surface upstream LLM/parse errors as 502
        raise HTTPException(status_code=502, detail=f"Triage failed: {exc}") from exc


@app.post("/blindspot")
def blindspot(payload: BlindspotFile, _user: dict = Depends(verify_jwt)) -> List[Dict[str, Any]]:
    if not _llm_configured():
        provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
        key_name = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "groq": "GROQ_API_KEY"}.get(provider, "")
        raise HTTPException(status_code=503, detail=f"{key_name or 'LLM'} not configured for provider '{provider}'")
    try:
        return run_blindspot_review(payload.file_path, payload.content)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Blindspot review failed: {exc}") from exc
