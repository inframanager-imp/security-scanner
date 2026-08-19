"""
Client for the agent-api LangGraph triage service (see services/agent-api/).

Best-effort by design: a scan must never fail or stall because the agent is
slow, unreachable, or unconfigured. Callers pass their own hardcoded
ai_analysis/remediation dict as `fallback` and get it back untouched on any
error or timeout — the agent only replaces it on a clean success.
"""
import logging
import os
import time
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

import jwt

from backend import database as db

logger = logging.getLogger(__name__)

AGENT_API_URL = os.environ.get("AGENT_API_URL", "http://agent-api:8100")
JWT_ACCESS_SECRET = os.environ.get("JWT_ACCESS_SECRET", "")
AGENT_TRIAGE_TIMEOUT = float(os.environ.get("AGENT_TRIAGE_TIMEOUT", "45"))

_OLLAMA_EMBED_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434") + "/api/embeddings"
FIX_CACHE_SIMILARITY_THRESHOLD = float(os.environ.get("FIX_CACHE_SIMILARITY_THRESHOLD", "0.85"))


def _service_token() -> str:
    return jwt.encode(
        {"sub": "aspm-scan-worker", "role": "SERVICE", "type": "access", "exp": int(time.time()) + 120},
        JWT_ACCESS_SECRET,
        algorithm="HS256",
    )


def _embed(text: str) -> Optional[List[float]]:
    try:
        body = json.dumps({"model": "nomic-embed-text", "prompt": text[:4000]}).encode()
        req = urllib.request.Request(_OLLAMA_EMBED_URL, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        vec = data.get("embedding")
        return vec if isinstance(vec, list) and vec else None
    except Exception as e:
        logger.warning(f"[agent_client] _embed failed: {type(e).__name__}: {e}")
        return None


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _check_fix_cache(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Returns a full triage result dict if a confident cached fix exists,
    else None. Deliberately only skips the LLM call on a hit for the
    *remediation* — the cache doesn't attempt to judge exploitability/false-
    positive for THIS specific instance (that's genuinely context-dependent
    and cheap relative to remediation generation), so cache hits get a
    clearly-labeled generic ai_analysis rather than a fabricated per-instance one."""
    cwe = finding.get("cwe")
    candidates = db.get_fix_cache_candidates(cwe=cwe)
    if not candidates:
        return None

    query = f"{finding.get('title', '')} {cwe or ''} {finding.get('description', '')}"
    qvec = _embed(query)
    if qvec is None:
        return None

    best, best_score = None, 0.0
    for c in candidates:
        score = _cosine(qvec, c["embedding"])
        if score > best_score:
            best, best_score = c, score

    if best is None or best_score < FIX_CACHE_SIMILARITY_THRESHOLD:
        return None

    db.record_fix_cache_hit(best["id"])
    return {
        "ai_analysis": {
            "exploitability": "Not independently re-analyzed — remediation reused from the fix cache.",
            "false_positive": f"Not re-verified for this instance (fix-cache hit, similarity={best_score:.2f}).",
            "risk_score": finding.get("ai_analysis", {}).get("risk_score", 5.0),
        },
        "remediation": {
            "language": finding.get("remediation", {}).get("language", "generic"),
            "unsafe": best["unsafe"],
            "safe": best["safe"],
            "explanation": best["explanation"] + f" (reused from fix cache — {best_score:.2f} similarity to a previously-solved {best['cwe'] or 'similar'} finding)",
        },
        "pt_verification": None,
    }


def triage_finding(finding: Dict[str, Any], fallback: Dict[str, Any], code_snippet: str = "", skip_cache: bool = False) -> Dict[str, Any]:
    """POST one finding to agent-api /triage. Returns fallback (unchanged) on
    any failure — timeout, agent-api down, no LLM configured, bad response.

    Checks the fix cache first (see _check_fix_cache) — a confident hit skips
    the agent-api call (and its analyze+judge+remediation LLM chain) entirely.
    A cache hit reuses a PRIOR finding's unsafe/safe text verbatim — fine for
    ai_analysis (genuinely reusable), but that text was generated against a
    different file and essentially never literally appears in this one.
    Confirmed live: a cache hit's "unsafe" was a generic templated example
    (os.system('ping ' + user_input)) that could never match the real file,
    silently defeating patch_node's exact/fuzzy matching. Set `skip_cache`
    when the caller already has real, current file content to ground a fresh
    generation with (see scanners.run_triage_stage's `_literal_snippet_for`)
    — that's strictly better for auto-patching than a foreign cached quote.

    `code_snippet` is optional RAG context (top-k similar chunks retrieved from
    the pipeline's vector store, see scanners.retrieve_context) — grounds the
    LLM's verdict in the actual surrounding code instead of the bare finding
    text alone. Falls through to agent-api's own description-only prompt when
    empty, so callers without a vector store still work unchanged."""
    cached = None if skip_cache else _check_fix_cache(finding)
    if cached is not None:
        return cached

    if not JWT_ACCESS_SECRET:
        return fallback

    body = json.dumps({
        "title": finding.get("title", ""),
        "type": finding.get("type"),
        "cwe": finding.get("cwe"),
        "asset": finding.get("asset"),
        "description": finding.get("description"),
        "poc": json.dumps(finding.get("poc")) if isinstance(finding.get("poc"), dict) else finding.get("poc"),
        "code_snippet": code_snippet or None,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{AGENT_API_URL}/triage",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_service_token()}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=AGENT_TRIAGE_TIMEOUT) as resp:
            result = json.loads(resp.read())
            remediation = result.get("remediation") or fallback.get("remediation")
            unsafe = (remediation or {}).get("unsafe", "").strip()
            safe = (remediation or {}).get("safe", "").strip()
            if unsafe and safe:
                qvec = _embed(f"{finding.get('title', '')} {finding.get('cwe', '')} {finding.get('description', '')}")
                if qvec is not None:
                    try:
                        db.save_fix(
                            cwe=finding.get("cwe", ""), title=finding.get("title", ""),
                            description=finding.get("description", ""), embedding=qvec,
                            unsafe=unsafe, safe=safe, explanation=remediation.get("explanation", ""),
                        )
                    except Exception:
                        pass  # caching is best-effort — never let it fail a real triage result
            return {
                "ai_analysis": result.get("ai_analysis") or fallback.get("ai_analysis"),
                "remediation": remediation,
                "pt_verification": result.get("pt_verification"),
            }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError) as e:
        logger.warning(f"[agent_client] triage_finding fallback for {finding.get('title', '')[:60]!r}: {type(e).__name__}: {e}")
        return fallback


def blindspot_review_file(file_path: str, content: str, timeout: Optional[float] = None) -> List[Dict[str, Any]]:
    """POST one source file to agent-api /blindspot for an adversarial
    single-file review. Returns [] on any failure — same fail-closed,
    best-effort contract as triage_finding: a slow/unreachable agent-api
    must never stall or fail the blind-spot sweep stage."""
    if not JWT_ACCESS_SECRET:
        return []

    body = json.dumps({"file_path": file_path, "content": content}).encode("utf-8")
    req = urllib.request.Request(
        f"{AGENT_API_URL}/blindspot",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_service_token()}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout or AGENT_TRIAGE_TIMEOUT) as resp:
            result = json.loads(resp.read())
            return result if isinstance(result, list) else []
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError) as e:
        logger.warning(f"[agent_client] blindspot_review_file fallback for {file_path!r}: {type(e).__name__}: {e}")
        return []
