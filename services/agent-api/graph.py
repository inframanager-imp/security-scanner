"""
LangGraph SAST/DAST finding-triage agent.

Takes a raw finding produced by the existing scanners (Semgrep, Bandit, ZAP,
SQLMap, ...) and turns it into the same three fields the `vulnerabilities`
table already has columns for (ai_analysis / remediation / pt_verification) —
today those are hardcoded stub dicts in scanners.py; this replaces them with
a real, grounded LLM analysis.

Graph:  load_references -> analyze -> judge -> format
"""
import os
import re
import json
import difflib
from pathlib import Path
from typing import Any, Dict, List, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END

REFERENCES_DIR = Path(__file__).parent / "references"

_KEYWORD_MAP: Dict[str, List[str]] = {
    "sql": ["sql_injection.md"],
    "xss": ["xss.md"],
    "cross-site scripting": ["xss.md"],
    "ssti": ["ssti.md"],
    "template injection": ["ssti.md"],
    "nosql": ["nosql_injection.md"],
    "graphql": ["graphql_injection.md"],
    "xxe": ["xxe.md"],
    "xml external entity": ["xxe.md"],
    "rce": ["rce.md"],
    "command injection": ["rce.md"],
    "el injection": ["expression_language_injection.md"],
    "ognl": ["expression_language_injection.md"],
    "idor": ["idor.md"],
    "direct object reference": ["idor.md"],
    "privilege escalation": ["privilege_escalation.md"],
    "jwt": ["authentication_jwt.md"],
    "default credential": ["default_credentials.md"],
    "hardcoded credential": ["default_credentials.md"],
    "brute force": ["brute_force.md"],
    "rate limit": ["brute_force.md"],
    "csrf": ["csrf.md"],
    "cve-": ["cve_patterns.md"],
    "denial of service": ["denial_of_service.md"],
    "http method": ["http_method_tamper.md"],
    "information disclosure": ["information_disclosure.md"],
    "insecure cookie": ["insecure_cookie.md"],
    "deserialization": ["insecure_deserialization.md"],
    "jndi": ["jndi_injection.md"],
    "open redirect": ["open_redirect.md"],
    "path traversal": ["path_traversal_lfi_rfi.md"],
    "lfi": ["path_traversal_lfi_rfi.md"],
    "rfi": ["path_traversal_lfi_rfi.md"],
    "php": ["php_security.md"],
    "race condition": ["race_conditions.md"],
    "session fixation": ["session_fixation.md"],
    "smuggling": ["smuggling_desync.md"],
    "request smuggling": ["smuggling_desync.md"],
    "weak crypto": ["weak_crypto_hash.md"],
    "hash": ["weak_crypto_hash.md"],
    "trust boundary": ["trust_boundary.md"],
    "verification code": ["verification_code_abuse.md"],
    "otp": ["verification_code_abuse.md"],
    "ssrf": ["ssrf.md"],
    "business logic": ["business_logic.md"],
    "arbitrary file upload": ["arbitrary_file_upload.md"],
    "file upload": ["arbitrary_file_upload.md"],

    "mass assignment": ["mass_assignment.md"],
    "oauth": ["oauth_oidc_misconfiguration.md"],
    "oidc": ["oauth_oidc_misconfiguration.md"],
    "session puzzling": ["session_puzzling.md"],
    "cache leak": ["shared_client_cache_leak.md"],
    "cleartext": ["cleartext_transmission.md"],
    "certificate": ["certificate_validation.md"],
    "tls": ["certificate_validation.md"],
    "privacy": ["privacy_data_protection.md"],
    "pii": ["privacy_data_protection.md"],
    "prompt injection": ["prompt_injection.md"],
    "insecure output handling": ["insecure_output_handling.md"],
    "excessive agency": ["excessive_agency.md"],
    "system prompt leak": ["system_prompt_leakage.md"],
    "rag": ["rag_vector_security.md"],
    "vector security": ["rag_vector_security.md"],
    "ml supply chain": ["ml_supply_chain_poisoning.md"],
    "mcp": ["mcp_security.md"],
    "ai editor": ["ai_editor_config_poisoning.md"],
    "ldap": ["ldap_injection.md"],
    "xpath": ["xpath_injection.md"],
    "xquery": ["xpath_injection.md"],
    "log injection": ["log_injection.md"],
    "csv injection": ["csv_injection.md"],
    "formula injection": ["csv_injection.md"],
    "prototype pollution": ["client_side_prototype_pollution.md", "server_side_prototype_pollution.md"],
    "dom clobbering": ["dom_clobbering.md"],
    "clickjacking": ["clickjacking.md"],
    "reverse tabnabbing": ["reverse_tabnabbing.md"],
    "websocket": ["websocket_security.md"],
    "postmessage": ["postmessage_security.md"],
    "xssi": ["xssi_jsonp.md"],
    "jsonp": ["xssi_jsonp.md"],
    "reflected file download": ["xssi_jsonp.md"],
    "web cache": ["web_cache_deception.md"],
    "cache poisoning": ["web_cache_deception.md"],
    "cors": ["cors_misconfiguration.md"],
    "host header": ["host_header_poisoning.md"],
    "response splitting": ["http_response_splitting.md"],
    "correlation header": ["correlation_header_injection.md"],
    "tracing header": ["correlation_header_injection.md"],
    "content security policy": ["content_security_policy.md"],
    "csp": ["content_security_policy.md"],
    "xs-leak": ["xs_leaks.md"],
    "regex": ["regex_injection_redos.md"],
    "redos": ["regex_injection_redos.md"],
    "format string": ["format_string_injection.md"],
    "reverse proxy": ["reverse_proxy_access_bypass.md"],
    "xff": ["xff_spoofing.md"],
    "x-forwarded-for": ["xff_spoofing.md"],
    "email parser": ["email_parser_differential.md"],
    "webhook": ["webhook_integration_security.md"],
    "grpc": ["grpc_security.md"],
    "graphql denial": ["graphql_dos.md"],
    "dependency confusion": ["dependency_confusion.md"],
    "supply chain": ["supply_chain_security.md"],
    "hardcoded secret": ["hardcoded_secrets.md"],
    "hardcoded backdoor": ["hardcoded_code_backdoor.md"],
    "backdoor": ["hardcoded_code_backdoor.md"],
    "input validation": ["input_validation.md"],
    "output encoding": ["output_encoding.md"],
    "temp file": ["insecure_temp_file.md"],
    "file permission": ["file_permissions.md"],
    "ssrf": ["ssrf.md"],
    "ssi": ["ssi_injection.md"],
    "esi": ["esi_injection.md"],
    "subdomain takeover": ["subdomain_takeover.md"],
    "iac": ["iac_security.md"],
    "terraform": ["iac_security.md"],
    "cloudformation": ["iac_security.md"],
    "kubernetes": ["kubernetes_cloud_security.md"],
    "k8s": ["kubernetes_cloud_security.md"],
    "cicd": ["cicd_container_security.md"],
    "ci/cd": ["cicd_container_security.md"],
    "container": ["cicd_container_security.md"],
    "nginx": ["nginx_security.md"],
    "baas": ["baas_security.md"],
    "supabase": ["baas_security.md"],
    "firebase": ["baas_security.md"],
    "aspnet": ["aspnet_security_misconfig.md"],
    "asp.net": ["aspnet_security_misconfig.md"],
    "api security": ["api_security.md"],
    "rest api": ["api_security.md"],
}


def _select_references(finding: Dict[str, Any]) -> List[str]:
    haystack = " ".join(
        str(finding.get(k, "")) for k in ("title", "type", "cwe", "description")
    ).lower()
    hits: List[str] = []
    for kw, files in _KEYWORD_MAP.items():
        if kw in haystack:
            for f in files:
                if f not in hits:
                    hits.append(f)
    return hits[:3]  # keep the prompt small; top 3 is plenty for one finding


def _load_reference_text(filenames: List[str]) -> str:
    chunks = []
    for name in filenames:
        path = REFERENCES_DIR / name
        if path.exists():
            chunks.append(f"### Reference: {name}\n{path.read_text(encoding='utf-8')}")
    return "\n\n".join(chunks)


class TriageState(TypedDict, total=False):
    finding: Dict[str, Any]          # raw finding from scanners.py (title, type, cwe, description, poc, code_snippet, ...)
    reference_text: str
    analysis: Dict[str, Any]         # {exploitability, false_positive, risk_score}
    verdict: Dict[str, Any]          # judge output: {confirmed: bool, reason: str}
    remediation: Dict[str, Any]      # {unsafe, safe, explanation}


def _build_llm(provider: str, model_env: str, default_model: str):
    provider = provider.lower()

    if provider == "anthropic":
        model = os.environ.get(model_env, default_model or "claude-sonnet-5")
        return ChatAnthropic(model=model, temperature=0, max_tokens=1024)

    if provider == "openai":
        model = os.environ.get(model_env, default_model or "gpt-4.1-mini")
        return ChatOpenAI(model=model, temperature=0, max_tokens=1024)

    if provider == "groq":
        model = os.environ.get(model_env, default_model or "llama-3.3-70b-versatile")
        return ChatGroq(model=model, temperature=0, max_tokens=1024)

    # default: ollama
    model = os.environ.get(model_env, default_model or "qwen2.5-coder:7b")
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    return ChatOllama(model=model, base_url=base_url, temperature=0, format="json")


def _get_llm_config() -> tuple:
    provider = os.environ.get("LLM_PROVIDER", "ollama")
    return provider, "AGENT_MODEL", "qwen2.5-coder:7b"


def _get_judge_llm_config() -> tuple:
    provider = os.environ.get("JUDGE_PROVIDER") or os.environ.get("LLM_PROVIDER", "ollama")
    return provider, "JUDGE_MODEL", None


_OLLAMA_FALLBACK_ENABLED = os.environ.get("OLLAMA_FALLBACK_ENABLED", "true").lower() != "false"
_OLLAMA_FALLBACK_MODEL = os.environ.get("OLLAMA_FALLBACK_MODEL", "qwen2.5-coder:7b")


def _is_quota_or_credit_error(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
    if status == 429:
        return True
    msg = str(exc).lower()
    return any(s in msg for s in (
        "insufficient_quota", "insufficient quota", "quota exceeded", "exceeded your current quota",
        "rate_limit_exceeded", "rate limit", "429", "credit balance is too low", "billing",
    ))


def _invoke_with_fallback(provider: str, model_env: str, default_model: str, prompt: str):
    llm = _build_llm(provider, model_env, default_model)
    try:
        return llm.invoke(prompt)
    except Exception as exc:
        if provider.lower() == "ollama" or not _OLLAMA_FALLBACK_ENABLED or not _is_quota_or_credit_error(exc):
            raise
        fallback_llm = _build_llm("ollama", "__unused__", _OLLAMA_FALLBACK_MODEL)
        return fallback_llm.invoke(prompt)


def load_references_node(state: TriageState) -> TriageState:
    files = _select_references(state["finding"])
    return {"reference_text": _load_reference_text(files)}


def analyze_node(state: TriageState) -> TriageState:
    finding = state["finding"]
    provider, model_env, default_model = _get_llm_config()
    prompt = f"""You are a SAST/DAST triage analyst. Analyze this finding using the
taint-analysis method (identify source, trace flow, identify sink) described
in the reference material below. Be evidence-based — cite the specific line
or request/response evidence given, don't speculate.

# Reference material
{state.get('reference_text') or '(no specific reference matched — use general AppSec judgement)'}

# Finding
Title: {finding.get('title')}
Type: {finding.get('type')}
CWE: {finding.get('cwe')}
Asset: {finding.get('asset')}
Description: {finding.get('description')}
Evidence/PoC: {finding.get('poc')}
Code:
{finding.get('code_snippet') or '(no code snippet available — reason from the description/PoC alone)'}

If a code snippet is provided above, it is your primary evidence — read the
actual data flow it shows (does tainted input reach the sink unsanitized?
is there a validation/parameterization/allow-list step before the sink?)
rather than defaulting to "insufficient evidence" because no live request
was replayed. Static evidence of an unsanitized flow is sufficient to call
something exploitable; you don't need proof of an actual exploited request.

Respond with ONLY a JSON object (no markdown fences) with keys:
"exploitability" (string, one paragraph),
"false_positive" (string: "Confirmed" or "Likely false positive: <why>"),
"risk_score" (number 0-10)."""
    resp = _invoke_with_fallback(provider, model_env, default_model, prompt)
    analysis = _parse_json(resp.content)
    return {"analysis": analysis}


def judge_node(state: TriageState) -> TriageState:
    finding = state["finding"]
    analysis = state["analysis"]
    provider, model_env, default_model = _get_judge_llm_config()
    prompt = f"""You are a skeptical second reviewer (the "Judge" step). An analyst
produced this verdict on a security finding. Your job is to try to DISPROVE it —
but "I wasn't shown a live exploited request" is NOT grounds for disproof if the
code snippet itself shows tainted input reaching a dangerous sink with no
sanitization/parameterization/allow-list step in between. Static evidence of an
unsanitized flow is sufficient to confirm; reserve rejection for cases where the
code shows a guard/validation/parameterization step the analyst missed, or where
the description's claim isn't actually supported by what the snippet shows.

Finding: {finding.get('title')} ({finding.get('type')}, {finding.get('cwe')})
Evidence/PoC: {finding.get('poc') or finding.get('description')}
Code:
{finding.get('code_snippet') or '(no code snippet available — judge the analyst verdict on the description/PoC alone)'}
Analyst verdict: {json.dumps(analysis)}

Respond with ONLY a JSON object (no markdown fences):
"confirmed" (boolean — true if the code/evidence genuinely shows an unsanitized
exploitable flow, false only if there's a real mitigating control or the claim
isn't actually supported),
"reason" (one sentence, cite the specific line/pattern that decided it)."""
    resp = _invoke_with_fallback(provider, model_env, default_model, prompt)
    verdict = _parse_json(resp.content)
    return {"verdict": verdict}


def remediation_node(state: TriageState) -> TriageState:
    if not state["verdict"].get("confirmed", True):
        return {"remediation": {"unsafe": "", "safe": "", "explanation": "Not remediated — judge marked this as a likely false positive."}}
    finding = state["finding"]
    provider, model_env, default_model = _get_llm_config()
    prompt = f"""Given this confirmed vulnerability, produce a minimal before/after code fix.

Finding: {finding.get('title')} ({finding.get('type')}, {finding.get('cwe')})
Context/snippet:
{finding.get('code_snippet') or finding.get('description')}

Respond with ONLY a JSON object (no markdown fences):
"unsafe": an EXACT, VERBATIM, character-for-character substring copy-pasted from
  the Context/snippet above — the smallest contiguous span of lines that contains
  the vulnerable code. Do NOT paraphrase, summarize, reformat, fix indentation, or
  change whitespace in ANY way. This string will be used to find-and-replace the
  original file, so if it does not match the snippet above byte-for-byte, the fix
  will fail to apply. Copy it exactly as written, including original indentation
  and line breaks.
"safe": the corrected version of that exact same span, with the same surrounding
  formatting/indentation style, containing only the changes needed to fix the
  vulnerability.
"explanation": one paragraph, why this fixes it."""
    resp = _invoke_with_fallback(provider, model_env, default_model, prompt)
    remediation = _parse_json(resp.content)

    unsafe_val = (remediation.get("unsafe") or "").strip()
    safe_val = (remediation.get("safe") or "").strip()
    is_near_duplicate = (
        unsafe_val and safe_val and
        difflib.SequenceMatcher(None, unsafe_val, safe_val).ratio() > 0.85
    )
    if is_near_duplicate:
        remediation = {
            "unsafe": "",
            "safe": "",
            "explanation": remediation.get("explanation") or
                "No concrete code fix available — this finding isn't tied to an editable code span.",
        }
    return {"remediation": remediation}


def _parse_json(text: str) -> Dict[str, Any]:
    text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text, "parse_error": True}


def _parse_json_array(text: str) -> List[Dict[str, Any]]:
    text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


BLINDSPOT_SYSTEM_PROMPT = """You are the attacker. You found a zero-day in this file last week.
Review it for concrete, exploitable security vulnerabilities — not theoretical concerns, not
style issues, not missing best practices. Only report something you could actually demonstrate
an attacker exploiting: how would you break this file?

Skip anything that requires context from other files you cannot see, unless the vulnerability
is still concretely demonstrable from this file alone (e.g. a function with no input validation
that's clearly meant to receive external input).

Rank by lethality: remote code execution > file access/disclosure > auth bypass > information
disclosure > everything else. Report at most 5 findings. If there is genuinely nothing exploitable
here, return an empty array — do not invent findings to have something to report."""


def run_blindspot_review(file_path: str, content: str, max_chars: int = 8000) -> List[Dict[str, Any]]:
    provider, model_env, default_model = _get_llm_config()
    truncated = content[:max_chars]
    prompt = f"""{BLINDSPOT_SYSTEM_PROMPT}

# File: {file_path}
```
{truncated}
```

Respond with ONLY a JSON array (no markdown fences) of objects, each with keys:
"title" (short, specific), "severity" ("Critical"|"High"|"Medium"|"Low"),
"cwe" (e.g. "CWE-78"), "line" (integer or null), "description" (what the flaw is and why it's
exploitable), "exploit_scenario" (concrete one-paragraph attack narrative, not generic)."""
    resp = _invoke_with_fallback(provider, model_env, default_model, prompt)
    return _parse_json_array(resp.content)


def build_graph():
    g = StateGraph(TriageState)
    g.add_node("load_references", load_references_node)
    g.add_node("analyze", analyze_node)
    g.add_node("judge", judge_node)
    g.add_node("remediate", remediation_node)

    g.set_entry_point("load_references")
    g.add_edge("load_references", "analyze")
    g.add_edge("analyze", "judge")
    g.add_edge("judge", "remediate")
    g.add_edge("remediate", END)
    return g.compile()


_compiled_graph = None


def run_triage(finding: Dict[str, Any]) -> Dict[str, Any]:
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    result = _compiled_graph.invoke({"finding": finding})
    return {
        "ai_analysis": result["analysis"],
        "pt_verification": result["verdict"],
        "remediation": result["remediation"],
    }
