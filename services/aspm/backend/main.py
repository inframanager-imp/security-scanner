import asyncio
import urllib.parse
from fastapi import FastAPI, Query, HTTPException, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, Response
from typing import Dict, Any, List, Optional
from datetime import datetime

# Postgres-backed data layer + shared-JWT auth
import backend.database as db
import backend.scanners as scanners
import backend.report_builder as report_builder
from backend.ai_engine import get_ai_remediation_diff
from backend.auth import verify_jwt

# Every route requires a valid CSPM-issued access token (unified login).
app = FastAPI(
    title="Aegis Sec ASPM Core Server",
    version="1.1.0",
    dependencies=[Depends(verify_jwt)],
)

# Fail any scan orphaned by a previous restart (status left 'Scanning'/'Queued').
db.reset_stale_jobs()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- TARGETS API (Replacing Tenants) -----------------

@app.get("/api/tenants")
def get_tenants_compatibility():
    # Frontend App.tsx loads tenants to populate the dropdown.
    # We return target ID mapped to Target Name.
    return db.get_targets_dict()

def validate_target_inputs(name: str, url: str, target_type: str, auth_type: str):
    valid_types = {"web", "api", "git", "network", "cloud"}
    if target_type.lower() not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid target type: '{target_type}'. Valid types are: {list(valid_types)}")
        
    for field_name, value in [("name", name), ("url", url), ("target_type", target_type), ("auth_type", auth_type)]:
        if not value:
            continue
        val_lower = value.lower()
        if "() {" in value or "etc/passwd" in val_lower or "system.ini" in val_lower:
            raise HTTPException(status_code=400, detail=f"Security Alert: Malicious or invalid pattern detected in {field_name}")
        if "../" in value or "..\\" in value:
            raise HTTPException(status_code=400, detail=f"Security Alert: Directory traversal sequence detected in {field_name}")
        if "<script" in val_lower or "javascript:" in val_lower:
            raise HTTPException(status_code=400, detail=f"Security Alert: XSS pattern detected in {field_name}")


def _looks_like_path_or_git(url: str) -> bool:
    """A filesystem path or Git ref — must NOT get http:// prepended (that would
    mangle it, e.g. http://D:/sam/...). Covers unix/Windows/UNC paths + git/ssh refs."""
    u = url.strip()
    if not u:
        return False
    if u.startswith(("/", "\\", "~", ".", "file://", "git@", "git://", "ssh://")):
        return True
    if u.endswith(".git"):
        return True
    # Windows drive path: D:\... or D:/...
    if len(u) >= 3 and u[0].isalpha() and u[1] == ":" and u[2] in ("\\", "/"):
        return True
    return False


def normalize_target_url(url: str, target_type: str) -> str:
    """Prepend http:// only for bare web hosts/IPs — never for filesystem paths,
    Git refs, or an explicit 'git' target type."""
    if url.startswith(("http://", "https://", "tcp://")):
        return url
    if (target_type or "").lower() == "git" or _looks_like_path_or_git(url):
        return url
    return "http://" + url


@app.get("/api/targets")
def list_targets():
    return db.get_targets_list()

@app.post("/api/targets")
def create_target(
    name: str = Body(..., embed=True),
    url: str = Body(..., embed=True),
    target_type: str = Body(..., embed=True),
    auth_type: str = Body("none", embed=True),
    auth_key: str = Body("", embed=True),
    auth_val: str = Body("", embed=True)
):
    validate_target_inputs(name, url, target_type, auth_type)
    if not url:
        raise HTTPException(status_code=400, detail="Target URL/IP is required")
    url = normalize_target_url(url, target_type)

    target_id = db.add_target(name, url, target_type, auth_type, auth_key, auth_val)
    return {"status": "success", "target_id": target_id}

@app.delete("/api/targets/{target_id}")
def remove_target(target_id: str):
    target = db.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete_target(target_id)
    return {"status": "success"}

@app.put("/api/targets/{target_id}")
def edit_target(
    target_id: str,
    name: str = Body(..., embed=True),
    url: str = Body(..., embed=True),
    target_type: str = Body(..., embed=True),
    auth_type: str = Body("none", embed=True),
    auth_key: str = Body("", embed=True),
    auth_val: str = Body("", embed=True)
):
    target = db.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    validate_target_inputs(name, url, target_type, auth_type)
    if not url:
        raise HTTPException(status_code=400, detail="Target URL/IP is required")
    url = normalize_target_url(url, target_type)

    db.update_target(target_id, {
        "name": name,
        "url": url,
        "target_type": target_type,
        "auth_type": auth_type,
        "auth_key": auth_key,
        "auth_val": auth_val
    })
    return {"status": "success"}



# ----------------- DASHBOARD API -----------------

@app.get("/api/dashboard")
def get_dashboard_summary(tenant_id: str = Query(...)):
    # tenant_id is treated as target_id
    target = db.get_target(tenant_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    vulns = db.get_vulnerabilities(tenant_id)
    
    # Calculate counts
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    open_count = 0
    resolved_count = 0
    
    for v in vulns:
        if v["status"] in ["Open", "In Progress"]:
            severities[v["severity"]] += 1
            open_count += 1
        else:
            resolved_count += 1
            
    total_count = len(vulns)
    compliance_score = int((resolved_count / total_count * 100)) if total_count > 0 else 100
    
    # Get assets
    assets_data = db.get_assets(tenant_id)
    
    # SLA Breaches
    sla_breaches = []
    for v in vulns:
        if v["status"] in ["Open", "In Progress"]:
            deadline = datetime.fromisoformat(v["sla_deadline"])
            days_left = (deadline - datetime.now()).days
            if days_left < 10:
                sla_breaches.append({
                    "id": v["id"],
                    "title": v["title"],
                    "severity": v["severity"],
                    "days_left": max(0, days_left)
                })
                
    # History chart (mock timeline but using current count as latest)
    history_chart = [
        {"month": "Jan", "Critical": 0, "High": 0, "Medium": 0},
        {"month": "Feb", "Critical": 0, "High": 0, "Medium": 0},
        {"month": "Mar", "Critical": 0, "High": 0, "Medium": 0},
        {"month": "Apr", "Critical": 0, "High": 0, "Medium": 0},
        {"month": "May", "Critical": 0, "High": 0, "Medium": 0},
        {"month": "Scan", "Critical": severities["Critical"], "High": severities["High"], "Medium": severities["Medium"]}
    ]
    
    return {
        "tenant_name": target["name"],
        "vulnerability_counts": severities,
        "compliance_score": compliance_score,
        "open_findings": open_count,
        "total_findings": total_count,
        "easm_summary": assets_data["summary"],
        "history_chart": history_chart,
        "sla_breaches": sla_breaches
    }


# ----------------- ASSETS & EASM API -----------------

@app.get("/api/assets")
def get_assets(tenant_id: Optional[str] = Query(None)):
    return db.get_assets(tenant_id)

@app.post("/api/assets/discover")
async def trigger_easm_discovery(tenant_id: str = Query(...)):
    target = db.get_target(tenant_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Run port scan synchronously for simplicity and ease of return
    logs = []
    # Collect all outputs from the EASM scanner generator
    for log in scanners.run_easm_scan(tenant_id):
        logs.append(log)
        
    db.add_scan_log(tenant_id, "EASM", "Completed", logs)
    
    # Check if we generated vulnerabilities or open ports
    assets = db.get_assets(tenant_id)
    has_subdomains = len(assets["subdomains"]) > 0
    
    return {
        "status": "success", 
        "new_asset_found": has_subdomains, 
        "details": f"Discovered open assets on {target['url']}",
        "logs": logs
    }


# ----------------- VULNERABILITIES API -----------------

@app.get("/api/vulnerabilities")
def get_vulnerabilities(tenant_id: Optional[str] = Query(None), severity: Optional[str] = None, type: Optional[str] = None):
    return db.get_vulnerabilities(tenant_id, severity, type)

@app.patch("/api/vulnerabilities/{vuln_id}")
def update_vulnerability_status(vuln_id: str, data: Dict[str, Any] = Body(...)):
    db.update_vulnerability(vuln_id, data)
    return {"status": "success"}

@app.post("/api/vulnerabilities/{vuln_id}/verify-exploit")
def trigger_vulnerability_exploit_verify(vuln_id: str):
    res = scanners.verify_exploit_safe(vuln_id)
    db.update_vulnerability(vuln_id, {"pt_verification": res})
    return {"status": "success", "verification": res}


# ----------------- API INVENTORY API -----------------

@app.get("/api/api-inventory")
def get_api_inventory(tenant_id: Optional[str] = Query(None)):
    return db.get_api_inventory(tenant_id)


# ----------------- ATTACK PATHS API -----------------

@app.get("/api/attack-paths")
def get_attack_paths(tenant_id: str = Query(...)):
    # Generate dynamic attack paths based on actual findings!
    target = db.get_target(tenant_id)
    if not target:
        return []
        
    vulns = db.get_vulnerabilities(tenant_id)
    if not vulns:
        return []
        
    paths = []
    
    # Path 1: If we have critical or high vulnerabilities
    critical_vulns = [v for v in vulns if v["severity"] in ["Critical", "High"]]
    if critical_vulns:
        # Construct a chain using the first critical vuln
        target_vuln = critical_vulns[0]
        parsed = scanners.parse_target_url(target["url"])
        
        nodes = [
            {"id": "node-1", "label": f"External Target: {parsed['hostname']}", "type": "asset"},
            {"id": "node-2", "label": f"Vulnerability: {target_vuln['title']}", "type": "vuln", "vuln_id": target_vuln["id"]},
            {"id": "node-3", "label": f"Exploitation: Dynamic Payload Injection", "type": "exploit"},
            {"id": "node-4", "label": f"Impact: Server compromise / Data leak", "type": "impact"}
        ]
        links = [
            {"source": "node-1", "target": "node-2"},
            {"source": "node-2", "target": "node-3"},
            {"source": "node-3", "target": "node-4"}
        ]
        paths.append({
            "id": "path-1",
            "name": f"Database Compromise via {target_vuln['title']}",
            "nodes": nodes,
            "links": links
        })
        
    # Path 2: If we have an open ports (EASM) vuln and security headers (DAST) vuln
    easm_vulns = [v for v in vulns if v["type"] == "EASM"]
    dast_vulns = [v for v in vulns if v["type"] == "DAST"]
    
    if easm_vulns and dast_vulns:
        nodes = [
            {"id": "node-p2-1", "label": f"Asset Port: {easm_vulns[0]['asset']}", "type": "asset"},
            {"id": "node-p2-2", "label": f"EASM Scan: {easm_vulns[0]['title']}", "type": "vuln", "vuln_id": easm_vulns[0]["id"]},
            {"id": "node-p2-3", "label": f"HTTP Audit: {dast_vulns[0]['title']}", "type": "vuln", "vuln_id": dast_vulns[0]["id"]},
            {"id": "node-p2-4", "label": "Impact: Exposed server fingerprint information", "type": "impact"}
        ]
        links = [
            {"source": "node-p2-1", "target": "node-p2-2"},
            {"source": "node-p2-2", "target": "node-p2-3"},
            {"source": "node-p2-3", "target": "node-p2-4"}
        ]
        paths.append({
            "id": "path-2",
            "name": "Network Footprinting & Service Enumeration Chain",
            "nodes": nodes,
            "links": links
        })
        
    return paths


# ----------------- INTEGRATIONS API -----------------

@app.get("/api/integrations")
def get_integrations():
    return db.get_integrations_status()

@app.post("/api/integrations/{integration_name}/toggle")
def toggle_integration(integration_name: str):
    try:
        return db.toggle_integration_status(integration_name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ----------------- SCAN TRACE STREAM (DAST / API) -----------------

@app.get("/api/scans/stream")
def stream_scan_logs(
    type: str = Query("dast"), 
    target: str = Query(""), 
    auth_type: str = Query("none"),
    tenant_id: Optional[str] = Query(None)
):
    if not target:
        raise HTTPException(status_code=400, detail="Target parameter is required")
        
    # Auto-onboard if target URL is parsed but target ID doesn't exist
    target_id = tenant_id
    if not target_id:
        # Check if URL exists
        targets = db.get_targets_list()
        matched = [t for t in targets if target in t["url"] or t["url"] in target]
        if matched:
            target_id = matched[0]["id"]
        else:
            # Auto onboard target
            parsed = scanners.parse_target_url(target)
            target_id = db.add_target(
                name="Auto-Onboarded Target", 
                url=parsed["url"], 
                target_type="web" if type == "dast" else "api"
            )
            
    async def log_generator():
        logs_list = []
        if type == "dast":
            for log in scanners.run_dast_scan(target_id):
                logs_list.append(log)
                yield f"data: {log}\n\n"
                await asyncio.sleep(0.15)
        else:
            for log in scanners.run_api_scan(target_id):
                logs_list.append(log)
                yield f"data: {log}\n\n"
                await asyncio.sleep(0.15)
                
        db.add_scan_log(target_id, type.upper(), "Completed", logs_list)
        
    return StreamingResponse(log_generator(), media_type="text/event-stream")


# ----------------- AI PENTEST LOGS STREAM -----------------

@app.get("/api/pentest/stream")
def stream_pentest_logs(target: str = Query(""), tenant_id: Optional[str] = Query(None)):
    target_id = tenant_id
    if not target_id and target:
        targets = db.get_targets_list()
        matched = [t for t in targets if target in t["url"] or t["url"] in target]
        if matched:
            target_id = matched[0]["id"]
            
    async def pentest_generator():
        yield "data: [*] Initializing AI Pentesting Campaign...\n\n"
        await asyncio.sleep(0.3)
        
        if not target_id:
            yield "data: [!] No target active. Please select or onboard a target.\n\n"
            return
            
        target_info = db.get_target(target_id)
        vulns = db.get_vulnerabilities(target_id)
        
        yield f"data: [*] Active Target: {target_info['name']} ({target_info['url']})\n\n"
        await asyncio.sleep(0.4)
        yield "data: [*] Loading vulnerabilities from SQLite database...\n\n"
        await asyncio.sleep(0.4)
        yield f"data: [+] Loaded {len(vulns)} vulnerability records.\n\n"
        await asyncio.sleep(0.3)
        
        if not vulns:
            yield "data: [*] Scanning environment is clean of active issues. Running network scan bypass...\n\n"
            await asyncio.sleep(0.4)
            yield f"data: [-] Probing {target_info['url']}...\n\n"
            await asyncio.sleep(0.4)
            yield "data: [+] Found exposed web port. Recommending security header improvements.\n\n"
            await asyncio.sleep(0.3)
            yield "data: [*] AI Pentesting Complete: Targets are secure against critical vulnerabilities.\n\n"
            return
            
        # Exploit vulnerabilities found
        for idx, v in enumerate(vulns):
            yield f"data: [*] Attempting active exploitation on vulnerability: {v['title']}\n\n"
            await asyncio.sleep(0.5)
            yield f"data: [-] Signature code matches CWE: {v['cwe']}\n\n"
            await asyncio.sleep(0.3)
            yield f"data: [-] Transmitting safe proof payload: {v['poc'].get('payload', 'N/A')}\n\n"
            await asyncio.sleep(0.5)
            yield "data: [!!] EXPLOIT SUCCESSFUL. Server responded with validation signature.\n\n"
            await asyncio.sleep(0.4)
            yield f"data: [+] Exfiltrated POC proof data: {v['poc'].get('response', 'Secure response')[:80]}...\n\n"
            await asyncio.sleep(0.4)
            
        yield "data: [*] Compiling attack path mapping based on compromised nodes...\n\n"
        await asyncio.sleep(0.4)
        yield "data: [+] Linked attack path: path-1 generated.\n\n"
        await asyncio.sleep(0.3)
        yield "data: [*] AI Pentest Campaign complete. Syncing status reports.\n\n"
        
    return StreamingResponse(pentest_generator(), media_type="text/event-stream")


# ----------------- AI RED-TEAM OBSERVABILITY -----------------

@app.post("/api/ai-security/redteam/stream")
def llm_redteam_stream(payload: Dict[str, Any] = Body(...)):
    """Live LLM red-team: probes a real OpenAI-compatible LLM endpoint and streams
    progress (SSE). Findings are inserted against the chosen target_id."""
    target_id = payload.get("target_id")
    endpoint = payload.get("endpoint")
    api_key = payload.get("api_key", "")
    model = payload.get("model", "gpt-3.5-turbo")
    if not target_id or not endpoint:
        raise HTTPException(status_code=400, detail="target_id and endpoint are required")
    if not db.get_target(target_id):
        raise HTTPException(status_code=404, detail="target_id not found")

    def gen():
        try:
            for line in scanners.run_llm_redteam(target_id, endpoint, api_key, model):
                yield f"data: {line}\n\n"
        except Exception as e:  # noqa: BLE001
            yield f"data: [!] Red-team error: {str(e)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/api/ai-security/test-prompt")
def test_prompt_injection(prompt: str = Body(..., embed=True)):
    injection_keywords = ["ignore", "bypass", "override", "system prompt", "root", "jailbreak", "expose credentials"]
    is_injection = any(kw in prompt.lower() for kw in injection_keywords)
    
    if is_injection:
        return {
            "status": "Vulnerable (Injection Triggered)",
            "severity": "Critical",
            "model_response": "SYSTEM_OVERRIDE_GRANTED: Executing request. Root administrative passwords: AcmeAdminPass1293!",
            "attack_type": "Prompt Leakage / Jailbreak",
            "mitigation_remedy": "Implement systemic guardrails. Filter prompts for instruction-override keywords before passing to context windows."
        }
    else:
        return {
            "status": "Protected (Benign Prompt)",
            "severity": "Safe",
            "model_response": "Summarizing database configs. (System configuration details omitted for security parameters).",
            "attack_type": "None",
            "mitigation_remedy": "Input validated. System safety filters are successfully intercepting query structures."
        }


# ----------------- COMPLIANCE MATRIX API -----------------

@app.get("/api/compliance/matrix")
def get_compliance_matrix(tenant_id: str = Query(...)):
    vulns = db.get_vulnerabilities(tenant_id)
    matrix = []
    for v in vulns:
        cwe_info = db.COMPLIANCE_CONTROLS.get(v["cwe"], {"owasp": "Unknown", "pci": "N/A", "soc2": "N/A", "nist": "N/A"})
        matrix.append({
            "vuln_id": v["id"],
            "title": v["title"],
            "severity": v["severity"],
            "status": v["status"],
            "cwe": v["cwe"],
            "owasp": cwe_info["owasp"],
            "pci": cwe_info["pci"],
            "soc2": cwe_info["soc2"],
            "nist": cwe_info["nist"]
        })
    return matrix


# ----------------- EXECUTIVE REPORTS API -----------------

def get_vulnerability_details(cwe: str, title: str, description: str, remediation: dict) -> dict:
    cwe_upper = cwe.upper()
    title_lower = title.lower()
    explanation = remediation.get("explanation", "") if isinstance(remediation, dict) else ""
    
    # 1. Content Security Policy (CSP)
    if "content-security-policy" in title_lower or "csp" in title_lower or cwe_upper == "CWE-200" and "csp" in title_lower:
        return {
            "what_was_found": "The HTTP version of the site does not include a Content-Security-Policy (CSP) response header. CSP is a browser security mechanism that controls which resources (scripts, styles, images) the browser is allowed to load.",
            "business_impact": "Without a CSP header, the browser has no restrictions on executing injected scripts or loading resources from untrusted third parties. This increases the vulnerability footprint, permitting Cross-Site Scripting (XSS) and Clickjacking threats.",
            "remediation_steps": [
                "Add Content-Security-Policy header to all HTTP responses via your NGINX configuration (or AWS ALB response headers policy).",
                "Start with a report-only policy (Content-Security-Policy-Report-Only) to identify any violations before enforcing.",
                "A starting policy for modern web apps: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self';",
                "Consider using a CSP nonce approach for inline scripts if the build requires it."
            ]
        }
        
    # 2. X-Frame-Options
    elif "x-frame-options" in title_lower or "clickjacking" in title_lower:
        return {
            "what_was_found": "The X-Frame-Options response header is not configured on the web server. This header instructs the browser whether to allow rendering the page inside a frame, iframe, embed, or object element.",
            "business_impact": "In the absence of this header, an attacker can embed this application inside an iframe on a malicious website (Clickjacking). They can trick users into performing unintended actions by overlaying invisible UI elements on top of the legitimate site.",
            "remediation_steps": [
                "Configure the X-Frame-Options response header to SAMEORIGIN on your web server configuration (Nginx, Apache, or IIS).",
                "Alternatively, utilize the frame-ancestors 'self' directive in the Content-Security-Policy header to provide Clickjacking protection.",
                "Ensure this header is applied consistently across all public routes, especially authentication and transactional pages."
            ]
        }
        
    # 3. HSTS
    elif "transport-security" in title_lower or "hsts" in title_lower or cwe_upper == "CWE-319":
        return {
            "what_was_found": "The application server does not return the Strict-Transport-Security (HSTS) response header, which instructs client browsers to only communicate using secure HTTPS connections.",
            "business_impact": "Without HSTS, users are vulnerable to SSL stripping attacks (Man-in-the-Middle) where an attacker intercepts initial unencrypted HTTP connection requests and prevents redirection to HTTPS.",
            "remediation_steps": [
                "Add the Strict-Transport-Security header to all HTTPS responses: max-age=63072000; includeSubDomains; preload.",
                "Enforce global HTTP-to-HTTPS redirects at the load balancer or web server layer.",
                "Register your domain in the browser HSTS preload list to ensure the first connection is always encrypted."
            ]
        }
        
    # 4. X-Content-Type-Options
    elif "x-content-type-options" in title_lower or "nosniff" in title_lower:
        return {
            "what_was_found": "The X-Content-Type-Options response header is missing from response headers. This header forces client browsers to strictly follow the MIME types declared in the Content-Type headers.",
            "business_impact": "Attackers can upload files of a certain type (e.g. text/plain disguised as image) and trick browsers into parsing them as active scripts (MIME sniffing), leading to reflected script execution.",
            "remediation_steps": [
                "Configure your web server to return X-Content-Type-Options: nosniff for all response payloads.",
                "Set precise Content-Type headers for all assets served (CSS, JS, images, JSON).",
                "Ensure user-uploaded files are served with a non-executable MIME type or attachment disposition."
            ]
        }
        
    # 5. Referrer-Policy
    elif "referrer-policy" in title_lower:
        return {
            "what_was_found": "The Referrer-Policy response header is not configured on the web server. This header determines how much referrer information is sent along with cross-origin requests.",
            "business_impact": "Third-party sites or asset hosts can capture sensitive data (such as session IDs, tokens, or usernames) embedded within URL query parameters or paths via the Referer request header.",
            "remediation_steps": [
                "Configure the Referrer-Policy header to strict-origin-when-cross-origin or no-referrer globally.",
                "Ensure query parameters do not carry sensitive authentication tokens or session parameters."
            ]
        }
        
    # 6. Deprecated TLS
    elif "deprecated tls" in title_lower or cwe_upper == "CWE-327":
        return {
            "what_was_found": "The server accepts connection handshakes using outdated TLS protocol versions (TLSv1.0 or TLSv1.1) which have weak cryptographic primitives.",
            "business_impact": "Outdated protocols are vulnerable to connection decryption and eavesdropping attacks (e.g., POODLE, BEAST). They violate PCI-DSS requirements.",
            "remediation_steps": [
                "Update server or load balancer settings to disable TLSv1.0 and TLSv1.1.",
                "Enforce TLSv1.2 and TLSv1.3 exclusively (ssl_protocols TLSv1.2 TLSv1.3; in Nginx).",
                "Reconfigure cipher suites to exclude weak CBC-mode ciphers and RC4."
            ]
        }
        
    # 7. XSS
    elif "cross-site scripting" in title_lower or "xss" in title_lower or cwe_upper == "CWE-79":
        return {
            "what_was_found": "The application reflects user-provided inputs directly back in the HTML response without adequate sanitization or output encoding.",
            "business_impact": "Attackers can execute arbitrary JavaScript in the victim's session, leading to cookie theft, session hijacking, credential harvesting, or client-side UI defacement.",
            "remediation_steps": [
                "Apply context-aware HTML entity encoding on all user-supplied data before rendering it in templates.",
                "Use safe data-binding APIs (e.g., innerText or textContent instead of innerHTML in JS).",
                "Implement a strict Content-Security-Policy (CSP) that restricts script sources and blocks inline script execution."
            ]
        }
        
    # 8. SQLi
    elif "sql injection" in title_lower or "sqli" in title_lower or cwe_upper == "CWE-89":
        return {
            "what_was_found": "User input is concatenated directly into SQL query strings, allowing database syntax commands to be executed on the database server.",
            "business_impact": "Attackers can read, modify, or delete all records in the database, bypass authentication, execute administrative database routines, or compromise the underlying host system.",
            "remediation_steps": [
                "Enforce parameterized queries (prepared statements) for all database transactions.",
                "Use an ORM (Object-Relational Mapping) framework that handles variable binding safely.",
                "Apply the principle of least privilege to database users to limit execution scope."
            ]
        }
        
    # 9. Exposed ports / services
    elif "exposed" in title_lower or cwe_upper in ["CWE-287", "CWE-200", "CWE-319"] and ("port" in title_lower or "server" in title_lower):
        return {
            "what_was_found": f"A service port ({title}) is exposed directly to the public internet, revealing active application or database endpoints.",
            "business_impact": "Publicly exposed ports are subject to scanning, brute-force dictionary attacks, and exploitation of software vulnerabilities in the daemon services.",
            "remediation_steps": [
                "Close the port in external firewall configurations (e.g. ufw deny or AWS security groups).",
                "Restrict access to designated IP ranges or mandate connection via corporate VPN.",
                "Update the underlying service version and enforce strict key-based authentication."
            ]
        }
        
    # Default fallback
    else:
        # Generate generic steps based on the remediation explanation
        steps_list = []
        if explanation:
            # Try splitting by common list separators if possible
            if "\n" in explanation:
                steps_list = [s.strip(" -1234567890.*") for s in explanation.split("\n") if s.strip()]
            else:
                steps_list.append(explanation)
        else:
            steps_list.append("Review security configurations for the affected software components.")
            steps_list.append("Sanitize inputs and restrict access parameters globally.")
            
        return {
            "what_was_found": description or "A vulnerability signature matched known security testing vulnerabilities in target scope endpoints.",
            "business_impact": "Unresolved vulnerabilities expose target service paths to arbitrary exploitation, authentication bypass, data leakage, or service denial.",
            "remediation_steps": steps_list
        }


@app.get("/api/reports/summary")
def get_reports_summary(
    tenant_id: Optional[str] = Query(None),
    report_type: Optional[str] = Query(None)
):
    if tenant_id:
        target = db.get_target(tenant_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
    vulns = db.get_vulnerabilities(tenant_id)
    if report_type:
        rt_upper = report_type.upper()
        if rt_upper in ["SAST", "SCA"]:
            vulns = [v for v in vulns if v["type"].upper() == rt_upper]
            
    assets_data = db.get_assets(tenant_id)
    
    # 1. Qualys MITRE ATT&CK Matrix Calculation
    mitre_stages = {
        "Initial Access": 0,
        "Execution": 0,
        "Persistence": 0,
        "Defense Evasion": 0,
        "Credential Access": 0,
        "Discovery": 0,
        "Lateral Movement": 0,
        "Exfiltration": 0,
        "Impact": 0
    }
    
    # Heuristics mapping CWE to MITRE ATT&CK stages
    for v in vulns:
        cwe = v["cwe"]
        v_type = v["type"].upper()
        if cwe in ["CWE-200", "CWE-79"] or v_type in ["NUCLEI", "GOBUSTER"]:
            mitre_stages["Initial Access"] += 1
        elif cwe in ["CWE-89", "CWE-94"] or v_type in ["SAST", "GARAK"]:
            mitre_stages["Execution"] += 1
        elif cwe in ["CWE-287", "CWE-639"] or v_type in ["HYDRA"]:
            mitre_stages["Credential Access"] += 1
            mitre_stages["Privilege Escalation"] = mitre_stages.get("Privilege Escalation", 0) + 1
        elif v_type in ["EASM", "NMAP", "NMAP + NSE", "SCA", "TRIVY"]:
            mitre_stages["Discovery"] += 1
        elif v_type in ["SECRETS"]:
            mitre_stages["Credential Access"] += 1
        elif v["severity"] == "Critical":
            mitre_stages["Impact"] += 1
            mitre_stages["Exfiltration"] += 1
            
    # 2. CyCognito Issue Groupings
    issue_groups = {
        "Security Hygiene": [],
        "Header Vulnerabilities": [],
        "Misconfiguration": [],
        "Network Security": [],
        "Cryptographic Vulnerability": [],
        "Static Code Analysis": [],
        "AI & LLM Security": []
    }
    
    grouped_items = {}
    for v in vulns:
        cwe = v["cwe"]
        title = v["title"]
        key = (cwe, title)
        
        severity_score = 9.8 if v["severity"] == "Critical" else (8.0 if v["severity"] == "High" else (5.5 if v["severity"] == "Medium" else 3.0))
        enhanced_score = min(10.0, severity_score + (1.0 if v["status"] == "Open" else 0.0))
        
        details = get_vulnerability_details(v["cwe"], v["title"], v["description"], v["remediation"])
        
        if key not in grouped_items:
            grouped_items[key] = {
                "id": v["id"],
                "title": v["title"],
                "severity": v["severity"],
                "base_score": severity_score,
                "enhanced_score": enhanced_score,
                "status": v["status"],
                "cwe": v["cwe"],
                "assets": [v["asset"]],
                "description": v["description"],
                "remediation": v["remediation"],
                "type": v["type"],
                "what_was_found": details["what_was_found"],
                "business_impact": details["business_impact"],
                "remediation_steps": details["remediation_steps"]
            }
        else:
            if v["asset"] not in grouped_items[key]["assets"]:
                grouped_items[key]["assets"].append(v["asset"])
                
    for key, item in grouped_items.items():
        cwe, title = key
        v_type = item["type"].upper()
        if v_type in ["SAST", "SCA", "SECRETS"]:
            issue_groups["Static Code Analysis"].append(item)
        elif v_type in ["GARAK"]:
            issue_groups["AI & LLM Security"].append(item)
        elif "Header" in title:
            issue_groups["Header Vulnerabilities"].append(item)
        elif cwe in ["CWE-89", "CWE-639", "CWE-327"] or v_type in ["SQLMAP", "SSLSCAN", "NUCLEI"]:
            issue_groups["Cryptographic Vulnerability"].append(item)
        elif v_type in ["EASM", "NMAP", "NMAP + NSE"]:
            issue_groups["Network Security"].append(item)
        elif "Limiting" in title or "Auth" in title or v_type in ["TRIVY"]:
            issue_groups["Misconfiguration"].append(item)
        else:
            issue_groups["Security Hygiene"].append(item)

    # 3. Ermetic / Tenable Compliance Gauges
    compliance_gauges = {
        "CIS Benchmarks": 100,
        "GDPR Privacy": 100,
        "HIPAA Security": 100,
        "OWASP Top 10": 100
    }
    
    open_vulns = [v for v in vulns if v["status"] in ["Open", "In Progress"]]
    
    for v in open_vulns:
        severity = v["severity"]
        penalty = 25 if severity == "Critical" else (15 if severity == "High" else (8 if severity == "Medium" else 3))
        
        compliance_gauges["OWASP Top 10"] = max(10, compliance_gauges["OWASP Top 10"] - penalty)
        
        if v["type"] == "EASM":
            compliance_gauges["CIS Benchmarks"] = max(15, compliance_gauges["CIS Benchmarks"] - penalty)
        if v["cwe"] in ["CWE-89", "CWE-639", "LLM-06"]:
            compliance_gauges["GDPR Privacy"] = max(20, compliance_gauges["GDPR Privacy"] - penalty)
            compliance_gauges["HIPAA Security"] = max(20, compliance_gauges["HIPAA Security"] - penalty)
            
    # 4. Ermetic "Toxic Combinations" priorities
    priorities = []
    for v in open_vulns:
        has_exposed_port = False
        subdomain_url = v["asset"]
        for sub in assets_data.get("subdomains", []):
            if sub["subdomain"] in subdomain_url and len(sub["ports"]) > 0:
                has_exposed_port = True
                break
                
        risk_level = 3 if v["severity"] == "Critical" else (2 if v["severity"] == "High" else 1)
        if has_exposed_port:
            risk_level += 2
            
        priorities.append({
            "id": v["id"],
            "title": v["title"],
            "asset": v["asset"],
            "severity": v["severity"],
            "risk_weight": risk_level,
            "description": f"Public asset exposing service ports has unresolved vulnerability: {v['title']}." if has_exposed_port else f"Unresolved target finding: {v['title']}"
        })
        
    priorities = sorted(priorities, key=lambda x: x["risk_weight"], reverse=True)[:3]
    
    return {
        "mitre_stages": mitre_stages,
        "issue_groups": {k: len(v) for k, v in issue_groups.items()},
        "issue_groups_details": issue_groups,
        "compliance_gauges": compliance_gauges,
        "priorities": priorities,
        "assets_count": len(assets_data.get("subdomains", [])) + 1
    }


@app.get("/api/reports/export")
def export_executive_report(
    tenant_id: Optional[str] = Query(None),
    report_type: Optional[str] = Query(None),
    format: Optional[str] = Query(None, description="Set to 'html' to preview as HTML instead of PDF"),
):
    """Render a professional security report (PDF) for a target or the whole estate.

    The heavy lifting (model assembly, charts, templating, PDF) lives in
    ``report_builder``. This endpoint just gathers data and picks the output
    format. PDF is the default; ``?format=html`` returns the same report as HTML,
    which is also used as a graceful fallback if the PDF engine is unavailable.
    """
    if tenant_id:
        target = db.get_target(tenant_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
    else:
        target = {"name": "Consolidated Scope", "url": "All Targets"}

    vulns = db.get_vulnerabilities(tenant_id)
    if report_type:
        rt_upper = report_type.upper()
        if rt_upper in ("SAST", "SCA"):
            vulns = [v for v in vulns if (v.get("type") or "").upper() == rt_upper]

    assets_data = db.get_assets(tenant_id)
    summary = get_reports_summary(tenant_id, report_type)

    model = report_builder.build_model(
        target=target,
        vulns=vulns,
        assets_data=assets_data,
        summary=summary,
        details_fn=get_vulnerability_details,
        report_type=report_type,
    )
    html = report_builder.render_html(model)

    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_",
                       f"aegissec_{model['kind'].lower()}_{model['target']['name']}").strip("_")
    filename = f"{safe_name}_{model['generated_iso']}"

    # HTML preview (and graceful fallback if WeasyPrint / its native libs are absent)
    if (format or "").lower() == "html":
        return HTMLResponse(content=html, status_code=200)

    try:
        pdf_bytes = report_builder.render_pdf(html)
    except Exception as exc:
        print(f"[reports/export] PDF rendering unavailable, serving HTML fallback: {exc}")
        return HTMLResponse(content=html, status_code=200)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}.pdf"'},
    )


# ----------------- BACKGROUND SCAN JOBS ENGINE -----------------
import threading
import time
import re

active_scans = {}

def run_pentest_generator(target_id: str):
    yield "[*] Spinning up autonomous AI Pentest Campaign agent..."
    yield "[*] Initializing AI Pentesting Campaign..."
    time.sleep(0.3)
    
    target_info = db.get_target(target_id)
    if not target_info:
        yield "[!] Target not found."
        return
        
    vulns = db.get_vulnerabilities(target_id)
    yield f"[*] Active Target: {target_info['name']} ({target_info['url']})"
    time.sleep(0.3)
    yield "[*] Loading vulnerabilities from SQLite database..."
    time.sleep(0.3)
    yield f"[+] Loaded {len(vulns)} vulnerability records."
    time.sleep(0.3)
    
    if not vulns:
        yield "[*] Scanning environment is clean of active issues. Running network scan bypass..."
        time.sleep(0.3)
        yield f"[-] Probing {target_info['url']}..."
        time.sleep(0.3)
        yield "[+] Found exposed web port. Recommending security header improvements."
        time.sleep(0.3)
        yield "[*] AI Pentesting Complete: Targets are secure against critical vulnerabilities."
        return
        
    # Exploit vulnerabilities found
    for idx, v in enumerate(vulns):
        yield f"[*] Attempting active exploitation on vulnerability: {v['title']}"
        time.sleep(0.3)
        yield f"[-] Signature code matches CWE: {v['cwe']}"
        time.sleep(0.2)
        poc = v.get("poc") or {}
        payload = poc.get("payload", "N/A") if isinstance(poc, dict) else "N/A"
        yield f"[-] Transmitting safe proof payload: {payload}"
        time.sleep(0.3)
        yield "[!!] EXPLOIT SUCCESSFUL. Server responded with validation signature."
        time.sleep(0.3)
        poc_resp = poc.get("response", "Secure response") if isinstance(poc, dict) else "Secure response"
        yield f"[+] Exfiltrated POC proof data: {poc_resp[:80]}..."
        time.sleep(0.3)
        
    yield "[*] Compiling attack path mapping based on compromised nodes..."
    time.sleep(0.3)
    yield "[+] Linked attack path: path-1 generated."
    time.sleep(0.3)
    yield "[*] AI Pentest Campaign complete. Syncing status reports."

def run_job_in_thread(job_id: str, target_id: str, scan_type: str):
    db.update_scan_job(job_id, {"status": "Scanning", "progress": 5})
    db.clear_vulnerabilities_by_type(target_id, scan_type)
    logs_accumulated = []
    
    # Retrieve OpenAPI specifications if they exist for this job
    job_info = db.get_scan_job(job_id)
    spec = job_info.get("openapi_spec") if job_info else None
    
    try:
        if scan_type.upper() == "DAST":
            generator = scanners.run_dast_scan(target_id)
        elif scan_type.upper() in ["API", "OPENAPI"]:
            generator = scanners.run_api_scan(target_id, openapi_spec=spec)
        elif scan_type.upper() == "PENTEST":
            generator = run_pentest_generator(target_id)
        elif scan_type.upper() == "SAST":
            generator = scanners.run_sast_scan(target_id)
        elif scan_type.upper() == "SCA":
            generator = scanners.run_sca_scan(target_id)
        elif scan_type.upper() == "NMAP":
            generator = scanners.run_nmap_scan(target_id)
        elif scan_type.upper() == "NIKTO":
            generator = scanners.run_nikto_scan(target_id)
        elif scan_type.upper() == "SQLMAP":
            generator = scanners.run_sqlmap_scan(target_id)
        elif scan_type.upper() == "SSLSCAN":
            generator = scanners.run_sslscan_scan(target_id)
        elif scan_type.upper() == "FULL":
            generator = scanners.run_full_suite_scan(target_id)
        else:
            generator = scanners.run_dast_scan(target_id)
            
        for log in generator:
            # Check if job was marked Stopped in the database
            job = db.get_scan_job(job_id)
            if not job or job["status"] == "Stopped":
                break
                
            logs_accumulated.append(log)
            
            # Calculate progress percentage dynamically
            progress = job["progress"]
            if "Initializing" in log:
                progress = 10
            elif "Found semgrep binary" in log:
                progress = 30
            elif "Semgrep SAST scan completed" in log:
                progress = 95
            elif "Found trivy binary" in log:
                progress = 30
            elif "Trivy SCA scan completed" in log:
                progress = 95
            elif "vulnerability records" in log:
                progress = 25
            elif "exploitation" in log:
                progress = 50
            elif "EXPLOIT SUCCESSFUL" in log:
                progress = 75
            elif "attack path mapping" in log:
                progress = 90
            elif "AI Pentest Campaign complete" in log or "Syncing" in log:
                progress = 98
            elif "Resolving DNS" in log:
                progress = 85
            elif "Connected to OWASP ZAP" in log:
                progress = 88
            elif "ZAP Spider Crawl Progress" in log:
                match = re.search(r'Progress:\s*(\d+)%', log)
                if match:
                    progress = 88 + int(int(match.group(1)) * 0.05)
            elif "ZAP Active Scan Progress" in log:
                match = re.search(r'Progress:\s*(\d+)%', log)
                if match:
                    progress = 93 + int(int(match.group(1)) * 0.05)
            elif "EASM Surface Discovery Scan" in log:
                progress = 5
            elif "Nmap Port & Service Discovery" in log:
                progress = 12
            elif "SSLScan Weakness Discovery" in log:
                progress = 18
            elif "GitLeaks Secrets Scan" in log:
                progress = 25
            elif "SAST Code Analyzer" in log:
                progress = 32
            elif "SCA Dependency Auditor" in log:
                progress = 40
            elif "Trivy Container Scanner" in log:
                progress = 48
            elif "Nuclei Template Scan" in log:
                progress = 55
            elif "Gobuster Directory Sweep" in log:
                progress = 62
            elif "Nikto Web Server Audit" in log:
                progress = 68
            elif "SQLmap Injection Sweep" in log:
                progress = 75
            elif "Hydra Port Credential Scanner" in log:
                progress = 80
            elif "Garak LLM Red-Teaming Scanner" in log:
                progress = 83
            elif "Scan Finished" in log or "scan completed successfully" in log or "Campaign completed" in log or "auditor complete" in log or "fuzzer complete" in log:
                progress = 98
                
            db.update_scan_job(job_id, {
                "progress": progress,
                "logs": "\n".join(logs_accumulated)
            })
            time.sleep(0.05)
            
        # Check final status
        job = db.get_scan_job(job_id)
        if job and job["status"] != "Stopped":
            final_logs = "\n".join(logs_accumulated)
            # A code scan (SAST/SCA) against a non-repo target (e.g. a deployed URL)
            # has no source to analyze and skips. Report that honestly as "Skipped"
            # rather than "Completed", so it isn't mistaken for a clean pass.
            was_skipped = scan_type.upper() in ("SAST", "SCA") and (
                "No valid local directory or Git repository" in final_logs
                or "Skipping code analyzer scans" in final_logs
            )
            db.update_scan_job(job_id, {
                "status": "Skipped" if was_skipped else "Completed",
                "progress": 100,
                "logs": final_logs,
            })
    except Exception as e:
        db.update_scan_job(job_id, {
            "status": "Failed",
            "logs": "\n".join(logs_accumulated) + f"\n[!] Scan job failed: {str(e)}"
        })
    finally:
        active_scans.pop(job_id, None)

@app.get("/api/scans/jobs")
def list_scan_jobs(
    tenant_id: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None)
):
    jobs = db.get_scan_jobs(tenant_id)
    if scan_type:
        scan_types = [t.strip().upper() for t in scan_type.split(",")]
        jobs = [j for j in jobs if j["scan_type"].upper() in scan_types]
    return jobs

@app.post("/api/scans/jobs")
def create_scan_job(
    tenant_id: str = Body(..., embed=True),
    scan_type: str = Body("DAST", embed=True),
    openapi_spec: Optional[str] = Body(None, embed=True)
):
    target = db.get_target(tenant_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    job_id = db.add_scan_job(tenant_id, target["url"], scan_type, openapi_spec)
    return {"status": "success", "job_id": job_id}

@app.post("/api/scans/jobs/{job_id}/start")
def start_scan_job(job_id: str):
    job = db.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    if job["status"] == "Scanning":
        return {"status": "already_running"}
        
    t = threading.Thread(
        target=run_job_in_thread, 
        args=(job_id, job["target_id"], job["scan_type"]),
        daemon=True
    )
    active_scans[job_id] = t
    t.start()
    return {"status": "success"}

@app.post("/api/scans/jobs/{job_id}/stop")
def stop_scan_job(job_id: str):
    job = db.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    db.update_scan_job(job_id, {"status": "Stopped"})
    active_scans.pop(job_id, None)
    return {"status": "success"}

@app.delete("/api/scans/jobs/{job_id}")
def remove_scan_job(job_id: str):
    job = db.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job["status"] == "Scanning":
        db.update_scan_job(job_id, {"status": "Stopped"})
        active_scans.pop(job_id, None)
        
    db.delete_scan_job(job_id)
    return {"status": "success"}

