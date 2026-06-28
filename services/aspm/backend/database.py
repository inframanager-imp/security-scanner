import json
import uuid
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import psycopg
from psycopg.rows import dict_row

# ── Connection config ─────────────────────────────────────────────────────────
# Shared Postgres with the CSPM service; ASPM data lives in its own schema.
DB_SCHEMA = os.environ.get("DB_SCHEMA", "aspm")
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", DB_SCHEMA):
    raise ValueError(f"Invalid DB_SCHEMA: {DB_SCHEMA!r}")


def _dsn() -> str:
    """Normalise DATABASE_URL into a libpq DSN psycopg understands."""
    url = os.environ.get(
        "DATABASE_URL",
        "postgresql://scanner:scanner_pass@localhost:5432/vapt",
    )
    # Accept SQLAlchemy-style URLs too (postgresql+psycopg://...).
    return re.sub(r"^postgresql\+\w+://", "postgresql://", url)


def get_db_connection():
    """Open an autocommit connection with dict rows, scoped to the aspm schema.

    Mirrors the old sqlite helper: callers do conn.execute(...).fetch*()/commit()/close().
    autocommit keeps the many short-lived connections from idling in a transaction;
    the explicit .commit() calls left in the helpers become harmless no-ops.
    """
    conn = psycopg.connect(
        _dsn(),
        autocommit=True,
        row_factory=dict_row,
        options=f"-c search_path={DB_SCHEMA}",
    )
    return conn


def init_db():
    # On a cold container start Postgres may need a moment even with healthchecks.
    last_err = None
    for _ in range(30):
        try:
            conn = get_db_connection()
            break
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2)
    else:
        raise RuntimeError(f"Could not connect to Postgres: {last_err}")

    cursor = conn.cursor()

    cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {DB_SCHEMA};")

    # Targets
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        target_type TEXT NOT NULL,
        auth_type TEXT,
        auth_key TEXT,
        auth_val TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # Vulnerabilities
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        type TEXT NOT NULL,
        cwe TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        sla_deadline TEXT NOT NULL,
        assigned_to TEXT NOT NULL,
        asset TEXT NOT NULL,
        description TEXT,
        poc TEXT,
        ai_analysis TEXT,
        remediation TEXT,
        pt_verification TEXT,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    """)

    # Assets (subdomains / hosts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        ip TEXT NOT NULL,
        cdn TEXT NOT NULL,
        ports TEXT NOT NULL,
        ssl_expiry TEXT NOT NULL,
        cert_issuer TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        tls_version TEXT,
        cipher_suite TEXT,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    """)

    # API inventory
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_inventory (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        path TEXT NOT NULL,
        method TEXT NOT NULL,
        auth TEXT NOT NULL,
        classification TEXT NOT NULL,
        risk TEXT NOT NULL,
        findings INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    """)

    # Scan logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_logs (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        status TEXT NOT NULL,
        logs TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    """)

    # Scan jobs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        target_url TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        status TEXT NOT NULL,
        progress INTEGER NOT NULL,
        logs TEXT NOT NULL,
        openapi_spec TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    """)

    # Integrations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrations (
        name TEXT PRIMARY KEY,
        connected INTEGER NOT NULL,
        config TEXT
    );
    """)

    # Seed integrations (idempotent)
    cursor.execute("INSERT INTO integrations (name, connected, config) VALUES ('jira', 1, '{\"url\": \"https://acme.atlassian.net\", \"project\": \"SEC\"}') ON CONFLICT (name) DO NOTHING;")
    cursor.execute("INSERT INTO integrations (name, connected, config) VALUES ('slack', 1, '{\"channel\": \"#sec-alerts\"}') ON CONFLICT (name) DO NOTHING;")
    cursor.execute("INSERT INTO integrations (name, connected, config) VALUES ('splunk', 0, '{\"host\": \"\"}') ON CONFLICT (name) DO NOTHING;")

    # Forward-compatible column adds (Postgres supports IF NOT EXISTS natively)
    cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS tls_version TEXT;")
    cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS cipher_suite TEXT;")
    cursor.execute("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS openapi_spec TEXT;")

    # ── Duplicate prevention ──────────────────────────────────────────────────
    # Tool/scan-generated rows must be unique. We (1) purge any pre-existing
    # duplicates, then (2) add DB-level UNIQUE constraints so concurrent scans
    # can't race past the app-level checks. Each step is wrapped so re-running
    # init_db() on an already-migrated DB is a no-op (autocommit isolates failures).
    def _safe(sql: str):
        try:
            cursor.execute(sql)
        except Exception:
            pass

    # (1) collapse existing duplicates, keeping one row per logical key
    _safe("DELETE FROM assets a USING assets b WHERE a.ctid < b.ctid AND a.target_id = b.target_id AND a.subdomain = b.subdomain;")
    _safe("DELETE FROM api_inventory a USING api_inventory b WHERE a.ctid < b.ctid AND a.target_id = b.target_id AND a.path = b.path AND a.method = b.method;")
    _safe("DELETE FROM vulnerabilities a USING vulnerabilities b WHERE a.ctid < b.ctid AND a.target_id = b.target_id AND a.cwe = b.cwe AND a.asset = b.asset AND a.title = b.title;")

    # (2) enforce uniqueness going forward
    _safe("ALTER TABLE assets ADD CONSTRAINT uq_assets_target_subdomain UNIQUE (target_id, subdomain);")
    _safe("ALTER TABLE api_inventory ADD CONSTRAINT uq_api_target_path_method UNIQUE (target_id, path, method);")
    _safe("ALTER TABLE vulnerabilities ADD CONSTRAINT uq_vuln_target_cwe_asset_title UNIQUE (target_id, cwe, asset, title);")

    conn.close()


# Initialize DB on import
init_db()

# --- TARGETS API helpers ---
def add_target(name: str, url: str, target_type: str, auth_type: str = "none", auth_key: str = "", auth_val: str = "") -> str:
    conn = get_db_connection()
    # Avoid duplicate onboarding of the same application (same name + url).
    existing = conn.execute("SELECT id FROM targets WHERE name = %s AND url = %s", (name, url)).fetchone()
    if existing:
        conn.close()
        return existing["id"]
    target_id = f"target-{uuid.uuid4().hex[:8]}"
    conn.execute(
        "INSERT INTO targets (id, name, url, target_type, auth_type, auth_key, auth_val, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (target_id, name, url, target_type, auth_type, auth_key, auth_val, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return target_id

def get_targets_dict() -> Dict[str, str]:
    conn = get_db_connection()
    rows = conn.execute("SELECT id, name, url FROM targets ORDER BY created_at DESC").fetchall()
    conn.close()
    # Format: {"target-id": "Name (URL)"}
    return {row["id"]: f"{row['name']} ({row['url']})" for row in rows}

def get_targets_list() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_target(target_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM targets WHERE id = %s", (target_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def delete_target(target_id: str):
    conn = get_db_connection()
    conn.execute("DELETE FROM targets WHERE id = %s", (target_id,))
    conn.commit()
    conn.close()

def update_target(target_id: str, fields: Dict[str, Any]):
    conn = get_db_connection()
    keys = list(fields.keys())
    values = list(fields.values())
    set_clause = ", ".join([f"{k} = %s" for k in keys])
    conn.execute(f"UPDATE targets SET {set_clause} WHERE id = %s", values + [target_id])
    conn.commit()
    conn.close()


# --- VULNERABILITIES API helpers ---
def get_vulnerabilities(target_id: Optional[str] = None, severity: Optional[str] = None, type_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if target_id:
        query = "SELECT * FROM vulnerabilities WHERE target_id = %s"
        params = [target_id]
    else:
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
    if severity and severity != "All":
        query += " AND severity = %s"
        params.append(severity)
    if type_filter and type_filter != "All":
        query += " AND type = %s"
        params.append(type_filter)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    vulns = []
    for r in rows:
        vd = dict(r)
        vd["poc"] = json.loads(vd["poc"]) if vd["poc"] else {"request": "", "response": "", "payload": ""}
        vd["ai_analysis"] = json.loads(vd["ai_analysis"]) if vd["ai_analysis"] else {"exploitability": "", "false_positive": "", "risk_score": 5.0}
        vd["remediation"] = json.loads(vd["remediation"]) if vd["remediation"] else {"language": "generic", "unsafe": "", "safe": "", "explanation": ""}
        vd["pt_verification"] = json.loads(vd["pt_verification"]) if vd["pt_verification"] else None
        vulns.append(vd)
    return vulns

def add_vulnerability(target_id: str, title: str, severity: str, type_val: str, cwe: str, asset: str, description: str, poc: Dict[str, Any], ai_analysis: Dict[str, Any], remediation: Dict[str, Any], status: str = "Open") -> str:
    conn = get_db_connection()
    vuln_id = f"vuln-{uuid.uuid4().hex[:8]}"
    created_at = datetime.now().isoformat()
    sla_days = 14 if severity == "Critical" else (30 if severity == "High" else 60)
    sla_deadline = (datetime.now() + timedelta(days=sla_days)).isoformat()

    # Race-safe dedup: one row per (target_id, cwe, asset, title). On a repeat
    # finding we refresh the evidence and return the existing row id (no duplicate).
    row = conn.execute(
        """INSERT INTO vulnerabilities
        (id, target_id, title, severity, type, cwe, status, created_at, sla_deadline, assigned_to, asset, description, poc, ai_analysis, remediation, pt_verification)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (target_id, cwe, asset, title) DO UPDATE
          SET severity = EXCLUDED.severity,
              description = EXCLUDED.description,
              poc = EXCLUDED.poc,
              ai_analysis = EXCLUDED.ai_analysis,
              remediation = EXCLUDED.remediation
        RETURNING id""",
        (
            vuln_id, target_id, title, severity, type_val, cwe, status, created_at, sla_deadline, "Unassigned", asset, description,
            json.dumps(poc), json.dumps(ai_analysis), json.dumps(remediation), None
        )
    ).fetchone()
    conn.commit()
    conn.close()
    return row["id"] if row else vuln_id

def update_vulnerability(vuln_id: str, fields: Dict[str, Any]):
    conn = get_db_connection()

    allowed = ["status", "assigned_to", "pt_verification"]
    set_clauses = []
    params = []

    for k, v in fields.items():
        if k in allowed:
            set_clauses.append(f"{k} = %s")
            if k == "pt_verification":
                params.append(json.dumps(v))
            else:
                params.append(v)

    if set_clauses:
        params.append(vuln_id)
        conn.execute(f"UPDATE vulnerabilities SET {', '.join(set_clauses)} WHERE id = %s", params)
        conn.commit()
    conn.close()

# --- ASSETS API helpers ---
def get_assets(target_id: Optional[str] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    if target_id:
        rows = conn.execute("SELECT * FROM assets WHERE target_id = %s", (target_id,)).fetchall()
        target_row = conn.execute("SELECT name, url FROM targets WHERE id = %s", (target_id,)).fetchone()
    else:
        rows = conn.execute("SELECT * FROM assets").fetchall()
        target_row = None
    conn.close()

    subdomains = []
    for r in rows:
        ad = dict(r)
        ad["ports"] = json.loads(ad["ports"]) if ad["ports"] else []
        subdomains.append(ad)

    domain = target_row["url"].replace("https://", "").replace("http://", "").split("/")[0].split(":")[0] if target_row else "consolidated.com"

    # Compute summary
    live_hosts = len(subdomains)
    open_ports_count = sum(len(s["ports"]) for s in subdomains)

    return {
        "summary": {
            "domains": 1 if target_row else 0,
            "subdomains": live_hosts,
            "open_ports": open_ports_count,
            "live_hosts": live_hosts
        },
        "domains": [
            {"domain": domain, "registrar": "Detected", "dns_sec": False, "created": "N/A"}
        ] if target_row else [],
        "subdomains": subdomains
    }

def add_asset(target_id: str, subdomain: str, ip: str, cdn: str, ports: List[int], ssl_expiry: str, cert_issuer: str, tls_version: str = "", cipher_suite: str = "", status: str = "Active"):
    conn = get_db_connection()
    asset_id = f"asset-{uuid.uuid4().hex[:8]}"
    # Race-safe upsert keyed on (target_id, subdomain) — repeated EASM pulls update in place.
    conn.execute(
        """INSERT INTO assets (id, target_id, subdomain, ip, cdn, ports, ssl_expiry, cert_issuer, tls_version, cipher_suite, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (target_id, subdomain) DO UPDATE
          SET ip = EXCLUDED.ip, cdn = EXCLUDED.cdn, ports = EXCLUDED.ports,
              ssl_expiry = EXCLUDED.ssl_expiry, cert_issuer = EXCLUDED.cert_issuer,
              tls_version = EXCLUDED.tls_version, cipher_suite = EXCLUDED.cipher_suite,
              status = EXCLUDED.status""",
        (asset_id, target_id, subdomain, ip, cdn, json.dumps(ports), ssl_expiry, cert_issuer, tls_version, cipher_suite, status, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

# --- API INVENTORY helpers ---
def get_api_inventory(target_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if target_id:
        rows = conn.execute("SELECT * FROM api_inventory WHERE target_id = %s", (target_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM api_inventory").fetchall()
    conn.close()
    return [dict(row) for row in rows]

def add_api_route(target_id: str, path: str, method: str, auth: str, classification: str, risk: str, findings: int = 0):
    conn = get_db_connection()
    api_id = f"api-{uuid.uuid4().hex[:8]}"
    # Race-safe upsert keyed on (target_id, path, method) — repeated API discovery updates in place.
    conn.execute(
        """INSERT INTO api_inventory (id, target_id, path, method, auth, classification, risk, findings, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (target_id, path, method) DO UPDATE
          SET auth = EXCLUDED.auth, classification = EXCLUDED.classification,
              risk = EXCLUDED.risk, findings = EXCLUDED.findings""",
        (api_id, target_id, path, method, auth, classification, risk, findings, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

# --- INTEGRATIONS helpers ---
def get_integrations_status() -> Dict[str, Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT name, connected, config FROM integrations").fetchall()
    conn.close()
    res = {}
    for r in rows:
        conf = json.loads(r["config"]) if r["config"] else {}
        res[r["name"]] = {
            "connected": bool(r["connected"]),
            **conf
        }
    return res

def toggle_integration_status(name: str) -> Dict[str, Any]:
    conn = get_db_connection()
    row = conn.execute("SELECT connected, config FROM integrations WHERE name = %s", (name,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("Integration not found")

    new_connected = 0 if row["connected"] else 1
    conn.execute("UPDATE integrations SET connected = %s WHERE name = %s", (new_connected, name))
    conn.commit()
    conn.close()

    conf = json.loads(row["config"]) if row["config"] else {}
    return {"connected": bool(new_connected), **conf}

# --- SCAN LOGS helpers ---
def add_scan_log(target_id: str, scan_type: str, status: str, log_list: List[str]) -> str:
    log_id = f"scan-{uuid.uuid4().hex[:8]}"
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO scan_logs (id, target_id, scan_type, status, logs, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (log_id, target_id, scan_type, status, json.dumps(log_list), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return log_id

# --- SCAN JOBS helpers ---
def add_scan_job(target_id: str, target_url: str, scan_type: str, openapi_spec: Optional[str] = None) -> str:
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO scan_jobs (id, target_id, target_url, scan_type, status, progress, logs, openapi_spec, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (job_id, target_id, target_url, scan_type, "Idle", 0, "", openapi_spec, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return job_id

def get_scan_jobs(target_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if target_id:
        rows = conn.execute("SELECT * FROM scan_jobs WHERE target_id = %s ORDER BY created_at DESC", (target_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM scan_jobs ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_job(job_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM scan_jobs WHERE id = %s", (job_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def update_scan_job(job_id: str, fields: Dict[str, Any]):
    conn = get_db_connection()
    allowed = ["status", "progress", "logs"]
    set_clauses = []
    params = []

    for k, v in fields.items():
        if k in allowed:
            set_clauses.append(f"{k} = %s")
            params.append(v)

    if set_clauses:
        params.append(job_id)
        conn.execute(f"UPDATE scan_jobs SET {', '.join(set_clauses)} WHERE id = %s", params)
        conn.commit()
    conn.close()

def delete_scan_job(job_id: str):
    conn = get_db_connection()
    conn.execute("DELETE FROM scan_jobs WHERE id = %s", (job_id,))
    conn.commit()
    conn.close()

def clear_vulnerabilities_by_type(target_id: str, scan_type: str):
    conn = get_db_connection()
    scan_type_upper = scan_type.upper()
    if scan_type_upper in ["DAST", "FULL"]:
        conn.execute("DELETE FROM vulnerabilities WHERE target_id = %s", (target_id,))
    elif scan_type_upper == "SAST":
        conn.execute("DELETE FROM vulnerabilities WHERE target_id = %s AND type = 'SAST'", (target_id,))
    elif scan_type_upper == "SCA":
        conn.execute("DELETE FROM vulnerabilities WHERE target_id = %s AND type = 'SCA'", (target_id,))
    elif scan_type_upper in ["API", "OPENAPI"]:
        conn.execute("DELETE FROM vulnerabilities WHERE target_id = %s AND type IN ('API', 'SQLmap', 'SECRETS')", (target_id,))
    else:
        conn.execute("DELETE FROM vulnerabilities WHERE target_id = %s AND type = %s", (target_id, scan_type_upper))
    conn.commit()
    conn.close()

# --- Compliance Mapping controls helper ---
COMPLIANCE_CONTROLS = {
    "CWE-89": {"owasp": "A03:2021-Injection", "pci": "PCI-DSS v4.0 6.2.4", "soc2": "CC7.1", "nist": "SP 800-53 SI-10"},
    "CWE-79": {"owasp": "A03:2021-Injection", "pci": "PCI-DSS v4.0 6.2.4", "soc2": "CC7.1", "nist": "SP 800-53 SI-10"},
    "CWE-918": {"owasp": "A10:2021-SSRF", "pci": "PCI-DSS v4.0 6.2.1", "soc2": "CC7.2", "nist": "SP 800-53 SC-7"},
    "CWE-611": {"owasp": "A05:2021-Security Misconfiguration", "pci": "PCI-DSS v4.0 6.2.4", "soc2": "CC7.1", "nist": "SP 800-53 SI-10"},
    "CWE-287": {"owasp": "A07:2021-Identification & Auth Failures", "pci": "PCI-DSS v4.0 8.1.1", "soc2": "CC6.1", "nist": "SP 800-53 IA-2"},
    "CWE-639": {"owasp": "A01:2021-Broken Access Control", "pci": "PCI-DSS v4.0 6.5.1", "soc2": "CC6.3", "nist": "SP 800-53 AC-3"},
    "CWE-94": {"owasp": "A03:2021-Injection", "pci": "PCI-DSS v4.0 6.2.4", "soc2": "CC7.1", "nist": "SP 800-53 SI-10"},
    "CWE-924": {"owasp": "A02:2021-Cryptographic Failures", "pci": "PCI-DSS v4.0 6.5.3", "soc2": "CC6.1", "nist": "SP 800-53 SC-8"},
    "LLM-01": {"owasp": "OWASP LLM Top 10 - Prompt Injection", "pci": "PCI-DSS v4.0 6.2.4", "soc2": "CC7.1", "nist": "SP 800-53 SI-16"},
    "LLM-06": {"owasp": "OWASP LLM Top 10 - Sensitive Information Disclosure", "pci": "PCI-DSS v4.0 6.5.1", "soc2": "CC6.3", "nist": "SP 800-53 AC-4"},
    "CWE-524": {"owasp": "A05:2021-Security Misconfiguration", "pci": "PCI-DSS v4.0 6.2.4", "soc2": "CC7.1", "nist": "SP 800-53 SC-8"},  # Missing Secure Cookie Flags
    "CWE-200": {"owasp": "A05:2021-Security Misconfiguration", "pci": "PCI-DSS v4.0 6.5.1", "soc2": "CC6.3", "nist": "SP 800-53 SI-10"},  # Missing Security Headers
    "CWE-319": {"owasp": "A02:2021-Cryptographic Failures", "pci": "PCI-DSS v4.0 6.5.3", "soc2": "CC6.1", "nist": "SP 800-53 SC-8"}  # Unencrypted Transport
}
