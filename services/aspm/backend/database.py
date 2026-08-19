import json
import uuid
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import psycopg
from psycopg.rows import dict_row

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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS git_platforms (
        id            TEXT PRIMARY KEY,
        platform_id   TEXT NOT NULL,
        host_pattern  TEXT NOT NULL,
        pr_term       TEXT NOT NULL DEFAULT 'pull request',
        api_base      TEXT,
        self_hosted   INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    );
    """)
    _now = datetime.now().isoformat()
    _default_platforms = [
        ("github",    r"(^|[./])github\.com$",    "pull request",  "https://api.github.com"),
        ("gitlab",    r"(^|[./])gitlab\.com$",     "merge request", "https://gitlab.com/api/v4"),
        ("bitbucket", r"(^|[./])bitbucket\.org$",  "merge request", "https://api.bitbucket.org/2.0"),
        ("gitee",     r"(^|[./])gitee\.com$",      "pull request",  "https://gitee.com/api/v5"),
        ("gitcode",   r"(^|[./])gitcode\.com$",    "pull request",  "https://api.gitcode.com/api/v5"),
    ]
    for platform_id, pattern, pr_term, api_base in _default_platforms:
        cursor.execute(
            """INSERT INTO git_platforms (id, platform_id, host_pattern, pr_term, api_base, self_hosted, created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, 0, %s, %s)
               ON CONFLICT (id) DO NOTHING""",
            (f"default-{platform_id}", platform_id, pattern, pr_term, api_base, _now, _now),
        )

    # Forward-compatible column adds (Postgres supports IF NOT EXISTS natively)
    cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS tls_version TEXT;")
    cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS cipher_suite TEXT;")
    cursor.execute("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS openapi_spec TEXT;")
    # Vulnerability Pipeline: which branch to checkout (blank = provider default).
    cursor.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS branch TEXT;")
    cursor.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_index_hash TEXT;")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS code_embeddings (
        id            TEXT PRIMARY KEY,
        target_id     TEXT NOT NULL,
        file_path     TEXT NOT NULL,
        chunk_index   INTEGER NOT NULL,
        chunk_text    TEXT NOT NULL,
        embedding     JSONB NOT NULL,
        created_at    TEXT NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_code_embeddings_target ON code_embeddings (target_id);")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fix_cache (
        id            TEXT PRIMARY KEY,
        cwe           TEXT,
        title         TEXT NOT NULL,
        description   TEXT,
        embedding     JSONB NOT NULL,
        unsafe        TEXT NOT NULL,
        safe          TEXT NOT NULL,
        explanation   TEXT NOT NULL,
        hit_count     INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fix_cache_cwe ON fix_cache (cwe);")

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

def add_vulnerability(target_id: str, title: str, severity: str, type_val: str, cwe: str, asset: str, description: str, poc: Dict[str, Any], ai_analysis: Dict[str, Any], remediation: Dict[str, Any], status: str = "Open", pt_verification: Optional[Dict[str, Any]] = None) -> str:
    conn = get_db_connection()
    vuln_id = f"vuln-{uuid.uuid4().hex[:8]}"
    created_at = datetime.now().isoformat()
    sla_days = 14 if severity == "Critical" else (30 if severity == "High" else 60)
    sla_deadline = (datetime.now() + timedelta(days=sla_days)).isoformat()

    row = conn.execute(
        """INSERT INTO vulnerabilities
        (id, target_id, title, severity, type, cwe, status, created_at, sla_deadline, assigned_to, asset, description, poc, ai_analysis, remediation, pt_verification)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (target_id, cwe, asset, title) DO UPDATE
          SET severity = EXCLUDED.severity,
              description = EXCLUDED.description,
              poc = EXCLUDED.poc,
              ai_analysis = EXCLUDED.ai_analysis,
              remediation = EXCLUDED.remediation,
              pt_verification = COALESCE(EXCLUDED.pt_verification, vulnerabilities.pt_verification)
        RETURNING id""",
        (
            vuln_id, target_id, title, severity, type_val, cwe, status, created_at, sla_deadline, "Unassigned", asset, description,
            json.dumps(poc), json.dumps(ai_analysis), json.dumps(remediation),
            json.dumps(pt_verification) if pt_verification else None
        )
    ).fetchone()
    conn.commit()
    conn.close()
    return row["id"] if row else vuln_id

def update_vulnerability(vuln_id: str, fields: Dict[str, Any]):
    conn = get_db_connection()

    allowed = ["status", "assigned_to", "pt_verification", "ai_analysis", "remediation", "severity"]
    json_fields = ("pt_verification", "ai_analysis", "remediation")
    set_clauses = []
    params = []

    for k, v in fields.items():
        if k in allowed:
            set_clauses.append(f"{k} = %s")
            params.append(json.dumps(v) if k in json_fields else v)

    if set_clauses:
        params.append(vuln_id)
        conn.execute(f"UPDATE vulnerabilities SET {', '.join(set_clauses)} WHERE id = %s", params)
        conn.commit()
    conn.close()


def clear_embeddings(target_id: str):
    conn = get_db_connection()
    conn.execute("DELETE FROM code_embeddings WHERE target_id = %s", (target_id,))
    conn.commit()
    conn.close()


def save_embedding(target_id: str, file_path: str, chunk_index: int, chunk_text: str, embedding: List[float]):
    conn = get_db_connection()
    row_id = f"emb-{uuid.uuid4().hex[:10]}"
    conn.execute(
        """INSERT INTO code_embeddings (id, target_id, file_path, chunk_index, chunk_text, embedding, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (row_id, target_id, file_path, chunk_index, chunk_text, json.dumps(embedding), datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_embeddings(target_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT file_path, chunk_index, chunk_text, embedding FROM code_embeddings WHERE target_id = %s",
        (target_id,),
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["embedding"] = json.loads(d["embedding"]) if isinstance(d["embedding"], str) else d["embedding"]
        out.append(d)
    return out


def save_fix(cwe: str, title: str, description: str, embedding: List[float], unsafe: str, safe: str, explanation: str) -> str:
    """Stores a new AI-generated fix for future reuse. Called after agent-api
    generates a fix that wasn't already served from the cache."""
    conn = get_db_connection()
    row_id = f"fix-{uuid.uuid4().hex[:10]}"
    conn.execute(
        """INSERT INTO fix_cache (id, cwe, title, description, embedding, unsafe, safe, explanation, hit_count, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, %s)""",
        (row_id, cwe, title[:300], (description or "")[:2000], json.dumps(embedding), unsafe, safe, explanation, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return row_id


def get_fix_cache_candidates(cwe: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
    """Candidates for a similarity search. Narrows by CWE first when known —
    a fix for CWE-89 (SQLi) is never a valid reuse for CWE-79 (XSS) regardless
    of how similar the embeddings look, so this is a correctness filter, not
    just a perf one — then caps at `limit` rows the same way code_embeddings'
    RAG lookups do, since Python-side cosine scoring is O(rows)."""
    conn = get_db_connection()
    if cwe:
        rows = conn.execute(
            "SELECT id, cwe, title, unsafe, safe, explanation, embedding FROM fix_cache WHERE cwe = %s ORDER BY hit_count DESC LIMIT %s",
            (cwe, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, cwe, title, unsafe, safe, explanation, embedding FROM fix_cache ORDER BY hit_count DESC LIMIT %s",
            (limit,),
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["embedding"] = json.loads(d["embedding"]) if isinstance(d["embedding"], str) else d["embedding"]
        out.append(d)
    return out


def record_fix_cache_hit(fix_id: str):
    conn = get_db_connection()
    conn.execute("UPDATE fix_cache SET hit_count = hit_count + 1 WHERE id = %s", (fix_id,))
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

# --- GIT PLATFORMS (Vulnerability Pipeline platform detection) helpers ---

def _git_platform_row_to_dict(r) -> Dict[str, Any]:
    return {
        "id": r["id"], "platform_id": r["platform_id"], "host_pattern": r["host_pattern"],
        "pr_term": r["pr_term"], "api_base": r["api_base"], "self_hosted": bool(r["self_hosted"]),
        "created_at": r["created_at"], "updated_at": r["updated_at"],
    }

def list_git_platforms() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM git_platforms ORDER BY created_at ASC").fetchall()
    conn.close()
    return [_git_platform_row_to_dict(r) for r in rows]

def create_git_platform(platform_id: str, host_pattern: str, pr_term: str = "pull request",
                         api_base: Optional[str] = None, self_hosted: bool = False) -> Dict[str, Any]:
    try:
        re.compile(host_pattern)
    except re.error as e:
        raise ValueError(f"host_pattern is not a valid regex: {e}")

    row_id = f"gp-{uuid.uuid4().hex[:8]}"
    now = datetime.now().isoformat()
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO git_platforms (id, platform_id, host_pattern, pr_term, api_base, self_hosted, created_at, updated_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (row_id, platform_id, host_pattern, pr_term, api_base, int(self_hosted), now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM git_platforms WHERE id = %s", (row_id,)).fetchone()
    conn.close()
    return _git_platform_row_to_dict(row)

def update_git_platform(gp_id: str, **fields) -> Dict[str, Any]:
    allowed = {"platform_id", "host_pattern", "pr_term", "api_base", "self_hosted"}
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not updates:
        raise ValueError("No updatable fields provided")
    if "host_pattern" in updates:
        try:
            re.compile(updates["host_pattern"])
        except re.error as e:
            raise ValueError(f"host_pattern is not a valid regex: {e}")
    if "self_hosted" in updates:
        updates["self_hosted"] = int(bool(updates["self_hosted"]))

    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM git_platforms WHERE id = %s", (gp_id,)).fetchone()
    if not existing:
        conn.close()
        raise ValueError("Git platform not found")

    set_clause = ", ".join(f"{k} = %s" for k in updates)
    params = list(updates.values()) + [datetime.now().isoformat(), gp_id]
    conn.execute(f"UPDATE git_platforms SET {set_clause}, updated_at = %s WHERE id = %s", params)
    conn.commit()
    row = conn.execute("SELECT * FROM git_platforms WHERE id = %s", (gp_id,)).fetchone()
    conn.close()
    return _git_platform_row_to_dict(row)

def delete_git_platform(gp_id: str) -> None:
    conn = get_db_connection()
    row = conn.execute("SELECT id FROM git_platforms WHERE id = %s", (gp_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("Git platform not found")
    conn.execute("DELETE FROM git_platforms WHERE id = %s", (gp_id,))
    conn.commit()
    conn.close()

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


def get_scan_logs(target_id: str, scan_type: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    """Persisted scan-log rows (newest first) so a pipeline run's log lines
    survive navigating away/back — the frontend no longer has to hold them
    only in component state."""
    conn = get_db_connection()
    if scan_type:
        rows = conn.execute(
            "SELECT id, target_id, scan_type, status, logs, created_at FROM scan_logs "
            "WHERE target_id = %s AND scan_type = %s ORDER BY created_at DESC LIMIT %s",
            (target_id, scan_type, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, target_id, scan_type, status, logs, created_at FROM scan_logs "
            "WHERE target_id = %s ORDER BY created_at DESC LIMIT %s",
            (target_id, limit),
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["logs"] = json.loads(d["logs"])
        except Exception:
            d["logs"] = []
        out.append(d)
    return out

# --- SCAN JOBS helpers ---
def reset_stale_jobs():
    """On startup, fail any job left mid-flight by a crash/restart.
    The in-process scan threads don't survive a container restart, so a job still
    marked 'Scanning'/'Queued' is orphaned — mark it Failed instead of stuck forever."""
    conn = get_db_connection()
    conn.execute(
        "UPDATE scan_jobs SET status = 'Failed', logs = COALESCE(NULLIF(logs,''),'') || '\n[!] Scan interrupted (backend restarted). Please re-run.' WHERE status IN ('Scanning', 'Queued')"
    )
    conn.commit()
    conn.close()

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
