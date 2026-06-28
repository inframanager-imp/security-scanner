"""Professional security-report generator for the ASPM service.

Replaces the old hand-built HTML f-string in ``main.py`` with a clean pipeline:

    raw data  ->  build_model(...)  ->  Jinja2 template  ->  HTML  ->  WeasyPrint PDF

Design goals:
  * One Jinja2 template + design-token CSS (no inline-style soup, all data escaped).
  * Charts are small, well-scaled, fully-labelled server-rendered SVG (no JS).
  * Real, paginated PDF via WeasyPrint with cover page, running header/footer and
    page numbers. If WeasyPrint (or its native libs) is unavailable we fall back
    to the same HTML so the endpoint never hard-fails.

The module is import-light: WeasyPrint is only imported the first time a PDF is
actually requested, so the service starts fine even on hosts without the libs.
"""
from __future__ import annotations

import math
import os
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

# ── Palette (single source of truth, mirrored in the template CSS) ────────────
SEVERITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#ea580c",
    "Medium": "#d4a017",
    "Low": "#2563eb",
    "Info": "#64748b",
    "Secrets": "#7c3aed",
    "Recon": "#0e9aa7",
}
GROUP_COLORS = {
    "XSS": "#2563eb",
    "SQLi": "#16a34a",
    "Path Traversal": "#d4a017",
    "Info Disclosure": "#0e9aa7",
    "Other": "#64748b",
}
OWASP_COLOR = "#3949ab"

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


# ── small SVG charting helpers ────────────────────────────────────────────────

def _nice_max(value: int) -> int:
    """Round a count up to a clean axis maximum (1/2/5 x 10^n)."""
    value = int(value)
    if value <= 1:
        return 1
    if value <= 5:
        return value
    mag = 10 ** (len(str(value)) - 1)
    for m in (1, 2, 5, 10):
        if value <= m * mag:
            return m * mag
    return 10 * mag


def _svg_open(width: int, height: int) -> str:
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg" '
        f'font-family="Segoe UI, Helvetica, Arial, sans-serif">'
    )


def vbar_chart(cats: List[tuple], width: int = 480, height: int = 215) -> str:
    """Vertical bar chart. ``cats`` is a list of (label, value, color) tuples."""
    pad_l, pad_r, pad_t, pad_b = 38, 14, 20, 34
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    baseline = pad_t + plot_h
    nice = _nice_max(max([c[1] for c in cats] + [0]))

    parts = [_svg_open(width, height)]
    # horizontal gridlines at 0 / 50% / 100% of the axis
    for frac in (0.0, 0.5, 1.0):
        y = baseline - frac * plot_h
        solid = frac == 0.0
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
            f'stroke="{"#cbd5e1" if solid else "#eef1f5"}" stroke-width="1"/>'
        )
    # axis labels (just 0 and the max — no fractional ticks)
    for frac, label in ((0.0, "0"), (1.0, str(nice))):
        y = baseline - frac * plot_h
        parts.append(
            f'<text x="{pad_l - 6}" y="{y + 3:.1f}" font-size="9" fill="#94a3b8" '
            f'text-anchor="end">{label}</text>'
        )

    n = len(cats)
    slot = plot_w / n
    bw = min(38.0, slot * 0.54)
    for i, (label, value, color) in enumerate(cats):
        cx = pad_l + slot * (i + 0.5)
        bh = (value / nice) * plot_h if nice else 0.0
        y = baseline - bh
        parts.append(
            f'<rect x="{cx - bw / 2:.1f}" y="{y:.1f}" width="{bw:.1f}" '
            f'height="{bh:.1f}" rx="3" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{y - 5:.1f}" font-size="11" font-weight="700" '
            f'fill="#1f2937" text-anchor="middle">{value}</text>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{baseline + 16:.1f}" font-size="9.5" fill="#475569" '
            f'text-anchor="middle">{label}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def hbar_chart(rows: List[tuple], width: int = 700, label_w: int = 262) -> str:
    """Horizontal bar chart with full (untruncated) labels for OWASP categories."""
    row_h = 23
    pad_t, pad_b = 10, 6
    height = len(rows) * row_h + pad_t + pad_b
    bar_x = label_w + 10
    bar_w_max = width - bar_x - 34
    nice = _nice_max(max([r[1] for r in rows] + [0]))

    parts = [_svg_open(width, height)]
    for i, (label, value, color) in enumerate(rows):
        cy = pad_t + i * row_h
        bar_y = cy + 4
        bh = 15
        parts.append(
            f'<text x="{label_w}" y="{bar_y + bh - 3:.1f}" font-size="9" fill="#475569" '
            f'text-anchor="end">{label}</text>'
        )
        # track
        parts.append(
            f'<rect x="{bar_x}" y="{bar_y}" width="{bar_w_max}" height="{bh}" rx="3" '
            f'fill="#f1f5f9"/>'
        )
        bw = (value / nice) * bar_w_max if nice else 0.0
        if value > 0:
            parts.append(
                f'<rect x="{bar_x}" y="{bar_y}" width="{max(bw, 2):.1f}" height="{bh}" '
                f'rx="3" fill="{color}"/>'
            )
        parts.append(
            f'<text x="{bar_x + max(bw, 2) + 6:.1f}" y="{bar_y + bh - 3:.1f}" font-size="9.5" '
            f'font-weight="700" fill="{color if value else "#94a3b8"}">{value}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


# ── model assembly ────────────────────────────────────────────────────────────

def _css_safe(text: str) -> str:
    """Make a string safe to drop inside a CSS ``content: "..."`` value."""
    return re.sub(r'["\\\r\n]', " ", str(text)).strip()


def _severity_counts(open_vulns: List[dict]) -> Dict[str, int]:
    c = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info", "Secrets", "Recon")}
    for v in open_vulns:
        vtype = (v.get("type") or "").upper()
        sev = v.get("severity") or ""
        if vtype == "SECRETS":
            c["Secrets"] += 1
        elif vtype in ("EASM", "NMAP", "NMAP + NSE", "SSLSCAN"):
            c["Recon"] += 1
        elif sev == "Critical":
            c["Critical"] += 1
        elif sev == "High":
            c["High"] += 1
        elif sev == "Medium":
            c["Medium"] += 1
        elif sev == "Low":
            c["Low"] += 1
        else:
            c["Info"] += 1
    return c


def _group_counts(open_vulns: List[dict]) -> Dict[str, int]:
    c = {k: 0 for k in ("XSS", "SQLi", "Path Traversal", "Info Disclosure", "Other")}
    for v in open_vulns:
        cwe = (v.get("cwe") or "").upper()
        title = (v.get("title") or "").lower()
        if "cross-site scripting" in title or "xss" in title or cwe == "CWE-79":
            c["XSS"] += 1
        elif "sql injection" in title or "sqli" in title or cwe == "CWE-89":
            c["SQLi"] += 1
        elif ("path disclosure" in title or "directory traversal" in title
              or "file inclusion" in title or cwe in ("CWE-22", "CWE-23")):
            c["Path Traversal"] += 1
        elif ("disclosure" in title or "header" in title or "csp" in title
              or "referrer" in title or "hsts" in title or "nosniff" in title
              or "x-frame-options" in title or "clickjacking" in title or cwe == "CWE-200"):
            c["Info Disclosure"] += 1
        else:
            c["Other"] += 1
    return c


def _owasp_counts(open_vulns: List[dict]) -> Dict[str, int]:
    counts = {
        "A01:2021 – Broken Access Control": 0,
        "A02:2021 – Cryptographic Failures": 0,
        "A03:2021 – Injection": 0,
        "A04:2021 – Insecure Design": 0,
        "A05:2021 – Security Misconfiguration": 0,
        "A06:2021 – Vulnerable & Outdated Components": 0,
        "A07:2021 – Identification & Auth Failures": 0,
        "A08:2021 – Software & Data Integrity Failures": 0,
        "A09:2021 – Logging & Monitoring Failures": 0,
        "A10:2021 – Server-Side Request Forgery": 0,
    }
    keys = list(counts.keys())
    for v in open_vulns:
        cwe = (v.get("cwe") or "").upper()
        title = (v.get("title") or "").lower()
        vtype = (v.get("type") or "").upper()
        if cwe in ("CWE-287", "CWE-639") or "x-frame-options" in title or "clickjacking" in title:
            counts[keys[0]] += 1
        elif cwe in ("CWE-327", "CWE-319") or "tls" in title or "ssl" in title:
            counts[keys[1]] += 1
        elif (cwe in ("CWE-89", "CWE-79") or "sqli" in title or "injection" in title
              or "xss" in title):
            counts[keys[2]] += 1
        elif ("csp" in title or "content-security-policy" in title or "referrer-policy" in title
              or "nosniff" in title or "x-content-type-options" in title or "hsts" in title):
            counts[keys[4]] += 1
        elif "outdated" in title or vtype in ("SCA", "TRIVY"):
            counts[keys[5]] += 1
        elif ("credential" in title or "password" in title or vtype == "HYDRA"
              or vtype == "SECRETS"):
            counts[keys[6]] += 1
        elif "ssrf" in title or cwe == "CWE-918":
            counts[keys[9]] += 1
        else:
            counts[keys[4]] += 1
    return counts


def _risk_rating(sev: Dict[str, int], open_count: int) -> Dict[str, str]:
    if sev["Critical"] > 0:
        return {"label": "Critical", "color": SEVERITY_COLORS["Critical"],
                "blurb": "Critical-severity exposures are present and require immediate remediation."}
    if sev["High"] > 0:
        return {"label": "High", "color": SEVERITY_COLORS["High"],
                "blurb": "High-severity issues were identified and should be prioritised for fixing."}
    if sev["Medium"] > 0:
        return {"label": "Medium", "color": SEVERITY_COLORS["Medium"],
                "blurb": "Medium-severity issues were found; schedule remediation in the current cycle."}
    if open_count > 0:
        return {"label": "Low", "color": SEVERITY_COLORS["Low"],
                "blurb": "Only low-severity or informational findings remain open."}
    return {"label": "Secure", "color": "#16a34a",
            "blurb": "No open vulnerabilities were detected in the assessed scope."}


def _grouped_findings(vulns: List[dict], details_fn: Callable) -> List[dict]:
    """Collapse duplicate (cwe, title) rows into one finding with merged assets."""
    grouped: Dict[tuple, dict] = {}
    for v in vulns:
        key = (v.get("cwe", ""), v.get("title", ""))
        if key not in grouped:
            grouped[key] = {
                "severity": v.get("severity", "Info"),
                "cwe": v.get("cwe", "N/A"),
                "title": v.get("title", "Untitled finding"),
                "status": v.get("status", "Open"),
                "assets": [],
                "description": v.get("description", "No description provided."),
                "remediation": v.get("remediation", {}) or {},
                "type": v.get("type", "DAST"),
            }
        asset = v.get("asset")
        if asset and asset not in grouped[key]["assets"]:
            grouped[key]["assets"].append(asset)

    findings = []
    for idx, gv in enumerate(grouped.values(), 1):
        details = details_fn(gv["cwe"], gv["title"], gv["description"], gv["remediation"])
        sev = gv["severity"] if gv["severity"] in SEVERITY_COLORS else "Info"
        findings.append({
            "idx": idx,
            "title": gv["title"],
            "severity": gv["severity"],
            "severity_color": SEVERITY_COLORS.get(sev, SEVERITY_COLORS["Info"]),
            "cwe": gv["cwe"],
            "status": gv["status"],
            "source": gv["type"],
            "assets": gv["assets"] or ["—"],
            "instances": len(gv["assets"]),
            "what_was_found": details.get("what_was_found", ""),
            "business_impact": details.get("business_impact", ""),
            "remediation_steps": details.get("remediation_steps", []) or [],
        })
    return findings


def build_model(
    target: dict,
    vulns: List[dict],
    assets_data: dict,
    summary: dict,
    details_fn: Callable,
    report_type: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Assemble the full data model the template renders. Pure (no I/O)."""
    generated_at = generated_at or datetime.now()
    gen_local = generated_at.astimezone()  # make tz-aware so the time carries a zone label
    generated_date = gen_local.strftime("%d %B %Y")
    generated_time = gen_local.strftime("%H:%M %Z").strip() or gen_local.strftime("%H:%M UTC")
    generated_full = f"{generated_date} at {generated_time}"
    open_vulns = [v for v in vulns if v.get("status") in ("Open", "In Progress")]

    sev = _severity_counts(open_vulns)
    groups = _group_counts(open_vulns)
    owasp = _owasp_counts(open_vulns)
    gauges = summary.get("compliance_gauges", {}) or {}
    compliance_avg = int(sum(gauges.values()) / len(gauges)) if gauges else 0
    risk = _risk_rating(sev, len(open_vulns))

    kind = "Executive"
    report_title = "Application Security Assessment"
    subtitle = "Executive Security Report"
    rt = (report_type or "").upper()
    if rt == "SAST":
        kind, subtitle = "SAST", "Static Application Security Testing (SAST) Report"
    elif rt == "SCA":
        kind, subtitle = "SCA", "Software Composition Analysis (SCA) Report"

    findings = _grouped_findings(vulns, details_fn)

    # A type-filtered (SAST/SCA) report with no findings almost always means that
    # scan type was never run for this scope (e.g. a deployed URL, not a source
    # repo) — NOT that the code is clean. Reporting "Secure / 100% compliant" there
    # would be misleading, so flag it "Not Assessed" and suppress the empty charts
    # and the (vacuous) 100% compliance gauges.
    not_assessed = rt in ("SAST", "SCA") and len(vulns) == 0
    type_full = {"SAST": "Static Application Security Testing (SAST)",
                 "SCA": "Software Composition Analysis (SCA)"}.get(rt, "")

    if not_assessed:
        risk = {"label": "Not Assessed", "color": "#64748b",
                "blurb": f"No {rt} scan data is recorded for this scope."}
        exec_summary = (
            f"No {type_full} results are available for {target.get('name', 'this scope')}. "
            f"This usually means a {rt} scan has not been run against this scope — for example, the "
            f"target is a deployed endpoint rather than a source repository, or the {rt} engine has not "
            f"yet been executed. Run a {rt} scan to populate the severity, group and OWASP breakdowns."
        )
        compliance = []
        compliance_display = "N/A"
    else:
        exec_summary = (
            f"This report presents the security posture of {target.get('name', 'the assessed scope')} "
            f"based on automated discovery, scanning and analysis across "
            f"{summary.get('assets_count', 0)} asset(s). The assessment identified "
            f"{len(vulns)} finding(s) in total, of which {len(open_vulns)} remain open — "
            f"including {sev['Critical']} critical and {sev['High']} high-severity issue(s). "
            f"The overall risk posture is rated {risk['label']}. {risk['blurb']}"
        )
        compliance = []
        for name, score in gauges.items():
            color = "#16a34a" if score > 75 else ("#d4a017" if score > 50 else "#b91c1c")
            compliance.append({"name": name, "score": score, "color": color})
        compliance_display = f"{compliance_avg}%"

    subdomains = []
    for s in assets_data.get("subdomains", []):
        subdomains.append({
            "subdomain": s.get("subdomain", "—"),
            "ip": s.get("ip", "—"),
            "cdn": s.get("cdn", "—"),
            "ports": s.get("ports", []) or [],
            "ssl_expiry": s.get("ssl_expiry", "N/A"),
            "tls_version": s.get("tls_version") or "N/A",
            "cipher_suite": s.get("cipher_suite") or "None",
        })

    target_url = target.get("url", "")
    return {
        "kind": kind,
        "report_title": report_title,
        "subtitle": subtitle,
        "doc_title": f"{target.get('name', 'Scope')} — {subtitle}",
        "generated_date": generated_date,
        "generated_time": generated_time,
        "generated_full": generated_full,
        "generated_iso": generated_at.date().isoformat(),
        "not_assessed": not_assessed,
        "page_footer_center": _css_safe(f"Generated {generated_full}"),
        "classification": "CONFIDENTIAL",
        "target": {
            "name": target.get("name", "Consolidated Scope"),
            "url": target_url,
            "url_is_link": isinstance(target_url, str) and target_url.startswith(("http://", "https://")),
        },
        "page_header": _css_safe(f"{target.get('name', 'Security Assessment')} · {subtitle}"),
        "metrics": {
            "total": len(vulns),
            "open": len(open_vulns),
            "assets": summary.get("assets_count", 0),
            "compliance": compliance_avg,
            "compliance_display": compliance_display,
            **sev,
        },
        "risk": risk,
        "exec_summary": exec_summary,
        "charts": {
            "severity": vbar_chart([
                ("Critical", sev["Critical"], SEVERITY_COLORS["Critical"]),
                ("High", sev["High"], SEVERITY_COLORS["High"]),
                ("Medium", sev["Medium"], SEVERITY_COLORS["Medium"]),
                ("Low", sev["Low"], SEVERITY_COLORS["Low"]),
                ("Info", sev["Info"], SEVERITY_COLORS["Info"]),
                ("Secrets", sev["Secrets"], SEVERITY_COLORS["Secrets"]),
                ("Recon", sev["Recon"], SEVERITY_COLORS["Recon"]),
            ]),
            "group": vbar_chart([
                (label, groups[label], GROUP_COLORS[label]) for label in groups
            ]),
            "owasp": hbar_chart([
                (label, count, OWASP_COLOR) for label, count in owasp.items()
            ]),
        },
        "compliance": compliance,
        "subdomains": subdomains,
        "findings": findings,
    }


# ── rendering ─────────────────────────────────────────────────────────────────

def render_html(model: Dict[str, Any]) -> str:
    return _env.get_template("report.html.j2").render(**model)


def render_pdf(html: str) -> bytes:
    """Render HTML to PDF bytes via WeasyPrint. Raises if WeasyPrint is unavailable."""
    from weasyprint import HTML  # imported lazily — native libs only needed here
    return HTML(string=html).write_pdf()
