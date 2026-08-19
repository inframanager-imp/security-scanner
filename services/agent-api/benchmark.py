"""
Triage benchmark — scores agent-api's /triage endpoint against a small,
hand-labeled dataset of known-vulnerable and known-safe code findings.

Why this exists: every RAG/reranking/CVE-context/prompt change this session
was verified by spot-checking a handful of live examples — real, but not
repeatable or comparable across changes. This gives a fixed baseline: run it
before and after a change, diff precision/recall/F1, and know whether the
change actually helped instead of guessing from a few manual checks.

Each case's ground truth is "is this genuinely exploitable as described" —
matched against pt_verification.confirmed, the judge node's verdict. This
specifically measures the judge's false-positive/false-negative rate, which
is the node most sensitive to getting this wrong (see graph.py's comment on
_get_judge_llm_config): a wrong "confirmed" on a safe pattern wastes a fix
cycle; a wrong "not confirmed" on a real vuln is a false negative that ships.

Usage (run inside the agent-api container, where PyJWT + the LLM provider
config are already available):
    docker exec vapt-agent-api python3 benchmark.py
    docker exec vapt-agent-api python3 benchmark.py --output /tmp/results.json

Results are also appended to benchmark_history.jsonl (one line per run) so
runs can be compared over time — see --history-file.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import jwt

AGENT_API_URL = os.environ.get("BENCHMARK_AGENT_API_URL", "http://localhost:8100")
JWT_ACCESS_SECRET = os.environ.get("JWT_ACCESS_SECRET", "")

# ── Labeled dataset ──────────────────────────────────────────────────────────
CASES = [
    {
        "id": "sqli-concat-vulnerable",
        "ground_truth": True,
        "finding": {
            "title": "SQL Injection via string concatenation",
            "type": "SAST", "cwe": "CWE-89",
            "description": "User-supplied 'username' parameter is concatenated directly into a SQL query string without parameterization.",
            "poc": "GET /login?username=' OR '1'='1",
            "code_snippet": 'const query = "SELECT * FROM users WHERE username = \'" + req.query.username + "\'";\ndb.query(query, callback);',
        },
    },
    {
        "id": "sqli-parameterized-safe",
        "ground_truth": False,
        "finding": {
            "title": "SQL Injection via string concatenation",
            "type": "SAST", "cwe": "CWE-89",
            "description": "Semgrep flagged a query built with string formatting, but the actual query uses a parameterized placeholder, not concatenated user input.",
            "poc": "GET /login?username=admin",
            "code_snippet": 'const query = "SELECT * FROM users WHERE username = ?";\ndb.query(query, [req.query.username], callback);',
        },
    },
    {
        "id": "command-injection-vulnerable",
        "ground_truth": True,
        "finding": {
            "title": "OS Command Injection via unsanitized filename",
            "type": "SAST", "cwe": "CWE-78",
            "description": "User-supplied filename is passed directly into a shell command via exec().",
            "poc": "POST /convert {\"filename\": \"a.txt; rm -rf /\"}",
            "code_snippet": 'exec("convert " + req.body.filename + " output.png");',
        },
    },
    {
        "id": "command-execfile-safe",
        "ground_truth": False,
        "finding": {
            "title": "OS Command Injection via unsanitized filename",
            "type": "SAST", "cwe": "CWE-78",
            "description": "Semgrep flagged use of a subprocess call, but the argument list is passed as an array with no shell interpolation, and the filename is validated against an allow-list regex before use.",
            "poc": "POST /convert {\"filename\": \"a.txt\"}",
            "code_snippet": 'if (!/^[\\w.-]+$/.test(filename)) throw new Error("invalid");\nexecFile("convert", [filename, "output.png"]);',
        },
    },
    {
        "id": "path-traversal-vulnerable",
        "ground_truth": True,
        "finding": {
            "title": "Path Traversal via unsanitized file parameter",
            "type": "SAST", "cwe": "CWE-22",
            "description": "User-supplied 'file' query parameter is joined directly into a filesystem path with no normalization or bounds check.",
            "poc": "GET /download?file=../../../../etc/passwd",
            "code_snippet": 'const filePath = path.join(BASE_DIR, req.query.file);\nres.sendFile(filePath);',
        },
    },
    {
        "id": "path-traversal-normalized-safe",
        "ground_truth": False,
        "finding": {
            "title": "Path Traversal via unsanitized file parameter",
            "type": "SAST", "cwe": "CWE-22",
            "description": "Semgrep flagged a path.join call, but the resolved path is checked to still be within BASE_DIR after normalization before being used.",
            "poc": "GET /download?file=report.pdf",
            "code_snippet": 'const resolved = path.resolve(BASE_DIR, req.query.file);\nif (!resolved.startsWith(BASE_DIR)) throw new Error("invalid path");\nres.sendFile(resolved);',
        },
    },
    {
        "id": "hardcoded-secret-vulnerable",
        "ground_truth": True,
        "finding": {
            "title": "Hardcoded API credential in source",
            "type": "SECRET", "cwe": "CWE-798",
            "description": "A live-looking API key is hardcoded directly in the source file, committed to version control.",
            "poc": "grep match: const apiKey = \"sk-live-4f8a2b9c1d3e...\";",
            "code_snippet": 'const apiKey = "sk-live-4f8a2b9c1d3e7f6a9b2c8d1e4f7a3b6c";\nstripe.setApiKey(apiKey);',
        },
    },
    {
        "id": "env-var-reference-safe",
        "ground_truth": False,
        "finding": {
            "title": "Hardcoded API credential in source",
            "type": "SECRET", "cwe": "CWE-798",
            "description": "Secrets scanner flagged a variable named apiKey, but its value is read from an environment variable at runtime, not a literal secret in the source.",
            "poc": "grep match: const apiKey = process.env.STRIPE_API_KEY;",
            "code_snippet": 'const apiKey = process.env.STRIPE_API_KEY;\nstripe.setApiKey(apiKey);',
        },
    },
    {
        "id": "weak-crypto-md5-vulnerable",
        "ground_truth": True,
        "finding": {
            "title": "Use of weak hashing algorithm MD5 for passwords",
            "type": "SAST", "cwe": "CWE-327",
            "description": "User passwords are hashed with MD5 before storage — MD5 is cryptographically broken and unsuitable for password storage (no salt, fast to brute-force).",
            "poc": "grep match: crypto.createHash('md5').update(password).digest('hex')",
            "code_snippet": "const hash = crypto.createHash('md5').update(password).digest('hex');\nuser.passwordHash = hash;",
        },
    },
    {
        "id": "md5-non-security-checksum-safe",
        "ground_truth": False,
        "finding": {
            "title": "Use of weak hashing algorithm MD5",
            "type": "SAST", "cwe": "CWE-327",
            "description": "Semgrep flagged an MD5 call, but it's used only to generate a cache-busting checksum for a static asset filename, not for any security-sensitive purpose (no passwords, tokens, or signatures involved).",
            "poc": "grep match: crypto.createHash('md5').update(fileBuffer).digest('hex')",
            "code_snippet": "const cacheKey = crypto.createHash('md5').update(fileBuffer).digest('hex');\nconst assetUrl = `/static/bundle.${cacheKey}.js`;",
        },
    },
    {
        "id": "idor-vulnerable",
        "ground_truth": True,
        "finding": {
            "title": "Insecure Direct Object Reference on order lookup",
            "type": "SAST", "cwe": "CWE-639",
            "description": "The order ID from the URL is used to fetch and return order data with no check that the order belongs to the requesting user.",
            "poc": "GET /orders/1042 (as user A, returns user B's order)",
            "code_snippet": "app.get('/orders/:id', async (req, res) => {\n  const order = await Order.findById(req.params.id);\n  res.json(order);\n});",
        },
    },
    {
        "id": "authorized-lookup-safe",
        "ground_truth": False,
        "finding": {
            "title": "Insecure Direct Object Reference on order lookup",
            "type": "SAST", "cwe": "CWE-639",
            "description": "Semgrep flagged an ID-based lookup, but the query is scoped to the authenticated user's own ID, so a user cannot retrieve another user's order regardless of the ID supplied.",
            "poc": "GET /orders/1042 (as user A, returns 404 — order belongs to user B)",
            "code_snippet": "app.get('/orders/:id', async (req, res) => {\n  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });\n  if (!order) return res.status(404).end();\n  res.json(order);\n});",
        },
    },
]


def _service_token() -> str:
    return jwt.encode(
        {"sub": "benchmark-runner", "role": "SERVICE", "type": "access", "exp": int(time.time()) + 300},
        JWT_ACCESS_SECRET,
        algorithm="HS256",
    )


def _call_triage(finding: dict, timeout: float = 60.0) -> dict:
    body = json.dumps(finding).encode("utf-8")
    req = urllib.request.Request(
        f"{AGENT_API_URL}/triage",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {_service_token()}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def run_benchmark() -> dict:
    if not JWT_ACCESS_SECRET:
        raise RuntimeError("JWT_ACCESS_SECRET not set — run this inside the agent-api container/environment")

    results = []
    tp = fp = fn = tn = errors = 0
    for case in CASES:
        t0 = time.time()
        try:
            resp = _call_triage(case["finding"])
            predicted = bool((resp.get("pt_verification") or {}).get("confirmed"))
            reason = (resp.get("pt_verification") or {}).get("reason", "")
            truth = case["ground_truth"]
            outcome = (
                "TP" if predicted and truth else
                "FP" if predicted and not truth else
                "FN" if not predicted and truth else
                "TN"
            )
            if outcome == "TP": tp += 1
            elif outcome == "FP": fp += 1
            elif outcome == "FN": fn += 1
            else: tn += 1
            results.append({
                "id": case["id"], "ground_truth": truth, "predicted": predicted,
                "outcome": outcome, "reason": reason, "elapsed_s": round(time.time() - t0, 1),
            })
            print(f"[{outcome}] {case['id']} (predicted={predicted}, truth={truth}) — {reason[:100]}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as e:
            errors += 1
            results.append({"id": case["id"], "error": f"{type(e).__name__}: {e}"})
            print(f"[ERROR] {case['id']} — {type(e).__name__}: {e}")

    total_scored = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall and (precision + recall) else None
    accuracy = (tp + tn) / total_scored if total_scored else None

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": os.environ.get("LLM_PROVIDER", "ollama"),
        "judge_provider": os.environ.get("JUDGE_PROVIDER") or os.environ.get("LLM_PROVIDER", "ollama"),
        "total_cases": len(CASES),
        "errors": errors,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "accuracy": round(accuracy, 3) if accuracy is not None else None,
        "results": results,
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Score agent-api /triage against a labeled benchmark dataset.")
    parser.add_argument("--output", default=None, help="Write full JSON result to this path")
    parser.add_argument("--history-file", default="benchmark_history.jsonl", help="Append a summary line to this file for tracking runs over time")
    args = parser.parse_args()

    summary = run_benchmark()

    print("\n" + "=" * 60)
    print(f"Provider: {summary['provider']}  Judge: {summary['judge_provider']}")
    print(f"Precision: {summary['precision']}  Recall: {summary['recall']}  F1: {summary['f1']}  Accuracy: {summary['accuracy']}")
    print(f"TP={summary['tp']} FP={summary['fp']} FN={summary['fn']} TN={summary['tn']} Errors={summary['errors']}")
    print("=" * 60)

    if args.output:
        Path(args.output).write_text(json.dumps(summary, indent=2))
        print(f"Full results written to {args.output}")

    if args.history_file:
        history_summary = {k: v for k, v in summary.items() if k != "results"}
        with open(args.history_file, "a") as f:
            f.write(json.dumps(history_summary) + "\n")
        print(f"Summary appended to {args.history_file}")


if __name__ == "__main__":
    main()
