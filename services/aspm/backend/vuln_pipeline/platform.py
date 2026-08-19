"""
Git platform detection for the Vulnerability Pipeline (BCDD-adjacent feature —
see vulnerability-pipeline.md). Identifies which host a repo URL points at
(GitHub / GitLab / Bitbucket / Gitee / GitCode / self-hosted GitLab) so the
pipeline can pick the right clone-auth scheme and, later, the right PR/MR API.

Uses stdlib urllib (not `requests`) to match the rest of this service —
scanners.py has no third-party HTTP client dependency, and adding one just
for a single probe call isn't worth a new requirements.txt entry.
"""
from __future__ import annotations

import re
import json
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Optional

PLATFORM_PATTERNS = {
    "github":    r"(^|[./])github\.com$",
    "gitlab":    r"(^|[./])gitlab\.com$",
    "bitbucket": r"(^|[./])bitbucket\.org$",
    "gitee":     r"(^|[./])gitee\.com$",
    "gitcode":   r"(^|[./])gitcode\.com$",
}

PR_TERM = {
    "github": "pull request", "gitee": "pull request", "gitcode": "pull request",
    "gitlab": "merge request", "bitbucket": "merge request",
}

API_BASE = {
    "github":    "https://api.github.com",
    "gitlab":    "https://gitlab.com/api/v4",
    "bitbucket": "https://api.bitbucket.org/2.0",
    "gitee":     "https://gitee.com/api/v5",
    "gitcode":   "https://api.gitcode.com/api/v5",
}


def probe_gitlab_api(host: str, timeout: float = 5.0) -> bool:
    """Check if an unrecognised host responds to GitLab's version API —
    the signal that it's a self-hosted GitLab instance."""
    try:
        req = urllib.request.Request(f"https://{host}/api/v4/version", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 401)
    except urllib.error.HTTPError as e:
        return e.code in (200, 401)  # 401 = auth needed but GitLab is there
    except Exception:
        return False


def _default_pattern_rows() -> list[dict]:
    """The hardcoded 5 as {"platform_id","host_pattern","pr_term","api_base"}
    rows — same shape the DB table returns, used as a fallback so this module
    still works standalone (tests, no DB configured) without a DB round-trip."""
    return [
        {"platform_id": p, "host_pattern": pat, "pr_term": PR_TERM.get(p, "pull request"), "api_base": API_BASE.get(p)}
        for p, pat in PLATFORM_PATTERNS.items()
    ]


def detect_platform(repo_url: str, patterns: Optional[list[dict]] = None) -> dict:
    """Returns {"platform", "host", "self_hosted", "pr_term", "api_base"}.

    `patterns` — rows from database.list_git_platforms() (id/platform_id/
    host_pattern/pr_term/api_base/self_hosted), so users can add self-hosted/
    enterprise instances via the git-platforms CRUD API without a code
    change. Defaults to the hardcoded 5 when not given (standalone/test use).
    Rows are tried in order — first match wins, so more specific custom
    patterns should be created before broader ones if they could overlap.
    """
    host = urlparse(repo_url).hostname or ""
    rows = patterns if patterns is not None else _default_pattern_rows()

    for row in rows:
        if re.search(row["host_pattern"], host, re.IGNORECASE):
            return {
                "platform": row["platform_id"], "host": host,
                "self_hosted": bool(row.get("self_hosted", False)),
                "pr_term": row.get("pr_term") or PR_TERM.get(row["platform_id"], "pull request"),
                "api_base": row.get("api_base") or API_BASE.get(row["platform_id"], ""),
            }

    if probe_gitlab_api(host):
        return {
            "platform": "gitlab", "host": host, "self_hosted": True,
            "pr_term": "merge request", "api_base": f"https://{host}/api/v4",
        }

    raise ValueError(f"Unrecognised Git platform: {host}")


def detect_platform_from_db(repo_url: str) -> dict:
    """DB-aware convenience wrapper — imports backend.database lazily so this
    module has no hard DB dependency for callers that pass `patterns=` themselves."""
    from backend.database import list_git_platforms
    return detect_platform(repo_url, patterns=list_git_platforms())


@dataclass
class RepoContext:
    platform: str          # "github" | "gitlab" | "bitbucket" | "gitee" | "gitcode"
    host: str               # e.g. "github.com" or "git.company.internal"
    self_hosted: bool
    owner: str              # org or username
    repo: str               # repository slug
    clone_url: str          # https clone URL with token embedded
    default_branch: str = ""    # main / master / develop — filled in after clone
    head_sha: str = ""          # HEAD commit SHA — filled in after clone
    api_base: str = ""          # base URL for API calls
    auth_header: dict = field(default_factory=dict)  # {"Authorization": "Bearer <token>"} or platform-specific
    pr_term: str = ""  # resolved in __post_init__ if not passed explicitly

    def __post_init__(self):
        if not self.pr_term:
            self.pr_term = PR_TERM.get(self.platform, "pull request")
        if not self.api_base:
            if self.self_hosted:
                self.api_base = f"https://{self.host}/api/v4"
            else:
                self.api_base = API_BASE.get(self.platform, "")


def build_clone_url(ctx: RepoContext, token: str) -> str:
    """Embeds the token into an HTTPS clone URL using the auth scheme each
    platform actually expects — these differ (bare token vs "oauth2:" vs
    "x-token-auth:" prefix), unlike the generic userinfo injection previously
    used for ad-hoc git clone (services/aspm/backend/scanners.py's
    prepare_source_code), which worked for GitHub-style auth but not Bitbucket
    or GitLab's OAuth2 convention.
    """
    host = ctx.host  # self-hosted GitLab clones from its own host, not gitlab.com
    match ctx.platform:
        case "github":
            return f"https://{token}@{host}/{ctx.owner}/{ctx.repo}.git"
        case "gitlab":
            return f"https://oauth2:{token}@{host}/{ctx.owner}/{ctx.repo}.git"
        case "bitbucket":
            return f"https://x-token-auth:{token}@{host}/{ctx.owner}/{ctx.repo}.git"
        case "gitee":
            return f"https://{token}@{host}/{ctx.owner}/{ctx.repo}.git"
        case "gitcode":
            return f"https://oauth2:{token}@{host}/{ctx.owner}/{ctx.repo}.git"
        case _:
            raise ValueError(f"No clone-URL scheme known for platform: {ctx.platform}")


def parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """Extracts (owner, repo) from a repo URL's path — e.g.
    https://github.com/acme/widgets(.git) -> ("acme", "widgets")."""
    path = urlparse(repo_url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) < 2:
        raise ValueError(f"Could not parse owner/repo from URL: {repo_url}")
    return parts[-2], parts[-1]


def build_repo_context(repo_url: str, token: str, use_db_patterns: bool = True) -> RepoContext:
    """One-shot helper: detect platform (DB-configured patterns by default —
    set use_db_patterns=False for standalone/test use), parse owner/repo,
    build the auth'd clone URL. This is what Stage 1 (platform_node) calls."""
    detected = detect_platform_from_db(repo_url) if use_db_patterns else detect_platform(repo_url)
    owner, repo = parse_owner_repo(repo_url)
    ctx = RepoContext(
        platform=detected["platform"],
        host=detected["host"],
        self_hosted=detected["self_hosted"],
        owner=owner,
        repo=repo,
        clone_url="",  # filled below, needs ctx for host-aware URL building
        pr_term=detected.get("pr_term", ""),
        api_base=detected.get("api_base", ""),
    )
    ctx.clone_url = build_clone_url(ctx, token)
    return ctx



def _auth_headers(ctx: RepoContext, token: str) -> dict:
    if not token:
        return {}
    match ctx.platform:
        case "gitlab":
            return {"PRIVATE-TOKEN": token}
        case "gitee" | "gitcode":
            return {}  # these two authenticate via ?access_token= query param instead
        case _:  # github, bitbucket
            return {"Authorization": f"Bearer {token}"}


def _api_get(url: str, headers: dict, timeout: float = 10.0):
    req = urllib.request.Request(url, method="GET")
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"API request to {url} failed: HTTP {e.code}: {body}") from e


def _token_query(token: str) -> str:
    """Gitee/GitCode authenticate via ?access_token=; omit the param entirely
    for anonymous access to public repos rather than sending it empty."""
    return f"access_token={urllib.parse.quote(token, safe='')}&" if token else ""


def list_branches(ctx: RepoContext, token: str) -> list[dict]:
    """Returns [{"name": str, "commit_sha": str, "protected": bool}, ...],
    newest/most-relevant platform ordering preserved as returned by the API."""
    headers = _auth_headers(ctx, token)
    owner, repo = ctx.owner, ctx.repo

    match ctx.platform:
        case "github":
            url = f"{ctx.api_base}/repos/{owner}/{repo}/branches?per_page=100"
            data = _api_get(url, headers)
            return [{"name": b["name"], "commit_sha": b.get("commit", {}).get("sha", ""),
                     "protected": bool(b.get("protected", False))} for b in data]

        case "gitlab":
            project = urllib.parse.quote(f"{owner}/{repo}", safe="")
            url = f"{ctx.api_base}/projects/{project}/repository/branches?per_page=100"
            data = _api_get(url, headers)
            return [{"name": b["name"], "commit_sha": b.get("commit", {}).get("id", ""),
                     "protected": bool(b.get("protected", False))} for b in data]

        case "bitbucket":
            url = f"{ctx.api_base}/repositories/{owner}/{repo}/refs/branches?pagelen=100"
            data = _api_get(url, headers)
            return [{"name": b["name"], "commit_sha": b.get("target", {}).get("hash", ""),
                     "protected": False} for b in data.get("values", [])]

        case "gitee" | "gitcode":
            url = f"{ctx.api_base}/repos/{owner}/{repo}/branches?{_token_query(token)}per_page=100"
            data = _api_get(url, headers)
            return [{"name": b["name"], "commit_sha": b.get("commit", {}).get("sha", ""),
                     "protected": bool(b.get("protected", False))} for b in data]

        case _:
            raise ValueError(f"No branch-list API known for platform: {ctx.platform}")


def get_default_branch(ctx: RepoContext, token: str) -> str:
    """Fetches the repo's actual configured default branch from the platform
    API — 'main' vs 'master' vs anything else the repo owner set, rather than
    guessing. Falls back to 'main' if the lookup fails for any reason (never
    hard-fails branch listing just because this one convenience call broke)."""
    headers = _auth_headers(ctx, token)
    owner, repo = ctx.owner, ctx.repo
    try:
        match ctx.platform:
            case "github":
                data = _api_get(f"{ctx.api_base}/repos/{owner}/{repo}", headers)
                return data.get("default_branch") or "main"
            case "gitlab":
                project = urllib.parse.quote(f"{owner}/{repo}", safe="")
                data = _api_get(f"{ctx.api_base}/projects/{project}", headers)
                return data.get("default_branch") or "main"
            case "bitbucket":
                data = _api_get(f"{ctx.api_base}/repositories/{owner}/{repo}", headers)
                return data.get("mainbranch", {}).get("name") or "main"
            case "gitee" | "gitcode":
                data = _api_get(f"{ctx.api_base}/repos/{owner}/{repo}?{_token_query(token)}".rstrip("?&"), headers)
                return data.get("default_branch") or "master"
            case _:
                return "main"
    except Exception:
        return "main"



def push_branch(ctx: RepoContext, scan_dir: str, branch_name: str, token: str) -> None:
    """Pushes an already-committed local branch to the platform, using the
    same auth-embedded clone URL scheme build_clone_url already established
    per platform (bare token / oauth2: / x-token-auth: prefixes)."""
    import subprocess
    authed_url = build_clone_url(ctx, token)
    proc = subprocess.run(
        ["git", "push", authed_url, f"HEAD:refs/heads/{branch_name}"],
        cwd=scan_dir, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git push failed: {proc.stderr.strip()[:500]}")


def _api_post(url: str, headers: dict, body: dict, timeout: float = 15.0):
    req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode())
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"API request to {url} failed: HTTP {e.code}: {body_text}") from e


def create_pull_request(ctx: RepoContext, token: str, *, branch_name: str, base_branch: str,
                         title: str, body: str) -> dict:
    """Opens a real PR/MR on the detected platform. Returns
    {"url": str, "number_or_id": str|int}. Raises RuntimeError on failure —
    callers should treat that as "PR creation failed", not silently continue."""
    headers = _auth_headers(ctx, token)
    owner, repo = ctx.owner, ctx.repo

    match ctx.platform:
        case "github":
            url = f"{ctx.api_base}/repos/{owner}/{repo}/pulls"
            data = _api_post(url, headers, {"title": title, "head": branch_name, "base": base_branch, "body": body})
            return {"url": data.get("html_url", ""), "number_or_id": data.get("number")}

        case "gitlab":
            project = urllib.parse.quote(f"{owner}/{repo}", safe="")
            url = f"{ctx.api_base}/projects/{project}/merge_requests"
            data = _api_post(url, headers, {
                "source_branch": branch_name, "target_branch": base_branch,
                "title": title, "description": body,
            })
            return {"url": data.get("web_url", ""), "number_or_id": data.get("iid")}

        case "bitbucket":
            url = f"{ctx.api_base}/repositories/{owner}/{repo}/pullrequests"
            data = _api_post(url, headers, {
                "title": title,
                "source": {"branch": {"name": branch_name}},
                "destination": {"branch": {"name": base_branch}},
                "description": body,
            })
            links = data.get("links", {}).get("html", {})
            return {"url": links.get("href", ""), "number_or_id": data.get("id")}

        case "gitee" | "gitcode":
            url = f"{ctx.api_base}/repos/{owner}/{repo}/pulls?{_token_query(token)}".rstrip("?&")
            data = _api_post(url, headers, {
                "title": title, "head": branch_name, "base": base_branch, "body": body,
            })
            return {"url": data.get("html_url", ""), "number_or_id": data.get("number")}

        case _:
            raise ValueError(f"No PR-creation API known for platform: {ctx.platform}")
