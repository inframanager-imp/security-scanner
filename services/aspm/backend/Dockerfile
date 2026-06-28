# ── ASPM backend (FastAPI) — FULL real-scanner image ─────────────────────────
# Build context = services/aspm. Ships the real security tools so scans run for
# real (no emulator fallback). Talks to shared Postgres (schema "aspm") and an
# OWASP ZAP daemon container (ZAP_PROXY).
FROM python:3.12-slim

WORKDIR /app

# ── System scanners via apt + build/runtime deps ─────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget unzip git jq bind9-dnsutils \
      nmap sslscan hydra sqlmap \
      perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto isn't in Debian trixie — install the upstream Perl tool from GitHub
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
 && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
 && chmod +x /opt/nikto/program/nikto.pl

# ── Go/standalone binaries: pull the latest linux-amd64 release of each ──────
# Robust against version churn by resolving the asset URL from the GitHub API.
RUN set -eux; \
    fetch_gh() { \
      repo="$1"; suffix="$2"; out="$3"; \
      url=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
            | jq -r --arg s "$suffix" '.assets[]?.browser_download_url | select(endswith($s))' | head -1); \
      echo "Downloading ${repo}: ${url}"; \
      test -n "$url"; \
      curl -fsSL "$url" -o "/tmp/${out}"; \
    }; \
    fetch_gh "projectdiscovery/nuclei" "linux_amd64.zip" "nuclei.zip"; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    fetch_gh "OJ/gobuster" "Linux_x86_64.tar.gz" "gobuster.tgz"; \
    tar -xzf /tmp/gobuster.tgz -C /usr/local/bin gobuster; \
    fetch_gh "gitleaks/gitleaks" "linux_x64.tar.gz" "gitleaks.tgz"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    fetch_gh "trufflesecurity/trufflehog" "linux_amd64.tar.gz" "trufflehog.tgz"; \
    tar -xzf /tmp/trufflehog.tgz -C /usr/local/bin trufflehog; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/gobuster /usr/local/bin/gitleaks /usr/local/bin/trufflehog; \
    rm -f /tmp/*.zip /tmp/*.tgz

# trivy via its official installer
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ── Python deps (incl. semgrep / bandit / pip-audit / safety) ────────────────
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Pre-fetch nuclei templates so scans don't need to download them at runtime
RUN nuclei -update-templates || true

# Minimal bundled wordlists for gobuster (dir sweep) and hydra (credential audit)
RUN mkdir -p /opt/wordlists \
 && printf '%s\n' admin login dashboard config .env .git/config .git/HEAD .svn/entries \
      backup backup.zip backup.sql db.sql dump.sql wp-admin wp-login.php robots.txt \
      sitemap.xml server-status server-info actuator actuator/health swagger swagger-ui.html \
      api api/v1 api-docs .htaccess .htpasswd phpinfo.php info.php test dev old tmp uploads \
      .DS_Store console adminer.php phpmyadmin .well-known/security.txt > /opt/wordlists/common.txt \
 && printf '%s\n' root admin administrator user test oracle ubuntu > /opt/wordlists/users.txt \
 && printf '%s\n' admin password 123456 root toor admin123 password123 changeme test1234 P@ssw0rd > /opt/wordlists/passwords.txt

# ── Reporting engine: HTML -> PDF (WeasyPrint) ───────────────────────────────
# Installed as late, self-contained layers (deliberately kept OUT of the scanner
# apt block and requirements.txt) so the expensive scanner-download layers above
# stay cached on rebuilds. libpango/cairo/gdk-pixbuf + DejaVu fonts are
# WeasyPrint's native deps; fontconfig gives the PDF a consistent sans-serif face.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
      libgdk-pixbuf-2.0-0 libcairo2 libffi8 shared-mime-info \
      fonts-dejavu-core fontconfig tzdata \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "Jinja2>=3.1.0" "weasyprint>=62.0"

# Pre-fetch Trivy's vulnerability + Java index DBs so the FIRST SCA scan doesn't
# have to download them at runtime — a failed first-run download is exactly why an
# SCA scan can otherwise come back empty. Late layer: only needs the trivy binary.
RUN trivy image --download-db-only --no-progress || true
RUN trivy image --download-java-db-only --no-progress || true

# Application code (init_db() creates the aspm schema + tables on first start)
COPY backend ./backend

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
