# ─────────────────────────────────────────────────────────────────────────────
# BBHunter — Bug Bounty Automation Tool
# docker build -t bbhunter .
# docker run --rm -v $(pwd)/output:/output bbhunter -u example.com
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

LABEL maintainer="BBHunter" \
      description="Bug Bounty Automation: Recon → Vuln Scan → PDF Report" \
      version="1.0"

# ── System dependencies & security tools ─────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Core utilities
        curl wget git ca-certificates unzip \
        # nmap
        nmap \
        # whatweb
        whatweb \
        # DNS utilities
        dnsutils \
        # Build deps for some Go tools
        golang-go \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Go-based security tools ───────────────────────────────────────────────────
ENV GOPATH=/opt/go
ENV PATH=$PATH:/opt/go/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest            2>/dev/null || true && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       2>/dev/null || true && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest                          2>/dev/null || true && \
    go install -v github.com/tomnomnom/waybackurls@latest                       2>/dev/null || true && \
    go install -v github.com/OJ/gobuster/v3@latest                              2>/dev/null || true && \
    go install -v github.com/ffuf/ffuf/v2@latest                                2>/dev/null || true

# ── TruffleHog ────────────────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null || true

# ── Update nuclei templates ───────────────────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy tool ─────────────────────────────────────────────────────────────────
COPY bbhunter.py .
RUN chmod +x bbhunter.py

# ── Output volume & config dir ────────────────────────────────────────────────
RUN mkdir -p /output /root/.bbhunter
VOLUME ["/output"]

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["python", "bbhunter.py"]
CMD ["--help"]
