# BBHunter 🎯

> **Automated Bug Bounty Recon, Vulnerability Scanning & PDF Reporting**

BBHunter is a Python CLI tool that automates the three core phases of a bug bounty engagement — reconnaissance, vulnerability scanning, and report generation — into a single command.

```
python bbhunter.py -u target.com
```

> ⚠️ **Authorisation Required** — only use this tool against systems you have explicit written permission to test.

---

## Features

| Phase | What it does |
|---|---|
| **1 · Recon** | DNS records, subdomain discovery, port scan, HTTP fingerprinting, secret/credential hunting, directory brute-force |
| **2 · Vuln Scan** | Nuclei templates, security header analysis, SSL/TLS checks, CORS misconfig, open redirects, XSS probes, sensitive file exposure, default credentials |
| **3 · Report** | Colour-coded PDF + plain-text report with executive summary, all findings, and a manual testing checklist |
| **Tool Registry** | Add any external tool with a custom command template — it runs automatically in the right phase |

---

## Quick Start

### Option A — Python (local)

**Requirements:** Python 3.9+

```bash
git clone https://github.com/yourname/bbhunter.git
cd bbhunter
pip install -r requirements.txt
python bbhunter.py -u example.com
```

### Option B — Docker (recommended)

No Python or tool installation needed.

```bash
git clone https://github.com/yourname/bbhunter.git
cd bbhunter

# Build the image (installs nmap, nuclei, subfinder, httpx, gobuster, ffuf,
# gau, waybackurls, trufflehog, whatweb automatically)
docker build -t bbhunter .

# Run a full scan — output lands in ./output/
docker run --rm -v $(pwd)/output:/output bbhunter -u example.com

# Windows (PowerShell)
docker run --rm -v ${PWD}/output:/output bbhunter -u example.com
```

### Option C — Docker Compose

```bash
# Full scan
docker compose run bbhunter -u example.com

# Tool management
docker compose run bbhunter --list-tools
docker compose run bbhunter --add-tool amass \
    --tool-phase recon \
    --tool-cmd "amass enum -d {target} -o {out}/amass.txt" \
    --tool-desc "Amass subdomain enumeration"
```

---

## Usage

```
python bbhunter.py [options]
```

### Scan options

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | *(required)* | Target URL or domain |
| `-o`, `--output` | `./bbhunter_output` | Output directory |
| `--phase` | `all` | `all` · `recon` · `scan` · `report` |
| `--skip-recon` | — | Skip recon, load existing `recon.json` |
| `--no-pdf` | — | Skip PDF generation |

### Tool management

| Flag | Description |
|---|---|
| `--tools` / `--list-tools` | List all tools and availability |
| `--add-tool <name>` | Register a new external tool |
| `--tool-phase recon\|scan\|both` | Phase the tool belongs to |
| `--tool-cmd "<template>"` | Command with `{target}` and `{out}` placeholders |
| `--tool-desc "<text>"` | Short description shown in `--list-tools` |
| `--remove-tool <name>` | Remove a previously registered custom tool |

---

## Examples

```bash
# Full pipeline
python bbhunter.py -u example.com

# Recon only, custom output dir
python bbhunter.py -u example.com --phase recon -o ./results

# Vuln scan using saved recon data
python bbhunter.py -u example.com --phase scan

# Regenerate report from saved data
python bbhunter.py -u example.com --phase report

# Skip PDF (text report only)
python bbhunter.py -u example.com --no-pdf

# Check which tools are installed
python bbhunter.py --tools
```

---

## Tool Registry

BBHunter has a built-in registry stored at `~/.bbhunter/tools.json`. You can extend it with any tool that has a CLI interface.

### Adding a tool

```bash
# Add amass for subdomain recon
python bbhunter.py --add-tool amass \
    --tool-phase recon \
    --tool-cmd "amass enum -d {target} -o {out}/amass.txt" \
    --tool-desc "Amass subdomain enumeration"

# Add nikto for web scanning
python bbhunter.py --add-tool nikto \
    --tool-phase scan \
    --tool-cmd "nikto -h {target} -output {out}/nikto.txt" \
    --tool-desc "Nikto web server scanner"

# Add a tool that runs in both phases
python bbhunter.py --add-tool myreconscanner \
    --tool-phase both \
    --tool-cmd "myreconscanner -t {target} -o {out}/myreconscanner.txt" \
    --tool-desc "Custom in-house scanner"
```

**Command template placeholders:**

| Placeholder | Replaced with |
|---|---|
| `{target}` | Bare hostname (e.g. `example.com`) |
| `{out}` | Full path to the run's output directory |

### Removing a tool

```bash
python bbhunter.py --remove-tool amass
```

### Listing tools

```bash
python bbhunter.py --list-tools
```

```
══════════════════════════════════════════════════════════════
  Tool Availability
──────────────────────────────────────────────────────────────
  Built-in tools:
    nmap               available   — Port & service scanner
    nuclei             available   — Template-based vuln scanner
    subfinder          not found   — Subdomain discovery
    ...

  Custom tools:
    amass              available   [recon]  — Amass subdomain enumeration
      cmd: amass enum -d {target} -o {out}/amass.txt
    nikto              available   [scan]   — Nikto web server scanner
      cmd: nikto -h {target} -output {out}/nikto.txt
```

---

## Output Structure

Each run creates a timestamped folder:

```
bbhunter_output/
└── example.com_20260427_143022/
    ├── report.pdf          ← Full PDF report
    ├── report.txt          ← Plain-text report
    ├── recon.json          ← All recon data (reloadable)
    ├── vulns.json          ← All vuln findings (reloadable)
    ├── dns.json            ← DNS records
    ├── subdomains.txt      ← Discovered subdomains
    ├── nmap.txt            ← Port scan results
    ├── http_recon.txt      ← HTTP headers & tech
    ├── urls.txt            ← Collected URLs
    ├── secrets.txt         ← Potential secrets
    ├── dirs.txt            ← Discovered directories
    ├── nuclei.json         ← Nuclei findings
    ├── gobuster.txt        ← Dir brute results
    └── custom_<tool>.txt   ← Output from each custom tool
```

---

## Built-in Tools

| Tool | Phase | Purpose | Install |
|---|---|---|---|
| `nmap` | Recon | Port & service scan | `apt install nmap` |
| `subfinder` | Recon | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | Recon | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `gau` | Recon | Passive URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `waybackurls` | Recon | Wayback Machine URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| `trufflehog` | Recon | Secret scanning | [trufflesecurity.com](https://github.com/trufflesecurity/trufflehog) |
| `gobuster` | Recon | Dir brute-force | `go install github.com/OJ/gobuster/v3@latest` |
| `ffuf` | Recon | Web fuzzer | `go install github.com/ffuf/ffuf/v2@latest` |
| `whatweb` | Recon | Tech fingerprint | `apt install whatweb` |
| `nuclei` | Scan | Template-based vulns | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

All tools are **optional** — BBHunter degrades gracefully with fallbacks if a tool is missing.

---

## PDF Report

The generated PDF includes:

- **Cover page** — target, date, tool branding
- **Executive Summary** — severity breakdown table (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Reconnaissance Summary** — IP, DNS, subdomains, headers, custom tool outputs
- **Port Scan Results** — full nmap output
- **Vulnerability Findings** — colour-coded badge per finding with URL and detail
- **Manual Testing Checklist** — 15+ targeted areas flagged for human review
- **Disclaimer** — scope and responsible use statement

---

## Docker Reference

```bash
# Build
docker build -t bbhunter .

# Full scan
docker run --rm -v $(pwd)/output:/output bbhunter -u example.com

# Recon only
docker run --rm -v $(pwd)/output:/output bbhunter -u example.com --phase recon

# Register a tool inside the container (persisted via named volume)
docker run --rm -v bbhunter-config:/root/.bbhunter bbhunter \
    --add-tool amass \
    --tool-phase recon \
    --tool-cmd "amass enum -d {target} -o {out}/amass.txt" \
    --tool-desc "Amass"

# List tools
docker run --rm bbhunter --list-tools

# Open a shell inside the container
docker run --rm -it --entrypoint bash bbhunter
```

---

## Python Dependencies

```
requests>=2.31.0
dnspython>=2.4.0
fpdf2>=2.7.6
urllib3>=2.0.0
```

Install: `pip install -r requirements.txt`

---

## Responsible Use

- Only test against systems you **own** or have **explicit written authorisation** to test
- Comply with the target's bug bounty programme scope and rules of engagement
- Never run against production systems without change-window approval
- All findings are **preliminary** — manual verification is required before reporting

---

## License

MIT — see `LICENSE`

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Commit your changes
4. Open a pull request
