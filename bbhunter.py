#!/usr/bin/env python3
"""
BBHunter - Bug Bounty Automation Tool
Usage: python bbhunter.py -u <target>
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

TOOLS_CONFIG_PATH = Path.home() / ".bbhunter" / "tools.json"

# ── Optional deps — install via: pip install requests dnspython fpdf2 ──────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    from fpdf import FPDF
    FPDF_OK = True
except ImportError:
    FPDF_OK = False

# ─── Colour helpers ────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):    print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"  {C.RED}[-]{C.RESET} {msg}")
def info(msg):  print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def head(msg):  print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}\n{C.BOLD}  {msg}{C.RESET}\n{'─'*60}")

def banner():
    print(f"""{C.BOLD}{C.RED}
  ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}  {C.YELLOW}Bug Bounty Automation Tool  |  Use only on authorised targets{C.RESET}
""")

# ─── Auto-installer ───────────────────────────────────────────────────────────
import platform
import shutil
import stat

# Install recipes per tool.
# Each entry is a list of strategies tried in order; first success wins.
_INSTALL_RECIPES = {
    "nmap": [
        {"apt": "nmap"},
        {"brew": "nmap"},
        {"script": "choco install nmap -y"},
    ],
    "nuclei": [
        {"go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
        {"github": {"repo": "projectdiscovery/nuclei", "binary": "nuclei"}},
    ],
    "subfinder": [
        {"go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        {"github": {"repo": "projectdiscovery/subfinder", "binary": "subfinder"}},
    ],
    "httpx": [
        {"go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
        {"github": {"repo": "projectdiscovery/httpx", "binary": "httpx"}},
    ],
    "gau": [
        {"go": "github.com/lc/gau/v2/cmd/gau@latest"},
        {"github": {"repo": "lc/gau", "binary": "gau"}},
    ],
    "waybackurls": [
        {"go": "github.com/tomnomnom/waybackurls@latest"},
        {"github": {"repo": "tomnomnom/waybackurls", "binary": "waybackurls"}},
    ],
    "trufflehog": [
        {"script": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"},
        {"go": "github.com/trufflesecurity/trufflehog/v3@latest"},
        {"github": {"repo": "trufflesecurity/trufflehog", "binary": "trufflehog"}},
    ],
    "gobuster": [
        {"go": "github.com/OJ/gobuster/v3@latest"},
        {"apt": "gobuster"},
        {"github": {"repo": "OJ/gobuster", "binary": "gobuster"}},
    ],
    "ffuf": [
        {"go": "github.com/ffuf/ffuf/v2@latest"},
        {"apt": "ffuf"},
        {"github": {"repo": "ffuf/ffuf", "binary": "ffuf"}},
    ],
    "whatweb": [
        {"apt": "whatweb"},
        {"brew": "whatweb"},
        {"script": "gem install whatweb"},
    ],
}

# Python packages needed at runtime
_PY_PACKAGES = {
    "requests": "requests",
    "dns":      "dnspython",
    "fpdf":     "fpdf2",
}


def _detect_os():
    s = platform.system().lower()
    if s == "linux":
        try:
            txt = Path("/etc/os-release").read_text().lower()
            if any(x in txt for x in ["ubuntu", "debian", "kali", "parrot"]):
                return "debian"
            if any(x in txt for x in ["fedora", "centos", "rhel", "amazon"]):
                return "redhat"
            if "arch" in txt:
                return "arch"
        except Exception:
            pass
        return "linux"
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return "unknown"


def _run_silent(cmd, sudo=False):
    if sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=600, errors="replace")
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", -1


def _go_available():
    return shutil.which("go") is not None


def _install_go():
    os_type = _detect_os()
    info("Go not found — attempting to install Go…")
    if os_type in ("debian", "linux"):
        _run_silent("apt-get update -qq && apt-get install -y golang-go", sudo=True)
    elif os_type == "redhat":
        _run_silent("dnf install -y golang || yum install -y golang", sudo=True)
    elif os_type == "arch":
        _run_silent("pacman -Sy --noconfirm go", sudo=True)
    elif os_type == "macos":
        _run_silent("brew install go")
    else:
        warn("Cannot auto-install Go on this OS. Install from https://go.dev/dl/")
        return False
    return _go_available()


def _ensure_gobin_on_path():
    gopath = os.environ.get("GOPATH", str(Path.home() / "go"))
    gobin  = str(Path(gopath) / "bin")
    if gobin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = gobin + os.pathsep + os.environ.get("PATH", "")


def _install_via_go(pkg):
    if not _go_available():
        if not _install_go():
            return False
    _ensure_gobin_on_path()
    _, rc = _run_silent(f"go install -v {pkg}")
    return rc == 0


def _install_via_apt(pkg):
    if not shutil.which("apt-get"):
        return False
    _run_silent("apt-get update -qq", sudo=True)
    _, rc = _run_silent(f"apt-get install -y {pkg}", sudo=True)
    return rc == 0


def _install_via_brew(pkg):
    if not shutil.which("brew"):
        return False
    _, rc = _run_silent(f"brew install {pkg}")
    return rc == 0


def _install_via_script(script):
    _, rc = _run_silent(script)
    return rc == 0


def _install_via_github(repo, binary):
    """Download the latest release binary from GitHub for the current platform."""
    try:
        import urllib.request, tarfile, zipfile, tempfile

        os_type = _detect_os()
        machine  = platform.machine().lower()
        goos     = {"debian":"linux","linux":"linux","redhat":"linux",
                    "arch":"linux","macos":"darwin","windows":"windows"}.get(os_type, "linux")
        goarch   = "amd64" if machine in ("x86_64","amd64") else \
                   "arm64"  if machine in ("aarch64","arm64") else "amd64"

        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(
            api_url,
            headers={"User-Agent": "BBHunter/1.0",
                     "Accept": "application/vnd.github+json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        chosen = None
        for asset in data.get("assets", []):
            name = asset["name"].lower()
            if goos in name and goarch in name and name.endswith((".tar.gz", ".zip")):
                chosen = asset
                break
        if not chosen:
            return False

        info(f"Downloading {chosen['name']} from GitHub…")
        with tempfile.TemporaryDirectory() as tmp:
            dl_path = Path(tmp) / chosen["name"]
            urllib.request.urlretrieve(chosen["browser_download_url"], dl_path)

            if chosen["name"].endswith(".tar.gz"):
                with tarfile.open(dl_path, "r:gz") as tf:
                    tf.extractall(tmp)
            else:
                with zipfile.ZipFile(dl_path) as zf:
                    zf.extractall(tmp)

            found = list(Path(tmp).rglob(binary)) or list(Path(tmp).rglob(f"{binary}.exe"))
            if not found:
                return False

            dest_dir = Path("/usr/local/bin")
            if not os.access(dest_dir, os.W_OK):
                dest_dir = Path.home() / ".local" / "bin"
                dest_dir.mkdir(parents=True, exist_ok=True)
                if str(dest_dir) not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = str(dest_dir) + os.pathsep + os.environ["PATH"]

            dest = dest_dir / found[0].name
            shutil.copy2(found[0], dest)
            dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            return True
    except Exception as e:
        warn(f"GitHub release install failed: {e}")
        return False


def install_tool(name):
    """Try every recipe for *name* until one succeeds. Return True if installed."""
    recipes = _INSTALL_RECIPES.get(name, [])
    if not recipes:
        warn(f"No install recipe for '{name}'")
        return False

    info(f"Installing '{name}'…")
    for strategy in recipes:
        try:
            if "go" in strategy:
                success = _install_via_go(strategy["go"])
            elif "apt" in strategy:
                success = _install_via_apt(strategy["apt"])
            elif "brew" in strategy:
                success = _install_via_brew(strategy["brew"])
            elif "script" in strategy:
                success = _install_via_script(strategy["script"])
            elif "github" in strategy:
                g = strategy["github"]
                success = _install_via_github(g["repo"], g["binary"])
            else:
                success = False

            if success and shutil.which(name):
                ok(f"'{name}' installed successfully")
                return True
        except Exception as e:
            warn(f"Strategy {list(strategy.keys())[0]} failed: {e}")
            continue

    err(f"All strategies failed for '{name}' — install it manually.")
    return False


def ensure_python_deps():
    """Install missing Python packages via pip without restarting."""
    missing = []
    for mod, pkg in _PY_PACKAGES.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    info(f"Installing missing Python packages: {', '.join(missing)}")
    _, rc = _run_silent(f"{sys.executable} -m pip install --quiet {' '.join(missing)}")
    if rc == 0:
        ok("Python packages installed — some features now active")
    else:
        warn("pip install failed — some features may be unavailable")


def auto_install_missing(skip=False):
    """Check every built-in tool; install any that are missing."""
    if skip:
        return
    missing = [name for name in _BUILTIN_TOOLS if not shutil.which(name)]
    if not missing:
        ok("All built-in tools already installed.")
        return

    head("Auto-Installer")
    warn(f"{len(missing)} tool(s) not found: {', '.join(missing)}")
    info("Attempting automatic installation…\n")

    for name in missing:
        install_tool(name)

    # Refresh nuclei templates after install
    if shutil.which("nuclei"):
        info("Updating nuclei templates…")
        _run_silent("nuclei -update-templates -silent")

    # Refresh the global TOOLS availability map
    global TOOLS
    TOOLS = {n: shutil.which(n) is not None for n in _BUILTIN_TOOLS}


# ─── Tool registry ────────────────────────────────────────────────────────────
# Built-in tools with their metadata.
# phase: "recon" | "scan" | "both"
# cmd_template: use {target} and {out} as placeholders; None = managed in code
_BUILTIN_TOOLS = {
    "nmap":        {"phase": "recon", "cmd_template": None,
                    "description": "Port & service scanner"},
    "nuclei":      {"phase": "scan",  "cmd_template": None,
                    "description": "Template-based vuln scanner"},
    "subfinder":   {"phase": "recon", "cmd_template": None,
                    "description": "Subdomain discovery"},
    "httpx":       {"phase": "recon", "cmd_template": None,
                    "description": "HTTP probe & fingerprint"},
    "gau":         {"phase": "recon", "cmd_template": None,
                    "description": "Get all URLs from passive sources"},
    "waybackurls": {"phase": "recon", "cmd_template": None,
                    "description": "Wayback Machine URL collector"},
    "trufflehog":  {"phase": "recon", "cmd_template": None,
                    "description": "Secret/credential scanner"},
    "gobuster":    {"phase": "recon", "cmd_template": None,
                    "description": "Directory & DNS brute-forcer"},
    "ffuf":        {"phase": "recon", "cmd_template": None,
                    "description": "Fast web fuzzer"},
    "whatweb":     {"phase": "recon", "cmd_template": None,
                    "description": "Web technology fingerprinter"},
}


class ToolRegistry:
    """Persists built-in + user-added tools in ~/.bbhunter/tools.json."""

    def __init__(self):
        self._path = TOOLS_CONFIG_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = self._load()
        # Seed built-ins if first run
        changed = False
        for name, meta in _BUILTIN_TOOLS.items():
            if name not in self._db:
                self._db[name] = {**meta, "builtin": True}
                changed = True
        if changed:
            self._save()

    # ── Persistence ───────────────────────────────────────────────────────────
    def _load(self):
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except Exception:
                return {}
        return {}

    def _save(self):
        self._path.write_text(json.dumps(self._db, indent=2))

    # ── CRUD ──────────────────────────────────────────────────────────────────
    def add(self, name, phase, cmd_template, description=""):
        """Register a new tool (or update an existing custom one)."""
        if name in self._db and self._db[name].get("builtin"):
            raise ValueError(f"'{name}' is a built-in tool and cannot be overwritten.")
        if phase not in ("recon", "scan", "both"):
            raise ValueError("phase must be one of: recon, scan, both")
        self._db[name] = {
            "phase": phase,
            "cmd_template": cmd_template,
            "description": description,
            "builtin": False,
        }
        self._save()

    def remove(self, name):
        if name not in self._db:
            raise KeyError(f"Tool '{name}' not found.")
        if self._db[name].get("builtin"):
            raise ValueError(f"'{name}' is a built-in tool and cannot be removed.")
        del self._db[name]
        self._save()

    def all_tools(self):
        return dict(self._db)

    def available(self):
        """Return {name: bool} — True if executable is on PATH."""
        return {name: shutil.which(name) is not None for name in self._db}

    def is_available(self, name):
        return shutil.which(name) is not None

    def get(self, name):
        return self._db.get(name)

    def custom_tools_for_phase(self, phase):
        """Return non-builtin tools whose phase matches."""
        return {
            name: meta for name, meta in self._db.items()
            if not meta.get("builtin")
            and (meta["phase"] == phase or meta["phase"] == "both")
        }


# Singleton — imported everywhere
REGISTRY = ToolRegistry()
TOOLS = REGISTRY.available()   # backward-compat dict used throughout


def _which(cmd):
    return shutil.which(cmd) is not None


def print_tool_status():
    head("Tool Availability")
    avail = REGISTRY.available()
    db    = REGISTRY.all_tools()
    builtin_names  = [n for n, m in db.items() if m.get("builtin")]
    custom_names   = [n for n, m in db.items() if not m.get("builtin")]

    print(f"  {C.BOLD}Built-in tools:{C.RESET}")
    for t in builtin_names:
        meta     = db[t]
        is_ok    = avail.get(t)
        flag     = f"{C.GREEN}available{C.RESET}"    if is_ok else f"{C.YELLOW}not found{C.RESET}"
        auto_tag = f"  {C.CYAN}[auto-install]{C.RESET}" if (not is_ok and t in _INSTALL_RECIPES) else ""
        print(f"    {t:18} {flag}{auto_tag}  — {meta.get('description','')}")

    if custom_names:
        print(f"\n  {C.BOLD}Custom tools:{C.RESET}")
        for t in custom_names:
            meta = db[t]
            flag = f"{C.GREEN}available{C.RESET}" if avail.get(t) else f"{C.YELLOW}not found{C.RESET}"
            phase_tag = f"[{meta['phase']}]"
            print(f"    {t:18} {flag}  {phase_tag:8} — {meta.get('description','')}")
            if meta.get("cmd_template"):
                print(f"    {'':18}   cmd: {meta['cmd_template']}")
    else:
        print(f"\n  {C.CYAN}[*]{C.RESET} No custom tools registered yet.")
        print(f"      Add one: python bbhunter.py --add-tool <name> --tool-phase recon "
              f"--tool-cmd \"<name> {{target}} -o {{out}}\" --tool-desc \"My tool\"")

    needed_py = []
    if not REQUESTS_OK: needed_py.append("requests")
    if not DNS_OK:      needed_py.append("dnspython")
    if not FPDF_OK:     needed_py.append("fpdf2")
    if needed_py:
        warn(f"Missing Python packages: {', '.join(needed_py)}")
        warn(f"Install: pip install {' '.join(needed_py)}")

    print(f"\n  {C.CYAN}[*]{C.RESET} Config: {TOOLS_CONFIG_PATH}")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def run(cmd, timeout=300):
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        warn(f"Command timed out: {cmd[:80]}")
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1

def sanitise_domain(target):
    """Strip scheme/path, return bare hostname."""
    if "://" not in target:
        target = "https://" + target
    return urlparse(target).hostname or target

def write_file(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", errors="replace") as f:
        f.write(content)

def read_file(path):
    if not Path(path).exists():
        return ""
    with open(path, "r", errors="replace") as f:
        return f.read()


def run_custom_tools(phase, target, out_dir):
    """Execute all registered custom tools for the given phase, save output."""
    custom = REGISTRY.custom_tools_for_phase(phase)
    results = {}
    if not custom:
        return results
    head(f"Custom Tools · Phase: {phase}")
    for name, meta in custom.items():
        if not REGISTRY.is_available(name):
            warn(f"Custom tool '{name}' not found on PATH — skipping")
            continue
        tmpl = meta.get("cmd_template") or ""
        if not tmpl:
            warn(f"Custom tool '{name}' has no cmd_template — skipping")
            continue
        cmd = tmpl.replace("{target}", str(target)).replace("{out}", str(out_dir))
        out_file = Path(out_dir) / f"custom_{name}.txt"
        # Append output redirect if the template doesn't already contain one
        if "{out}" not in tmpl:
            cmd = f"{cmd} 2>&1 | tee {out_file}"
        info(f"Running custom tool: {name}")
        info(f"  cmd: {cmd[:100]}")
        stdout, stderr, rc = run(cmd, timeout=300)
        if rc == 0:
            ok(f"'{name}' completed successfully")
        else:
            warn(f"'{name}' exited with code {rc}")
        # Save raw output if tee wasn't used
        if not out_file.exists():
            write_file(out_file, stdout + ("\n" + stderr if stderr else ""))
        results[name] = read_file(out_file)
        ok(f"Output saved: {out_file}")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — RECON
# ══════════════════════════════════════════════════════════════════════════════
class ReconEngine:
    def __init__(self, target, out_dir, options):
        self.target  = sanitise_domain(target)
        self.raw_url = target
        self.out     = Path(out_dir)
        self.opts    = options
        self.results = {}   # key → list[str]

    # ── 1.1 DNS & subdomains ─────────────────────────────────────────────────
    def dns_enum(self):
        head("Phase 1 · DNS Enumeration")
        domain = self.target
        records = {}

        if DNS_OK:
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                    records[rtype] = [str(r) for r in answers]
                    if records[rtype]:
                        ok(f"{rtype:6} → {', '.join(records[rtype][:3])}")
                except Exception:
                    pass
        else:
            # Fallback: host command
            stdout, _, _ = run(f"host {domain}")
            records["raw"] = stdout.splitlines()

        # IP resolution
        try:
            ip = socket.gethostbyname(domain)
            ok(f"Resolved: {domain} → {ip}")
            records["ip"] = [ip]
        except Exception:
            err(f"Could not resolve {domain}")

        content = json.dumps(records, indent=2)
        write_file(self.out / "dns.json", content)
        self.results["dns"] = records
        return records

    # ── 1.2 Subdomain discovery ───────────────────────────────────────────────
    def subdomain_enum(self):
        head("Phase 1 · Subdomain Enumeration")
        subs = set()

        # subfinder
        if TOOLS["subfinder"]:
            stdout, _, _ = run(f"subfinder -d {self.target} -silent -timeout 30", timeout=120)
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    subs.add(line)
            ok(f"subfinder found {len(subs)} subdomains")
        else:
            warn("subfinder not available; using DNS brute (short list)")
            wordlist = ["www","mail","ftp","admin","api","dev","test","staging",
                        "beta","app","portal","vpn","remote","cdn","static"]
            for word in wordlist:
                sub = f"{word}.{self.target}"
                try:
                    socket.gethostbyname(sub)
                    subs.add(sub)
                    ok(f"Found: {sub}")
                except Exception:
                    pass

        sub_list = sorted(subs)
        write_file(self.out / "subdomains.txt", "\n".join(sub_list))
        self.results["subdomains"] = sub_list
        info(f"Total subdomains: {len(sub_list)}")
        return sub_list

    # ── 1.3 Port scanning ─────────────────────────────────────────────────────
    def port_scan(self):
        head("Phase 1 · Port Scanning")
        domain = self.target

        if TOOLS["nmap"]:
            cmd = (
                f"nmap -sV -sC -T4 --open -p 21,22,23,25,53,80,110,143,443,"
                f"445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,"
                f"8888,9200,27017 {domain} -oN {self.out}/nmap.txt"
            )
            info("Running nmap (this may take a minute)…")
            stdout, stderr, rc = run(cmd, timeout=300)
            raw = read_file(self.out / "nmap.txt") or stdout
        else:
            warn("nmap not found; performing basic TCP connect scan")
            common_ports = [21,22,23,25,53,80,110,143,443,445,993,995,
                            1433,3306,3389,5432,6379,8080,8443,27017]
            open_ports = []
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = domain
            for port in common_ports:
                try:
                    s = socket.socket()
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                        ok(f"Open: {port}/tcp")
                    s.close()
                except Exception:
                    pass
            raw = f"Open ports on {domain}:\n" + "\n".join(str(p) for p in open_ports)
            write_file(self.out / "nmap.txt", raw)

        self.results["ports"] = raw
        return raw

    # ── 1.4 HTTP headers & tech fingerprint ───────────────────────────────────
    def http_recon(self):
        head("Phase 1 · HTTP Recon & Tech Fingerprint")
        findings = []
        scheme = "https"
        url = f"{scheme}://{self.target}"

        if REQUESTS_OK:
            for u in [f"https://{self.target}", f"http://{self.target}"]:
                try:
                    r = requests.get(u, timeout=10, verify=False,
                                     allow_redirects=True,
                                     headers={"User-Agent": "BBHunter/1.0"})
                    ok(f"{u} → {r.status_code}")
                    interesting = ["server","x-powered-by","x-aspnet-version",
                                   "x-frame-options","strict-transport-security",
                                   "content-security-policy","x-content-type-options",
                                   "access-control-allow-origin","set-cookie"]
                    for h in interesting:
                        if h in [k.lower() for k in r.headers]:
                            val = r.headers.get(h, "")
                            findings.append(f"{h}: {val}")
                            ok(f"  {h}: {val[:80]}")
                    break
                except Exception as e:
                    warn(f"HTTP request failed for {u}: {e}")

        # whatweb fingerprint
        if TOOLS["whatweb"]:
            stdout, _, _ = run(f"whatweb -a 3 {url}", timeout=60)
            for line in stdout.splitlines():
                findings.append(line)
                ok(line[:120])

        write_file(self.out / "http_recon.txt", "\n".join(findings))
        self.results["http"] = findings
        return findings

    # ── 1.5 Secret / credentials hunting ─────────────────────────────────────
    def secret_scan(self):
        head("Phase 1 · Secret & Credential Hunt")
        secrets = []

        # Collect URLs via gau/waybackurls
        url_file = self.out / "urls.txt"
        if TOOLS["gau"]:
            stdout, _, _ = run(f"gau --subs {self.target}", timeout=120)
            write_file(url_file, stdout)
            info(f"gau collected {len(stdout.splitlines())} URLs")
        elif TOOLS["waybackurls"]:
            stdout, _, _ = run(f"echo {self.target} | waybackurls", timeout=120)
            write_file(url_file, stdout)
            info(f"waybackurls collected {len(stdout.splitlines())} URLs")
        else:
            warn("Neither gau nor waybackurls available")

        # trufflehog on collected URLs / git
        if TOOLS["trufflehog"]:
            out_secrets = self.out / "secrets.json"
            stdout, _, _ = run(
                f"trufflehog filesystem {self.out} --json --no-update 2>/dev/null",
                timeout=120
            )
            write_file(out_secrets, stdout)
            for line in stdout.splitlines():
                try:
                    obj = json.loads(line)
                    det = obj.get("DetectorName","?")
                    raw = obj.get("Raw","")[:60]
                    secrets.append(f"[{det}] {raw}")
                    warn(f"SECRET: [{det}] {raw}")
                except Exception:
                    pass
        else:
            warn("trufflehog not available; skipping secret scan")

        # Regex scan on collected URLs for obvious leaks
        patterns = {
            "AWS Key":       r"AKIA[0-9A-Z]{16}",
            "GCP Key":       r"AIza[0-9A-Za-z\-_]{35}",
            "API Token":     r"['\"]?(api[_-]?key|token|secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
            "JWT":           r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
            "Private Key":   r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            "Password":      r"password\s*[:=]\s*['\"]?[^\s'\"]{6,}",
            "DB Connection": r"(mysql|postgres|mongodb|redis):\/\/[^@\s]+@",
        }
        urls_text = read_file(url_file)
        for name, pat in patterns.items():
            matches = re.findall(pat, urls_text, re.IGNORECASE)
            if matches:
                m = matches[0]
                snippet = m if isinstance(m, str) else str(m)[:60]
                secrets.append(f"[REGEX:{name}] {snippet}")
                warn(f"Possible {name}: {snippet}")

        write_file(self.out / "secrets.txt", "\n".join(secrets))
        self.results["secrets"] = secrets
        return secrets

    # ── 1.6 Directory bruteforce ──────────────────────────────────────────────
    def dir_brute(self):
        head("Phase 1 · Directory Brute-force")
        url = f"https://{self.target}"
        found = []

        if TOOLS["gobuster"]:
            wl = "/usr/share/wordlists/dirb/common.txt"
            if not Path(wl).exists():
                wl = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
            if Path(wl).exists():
                cmd = (f"gobuster dir -u {url} -w {wl} -t 30 -q "
                       f"-o {self.out}/gobuster.txt 2>/dev/null")
                run(cmd, timeout=180)
                content = read_file(self.out / "gobuster.txt")
                found = [l for l in content.splitlines() if l.startswith("/")]
                ok(f"gobuster found {len(found)} paths")
            else:
                warn("No wordlist found for gobuster")
        elif TOOLS["ffuf"]:
            wl = "/usr/share/wordlists/dirb/common.txt"
            if Path(wl).exists():
                cmd = (f"ffuf -u {url}/FUZZ -w {wl} -mc 200,301,302,403 "
                       f"-o {self.out}/ffuf.json -of json -s 2>/dev/null")
                run(cmd, timeout=180)
                raw = read_file(self.out / "ffuf.json")
                try:
                    data = json.loads(raw)
                    for r in data.get("results", []):
                        found.append(r.get("url",""))
                    ok(f"ffuf found {len(found)} paths")
                except Exception:
                    pass
        else:
            warn("Neither gobuster nor ffuf available; trying common paths")
            common = ["/admin","/login","/dashboard","/config","/backup",
                      "/.git","/api","/swagger","/graphql","/.env","/wp-admin"]
            if REQUESTS_OK:
                for path in common:
                    try:
                        r = requests.get(f"{url}{path}", timeout=5, verify=False,
                                         headers={"User-Agent":"BBHunter/1.0"})
                        if r.status_code not in [404, 429]:
                            found.append(f"{path} [{r.status_code}]")
                            ok(f"Found: {path} [{r.status_code}]")
                    except Exception:
                        pass

        write_file(self.out / "dirs.txt", "\n".join(found))
        self.results["dirs"] = found
        return found

    # ── Run all recon ─────────────────────────────────────────────────────────
    def run_all(self):
        self.dns_enum()
        self.subdomain_enum()
        self.port_scan()
        self.http_recon()
        self.secret_scan()
        self.dir_brute()
        custom_out = run_custom_tools("recon", self.target, self.out)
        if custom_out:
            self.results["custom_recon"] = custom_out
        ok("Recon phase complete.")
        return self.results


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — VULNERABILITY SCANNING
# ══════════════════════════════════════════════════════════════════════════════
class VulnScanner:
    def __init__(self, target, out_dir, recon_results, options):
        self.target  = sanitise_domain(target)
        self.out     = Path(out_dir)
        self.recon   = recon_results
        self.opts    = options
        self.vulns   = []   # list of dicts: {severity, title, url, detail}

    def _add(self, severity, title, url, detail=""):
        self.vulns.append({"severity": severity, "title": title,
                           "url": url, "detail": detail})

    # ── 2.1 Nuclei ────────────────────────────────────────────────────────────
    def nuclei_scan(self):
        head("Phase 2 · Nuclei Scan")
        if not TOOLS["nuclei"]:
            warn("nuclei not installed; skipping")
            return

        targets_file = self.out / "nuclei_targets.txt"
        targets = [f"https://{self.target}"]
        for sub in self.recon.get("subdomains", [])[:20]:
            targets.append(f"https://{sub}")
        write_file(targets_file, "\n".join(targets))

        nuclei_out = self.out / "nuclei.json"
        cmd = (
            f"nuclei -l {targets_file} "
            f"-severity low,medium,high,critical "
            f"-json -o {nuclei_out} "
            f"-silent -timeout 10 -retries 1 2>/dev/null"
        )
        info(f"Running nuclei against {len(targets)} targets…")
        run(cmd, timeout=600)

        raw = read_file(nuclei_out)
        count = 0
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                sev   = obj.get("info", {}).get("severity", "info")
                title = obj.get("info", {}).get("name", "Unknown")
                url   = obj.get("matched-at", "")
                desc  = obj.get("info", {}).get("description", "")
                self._add(sev.upper(), title, url, desc)
                count += 1
                sym = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]"}.get(sev.upper(),"[i]")
                warn(f"{sym} {sev.upper()}: {title} @ {url}")
            except Exception:
                pass
        ok(f"Nuclei found {count} findings")

    # ── 2.2 Header & misconfig checks ─────────────────────────────────────────
    def header_checks(self):
        head("Phase 2 · Security Header Analysis")
        if not REQUESTS_OK:
            warn("requests not available; skipping header checks")
            return

        url = f"https://{self.target}"
        try:
            r = requests.get(url, timeout=10, verify=False,
                             headers={"User-Agent":"BBHunter/1.0"})
        except Exception as e:
            err(f"Cannot reach {url}: {e}")
            return

        headers = {k.lower(): v for k, v in r.headers.items()}

        # Missing security headers
        required = {
            "strict-transport-security": "Missing HSTS",
            "x-frame-options":           "Missing X-Frame-Options (Clickjacking risk)",
            "x-content-type-options":    "Missing X-Content-Type-Options",
            "content-security-policy":   "Missing Content-Security-Policy",
            "x-xss-protection":         "Missing X-XSS-Protection",
            "referrer-policy":           "Missing Referrer-Policy",
            "permissions-policy":        "Missing Permissions-Policy",
        }
        for hdr, msg in required.items():
            if hdr not in headers:
                self._add("MEDIUM", msg, url, f"Header '{hdr}' not present")
                warn(msg)
            else:
                ok(f"Present: {hdr}")

        # Dangerous info disclosure
        if "server" in headers:
            val = headers["server"]
            self._add("LOW", f"Server header discloses version: {val}", url,
                      "Attacker gains technology fingerprint")
            warn(f"Server disclosure: {val}")

        if "x-powered-by" in headers:
            val = headers["x-powered-by"]
            self._add("LOW", f"X-Powered-By discloses: {val}", url)
            warn(f"X-Powered-By disclosure: {val}")

        # CORS misconfig
        try:
            rc = requests.get(url, timeout=10, verify=False,
                              headers={"Origin": "https://evil.com",
                                       "User-Agent":"BBHunter/1.0"})
            acao = rc.headers.get("Access-Control-Allow-Origin","")
            if acao == "*" or acao == "https://evil.com":
                self._add("HIGH", "CORS Misconfiguration", url,
                          f"Access-Control-Allow-Origin: {acao}")
                warn(f"CORS issue: ACAO={acao}")
        except Exception:
            pass

    # ── 2.3 SSL/TLS checks ────────────────────────────────────────────────────
    def ssl_checks(self):
        head("Phase 2 · SSL/TLS Analysis")
        import ssl, socket as _socket

        try:
            ctx = ssl.create_default_context()
            with _socket.create_connection((self.target, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    ok(f"TLS version: {proto}")

                    # Expiry
                    expire_str = cert.get("notAfter","")
                    if expire_str:
                        from datetime import timezone
                        expire = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire - datetime.utcnow()).days
                        if days_left < 30:
                            self._add("HIGH", f"SSL certificate expires in {days_left} days",
                                      self.target, expire_str)
                            warn(f"Certificate expiring in {days_left} days!")
                        else:
                            ok(f"Certificate valid for {days_left} more days")

                    # Weak proto flag
                    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self._add("HIGH", f"Weak TLS version in use: {proto}",
                                  self.target)
                        warn(f"Weak protocol: {proto}")
        except ssl.SSLError as e:
            self._add("HIGH", f"SSL Error: {e}", self.target)
            err(f"SSL Error: {e}")
        except Exception as e:
            warn(f"SSL check skipped: {e}")

    # ── 2.4 Open redirect / XSS probe (passive) ───────────────────────────────
    def open_redirect_xss(self):
        head("Phase 2 · Open Redirect & XSS Probes")
        if not REQUESTS_OK:
            warn("requests not available")
            return

        url = f"https://{self.target}"
        payloads_redirect = [
            "//evil.com", "https://evil.com", "//evil.com/%2F..",
        ]
        xss_payloads = [
            "<script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

        # Check common redirect params
        redirect_params = ["url","redirect","next","dest","destination","return","returnUrl"]
        for param in redirect_params:
            for pay in payloads_redirect:
                test_url = f"{url}?{param}={pay}"
                try:
                    r = requests.get(test_url, timeout=5, verify=False,
                                     allow_redirects=False,
                                     headers={"User-Agent":"BBHunter/1.0"})
                    loc = r.headers.get("Location","")
                    if "evil.com" in loc:
                        self._add("HIGH", "Open Redirect", test_url,
                                  f"Redirects to: {loc}")
                        warn(f"Open Redirect: {test_url} → {loc}")
                except Exception:
                    pass

        # Reflected XSS (basic)
        xss_marker = "XSSTEST12345"
        for param in ["q","search","query","s","input","term"]:
            try:
                r = requests.get(f"{url}?{param}={xss_marker}", timeout=5,
                                 verify=False,
                                 headers={"User-Agent":"BBHunter/1.0"})
                if xss_marker in r.text:
                    self._add("MEDIUM", "Possible Reflected XSS (input reflected)",
                              f"{url}?{param}=…",
                              f"Parameter '{param}' reflected without encoding")
                    warn(f"Input reflected in response for param '{param}' — possible XSS")
            except Exception:
                pass

    # ── 2.5 Sensitive file exposure ───────────────────────────────────────────
    def sensitive_files(self):
        head("Phase 2 · Sensitive File Exposure")
        if not REQUESTS_OK:
            return
        url = f"https://{self.target}"
        files = [
            ".env", ".git/config", ".git/HEAD", "config.php",
            "wp-config.php", "database.yml", "settings.py",
            ".htpasswd", ".htaccess", "backup.zip", "backup.sql",
            "debug.log", "error.log", "phpinfo.php", "info.php",
            "Dockerfile", "docker-compose.yml", ".travis.yml",
            "package.json", "composer.json", "Gemfile",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "security.txt", ".well-known/security.txt",
            "api/swagger.json", "swagger.yaml", "openapi.json",
            "graphql", "graphiql",
        ]
        found = []
        for f in files:
            try:
                r = requests.get(f"{url}/{f}", timeout=5, verify=False,
                                 headers={"User-Agent":"BBHunter/1.0"})
                if r.status_code in [200, 206]:
                    detail = r.text[:200].replace("\n"," ")
                    sev = "CRITICAL" if f in [".env","wp-config.php","database.yml",
                                              ".htpasswd","backup.zip","backup.sql"] \
                          else "HIGH" if f in [".git/config",".git/HEAD","phpinfo.php"] \
                          else "MEDIUM"
                    self._add(sev, f"Sensitive file exposed: /{f}",
                              f"{url}/{f}", detail)
                    warn(f"[{sev}] /{f} accessible (HTTP {r.status_code})")
                    found.append(f)
            except Exception:
                pass
        if not found:
            ok("No obvious sensitive files exposed")

    # ── 2.6 Default credentials (passive check) ───────────────────────────────
    def default_creds_check(self):
        head("Phase 2 · Default Credentials Check")
        if not REQUESTS_OK:
            return
        targets = {
            "/admin":        [("admin","admin"),("admin","password"),("admin","")],
            "/wp-login.php": [("admin","admin"),("admin","password")],
            "/manager/html": [("tomcat","tomcat"),("admin","admin")],
            "/:8161/admin":  [("admin","admin")],
        }
        url_base = f"https://{self.target}"
        for path, creds in targets.items():
            try:
                r = requests.get(f"{url_base}{path}", timeout=5, verify=False,
                                 headers={"User-Agent":"BBHunter/1.0"})
                if r.status_code == 200 and ("password" in r.text.lower()
                                              or "login" in r.text.lower()):
                    for user, pwd in creds:
                        try:
                            rp = requests.post(
                                f"{url_base}{path}",
                                data={"username":user,"password":pwd,
                                      "user_login":user,"user_pass":pwd},
                                timeout=5, verify=False, allow_redirects=True,
                                headers={"User-Agent":"BBHunter/1.0"}
                            )
                            if rp.status_code in [200, 302]:
                                if any(k in rp.text.lower() for k in
                                       ["dashboard","welcome","logout","sign out"]):
                                    self._add("CRITICAL",
                                              f"Default credentials work: {user}:{pwd}",
                                              f"{url_base}{path}")
                                    warn(f"DEFAULT CREDS: {user}:{pwd} @ {path}")
                        except Exception:
                            pass
            except Exception:
                pass

    # ── Run all scans ─────────────────────────────────────────────────────────
    def run_all(self):
        self.nuclei_scan()
        self.header_checks()
        self.ssl_checks()
        self.open_redirect_xss()
        self.sensitive_files()
        self.default_creds_check()
        custom_out = run_custom_tools("scan", self.target, self.out)
        for name, output in custom_out.items():
            self._add("INFO", f"Custom tool output: {name}",
                      self.target, output[:300])
        ok(f"Vuln scan complete — {len(self.vulns)} findings")
        return self.vulns


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — PDF REPORT
# ══════════════════════════════════════════════════════════════════════════════
SEV_COLOR = {
    "CRITICAL": (180, 0, 0),
    "HIGH":     (220, 60, 0),
    "MEDIUM":   (240, 160, 0),
    "LOW":      (50, 130, 220),
    "INFO":     (80, 80, 80),
}

class ReportGenerator:
    def __init__(self, target, out_dir, recon, vulns):
        self.target = target
        self.out    = Path(out_dir)
        self.recon  = recon
        self.vulns  = vulns
        self.ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Text report (always generated) ───────────────────────────────────────
    def text_report(self):
        lines = []
        lines.append("=" * 70)
        lines.append("  BBHUNTER — BUG BOUNTY REPORT")
        lines.append(f"  Target : {self.target}")
        lines.append(f"  Date   : {self.ts}")
        lines.append("=" * 70)

        lines.append("\n[EXECUTIVE SUMMARY]")
        sev_counts = {}
        for v in self.vulns:
            sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if s in sev_counts:
                lines.append(f"  {s:10}: {sev_counts[s]}")

        lines.append("\n[RECON SUMMARY]")
        dns = self.recon.get("dns", {})
        if dns.get("ip"):
            lines.append(f"  IP Address : {', '.join(dns['ip'])}")
        subs = self.recon.get("subdomains", [])
        lines.append(f"  Subdomains : {len(subs)} discovered")
        dirs = self.recon.get("dirs", [])
        lines.append(f"  Directories: {len(dirs)} found")
        secrets = self.recon.get("secrets", [])
        lines.append(f"  Secrets    : {len(secrets)} potential findings")

        lines.append("\n[PORT SCAN]")
        ports_raw = self.recon.get("ports", "")
        for l in ports_raw.splitlines()[:30]:
            lines.append(f"  {l}")

        lines.append("\n[VULNERABILITIES]")
        for v in sorted(self.vulns, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"]) if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 5):
            lines.append(f"\n  [{v['severity']}] {v['title']}")
            lines.append(f"    URL   : {v['url']}")
            if v["detail"]:
                lines.append(f"    Detail: {v['detail'][:120]}")

        lines.append("\n[AREAS REQUIRING FURTHER INVESTIGATION]")
        manual = self._manual_checks()
        for item in manual:
            lines.append(f"  • {item}")

        lines.append("\n" + "=" * 70)
        lines.append("  End of Report — BBHunter")
        lines.append("=" * 70)

        txt = "\n".join(lines)
        report_path = self.out / "report.txt"
        write_file(report_path, txt)
        ok(f"Text report saved: {report_path}")
        return txt

    # ── PDF report ────────────────────────────────────────────────────────────
    def pdf_report(self):
        if not FPDF_OK:
            warn("fpdf2 not installed; PDF skipped. Install: pip install fpdf2")
            return None

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # ── Cover page ──────────────────────────────────────────────────────
        pdf.add_page()
        pdf.set_fill_color(20, 20, 40)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_font("Helvetica", "B", 32)
        pdf.set_text_color(255, 80, 80)
        pdf.set_y(60)
        pdf.cell(0, 15, "BBHunter", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 16)
        pdf.set_text_color(200, 200, 200)
        pdf.cell(0, 10, "Bug Bounty Reconnaissance & Vulnerability Report",
                 align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(130)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(255, 200, 0)
        pdf.cell(0, 10, f"Target: {self.target}",
                 align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(180, 180, 180)
        pdf.cell(0, 8, f"Report Date: {self.ts}",
                 align="C", new_x="LMARGIN", new_y="NEXT")

        # ── Severity summary ────────────────────────────────────────────────
        pdf.add_page()
        self._pdf_section_header(pdf, "Executive Summary")

        sev_counts = {}
        for v in self.vulns:
            sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1

        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(0, 0, 0)
        total = len(self.vulns)
        pdf.multi_cell(0, 7,
            f"BBHunter completed automated reconnaissance and vulnerability scanning "
            f"of {self.target} on {self.ts}. A total of {total} potential "
            f"security findings were identified across the target infrastructure.",
            new_x="LMARGIN", new_y="NEXT"
        )
        pdf.ln(4)

        # Severity table
        self._pdf_table_header(pdf, ["Severity", "Count", "Risk Level"])
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            count = sev_counts.get(sev, 0)
            risk = {"CRITICAL":"Immediate action","HIGH":"Fix urgently",
                    "MEDIUM":"Plan remediation","LOW":"Review",
                    "INFO":"Informational"}.get(sev,"")
            r, g, b = SEV_COLOR.get(sev, (80,80,80))
            self._pdf_table_row(pdf, [sev, str(count), risk], (r, g, b))

        # ── Recon summary ───────────────────────────────────────────────────
        pdf.add_page()
        self._pdf_section_header(pdf, "Phase 1 · Reconnaissance Summary")

        dns = self.recon.get("dns", {})
        subs = self.recon.get("subdomains", [])
        dirs = self.recon.get("dirs", [])
        secrets = self.recon.get("secrets", [])
        http_info = self.recon.get("http", [])

        self._pdf_kv_table(pdf, [
            ("IP Address(es)", ", ".join(dns.get("ip", []) or ["N/A"])),
            ("DNS Records",    ", ".join(f"{k}:{','.join(v[:2])}"
                                         for k, v in dns.items() if k != "ip")[:100]),
            ("Subdomains",     f"{len(subs)} discovered"),
            ("Directories",    f"{len(dirs)} found"),
            ("Potential Secrets", f"{len(secrets)} findings"),
        ])

        if subs:
            pdf.ln(4)
            self._pdf_subsection(pdf, "Discovered Subdomains (top 20)")
            for s in subs[:20]:
                pdf.set_font("Courier", "", 9)
                pdf.set_text_color(40, 40, 40)
                pdf.cell(0, 5, f"  • {s}", new_x="LMARGIN", new_y="NEXT")

        if http_info:
            pdf.ln(4)
            self._pdf_subsection(pdf, "HTTP Headers & Technology")
            for h in http_info[:15]:
                pdf.set_font("Courier", "", 9)
                pdf.set_text_color(40, 40, 40)
                pdf.multi_cell(0, 5, f"  {h[:100]}", new_x="LMARGIN", new_y="NEXT")

        # Custom recon tool outputs
        custom_recon = self.recon.get("custom_recon", {})
        if custom_recon:
            pdf.add_page()
            self._pdf_section_header(pdf, "Custom Recon Tool Results")
            for tool_name, output in custom_recon.items():
                self._pdf_subsection(pdf, tool_name)
                pdf.set_font("Courier", "", 8)
                pdf.set_text_color(30, 30, 30)
                for line in str(output).splitlines()[:40]:
                    pdf.cell(0, 4, line[:120], new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)

        # Port scan
        pdf.add_page()
        self._pdf_section_header(pdf, "Port Scan Results")
        ports_text = self.recon.get("ports","")
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(30, 30, 30)
        for line in ports_text.splitlines()[:60]:
            pdf.cell(0, 4, line[:120], new_x="LMARGIN", new_y="NEXT")

        # ── Vulnerabilities ─────────────────────────────────────────────────
        pdf.add_page()
        self._pdf_section_header(pdf, "Phase 2 · Vulnerability Findings")

        sorted_vulns = sorted(
            self.vulns,
            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(
                x["severity"]) if x["severity"] in
                ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 5
        )

        for i, v in enumerate(sorted_vulns, 1):
            r, g, b = SEV_COLOR.get(v["severity"], (80, 80, 80))
            # Severity badge
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(22, 6, v["severity"], fill=True,
                     new_x="RIGHT", new_y="LAST")
            # Title
            pdf.set_fill_color(245, 245, 245)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"  {i:02d}. {v['title'][:80]}", fill=True,
                     new_x="LMARGIN", new_y="NEXT")
            # URL + detail
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(0, 5, f"      URL: {v['url'][:100]}",
                           new_x="LMARGIN", new_y="NEXT")
            if v["detail"]:
                pdf.multi_cell(0, 5, f"      {v['detail'][:150]}",
                               new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        # ── Manual testing recommendations ─────────────────────────────────
        pdf.add_page()
        self._pdf_section_header(pdf, "Areas Requiring Manual Investigation")

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6,
            "The following areas were flagged by automated scanning as high-value "
            "targets for manual security testing. Automated tools cannot fully verify "
            "these findings — skilled manual review is required.",
            new_x="LMARGIN", new_y="NEXT"
        )
        pdf.ln(4)

        manual = self._manual_checks()
        for item in manual:
            self._pdf_bullet(pdf, item)

        # ── Disclaimer ──────────────────────────────────────────────────────
        pdf.add_page()
        self._pdf_section_header(pdf, "Disclaimer & Scope")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 6,
            "This report was generated by BBHunter, an automated bug bounty "
            "reconnaissance and scanning tool. All findings are preliminary and "
            "require manual verification before being treated as confirmed "
            "vulnerabilities.\n\n"
            "This tool must only be used against systems for which you have "
            "explicit written authorisation. Unauthorised use against third-party "
            "systems may be illegal and is strictly prohibited.\n\n"
            "False positives are expected. Treat all CRITICAL/HIGH findings as "
            "priority review items, then triage MEDIUM/LOW accordingly.",
            new_x="LMARGIN", new_y="NEXT"
        )

        # ── Save ─────────────────────────────────────────────────────────────
        pdf_path = self.out / "report.pdf"
        pdf.output(str(pdf_path))
        ok(f"PDF report saved : {pdf_path}")
        return pdf_path

    # ── PDF helpers ───────────────────────────────────────────────────────────
    def _pdf_section_header(self, pdf, title):
        pdf.set_fill_color(30, 30, 60)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, f"  {title}", fill=True,
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_text_color(0, 0, 0)

    def _pdf_subsection(self, pdf, title):
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(30, 30, 100)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    def _pdf_table_header(self, pdf, cols):
        pdf.set_fill_color(60, 60, 100)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        widths = [50, 30, 110]
        for i, col in enumerate(cols):
            pdf.cell(widths[i], 8, col, border=1, fill=True,
                     new_x="RIGHT", new_y="LAST")
        pdf.ln()

    def _pdf_table_row(self, pdf, cols, color=(40,40,40)):
        pdf.set_text_color(*color)
        pdf.set_font("Helvetica", "B" if color[0] > 100 else "", 10)
        pdf.set_fill_color(248, 248, 248)
        widths = [50, 30, 110]
        for i, col in enumerate(cols):
            pdf.cell(widths[i], 7, col, border=1, fill=True,
                     new_x="RIGHT", new_y="LAST")
        pdf.ln()
        pdf.set_text_color(0, 0, 0)

    def _pdf_kv_table(self, pdf, rows):
        pdf.set_font("Helvetica", "B", 10)
        for k, v in rows:
            pdf.set_fill_color(230, 230, 240)
            pdf.cell(55, 7, k, border=1, fill=True,
                     new_x="RIGHT", new_y="LAST")
            pdf.set_font("Helvetica", "", 10)
            pdf.set_fill_color(255, 255, 255)
            pdf.cell(0, 7, str(v)[:100], border=1, fill=True,
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 10)

    def _pdf_bullet(self, pdf, text):
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(0, 6, f"  •  {text}",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    # ── Manual check recommendations ─────────────────────────────────────────
    def _manual_checks(self):
        checks = [
            "Authentication & Session Management: test for brute-force, weak tokens, session fixation, and concurrent session flaws",
            "Business Logic: map all workflows and attempt to bypass steps, escalate privileges, or replay actions",
            "SQL Injection: manually test all input fields and API parameters with error-based and time-based payloads",
            "XSS (Stored & DOM): inject payloads into persistent storage fields and trace JavaScript sinks",
            "IDOR / Broken Object Level Authorisation: iterate IDs in API calls to access other users' resources",
            "SSRF: probe URL/import/webhook parameters for internal network access",
            "XXE: test XML endpoints with external entity payloads",
            "Race Conditions: test payment, coupon, and rate-limit endpoints under concurrent load",
            "Subdomain Takeover: verify unclaimed CNAME targets from subdomain list",
            "OAuth / SSO Flaws: test redirect_uri, state parameter, implicit flow, and token leakage",
            "API Keys & Secrets: manually review JS files, mobile apps, and public repos for leaked credentials",
            "File Upload: test for unrestricted file upload leading to RCE or stored XSS",
            "Insecure Deserialisation: probe serialised objects in cookies/parameters",
            "Password Reset Flaws: test token predictability, host-header injection, and response manipulation",
            "GraphQL: introspect schema, test for batching attacks, excessive permissions",
        ]
        # Append context-specific checks based on findings
        if any("git" in str(v.get("url","")).lower() for v in self.vulns):
            checks.append("Git Exposure: dump .git directory contents for source code and secrets")
        if any("admin" in str(v.get("url","")).lower() for v in self.vulns):
            checks.append("Admin Panel: perform targeted brute-force and privilege escalation testing")
        if self.recon.get("secrets"):
            checks.append("Validate all detected secrets/tokens — rotate confirmed live credentials immediately")
        return checks

    def run_all(self):
        txt = self.text_report()
        pdf = self.pdf_report()
        return txt, pdf


# ══════════════════════════════════════════════════════════════════════════════
# CLI Entry point
# ══════════════════════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        prog="bbhunter",
        description="BBHunter — Bug Bounty Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan examples:
  python bbhunter.py -u example.com
  python bbhunter.py -u https://example.com -o ./results --skip-recon
  python bbhunter.py -u example.com --phase recon
  python bbhunter.py -u example.com --phase scan
  python bbhunter.py -u example.com --no-pdf

Tool management examples:
  python bbhunter.py --tools                          # list all tools
  python bbhunter.py --add-tool amass \\
      --tool-phase recon \\
      --tool-cmd "amass enum -d {target} -o {out}/amass.txt" \\
      --tool-desc "Amass subdomain enumeration"
  python bbhunter.py --add-tool nikto \\
      --tool-phase scan \\
      --tool-cmd "nikto -h {target} -output {out}/nikto.txt" \\
      --tool-desc "Nikto web server scanner"
  python bbhunter.py --remove-tool amass
  python bbhunter.py --list-tools

Placeholders in --tool-cmd:
  {target}  replaced with the bare hostname
  {out}     replaced with the run output directory

Phases:
  all     Run full pipeline: recon → scan → report  (default)
  recon   Reconnaissance only
  scan    Vuln scan only (loads saved recon data)
  report  Generate PDF from saved recon + scan data

⚠  Use only on systems you are authorised to test.
"""
    )

    # ── Scan options ──────────────────────────────────────────────────────────
    scan = p.add_argument_group("Scan options")
    scan.add_argument("-u", "--url", help="Target URL or domain")
    scan.add_argument("-o", "--output", default="./bbhunter_output",
                      help="Output directory (default: ./bbhunter_output)")
    scan.add_argument("--phase", choices=["all", "recon", "scan", "report"],
                      default="all", help="Which phase to run")
    scan.add_argument("--skip-recon", action="store_true",
                      help="Skip recon, load saved recon.json")
    scan.add_argument("--no-pdf", action="store_true",
                      help="Skip PDF generation")
    scan.add_argument("--no-install", action="store_true",
                      help="Skip auto-installation of missing tools")

    # ── Tool management ───────────────────────────────────────────────────────
    tm = p.add_argument_group("Tool management")
    tm.add_argument("--tools", action="store_true",
                    help="Show all tool availability and exit")
    tm.add_argument("--list-tools", action="store_true",
                    help="Alias for --tools")
    tm.add_argument("--add-tool", metavar="NAME",
                    help="Register a new external tool by name")
    tm.add_argument("--tool-phase", choices=["recon", "scan", "both"],
                    default="recon",
                    help="Phase the tool belongs to (default: recon)")
    tm.add_argument("--tool-cmd", metavar="TEMPLATE",
                    help="Command template. Use {target} and {out} as placeholders")
    tm.add_argument("--tool-desc", metavar="TEXT", default="",
                    help="Short description of the tool")
    tm.add_argument("--remove-tool", metavar="NAME",
                    help="Remove a previously registered custom tool")

    return p.parse_args()


def _handle_tool_management(args):
    """Returns True if a tool-management action was performed (no scan needed)."""

    if args.tools or args.list_tools:
        ensure_python_deps()
        print_tool_status()
        return True

    if args.add_tool:
        name = args.add_tool.strip()
        if not args.tool_cmd:
            err("--tool-cmd is required when using --add-tool")
            err('Example: --tool-cmd "amass enum -d {target} -o {out}/amass.txt"')
            sys.exit(1)
        try:
            REGISTRY.add(name, args.tool_phase, args.tool_cmd, args.tool_desc)
            ok(f"Tool '{name}' registered successfully.")
            ok(f"  Phase   : {args.tool_phase}")
            ok(f"  Command : {args.tool_cmd}")
            ok(f"  Desc    : {args.tool_desc or '(none)'}")
            ok(f"  Config  : {TOOLS_CONFIG_PATH}")
            # Live availability check
            if REGISTRY.is_available(name):
                ok(f"  Status  : found on PATH — will run automatically")
            else:
                warn(f"  Status  : '{name}' not found on PATH yet — install it first")
        except ValueError as e:
            err(str(e))
            sys.exit(1)
        return True

    if args.remove_tool:
        name = args.remove_tool.strip()
        try:
            REGISTRY.remove(name)
            ok(f"Tool '{name}' removed from registry.")
            ok(f"Config: {TOOLS_CONFIG_PATH}")
        except (KeyError, ValueError) as e:
            err(str(e))
            sys.exit(1)
        return True

    return False


def main():
    banner()
    args = parse_args()

    # Tool-management commands don't need -u
    if _handle_tool_management(args):
        sys.exit(0)

    if not args.url:
        err("-u / --url is required for scanning.")
        err("Run with --help for usage.")
        sys.exit(1)

    # ── Bootstrap: Python deps first, then external tools ────────────────────
    ensure_python_deps()
    auto_install_missing(skip=getattr(args, "no_install", False))

    target = args.url
    domain = sanitise_domain(target)
    ts_safe = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) / f"{domain}_{ts_safe}"
    out_dir.mkdir(parents=True, exist_ok=True)

    info(f"Target     : {domain}")
    info(f"Output dir : {out_dir}")
    info(f"Phase      : {args.phase}")
    print_tool_status()

    recon_path = out_dir / "recon.json"
    vulns_path = out_dir / "vulns.json"

    recon_results = {}
    vulns = []

    # ── Phase 1: Recon ────────────────────────────────────────────────────────
    if args.phase in ("all", "recon") and not args.skip_recon:
        engine = ReconEngine(target, out_dir, args)
        recon_results = engine.run_all()
        write_file(recon_path, json.dumps(recon_results, indent=2))
        ok(f"Recon data saved: {recon_path}")
    elif recon_path.exists():
        recon_results = json.loads(read_file(recon_path))
        info("Loaded saved recon data")

    # ── Phase 2: Vulnerability Scan ───────────────────────────────────────────
    if args.phase in ("all", "scan"):
        scanner = VulnScanner(target, out_dir, recon_results, args)
        vulns = scanner.run_all()
        write_file(vulns_path, json.dumps(vulns, indent=2))
        ok(f"Vuln data saved : {vulns_path}")
    elif vulns_path.exists():
        vulns = json.loads(read_file(vulns_path))
        info("Loaded saved vuln data")

    # ── Phase 3: Report ───────────────────────────────────────────────────────
    if args.phase in ("all", "report"):
        reporter = ReportGenerator(domain, out_dir, recon_results, vulns)
        reporter.text_report()
        if not args.no_pdf:
            reporter.pdf_report()
        else:
            warn("PDF generation skipped (--no-pdf)")

    head("Run Complete")
    ok(f"All output saved to: {out_dir}")
    sev_counts = {}
    for v in vulns:
        sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if s in sev_counts:
            print(f"  {C.BOLD}{s:10}{C.RESET}: {sev_counts[s]}")
    print()


if __name__ == "__main__":
    main()
