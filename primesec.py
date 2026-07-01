import platform
import os
import sys
import re
import json
import ssl
import socket
import shutil
import subprocess
import threading
import itertools
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse


REQUIRED_PACKAGES = [
    ("python-nmap", "nmap"),
    ("python-whois", "whois"),
    ("requests", "requests"),
    ("beautifulsoup4", "bs4"),
    ("colorama", "colorama"),
    ("psutil", "psutil"),
    ("dnspython", "dns"),
]

def install_all_missing(packages):
    missing = []
    for package_name, import_name in packages:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)

    if not missing:
        return

    print(f"[!] Missing dependencies: {', '.join(missing)}. Installing all now...")
    try:
        cmd = [sys.executable, "-m", "pip", "install", "-q"] + missing
        if platform.system() == "Linux":
            cmd.append("--break-system-packages")
        subprocess.check_call(cmd)
        print("[+] All dependencies installed. Please re-run PrimeSec.")
        sys.exit(0)
    except Exception as e:
        print(f"[x] Failed to install dependencies: {e}")
        sys.exit(1)

install_all_missing(REQUIRED_PACKAGES)

import nmap
import whois
import requests
import urllib3
import psutil
import dns.resolver
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init

try:
    import distro
except ImportError:
    distro = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama_init(autoreset=True)

R, C, W, G, Y, M = Fore.RED, Fore.CYAN, Fore.WHITE, Fore.GREEN, Fore.YELLOW, Fore.MAGENTA
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PrimeSec/2.0; +https://github.com/PrimeSec)"}

VERSION = "2.0"
AUTHOR = "john.root"
RESULTS_DIR = os.path.join(os.getcwd(), "primesec_results")


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def divider(char="─", length=60, color=Y):
    print(f"{color}{char * length}")


def banner_line(text, color=W):
    print(f"{color}{text}")


def get_size(size_bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if size_bytes < factor:
            return f"{size_bytes:.2f}{unit}{suffix}"
        size_bytes /= factor
    return f"{size_bytes:.2f}P{suffix}"


def get_uptime():
    try:
        return str(timedelta(seconds=int(time.time() - psutil.boot_time())))
    except Exception:
        return "Unknown"


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_binary(name, install_hint=None):
    if shutil.which(name) is None:
        print(f"{R}[!] '{name}' not found in PATH.")
        print(f"{Y}[*] {install_hint or f'Install {name} and add it to PATH.'}")
        return False
    return True


class Spinner:
    def __init__(self, message="Working"):
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def _spin(self):
        for ch in itertools.cycle("|/-\\"):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r{C}[*] {self.message}... {ch}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 15) + "\r")

    def __enter__(self):
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join()


class ResultLogger:
    def __init__(self, module, target):
        self.module = module
        self.target = target
        self.lines = []
        self.data = {}

    def add(self, line):
        self.lines.append(line)

    def set_data(self, data):
        self.data = data

    def save(self):
        os.makedirs(RESULTS_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.target or "unknown")
        base = f"{safe_target}_{self.module}_{ts}"

        txt_path = os.path.join(RESULTS_DIR, base + ".txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines))

        json_path = None
        if self.data:
            json_path = os.path.join(RESULTS_DIR, base + ".json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, default=str)

        print(f"\n{G}[+] Results saved -> {txt_path}")
        if json_path:
            print(f"{G}[+] Structured data -> {json_path}")


def pause():
    input(f"\n{Y}Press Enter to return...")


def perform_whois():
    clear_screen()
    section_header("WHOIS LOOKUP")
    target = input(f"{Y}Enter Domain: {W}").strip()
    if not target:
        return

    log = ResultLogger("whois", target)
    try:
        with Spinner(f"Querying WHOIS for {target}"):
            results = whois.whois(target)

        def fmt(d):
            if isinstance(d, list):
                d = d[0] if d else None
            return d.strftime("%Y-%m-%d") if hasattr(d, "strftime") else (d or "N/A")

        fields = {
            "Registrar": results.registrar,
            "Organization": results.org,
            "Creation Date": fmt(results.creation_date),
            "Expiration Date": fmt(results.expiration_date),
            "Updated Date": fmt(results.updated_date),
            "Name Servers": ", ".join(results.name_servers) if isinstance(results.name_servers, list) else results.name_servers,
            "Status": ", ".join(results.status) if isinstance(results.status, list) else results.status,
            "Emails": ", ".join(results.emails) if isinstance(results.emails, list) else results.emails,
        }

        print(f"\n{G}[+] ANALYSIS COMPLETE:")
        divider()
        for k, v in fields.items():
            print(f"{C}{k + ':':<18}{W}{v}")
            log.add(f"{k}: {v}")
        log.set_data(fields)
        log.save()
    except Exception as e:
        print(f"{R}[!] Could not retrieve WHOIS data: {e}")
    pause()


def dns_lookup():
    clear_screen()
    section_header("DNS RECORD ENUMERATION")
    target = input(f"{Y}Enter Domain: {W}").strip()
    if not target:
        return

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    log = ResultLogger("dns", target)
    data = {}

    print()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            values = [str(r).strip() for r in answers]
            data[rtype] = values
            print(f"{C}{rtype:<8}{W}" + f"\n{'':8}".join(values))
            log.add(f"{rtype}: {', '.join(values)}")
        except Exception:
            continue

    if not data:
        print(f"{R}[!] No DNS records resolved for {target}.")
    else:
        log.set_data(data)
        log.save()
    pause()


def ssl_inspect():
    clear_screen()
    section_header("SSL / TLS CERTIFICATE INSPECTOR")
    target = input(f"{Y}Enter Domain (no https://): {W}").strip()
    if not target:
        return
    port_in = input(f"{Y}Port [443]: {W}").strip()
    port = int(port_in) if port_in.isdigit() else 443

    log = ResultLogger("ssl", target)
    try:
        with Spinner(f"Fetching certificate for {target}:{port}"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        info = {
            "Common Name": subject.get("commonName", "N/A"),
            "Issuer": issuer.get("commonName", "N/A"),
            "Valid From": cert.get("notBefore", "N/A"),
            "Valid Until": cert.get("notAfter", "N/A"),
            "TLS Version": tls_version,
            "Cipher Suite": cipher[0] if cipher else "N/A",
            "Subject Alt Names": ", ".join(san) if san else "N/A",
        }

        print(f"\n{G}[+] CERTIFICATE DETAILS:")
        divider()
        for k, v in info.items():
            print(f"{C}{k + ':':<20}{W}{v}")
            log.add(f"{k}: {v}")
        log.set_data(info)
        log.save()
    except Exception as e:
        print(f"{R}[!] SSL inspection failed: {e}")
    pause()


def nmap_scan_menu():
    clear_screen()
    section_header("NMAP PORT SCANNER")
    if not check_binary("nmap", "sudo apt install nmap  (Linux)  |  nmap.org  (Windows)"):
        pause()
        return

    print(f"{W}[1] Quick Scan         (Top 100 ports, -F)")
    print(f"{W}[2] Comprehensive Scan (-A -v)   {R}*Needs Root*")
    print(f"{W}[3] Stealth Scan       (SYN)     {R}*Needs Root*")
    print(f"{W}[4] Full Port Sweep    (-p-)")
    print(f"{W}[5] Return")

    choice = input(f"\n{Y}Select Option > {W}")
    if choice == "5" or choice not in ("1", "2", "3", "4"):
        return

    if choice in ("2", "3") and os.name != "nt" and os.geteuid() != 0:
        print(f"\n{R}[!] This scan type requires root privileges.")
        print(f"{Y}[*] Hint: sudo python3 primesec.py")
        pause()
        return

    target = input(f"{Y}Enter Target IP/Domain: {W}").strip()
    if not target:
        return

    args_map = {"1": "-F", "2": "-A -v", "3": "-sS", "4": "-p-"}
    args = args_map[choice]
    log = ResultLogger("nmap", target)
    data = {"target": target, "args": args, "hosts": []}

    try:
        nm = nmap.PortScanner()
        with Spinner(f"Scanning {target} ({args})"):
            nm.scan(hosts=target, arguments=args)

        if not nm.all_hosts():
            print(f"{R}[!] No hosts responded.")
            pause()
            return

        for host in nm.all_hosts():
            host_entry = {"host": host, "hostname": nm[host].hostname(), "state": nm[host].state(), "ports": []}
            print(f"\n{G}● {W}Host  : {C}{host} ({nm[host].hostname()})")
            state_color = G if nm[host].state() == "up" else R
            print(f"{G}● {W}Status: {state_color}{nm[host].state().upper()}")
            log.add(f"Host: {host} ({nm[host].hostname()}) - {nm[host].state()}")

            for proto in nm[host].all_protocols():
                print(f"\n{Y}{'PORT':<10}{'STATE':<10}{'SERVICE':<15}VERSION")
                divider()
                for port in sorted(nm[host][proto].keys()):
                    p = nm[host][proto][port]
                    version = f"{p.get('product','')} {p.get('version','')}".strip()
                    print(f"{W}{str(port):<10}{p['state']:<10}{p['name']:<15}{version}")
                    log.add(f"  {proto}/{port} {p['state']} {p['name']} {version}")
                    host_entry["ports"].append({"port": port, "proto": proto, **p})
            data["hosts"].append(host_entry)

        log.set_data(data)
        log.save()
    except Exception as e:
        print(f"{R}[!] Scan Error: {e}")
    pause()


def run_subfinder():
    clear_screen()
    section_header("SUBFINDER — SUBDOMAIN ENUMERATION")
    if not check_binary("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"):
        pause()
        return

    target = input(f"{Y}Enter Target Domain: {W}").strip()
    if not target:
        return

    log = ResultLogger("subfinder", target)
    try:
        with Spinner(f"Enumerating subdomains for {target}"):
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent"],
                capture_output=True, text=True, timeout=120
            )
        subdomains = sorted(set(l.strip() for l in result.stdout.splitlines() if l.strip()))
        if subdomains:
            print(f"{G}[+] Found {len(subdomains)} subdomain(s):\n")
            for sub in subdomains:
                print(f"  {W}↳ {C}{sub}")
                log.add(sub)
            log.set_data({"subdomains": subdomains})
            log.save()
        else:
            print(f"{R}[!] No subdomains found.")
        if result.stderr.strip():
            print(f"\n{R}[!] {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        print(f"{R}[!] Subfinder timed out (2 min).")
    except Exception as e:
        print(f"{R}[!] Error: {e}")
    pause()


def run_amass():
    clear_screen()
    section_header("AMASS — DEEP ASSET DISCOVERY")
    if not check_binary("amass", "go install -v github.com/owasp-amass/amass/v4/...@master"):
        pause()
        return

    print(f"{W}[1] Passive Enum  (amass enum -passive)")
    print(f"{W}[2] Active Enum   (amass enum -active)  {R}*Slower*")
    print(f"{W}[3] Return")
    choice = input(f"\n{Y}Select Option > {W}")
    if choice == "3" or choice not in ("1", "2"):
        return

    target = input(f"{Y}Enter Target Domain: {W}").strip()
    if not target:
        return

    flag = "-passive" if choice == "1" else "-active"
    log = ResultLogger("amass", target)
    try:
        with Spinner(f"Running Amass ({flag}) on {target}"):
            result = subprocess.run(
                ["amass", "enum", flag, "-d", target],
                capture_output=True, text=True, timeout=300
            )
        lines = sorted(set(l.strip() for l in result.stdout.splitlines() if l.strip()))
        if lines:
            print(f"{G}[+] {len(lines)} result(s):\n")
            for line in lines:
                print(f"  {W}↳ {C}{line}")
                log.add(line)
            log.set_data({"assets": lines})
            log.save()
        else:
            print(f"{R}[!] No results returned.")
    except subprocess.TimeoutExpired:
        print(f"{R}[!] Amass timed out (5 min limit).")
    except Exception as e:
        print(f"{R}[!] Error: {e}")
    pause()


def run_httpx():
    clear_screen()
    section_header("HTTPX — LIVE HOST PROBING")
    if not check_binary("httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"):
        pause()
        return

    print(f"{W}[1] Probe single domain")
    print(f"{W}[2] Probe from file  (one host per line)")
    print(f"{W}[3] Return")
    choice = input(f"\n{Y}Select Option > {W}")
    if choice == "3" or choice not in ("1", "2"):
        return

    if choice == "1":
        target = input(f"{Y}Enter Domain/IP: {W}").strip()
        if not target:
            return
        cmd = ["httpx", "-u", target, "-title", "-status-code", "-tech-detect", "-silent"]
        log_target = target
    else:
        filepath = input(f"{Y}Path to host list file: {W}").strip()
        if not filepath or not os.path.isfile(filepath):
            print(f"{R}[!] File not found: {filepath}")
            pause()
            return
        cmd = ["httpx", "-l", filepath, "-title", "-status-code", "-tech-detect", "-silent"]
        log_target = os.path.basename(filepath)

    log = ResultLogger("httpx", log_target)
    try:
        with Spinner("Probing hosts with HTTPX"):
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if lines:
            for line in lines:
                print(f"  {W}{line}")
                log.add(line)
            print(f"\n{G}[+] {len(lines)} live host(s) found.")
            log.set_data({"live_hosts": lines})
            log.save()
        else:
            print(f"{R}[!] No live hosts found.")
    except subprocess.TimeoutExpired:
        print(f"{R}[!] HTTPX timed out (2 min).")
    except Exception as e:
        print(f"{R}[!] Error: {e}")
    pause()


def robots_sitemap_crawl():
    clear_screen()
    section_header("ROBOTS.TXT / SITEMAP CRAWLER")
    target = input(f"{Y}Enter URL (e.g. https://example.com): {W}").strip()
    if not target:
        return
    if not target.startswith("http"):
        target = "https://" + target
    base = target.rstrip("/")

    log = ResultLogger("robots_sitemap", urlparse(base).netloc)
    findings = {"disallowed_paths": [], "sitemaps": [], "sitemap_urls": []}

    try:
        with Spinner("Fetching robots.txt"):
            r = requests.get(f"{base}/robots.txt", headers=HEADERS, timeout=10, verify=False)
        if r.status_code == 200:
            print(f"{G}[+] robots.txt found:\n")
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                print(f"  {W}{line}")
                log.add(line)
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        findings["disallowed_paths"].append(path)
                if line.lower().startswith("sitemap:"):
                    findings["sitemaps"].append(line.split(":", 1)[1].strip())
        else:
            print(f"{R}[!] No robots.txt (status {r.status_code}).")
    except Exception as e:
        print(f"{R}[!] Could not fetch robots.txt: {e}")

    sitemap_candidates = findings["sitemaps"] or [f"{base}/sitemap.xml"]
    for sm_url in sitemap_candidates:
        try:
            with Spinner(f"Fetching sitemap {sm_url}"):
                r = requests.get(sm_url, headers=HEADERS, timeout=10, verify=False)
            if r.status_code == 200 and "<" in r.text:
                urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                if urls:
                    print(f"\n{G}[+] {len(urls)} URL(s) in {sm_url}:")
                    for u in urls[:50]:
                        print(f"  {W}↳ {C}{u}")
                        log.add(u)
                    if len(urls) > 50:
                        print(f"  {R}… {len(urls) - 50} more (see saved file)")
                        log.add(f"... {len(urls) - 50} more")
                    findings["sitemap_urls"].extend(urls)
        except Exception:
            continue

    if findings["disallowed_paths"] or findings["sitemap_urls"]:
        log.set_data(findings)
        log.save()
    pause()


JS_PATTERNS = {
    "Endpoints":  r'(?:url|endpoint|path|api|route)\s*[=:]\s*["\']([/][^"\'<>\s]{3,})',
    "API Keys":   r'(?i)(?:api[_\-]?key|apikey|access[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})',
    "AWS Keys":   r'((?:AKIA|ASIA)[A-Z0-9]{16})',
    "Secrets":    r'(?i)(?:secret|token|password|passwd|pwd)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})',
    "S3 Buckets": r'([\w.\-]+\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com)',
    "Emails":     r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
    "IPs":        r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b',
    "Subdomains": r'https?://([a-zA-Z0-9][\w\-]*(?:\.[\w\-]+){1,})',
}


def _collect_js_urls(page_url):
    resp = requests.get(page_url, headers=HEADERS, timeout=15, verify=False)
    soup = BeautifulSoup(resp.text, "html.parser")
    parsed = urlparse(page_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    js_urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("//"):
            js_urls.append(f"{parsed.scheme}:{src}")
        elif src.startswith("/"):
            js_urls.append(f"{base_origin}{src}")
        else:
            js_urls.append(f"{page_url.rstrip('/')}/{src}")
    return list(dict.fromkeys(js_urls))


def _analyze_js(content):
    findings = {}
    for label, pattern in JS_PATTERNS.items():
        matches = list(dict.fromkeys(re.findall(pattern, content)))
        if matches:
            findings[label] = matches
    return findings


def js_recon():
    clear_screen()
    section_header("JS RECON — SECRET & ENDPOINT HUNTER")
    print(f"{W}[1] Auto-discover JS files from a page URL")
    print(f"{W}[2] Analyze a direct JS file URL")
    print(f"{W}[3] Return")
    choice = input(f"\n{Y}Select Option > {W}")
    if choice == "3" or choice not in ("1", "2"):
        return

    target = input(f"{Y}Enter URL (e.g. https://example.com): {W}").strip()
    if not target:
        return
    if not target.startswith("http"):
        target = "https://" + target

    js_urls = []
    try:
        if choice == "1":
            with Spinner(f"Crawling {target} for JS files"):
                js_urls = _collect_js_urls(target)
            if js_urls:
                print(f"{G}[+] Found {len(js_urls)} JS file(s):")
                for u in js_urls:
                    print(f"  {W}↳ {u}")
            else:
                print(f"{R}[!] No external JS files found on that page.")
        else:
            js_urls = [target]
    except Exception as e:
        print(f"{R}[!] Failed to reach target: {e}")
        pause()
        return

    if not js_urls:
        pause()
        return

    print(f"\n{C}[*] Analyzing {len(js_urls)} file(s)...")
    divider()

    log = ResultLogger("js_recon", urlparse(target).netloc)
    all_findings = {}
    total = 0
    for js_url in js_urls:
        try:
            r = requests.get(js_url, headers=HEADERS, timeout=15, verify=False)
            findings = _analyze_js(r.text)
            if findings:
                print(f"\n{G}[+] {js_url}")
                log.add(f"\n[{js_url}]")
                all_findings[js_url] = findings
                for label, matches in findings.items():
                    print(f"  {Y}{label}:")
                    log.add(f"  {label}:")
                    for m in matches[:10]:
                        print(f"    {W}→ {m}")
                        log.add(f"    -> {m}")
                    if len(matches) > 10:
                        print(f"    {R}    … {len(matches) - 10} more")
                    total += len(matches)
            else:
                print(f"\n{R}[-] {js_url}  —  no findings")
        except Exception as e:
            print(f"{R}[!] Could not fetch {js_url}: {e}")

    print(f"\n{G}[+] Total findings: {total}")
    if all_findings:
        log.set_data(all_findings)
        log.save()
    pause()


def banner_grab():
    clear_screen()
    section_header("TCP BANNER GRABBER")
    target = input(f"{Y}Enter Target IP/Domain: {W}").strip()
    if not target:
        return
    ports_in = input(f"{Y}Ports (comma-separated) [21,22,25,80,443,3306]: {W}").strip()
    ports = [int(p) for p in ports_in.split(",") if p.strip().isdigit()] or [21, 22, 25, 80, 443, 3306]

    log = ResultLogger("banner_grab", target)
    data = {}
    print()
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                try:
                    s.sendall(b"\r\n")
                except Exception:
                    pass
                banner = s.recv(256).decode(errors="ignore").strip()
                if banner:
                    print(f"{G}[+] {target}:{port:<6}{W}{banner}")
                    log.add(f"{port}: {banner}")
                    data[str(port)] = banner
                else:
                    print(f"{Y}[~] {target}:{port:<6}{W}open, no banner")
                    log.add(f"{port}: open (no banner)")
                    data[str(port)] = "open (no banner)"
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"{R}[-] {target}:{port:<6}{W}closed/filtered")
    if data:
        log.set_data(data)
        log.save()
    pause()


def section_header(title):
    print(f"{R}--- PrimeSec :: {title} ---\n")


def draw_fetch():
    uname = platform.uname()
    host_name = socket.gethostname()
    kernel = uname.release
    try:
        user = os.getlogin()
    except OSError:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"

    if platform.system() == "Linux":
        os_name = distro.name(pretty=True) if distro else "Linux"
        shell = os.environ.get("SHELL", "Unknown").split("/")[-1]
    else:
        os_name = f"{platform.system()} {platform.release()}"
        shell = "PowerShell"

    svmem = psutil.virtual_memory()
    ram_usage = f"{get_size(svmem.used)} / {get_size(svmem.total)}"
    ip_addr = get_ip()

    logo = [
        f"{R} ██████╗ ██████╗ ██╗███╗   ███╗███████╗███████╗███████╗ ██████╗",
        f"{R} ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝██╔════╝██╔════╝██╔════╝",
        f"{R} ██████╔╝██████╔╝██║██╔████╔██║█████╗  ███████╗█████╗  ██║     ",
        f"{R} ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══╝  ██║     ",
        f"{R} ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗███████║███████╗╚██████╗",
        f"{R} ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝",
        f"{W}              v{VERSION}  —  Recon & OSINT Toolkit  —  by {AUTHOR}",
    ]
    clear_screen()
    print()
    for line in logo:
        print(line)
    print()

    spacer = "  "
    print(f"{spacer}{C}USER    {W}: {user}@{host_name}")
    print(f"{spacer}{C}OS      {W}: {os_name}")
    print(f"{spacer}{C}KERNEL  {W}: {kernel}")
    print(f"{spacer}{C}UPTIME  {W}: {get_uptime()}")
    print(f"{spacer}{C}SHELL   {W}: {shell}")
    print(f"{spacer}{C}RAM     {W}: {ram_usage}")
    print(f"{spacer}{C}IP      {W}: {ip_addr}")
    print(f"{spacer}{C}RESULTS {W}: {RESULTS_DIR}")
    print(f"\n{spacer}{R}███{Fore.GREEN}███{Y}███{Fore.BLUE}███{M}███{C}███{W}███\n")


MENU = [
    ("1", "WHOIS", perform_whois),
    ("2", "DNS Records", dns_lookup),
    ("3", "Nmap Scan", nmap_scan_menu),
    ("4", "Subfinder", run_subfinder),
    ("5", "Amass", run_amass),
    ("6", "HTTPX Probe", run_httpx),
    ("7", "SSL/TLS Inspect", ssl_inspect),
    ("8", "Robots/Sitemap", robots_sitemap_crawl),
    ("9", "JS Recon", js_recon),
    ("10", "Banner Grab", banner_grab),
    ("11", "Refresh", None),
    ("12", "Exit", None),
]


def print_menu():
    cols = 3
    for i in range(0, len(MENU), cols):
        row = MENU[i:i + cols]
        line = "  ".join(f"{C}[{k}]{W} {name:<16}" for k, name, _ in row)
        print(f"  {line}")
    print()


def main():
    while True:
        try:
            draw_fetch()
            print_menu()
            cmd = input(f"{Y}PrimeSec > {W}").strip()

            if cmd == "11":
                continue
            if cmd == "12":
                print(f"{C}[*] Exiting PrimeSec. Stay sharp, {AUTHOR}.")
                sys.exit()

            action = next((fn for k, _, fn in MENU if k == cmd and fn), None)
            if action:
                action()
            else:
                print(f"{R}[!] Invalid option.")
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{C}[*] Interrupted. Exiting PrimeSec.")
            sys.exit()


if __name__ == "__main__":
    main()
