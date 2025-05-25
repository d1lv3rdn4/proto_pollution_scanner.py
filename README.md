🧬 File Name: proto_pollution_scanner.py
📦 Requirements (install with pip):

pip install requests playwright jinja2
playwright install


🚀 What This Script Does:
Fuzzes API endpoints (/api, /v1, etc.) with known prototype pollution payloads.

Uses Playwright to open the site and checks if Object.prototype.polluted appears.

Confirms real pollution by checking inherited property visibility in JS context.

Auto-generates a color-coded HTML report with results.

🛡️ Real-World Use Case:
You can run this against:

Web apps with exposed API paths.

Targets found during recon (waybackurls, gau, etc.).

Your own apps to validate unsafe merges, lodash, jQuery merges.

_______________________________________________________________________________________________

🧬 File Name: pollution_beast.py

📦 Requirements (install with pip):

pip install requests playwright jinja2
playwright install

🛡️ What Makes It "Way More Advanced":
💉 Combines CVE payloads with general fuzzing.

🕸️ Scans all script tags and versions for vulnerable libs.

✅ Confirms real pollution with browser-based Object.prototype validation.

📄 Pretty HTML report with CVEs, payloads, detection, and runtime result.
✅ What This Adds:
Full written explanation of how the vulnerability works
Actual working PoC
Mitigation steps
CVE links

🔥 All in one file — no modules, no nonsense.


Console Output Example:

==🧠 Prototype Pollution CVE+Payload Scanner==
Enter target URL (e.g., https://example.com): https://vulnerable-app.com

[*] Fetching target homepage...
[+] Detected JS library: lodash 4.17.11 (VULNERABLE - CVE-2018-3721, CVE-2019-10744)
[+] Detected JS library: jquery 3.3.1 (VULNERABLE - CVE-2020-11022, CVE-2020-11023)

[*] Launching payload fuzzing on target endpoints...
[+] POST /api/ -> 200
[+] GET  /api/?__proto__=%7Bpolluted%3A%22true%22%7D -> 200
[+] POST /v1/ -> 404
[+] GET  /debug/?constructor.prototype.polluted=true -> 200
...

[*] Payload fuzzing complete.

[*] Launching browser to confirm runtime pollution...
[+] Found polluted property: polluted

[*] Runtime validation complete.

[+] HTML report written: pollution_report_4d2a1f.html

