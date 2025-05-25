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
