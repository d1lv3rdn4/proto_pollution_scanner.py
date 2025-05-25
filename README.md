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
