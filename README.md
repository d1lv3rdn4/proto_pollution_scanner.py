🧬 File Name: proto_pollution_scanner.py
______________________________________________________
📦 Requirements (install with pip):

pip install requests playwright jinja2
playwright install

______________________________________________________
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
______________________________________________________
📦 Requirements (install with pip):

pip install requests playwright jinja2
playwright install
______________________________________________________
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

🔎 Advanced JS library detection (Lodash, jQuery, Underscore, Handlebars, Vue, etc.)

🌐 Dynamic endpoint discovery from JS parsing (not just static paths)

💉 Expanded and obfuscated prototype pollution payloads

🛡️ WAF and honeypot detection logic

📊 Enhanced colored output and runtime pollution confirmation

🔥 All in one file — no modules, no nonsense.

It includes:

🎨 colorama-based styled terminal output

📈 tqdm progress bar for fuzzing

🧠 AI-written summary in the HTML report

📋 Copyable curl buttons per payload

🔐 CVE severity labels with links

_______________________________________________________________________________________________

❌ What It Does Not Do (Yet)
Doesn’t brute-force hidden endpoints (use gau, ffuf, etc. for that)

Doesn’t try advanced chained exploits (yet)

Doesn’t log backend behavior (e.g., server logs, auth bypass unless it’s visible on frontend)

