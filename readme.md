# odooPen — Advanced Odoo Penetration Testing Framework

Advanced Odoo Penetration Testing Framework (odooPen) is a comprehensive, interactive tool to perform reconnaissance, vulnerability scanning, authentication testing, and post‑exploitation assessments against Odoo instances. This project is intended for security professionals, red teamers, and administrators who need to evaluate the security posture of Odoo deployments.

Version: 2.0  
Author: Enhanced Security Framework (ELMERIKH repository)

> WARNING: This tool performs intrusive security testing against Odoo servers (including database enumeration, password guessing and potential exploitation checks). Only run this against systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

## Key Features

- Interactive CLI with colored output and detailed logging
- Web interface reconnaissance (title, headers, exposed endpoints)
- XML-RPC connectivity checks and resilient transport with configurable timeouts and SSL handling
- Database enumeration and tests for exposed database operations
- Odoo version detection using XML-RPC and static file/header analysis
- Vulnerability database mapping per Odoo major version
- Master password discovery heuristics (config file checks, environment disclosure, backups)
- Multi-technique user enumeration (timing analysis, error-differential, web hints)
- Context-aware password generation and threaded password attacks
- Alternative login methods (direct IP, web-based) and hostname resolution bypass helpers
- Post-exploitation: extract system parameters, modules, companies, users and privilege analysis
- JSON and HTML report generation with a summary and recommendations
- Log file output for forensic/review purposes

## Requirements

- Python 3.8+ (tested with Python 3.x)
- Recommended packages (can be installed with pip):
  - requests
  - (The core standard library modules are used for xmlrpc, threading, etc.)

Example install:
```bash
python3 -m pip install requests
```

You can also create a small requirements file:
```text
requests
```

## Usage

This script is primarily interactive. Run it from a terminal:

```bash
python3 odooPen.py
```

You will be prompted for:
- Target Host (IP or hostname)
- Port (default 8069)
- Use HTTPS? (y/N)
- Disable SSL verification? (y/N) 
- Timeout (default 10)
- Silent mode toggle

After providing inputs the framework runs an end-to-end assessment:
1. Reconnaissance
2. Service discovery (XML-RPC + database enumeration)
3. Vulnerability assessment (version detection + checks)
4. Authentication testing (user enumeration + password attacks)
5. Post-exploitation (if valid credentials found)
6. Report generation (JSON and HTML saved to the working directory)

Example interactive session:
```
$ python3 odooPen.py
Target Host: demo.odoo-server.local
Port [8069]: 
Use HTTPS? (y/N): n
Timeout in seconds [10]: 
Silent mode? (Y/n):
```

Notes:
- The framework attempts to use XML-RPC endpoints at `/xmlrpc/2/common`, `/xmlrpc/2/db`, and `/xmlrpc/2/object`.
- Valid credentials, master password candidates, and security issues are saved in the generated JSON and HTML reports.

## Output

- Log file: `odoo_pentest_YYYYMMDD_HHMMSS.log`
- JSON report: `odoo_pentest_report_YYYYMMDD_HHMMSS.json`
- HTML report: `odoo_pentest_report_YYYYMMDD_HHMMSS.html`

Reports include:
- Target metadata and timestamps
- Enumerated databases and users
- Vulnerability list (mapped by detected version)
- Security issues and recommendations
- Any discovered valid credentials or master password candidates

## Configuration & Customization

- Timeout, SSL verification and port are configurable via the interactive prompts.
- The vulnerability database is stored in `OdooVulnerabilityDB` class inside `odooPen.py`. You can extend it with newer CVEs or project-specific checks.
- Password generation is handled by `AdvancedPasswordGenerator`. Customize keywords or patterns there for targeted wordlists.

## Ethical & Legal Notice

This repository is a security testing tool. You must have explicit written permission before using it against any system you do not own. The author and contributors accept no responsibility for misuse of this tool. Use responsibly.

## Contributing

Contributions are welcome (bug fixes, new checks, better reporting, CLI flags). Please follow common-sense rules:

- Open an issue describing the enhancement or bug with reproduction steps.
- Fork the repository and create a branch for your changes.
- Submit a clear PR with tests or demonstration where applicable.
- Keep security-sensitive enhancements documented with safe defaults.

If you submit code that enhances active testing capability (e.g., exploits), ensure it is clearly labeled and optional behind explicit flags and disclaimers.


