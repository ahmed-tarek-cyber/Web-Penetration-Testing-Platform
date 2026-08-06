# Vulnerable Test App

Intentionally vulnerable Flask app for testing your graduation project vulnerability scanner.

## Setup & Run

```bash
pip install flask
python app.py
# Visit http://127.0.0.1:5000
```

## Vulnerabilities & Test Payloads

| # | Type | Endpoint | Payload |
|---|------|----------|---------|
| 1 | **SQL Injection** | `GET /search?q=` | `' OR '1'='1` |
| 2 | **SQL Injection** | `POST /login-check` | username: `' OR 1=1 --` |
| 3 | **Reflected XSS** | `GET /greet?name=` | `<script>alert(1)</script>` |
| 4 | **Stored XSS** | `POST /comments` | comment body: `<img src=x onerror=alert(1)>` |
| 5 | **Open Redirect** | `GET /redirect?url=` | `https://evil.com` |
| 6 | **Directory Traversal** | `GET /file?name=` | `../app.py` |

## Fix Summary (in code comments)

Each vulnerable block is marked with `# ❌ VULNERABLE` and has a `# FIX:` comment directly above or below it explaining the correct approach.
