# SphinxEye (WebScanner)

SphinxEye is a graduation web security project. It scans websites, reviews uploaded source files, stores reports in SQL Server, and shows results in an Angular dashboard.

**Use it only on sites and files you own or have permission to test.**

## What's in the box

- **Website scan** — crawls up to 20 pages and runs Python scanners (XSS, SQLi helpers, IDOR, traversal, redirect, auth, CSRF, recon, sensitive data, and more).
- **Source Code Review** — upload `.js`, `.html`, or `.htm` (max 5 MB). Results are saved per user.
- **Dashboard** — view findings, download reports, delete old scans.
- **AI assistant** — chat about a scan or a source review report (needs a Gemini API key configured on the backend).

## Stack

| Layer | Tech |
|---|---|
| Backend | ASP.NET Core 8, EF Core, JWT auth |
| Frontend | Angular 19 (`WebScanner/wwwroot/frontend`) |
| Scanners | Python 3 scripts in `WebScanner/Scanners/` |
| Database | SQL Server — default DB name: `ScanlyDB` |

## Project layout

```
first/
├── WebScanner.sln
├── WebScanner/              ← backend + Scanners + frontend source
│   ├── Controllers/
│   ├── Services/
│   ├── Scanners/          ← scanner .py files
│   │   └── Wrappers/      ← run_*.py (called by the backend)
│   ├── Migrations/        ← EF Core migrations
│   └── wwwroot/frontend/  ← Angular app
├── sql_init/init_schema.sql   ← optional manual schema script
├── MIGRATIONS_README.txt
└── AUTHORS.md
```

## Requirements

- .NET 8 SDK
- Node.js + npm
- Python 3 (`requests`, `beautifulsoup4`; `esprima` for source review AST checks)
- SQL Server (local instance or LocalDB)
- Optional: SQLMap API on `http://127.0.0.1:8775` for advanced SQL injection checks

## Run the backend

From `WebScanner/`:

```bash
dotnet restore
dotnet run
```

API: `http://localhost:5000`  
Swagger: `http://localhost:5000/swagger`

Apply migrations first if the database is empty (see `MIGRATIONS_README.txt`).

## Run the frontend (development)

From `WebScanner/wwwroot/frontend/`:

```bash
npm install
npm start
```

UI: `http://localhost:4200`

The backend CORS policy expects the frontend on port 4200.

## Python scanners and `bin/`

Scanner files are copied to `bin/Debug/net8.0/Scanners/` on build. If you edit a `.py` file and changes do not show up, copy the file into the matching `bin/.../Scanners/` path or rebuild the project.

## Source Code Review

Separate from the main URL scan flow. Upload goes to `POST /api/source-code-review/scan`. Reports are stored in the database and as JSON/HTML files under the app output folder.

Install AST support:

```bash
pip install esprima
```

## Why some scans take a long time

A full scan is not one script — it is many runs in parallel (max 5 at a time):

- Up to **20 crawled pages**
- **6 scanners per page** (XSS, NoSQL, sensitive data, IDOR, traversal, redirect)
- **4 site-wide scanners** (auth, CSRF, sqlmap, recon)

On a large site like [OWASP Juice Shop](https://demo.owasp-juice.shop), that can mean **120+ Python jobs**. IDOR and NoSQL scans are slow on their own. Expect **10–20+ minutes** on Juice Shop. For a quick test, use something lighter, e.g. `http://testphp.vulnweb.com`.

## Test targets (authorized use only)

| Target | Notes |
|---|---|
| `http://testphp.vulnweb.com` | Small, good for a fast check |
| `https://demo.owasp-juice.shop` | Many findings, but slow |

## Team

See `AUTHORS.md`.
