"""
Vulnerable Web App - For Testing Purposes Only
Intentionally vulnerable: DO NOT deploy in production.
"""

from flask import Flask, request, redirect, send_file
import sqlite3
import os

app = Flask(__name__)

DB_PATH = "users.db"

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            author TEXT,
            body TEXT
        )
    """)
    # Seed some data
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM comments")
    c.executemany("INSERT INTO users (username, email, password) VALUES (?,?,?)", [
        ("alice",   "alice@test.com",   "secret123"),
        ("bob",     "bob@test.com",     "hunter2"),
        ("charlie", "charlie@test.com", "p@ssw0rd"),
    ])
    c.executemany("INSERT INTO comments (author, body) VALUES (?,?)", [
        ("alice", "Hello world!"),
        ("bob",   "Nice app :)"),
    ])
    conn.commit()
    conn.close()


# ─── HTML helpers ─────────────────────────────────────────────────────────────

NAV = """
<style>
  body { font-family: monospace; background:#1e1e2e; color:#cdd6f4; padding:20px; }
  a    { color:#89b4fa; }
  nav  { background:#313244; padding:10px; border-radius:6px; margin-bottom:20px; }
  nav a{ margin-right:16px; }
  h2   { color:#cba6f7; }
  input, textarea { background:#313244; color:#cdd6f4; border:1px solid #585b70;
                    padding:6px 10px; border-radius:4px; width:300px; }
  button { background:#89b4fa; color:#1e1e2e; border:none; padding:8px 18px;
           border-radius:4px; cursor:pointer; font-weight:bold; }
  table  { border-collapse:collapse; width:100%; margin-top:10px; }
  th,td  { border:1px solid #585b70; padding:8px; text-align:left; }
  th     { background:#313244; }
  .box   { background:#313244; padding:16px; border-radius:6px; margin-bottom:20px; }
  .vuln  { color:#f38ba8; font-size:12px; font-style:italic; }
  .result{ background:#45475a; padding:10px; border-radius:4px; margin-top:10px;
           white-space:pre-wrap; word-break:break-all; }
</style>
<nav>
  <a href="/">Home</a>
  <a href="/search">User Search (SQLi #1)</a>
  <a href="/greet">Greet (XSS #1)</a>
  <a href="/comments">Comments (XSS #2)</a>
  <a href="/redirect">Redirect (Open Redirect)</a>
</nav>
"""

def page(title, body):
    return f"<html><body>{NAV}<h2>{title}</h2>{body}</body></html>"


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return page("Vulnerable Test App", """
    <div class="box">
      <p>This app contains <b>4 intentional vulnerabilities</b> for scanner testing:</p>
      <ul>
        <li>🔴 SQLi #1 — User Search (<code>/search?q=</code>)</li>
        <li>🔴 XSS #1  — Reflected (<code>/greet?name=</code>)</li>
        <li>🔴 XSS #2  — Stored (Comments page)</li>
        <li>🔴 Open Redirect (<code>/redirect?url=</code>)</li>
      </ul>
    </div>
    """)


# ── VULN #1 — SQL Injection (Search) ─────────────────────────────────────────
#
#  VULNERABLE because:  user input is concatenated directly into the SQL query.
#  Payload to test:     ' OR '1'='1
#                       ' UNION SELECT id,username,password,email FROM users--
#
#  FIX: Use parameterised queries:
#       c.execute("SELECT * FROM users WHERE username LIKE ?", (f"%{q}%",))
#
@app.route("/search")
def search():
    q      = request.args.get("q", "")
    rows   = []
    error  = ""
    if q:
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            # ❌ VULNERABLE — raw string concatenation
            query = "SELECT id, username, email FROM users WHERE username LIKE '%" + q + "%'"
            c.execute(query)
            rows = c.fetchall()
            conn.close()
        except Exception as e:
            error = str(e)

    table = ""
    if rows:
        table = "<table><tr><th>ID</th><th>Username</th><th>Email</th></tr>"
        for r in rows:
            table += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"
        table += "</table>"

    return page("User Search — SQL Injection #1", f"""
    <div class="box">
      <p class="vuln">VULN: SQL Injection — raw string concat in SELECT query</p>
      <form method="get">
        <input name="q" value="{q}" placeholder="Search username...">
        <button type="submit">Search</button>
      </form>
      {'<div class="result">Error: ' + error + '</div>' if error else ''}
      {table or ('<div class="result">No results</div>' if q else '')}
    </div>
    """)




# ── VULN #2 — Reflected XSS (Greet) ──────────────────────────────────────────
#
#  VULNERABLE because:  the `name` parameter is reflected into the HTML
#                       response without escaping.
#  Payload to test:     /greet?name=<script>alert(document.cookie)</script>
#
#  FIX: Escape output with markupsafe or flask's escape():
#       from markupsafe import escape
#       name = escape(request.args.get("name",""))
#
@app.route("/greet")
def greet():
    # ❌ VULNERABLE — raw user input embedded in HTML response
    name = request.args.get("name", "")
    greeting = f"<div class='result'>Hello, {name}!</div>" if name else ""

    return page("Greet — Reflected XSS #1", f"""
    <div class="box">
      <p class="vuln">VULN: Reflected XSS — name param echoed without escaping</p>
      <form method="get">
        <input name="name" value="" placeholder="Your name...">
        <button type="submit">Greet Me</button>
      </form>
      {greeting}
    </div>
    """)


# ── VULN #3 — Stored XSS (Comments) ──────────────────────────────────────────
#
#  VULNERABLE because:  comment body is stored as-is and rendered without
#                       escaping, so any script tag executes for every visitor.
#  Payload to test:     Author: hacker
#                       Comment: <script>alert('stored XSS')</script>
#
#  FIX: Escape on output:
#       from markupsafe import escape
#       body_safe = escape(row[2])
#       Use body_safe in HTML rendering.
#
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        body   = request.form.get("body", "")
        conn   = sqlite3.connect(DB_PATH)
        c      = conn.cursor()
        # ❌ VULNERABLE — raw content stored and will be rendered unescaped
        c.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
        conn.commit()
        conn.close()

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT id, author, body FROM comments ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    rows_html = ""
    for r in rows:
        # ❌ VULNERABLE — body rendered directly without escaping
        rows_html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"

    return page("Comments — Stored XSS #2", f"""
    <div class="box">
      <p class="vuln">VULN: Stored XSS — comment body stored and rendered without HTML escaping</p>
      <form method="post">
        <input name="author" placeholder="Your name"><br><br>
        <textarea name="body" rows="3" placeholder="Write a comment..."></textarea><br><br>
        <button type="submit">Post Comment</button>
      </form>
    </div>
    <div class="box">
      <table>
        <tr><th>ID</th><th>Author</th><th>Comment</th></tr>
        {rows_html}
      </table>
    </div>
    """)


# ── VULN #4 — Open Redirect ───────────────────────────────────────────────────
#
#  VULNERABLE because:  the `url` parameter is passed directly to redirect()
#                       with no validation of the destination host.
#  Payload to test:     /redirect?url=https://evil.com
#
#  FIX: Whitelist allowed destinations:
#       ALLOWED = ["https://example.com", "/dashboard"]
#       if url not in ALLOWED:
#           return "Redirect blocked", 400
#       return redirect(url)
#
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "")
    if url:
        # ❌ VULNERABLE — any URL is accepted including external ones
        return redirect(url)

    return page("Open Redirect", """
    <div class="box">
      <p class="vuln">VULN: Open Redirect — url param accepted without host validation</p>
      <form method="get">
        <input name="url" placeholder="https://..." style="width:400px">
        <button type="submit">Go</button>
      </form>
      <p>Try: <code>/redirect?url=https://google.com</code></p>
    </div>
    """)



# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Create a small files/ directory with a dummy file
    os.makedirs("files", exist_ok=True)
    if not os.path.exists("files/readme.txt"):
        with open("files/readme.txt", "w") as f:
            f.write("This is a public file.\nTry traversing above this directory!")

    init_db()
    print("\n[*] Vulnerable test app running at http://127.0.0.1:5005\n")
    app.run(debug=True, host="0.0.0.0", port=5005)
