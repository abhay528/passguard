"""Optional web UI for PassGuard, built with Flask.

Run with::

    pip install flask
    python -m passguard.web

Then open http://127.0.0.1:5000. The password is analyzed server-side and is
never stored. This module is intentionally optional so the core library has no
third-party dependencies.
"""

from __future__ import annotations

try:
    from flask import Flask, jsonify, render_template_string, request
except ImportError as exc:  # pragma: no cover - optional dependency
    raise SystemExit(
        "Flask is required for the web UI. Install it with: pip install flask"
    ) from exc

from .analyzer import PasswordAnalyzer

app = Flask(__name__)

_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PassGuard - Password Strength Analyzer</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: #0f1220; color: #e7e9f3;
           margin: 0; min-height: 100vh; display: grid; place-items: center; }
    .card { width: min(520px, 92vw); background: #171a2b; padding: 32px;
            border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.4); }
    h1 { margin: 0 0 4px; font-size: 1.4rem; }
    p.sub { margin: 0 0 20px; color: #9aa0bf; font-size: .9rem; }
    input { width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #2c3150;
            background: #0f1220; color: #fff; font-size: 1rem; }
    .meter { height: 10px; border-radius: 6px; background: #2c3150; margin: 16px 0 8px;
             overflow: hidden; }
    .meter > div { height: 100%; width: 0; transition: width .3s, background .3s; }
    .label { display:flex; justify-content: space-between; font-size:.9rem; }
    ul { padding-left: 18px; color:#c9cded; font-size:.88rem; }
    .row { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }
    .chip { font-size:.72rem; padding:4px 8px; border-radius:999px; background:#2c3150; }
    .chip.ok { background:#12351f; color:#7ee2a2; }
    code { background:#0f1220; padding:2px 6px; border-radius:6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>PassGuard</h1>
    <p class="sub">Type a password to see its strength. Nothing is stored.</p>
    <input id="pw" type="password" placeholder="Enter a password" autocomplete="off">
    <label style="font-size:.8rem;color:#9aa0bf">
      <input type="checkbox" id="show"> show password
    </label>
    <div class="meter"><div id="bar"></div></div>
    <div class="label"><span id="rating">-</span><span id="crack"></span></div>
    <div class="row" id="chips"></div>
    <ul id="issues"></ul>
    <div id="suggestions"></div>
  </div>
  <script>
    const pw = document.getElementById('pw');
    const bar = document.getElementById('bar');
    const rating = document.getElementById('rating');
    const crack = document.getElementById('crack');
    const issues = document.getElementById('issues');
    const chips = document.getElementById('chips');
    const suggestions = document.getElementById('suggestions');
    const colors = ['#ff5c5c','#ff8a3d','#ffd23d','#7ee2a2','#4ade80'];
    document.getElementById('show').onchange = e =>
      pw.type = e.target.checked ? 'text' : 'password';
    let timer;
    pw.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(analyze, 150);
    });
    async function analyze() {
      const res = await fetch('/api/analyze', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: pw.value})
      });
      const d = await res.json();
      bar.style.width = d.score + '%';
      const idx = Math.min(4, Math.floor(d.score / 20));
      bar.style.background = colors[idx];
      rating.textContent = pw.value ? d.strength + ' (' + d.score + '/100)' : '-';
      crack.textContent = pw.value ? '~' + d.crack_time : '';
      chips.innerHTML = '';
      const map = {has_lower:'a-z',has_upper:'A-Z',has_digit:'0-9',has_symbol:'!@#',length_ok:'12+'};
      for (const k in map) {
        const c = document.createElement('span');
        c.className = 'chip' + (d.checks[k] ? ' ok' : '');
        c.textContent = map[k];
        chips.appendChild(c);
      }
      issues.innerHTML = (d.warnings||[]).map(w => '<li>'+w+'</li>').join('');
      suggestions.innerHTML = (d.suggestions||[]).length
        ? '<p style="font-size:.85rem;color:#9aa0bf;margin:.6rem 0 .2rem">Try instead:</p>'
          + d.suggestions.map(s => '<div><code>'+s+'</code></div>').join('')
        : '';
    }
  </script>
</body>
</html>
"""

_analyzer = PasswordAnalyzer()


@app.get("/")
def index() -> str:
    return render_template_string(_PAGE)


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    return jsonify(_analyzer.analyze(password).to_dict())


def main() -> None:
    app.run(debug=False, host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
