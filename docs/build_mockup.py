"""Build docs/mockup.html: the real dashboard (style.css + app.js) with a fetch shim and captured demo data.

Usage: python docs/build_mockup.py DATA_DIR
DATA_DIR holds meta.json, engagements.json, engagements_<slug>.json, ..._runs.json, ..._findings.json
captured from a ./start.sh --demo run against fixtures/demo.json (fictional Acme Demo Corp).
"""
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
data = pathlib.Path(sys.argv[1])
slug = "acme-demo-corp"
load = lambda n: json.loads((data / n).read_text())
blob = {
    "meta": load("meta.json"),
    "list": load("engagements.json"),
    "eng": load(f"engagements_{slug}.json"),
    "runs": load(f"engagements_{slug}_runs.json"),
    "findings": load(f"engagements_{slug}_findings.json"),
}
blob["runs"]["status"]["state"] = "idle"

shim = """
const SAMPLE = %s;
const SLUG = %s;
const json = (d, s = 200) => new Response(s === 204 ? null : JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json" } });
window.fetch = async (path, opts = {}) => {
  const method = (opts.method || "GET").toUpperCase();
  const body = opts.body ? JSON.parse(opts.body) : {};
  const m = path.match(/^\\/api\\/engagements\\/[^/]+\\/findings\\/(\\d+)$/);
  if (path === "/api/meta") return json(SAMPLE.meta);
  if (path === "/api/engagements" && method === "GET") return json(SAMPLE.list);
  if (path === `/api/engagements/${SLUG}` && method === "GET") return json(SAMPLE.eng);
  if (path === `/api/engagements/${SLUG}/runs` && method === "GET") return json(SAMPLE.runs);
  if (path.startsWith(`/api/engagements/${SLUG}/findings`) && method === "GET") return json(SAMPLE.findings);
  if (m && method === "PATCH") { const f = SAMPLE.findings.find((x) => x.id == m[1]); if (f && "verified" in body) f.verified = body.verified; return json({ ok: true }); }
  if (m && method === "DELETE") { SAMPLE.findings = SAMPLE.findings.filter((x) => x.id != m[1]); return json(null, 204); }
  return json({ detail: "Sample mode: this mockup is read-only. Run the real thing with ./start.sh --demo." }, 409);
};
""" % (json.dumps(blob), json.dumps(slug))

html = (root / "static/index.html").read_text()
css = (root / "static/style.css").read_text()
js = (root / "static/app.js").read_text()
banner_css = ".sample{position:fixed;right:12px;top:10px;z-index:9;padding:6px 10px;border:1px solid #f0b429;color:#f0b429;background:#0b120c;font:12px monospace;border-radius:6px}"
html = html.replace('<link rel="stylesheet" href="style.css">', f"<style>{css}\n{banner_css}</style>")
html = html.replace('<script src="app.js"></script>', f'<div class="sample">SAMPLE DATA: fictional company, read-only mockup</div>\n<script>{shim}</script>\n<script>{js}</script>')
out = root / "docs/mockup.html"
out.write_text(html)
print(f"wrote {out} ({len(html)//1024} KB)")
