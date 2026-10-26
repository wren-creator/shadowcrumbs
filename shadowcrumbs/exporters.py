"""Turn an engagement into a deliverable: markdown, JSON or PDF."""
import io
import json
import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from . import config


def _bundle(store):
    meta = store.meta()
    return {
        "engagement": meta,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "counts": store.counts(),
        "findings": store.findings(),
        "runs": list(reversed(store.runs())),
    }


def _by_category(findings):
    grouped = {k: [] for k in config.CATEGORY_KEYS}
    for f in findings:
        grouped.setdefault(f["category"], []).append(f)
    return grouped


_URL_OK = re.compile(r"https?://[^\s<>\"'`]+", re.I)


def _safe_url(url):
    """The URL if it is a plain http(s) address, else None. Findings come from the open internet, so a javascript: or
    file: address must never become a link a customer can click."""
    url = (url or "").strip()
    return url if _URL_OK.fullmatch(url) else None


def _evidence_rows(f):
    """(source, url) for every supporting link of a finding, one per distinct clickable URL."""
    rows = f.get("evidence") or ([{"plugin": f["plugins"][0] if f["plugins"] else "", "url": f["url"]}] if f["url"] else [])
    seen, out = set(), []
    for e in rows:
        u = _safe_url(e["url"])
        if u and u not in seen:
            seen.add(u)
            out.append((e["plugin"] or "source", u))
    return out


def _md_url(url):
    return url.replace("(", "%28").replace(")", "%29")


def _evidence_md(f):
    """Every supporting link for a finding, as markdown, each tagged with the source that found it."""
    return ", ".join(f"[{_md(label)}]({_md_url(u)})" for label, u in _evidence_rows(f))


def _conf(f):
    return f"{f['confidence']} ({f.get('confidence_label') or ''})".strip()


def _scope_line(meta):
    if meta["authorized"]:
        line = f"Authorized. Reference: {meta['auth_ref']}"
    else:
        line = "No authorization reference recorded (passive search tier only)"
    if meta.get("scope_domains"):
        line += ". Subdomains in scope: " + ", ".join(d["domain"] for d in meta["scope_domains"])
    return line


def to_json(store):
    return json.dumps(_bundle(store), indent=2, ensure_ascii=False)


def _md(text):
    return (text or "").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def to_markdown(store):
    b = _bundle(store)
    m = b["engagement"]
    out = [f"# Shadowcrumbs Recon Report: {m['name']}", ""]
    out += ["| | |", "|---|---|"]
    for label, val in (("Company", m["company"]), ("Domain", m["domain"]), ("IP or range", m["ip"]),
                       ("Scope", _scope_line(m)), ("Generated", b["generated_at"])):
        out.append(f"| {label} | {_md(val) or 'not given'} |")
    out += ["", "## Summary", "", "| Category | Findings |", "|---|---|"]
    for key, label in config.CATEGORIES:
        out.append(f"| {label} | {b['counts'].get(key, 0)} |")

    grouped = _by_category(b["findings"])
    for key, label in config.CATEGORIES:
        rows = grouped.get(key, [])
        out += ["", f"## {label}", ""]
        if not rows:
            out.append("Nothing found.")
            continue
        out += ["| Finding | Confidence | Verified | Plugins | Evidence | Notes |", "|---|---|---|---|---|---|"]
        for f in rows:
            value = f"[{_md(f['value'])}]({_md_url(_safe_url(f['url']))})" if _safe_url(f["url"]) else _md(f["value"])
            out.append(
                f"| {value} | {_conf(f)} | {'yes' if f['verified'] else 'no'} | "
                f"{_md(', '.join(f['plugins']))} | {_evidence_md(f)} | {_md(f['notes'])} |"
            )

    out += ["", "## Run history", "", "| Source | Tier | Started | Status | New findings | Error |", "|---|---|---|---|---|---|"]
    for r in b["runs"]:
        out.append(f"| {r['plugin']} | {r['tier']} | {r['started_at']} | {r['status']} | {r['found']} | {_md(r['error'])} |")
    return "\n".join(out) + "\n"


def to_pdf(store):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    b = _bundle(store)
    m = b["engagement"]
    styles = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=8, leading=10, splitLongWords=1)
    head = ParagraphStyle("head", parent=cell, fontName="Helvetica-Bold", textColor=colors.white)

    def P(text, style=cell):
        return Paragraph(escape(str(text if text is not None else "")), style)

    def P_links(f, style=cell):
        """Evidence as clickable links, one per line. The visible text is the URL, so a printed copy still shows it."""
        rows = _evidence_rows(f)
        return Paragraph("<br/>".join(
            f'{escape(label)}: <a href="{escape(u, {chr(34): "&quot;"})}" color="#1d4ed8"><u>{escape(u)}</u></a>' for label, u in rows), style)

    def P_value(f, style=cell):
        u = _safe_url(f["url"])
        if not u:
            return P(f["value"], style)
        return Paragraph(f'<a href="{escape(u, {chr(34): "&quot;"})}" color="#1d4ed8"><u>{escape(f["value"])}</u></a>', style)

    def table(rows, widths):
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14532d")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9ca3af")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ]))
        return t

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            title=f"Shadowcrumbs Recon Report: {m['name']}")
    story = [Paragraph(escape(f"Shadowcrumbs Recon Report: {m['name']}"), styles["Title"])]
    for label, val in (("Company", m["company"]), ("Domain", m["domain"]), ("IP or range", m["ip"]),
                       ("Scope", _scope_line(m)), ("Generated", b["generated_at"])):
        story.append(Paragraph(f"<b>{label}:</b> {escape(val or 'not given')}", styles["BodyText"]))
    story += [Spacer(1, 10), Paragraph("Summary", styles["Heading2"])]
    story.append(table([[P("Category", head), P("Findings", head)]] +
                       [[P(label), P(b["counts"].get(key, 0))] for key, label in config.CATEGORIES],
                       [3 * inch, 1 * inch]))

    grouped = _by_category(b["findings"])
    for key, label in config.CATEGORIES:
        story += [Spacer(1, 10), Paragraph(escape(label), styles["Heading2"])]
        rows = grouped.get(key, [])
        if not rows:
            story.append(Paragraph("Nothing found.", styles["BodyText"]))
            continue
        data = [[P(h, head) for h in ("Finding", "Conf.", "Plugins", "Evidence", "Notes")]]
        for f in rows:
            data.append([P_value(f), P(_conf(f)), P(", ".join(f["plugins"])), P_links(f), P(f["notes"] or "")])
        story.append(table(data, [1.8 * inch, 0.6 * inch, 0.9 * inch, 1.7 * inch, 2.2 * inch]))

    story += [Spacer(1, 10), Paragraph("Run history", styles["Heading2"])]
    data = [[P(h, head) for h in ("Source", "Tier", "Started", "Status", "New", "Error")]]
    for r in b["runs"]:
        data.append([P(r["plugin"]), P(r["tier"]), P(r["started_at"]), P(r["status"]), P(r["found"]), P(r["error"] or "")])
    story.append(table(data, [1.5 * inch, 0.6 * inch, 1.3 * inch, 0.7 * inch, 0.5 * inch, 2.6 * inch]))
    doc.build(story)
    return buf.getvalue()


def to_html(store):
    """One self-contained page the customer opens in any browser. Every link is real and opens in a new tab.
    Nothing is loaded from the internet and there is no script, so it is safe to email."""
    from html import escape as e

    b = _bundle(store)
    m = b["engagement"]

    def link(url, text):
        return f'<a href="{e(url, quote=True)}" target="_blank" rel="noopener noreferrer">{e(text)}</a>'

    out = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
           f"<title>{e('Shadowcrumbs Recon Report: ' + m['name'])}</title>",
           "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#111}"
           "table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}th{background:#14532d;color:#fff;text-align:left}"
           "th,td{border:1px solid #9ca3af;padding:.35rem .5rem;vertical-align:top;overflow-wrap:anywhere}"
           "tr:nth-child(even) td{background:#f3f4f6}a{color:#1d4ed8}.ev a{display:block}</style></head><body>",
           f"<h1>{e('Shadowcrumbs Recon Report: ' + m['name'])}</h1><table>"]
    for label, val in (("Company", m["company"]), ("Domain", m["domain"]), ("IP or range", m["ip"]),
                       ("Scope", _scope_line(m)), ("Generated", b["generated_at"])):
        out.append(f"<tr><th>{label}</th><td>{e(val or 'not given')}</td></tr>")
    out.append("</table><h2>Summary</h2><table><tr><th>Category</th><th>Findings</th></tr>")
    out += [f"<tr><td>{e(label)}</td><td>{b['counts'].get(key, 0)}</td></tr>" for key, label in config.CATEGORIES]
    out.append("</table>")
    grouped = _by_category(b["findings"])
    for key, label in config.CATEGORIES:
        rows = grouped.get(key, [])
        out.append(f"<h2>{e(label)}</h2>")
        if not rows:
            out.append("<p>Nothing found.</p>")
            continue
        out.append("<table><tr><th>Finding</th><th>Confidence</th><th>Verified</th><th>Plugins</th><th>Evidence</th><th>Notes</th></tr>")
        for f in rows:
            u = _safe_url(f["url"])
            ev = "".join(link(url, f"{label2}: {url}") for label2, url in _evidence_rows(f))
            out.append(f"<tr><td>{link(u, f['value']) if u else e(f['value'])}</td><td>{e(_conf(f))}</td>"
                       f"<td>{'yes' if f['verified'] else 'no'}</td><td>{e(', '.join(f['plugins']))}</td>"
                       f"<td class=\"ev\">{ev}</td><td>{e(f['notes'] or '')}</td></tr>")
        out.append("</table>")
    out.append("<h2>Run history</h2><table><tr><th>Source</th><th>Tier</th><th>Started</th><th>Status</th><th>New findings</th><th>Error</th></tr>")
    for r in b["runs"]:
        out.append(f"<tr><td>{e(r['plugin'])}</td><td>{e(r['tier'])}</td><td>{e(r['started_at'])}</td><td>{e(r['status'])}</td>"
                   f"<td>{r['found']}</td><td>{e(r['error'] or '')}</td></tr>")
    out.append("</table></body></html>")
    return "\n".join(out)


EXPORTERS = {
    "json": (to_json, "application/json", "json"),
    "md": (to_markdown, "text/markdown; charset=utf-8", "md"),
    "pdf": (to_pdf, "application/pdf", "pdf"),
    "html": (to_html, "text/html; charset=utf-8", "html"),
}
