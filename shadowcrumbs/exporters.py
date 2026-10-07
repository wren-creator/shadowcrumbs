"""Turn an engagement into a deliverable: markdown, JSON or PDF."""
import io
import json
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


def _scope_line(meta):
    if meta["authorized"]:
        return f"Authorized. Reference: {meta['auth_ref']}"
    return "No authorization reference recorded (passive search tier only)"


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
        out += ["| Finding | Confidence | Verified | Source | Notes |", "|---|---|---|---|---|"]
        for f in rows:
            value = f"[{_md(f['value'])}]({f['url']})" if f["url"] and key == "documents" else _md(f["value"])
            out.append(
                f"| {value} | {f['confidence']} | {'yes' if f['verified'] else 'no'} | "
                f"{_md(', '.join(f['plugins']))} | {_md(f['notes'])} |"
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
        data = [[P(h, head) for h in ("Finding", "Conf.", "Source", "Notes")]]
        for f in rows:
            data.append([P(f["value"]), P(f["confidence"]), P(", ".join(f["plugins"])), P(f["notes"] or "")])
        story.append(table(data, [2.5 * inch, 0.5 * inch, 1.2 * inch, 3.0 * inch]))

    story += [Spacer(1, 10), Paragraph("Run history", styles["Heading2"])]
    data = [[P(h, head) for h in ("Source", "Tier", "Started", "Status", "New", "Error")]]
    for r in b["runs"]:
        data.append([P(r["plugin"]), P(r["tier"]), P(r["started_at"]), P(r["status"]), P(r["found"]), P(r["error"] or "")])
    story.append(table(data, [1.5 * inch, 0.6 * inch, 1.3 * inch, 0.7 * inch, 0.5 * inch, 2.6 * inch]))
    doc.build(story)
    return buf.getvalue()


EXPORTERS = {
    "json": (to_json, "application/json", "json"),
    "md": (to_markdown, "text/markdown; charset=utf-8", "md"),
    "pdf": (to_pdf, "application/pdf", "pdf"),
}
