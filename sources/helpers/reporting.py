"""
sources/helpers/reporting.py
NOX Enterprise Reporting — Executive Summary, Pivot Chain, Data Sanitization.
"""

import hashlib
import html as _html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# ── Noise patterns stripped from all report output ────────────────────
_NOISE_RE = re.compile(
    r"(Traceback \(most recent|File \".*\.py\"|TimeoutError|ProxyError"
    r"|ConnectionError|aiohttp\.|ClientConnector|ssl\.|asyncio\."
    r"|Task exception|NoneType|Object of type)",
    re.I,
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _nox_ver() -> str:
    try:
        from nox import VERSION  # type: ignore
        return VERSION
    except ImportError:
        return "1.0.0"


def _clean(v: Any, maxlen: int = 200) -> str:
    """Strip control chars, technical noise, HTML-escape, truncate."""
    s = str(v) if v is not None else ""
    s = _CTRL_RE.sub("", s)
    if _NOISE_RE.search(s):
        return ""
    return _html.escape(s[:maxlen])


def _raw(v: Any, maxlen: int = 200) -> str:
    """Strip control chars only — no HTML escaping (PDF / plain-text paths)."""
    s = str(v) if v is not None else ""
    s = _CTRL_RE.sub("", s)
    if _NOISE_RE.search(s):
        return ""
    return s[:maxlen]


def _pdf_safe(s: str, maxlen: int = 180) -> str:
    # D4: sanitize for fpdf2 core fonts (latin-1 subset).
    # NFKD normalization decomposes accented chars (é→e + combining accent)
    # so common accented Latin characters survive as their base letter.
    # Truly non-latin-1 chars (Cyrillic, CJK, etc.) become '?' — intentional:
    # fpdf2 core fonts cannot render them and would raise UnicodeEncodeError.
    s = _raw(s, maxlen)
    try:
        import unicodedata
        normalized = unicodedata.normalize("NFKD", s)
        return normalized.encode("ascii", errors="replace").decode("ascii")
    except Exception:
        return s.encode("latin-1", errors="replace").decode("latin-1")


def _rget(r: Any, k: str) -> str:
    if isinstance(r, dict):
        return str(r.get(k, "") or "")
    return str(getattr(r, k, "") or "")


# ── Executive summary builder ─────────────────────────────────────────

def build_exec_summary(data: dict) -> dict:
    """
    Returns a dict with all dashboard KPIs needed by every format.
    Expects data keys: records, analysis, scan_meta (optional).
    """
    records   = data.get("records", [])
    meta      = data.get("scan_meta", {}) or {}
    analysis  = data.get("analysis", {}) or {}

    cleartext = sum(1 for r in records if _rget(r, "password"))
    nodes     = len({_rget(r, "email") or _rget(r, "username") for r in records} - {""})
    elapsed   = meta.get("elapsed_seconds")
    depth     = meta.get("pivot_depth", len(data.get("pivot_chain", [])))

    buckets: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in records:
        rs = float(_rget(r, "risk_score") or 0)
        if rs >= 90:   buckets["Critical"] += 1
        elif rs >= 70: buckets["High"]     += 1
        elif rs >= 40: buckets["Medium"]   += 1
        elif rs >= 10: buckets["Low"]      += 1
        else:          buckets["Info"]     += 1

    return {
        "total_records":    len(records),
        "nodes_discovered": nodes,
        "cleartext_passwords": cleartext,
        "pivot_depth":      depth,
        "elapsed":          f"{elapsed:.1f}s" if elapsed is not None else "N/A",
        "buckets":          buckets,
        "hvt_count":        analysis.get("hvt_count", sum(1 for r in records if getattr(r, "is_hvt", False))),
    }


# ── Pivot chain renderer ──────────────────────────────────────────────

def render_pivot_chain(data: dict) -> List[str]:
    """
    Build a human-readable pivot chain.
    D2: check pivot_log first before falling back to record-based reconstruction.
    """
    chain  = data.get("pivot_chain") or []
    target = _raw(data.get("target", "?"))

    # D2: if pivot_log is available, build chain from it (accurate tree)
    pivot_log = data.get("pivot_log") or []
    if pivot_log:
        lines: List[str] = []
        for e in pivot_log:
            depth  = e.get("depth", 0)
            asset  = _raw(e.get("asset", ""))
            phase  = _raw(e.get("found_in", e.get("source", "?")))
            parent = _raw(e.get("parent") or "")
            prefix = "  " * depth
            if depth == 0:
                lines.append(f"[SEED] {asset}")
            else:
                lines.append(f"{prefix}└─ [{phase}] {asset}  ← {parent}")
        return lines if lines else [f"[SEED] {target}  (no pivot data)"]

    if len(chain) <= 1:
        # No pivot data — reconstruct best-effort from records
        records = data.get("records", [])
        lines = [f"[SEED] {target}"]
        seen: set = {target.lower()}
        for r in records[:40]:
            src   = _raw(_rget(r, "source"))
            em    = _raw(_rget(r, "email"))
            usr   = _raw(_rget(r, "username"))
            ident = em or usr
            if not ident or ident.lower() in seen:
                continue
            seen.add(ident.lower())
            lines.append(f"  └─ [{src}] → {ident}")
        dork_results = data.get("dork_results") or []
        for d in dork_results[:5]:
            url = _raw(d.get("url", ""))
            if url and url.lower() not in seen:
                seen.add(url.lower())
                lines.append(f"  └─ [Dork] → {url[:80]}")
        return lines if len(lines) > 1 else [f"[SEED] {target}  (no pivot data)"]

    # Ordered pivot chain from AvalancheScanner
    lines = [f"[SEED] {_raw(chain[0])}"]
    for node in chain[1:]:
        lines.append(f"  └─ [Pivot] → {_raw(node)}")
    return lines


# ── JSON report ───────────────────────────────────────────────────────

def to_json(data: dict, path: str) -> None:
    summary = build_exec_summary(data)
    chain   = render_pivot_chain(data)
    records = data.get("records", [])

    def _ser(o):
        try:
            from enum import Enum
            if isinstance(o, Enum):
                return o.name
        except ImportError:
            pass
        if hasattr(o, "to_dict"):
            return o.to_dict()
        return str(o)

    clean_records = []
    for r in records:
        d = r.to_dict() if hasattr(r, "to_dict") else (r if isinstance(r, dict) else {})
        # drop noise fields
        clean_records.append({
            k: v for k, v in d.items()
            if k not in ("raw_data", "metadata") and not _NOISE_RE.search(str(v or ""))
        })

    try:
        from nox import VERSION as _NOX_VERSION  # type: ignore
    except ImportError:
        _NOX_VERSION = "1.0.0"

    # Include dork and scrape results in JSON output
    dork_results   = data.get("dork_results", []) or []
    scrape_results = data.get("scrape_results", {}) or {}

    # D3: apply consistent cap (1000) — same as HTML
    _RECORD_CAP = 1000

    out_data = {
        "framework":       f"NOX v{_NOX_VERSION}",
        "generated":       datetime.now().isoformat(),
        "target":          data.get("target", ""),
        # J3: self-describing metadata block
        "_meta": {
            "scan_id":        hashlib.sha256(
                f"{data.get('target','')}{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16],
            "target":         data.get("target", ""),
            "timestamp":      datetime.now().isoformat(),
            "nox_version":    _NOX_VERSION,
            "sources_queried": summary.get("total_records", 0),
            "pivot_depth_reached": summary.get("pivot_depth", 0),
            "record_cap":     _RECORD_CAP,
            "truncated":      len(clean_records) > _RECORD_CAP,
        },
        "executive_summary": summary,
        "pivot_chain":     chain,
        "records":         clean_records[:_RECORD_CAP],
        "dork_results":    dork_results,
        "scrape_results":  scrape_results,
    }
    Path(path).write_text(json.dumps(out_data, indent=2, default=_ser), encoding="utf-8")
    print(f"[+] JSON report saved: {path}")


# ── HTML report ───────────────────────────────────────────────────────

_CSS = (
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:'Courier New',monospace;background:#0a0a0a;color:#e0e0e0;padding:20px}"
    ".hdr{text-align:center;padding:28px;border:1px solid #333;margin-bottom:18px;background:#111}"
    ".hdr h1{color:#00ff41;font-size:26px;letter-spacing:4px}"
    ".hdr p{color:#888;margin-top:5px;font-size:12px}"
    ".kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:14px 0}"
    ".kpi{background:#111;border:1px solid #333;padding:16px;text-align:center}"
    ".kpi .n{font-size:30px;font-weight:bold;color:#00ff41}"
    ".kpi .l{color:#888;font-size:10px;margin-top:3px}"
    ".kpi.warn .n{color:#ff6600} .kpi.crit .n{color:#ff0040}"
    ".sec{margin:18px 0} .sec h2{color:#00ff41;border-bottom:1px solid #333;padding-bottom:5px;margin-bottom:10px}"
    ".chain{background:#0d1a0d;border:1px solid #1a3a1a;padding:12px;font-size:11px;color:#00cc33;word-break:break-all;margin:8px 0}"
    "table{width:100%;border-collapse:collapse} th,td{padding:7px;border:1px solid #222;font-size:11px;word-break:break-all}"
    "th{background:#1a1a1a;color:#00ff41;text-transform:uppercase;font-size:10px} td{background:#0d0d0d}"
    "tr.c td{background:#1a0005} tr.h td{background:#1a0a00} tr.m td{background:#1a1500}"
    ".pw{color:#ff0040;font-weight:bold}"
)


def to_html(data: dict, path: str) -> None:
    summary = build_exec_summary(data)
    chain   = render_pivot_chain(data)
    target  = _clean(data.get("target", "Unknown"))
    records = data.get("records", [])
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # KPI dashboard
    kpis = (
        f'<div class="kpi"><div class="n">{summary["total_records"]}</div><div class="l">TOTAL RECORDS</div></div>'
        f'<div class="kpi"><div class="n">{summary["nodes_discovered"]}</div><div class="l">NODES DISCOVERED</div></div>'
        f'<div class="kpi crit"><div class="n">{summary["cleartext_passwords"]}</div><div class="l">CLEARTEXT PASSWORDS</div></div>'
        f'<div class="kpi warn"><div class="n">{summary["hvt_count"]}</div><div class="l">HIGH-VALUE TARGETS</div></div>'
        f'<div class="kpi"><div class="n">{summary["pivot_depth"]}</div><div class="l">PIVOT DEPTH</div></div>'
        f'<div class="kpi"><div class="n">{summary["elapsed"]}</div><div class="l">TOTAL TIME</div></div>'
    )

    # Severity table
    sev_rows = "".join(
        f"<tr><td>{lvl}</td><td>{cnt}</td></tr>"
        for lvl, cnt in summary["buckets"].items() if cnt
    )

    # Pivot chain
    chain_html = "".join(f'<div class="chain">{_clean(c)}</div>' for c in chain)

    # Credential rows (top 500, noise-free)
    cred_rows = ""
    for r in records[:500]:
        rs  = float(_rget(r, "risk_score") or 0)
        cls = "c" if rs >= 90 else "h" if rs >= 70 else "m" if rs >= 40 else ""
        em  = _clean(_rget(r, "email") or _rget(r, "username"))
        pw  = _clean(_rget(r, "password"))
        src = _clean(_rget(r, "source"))
        bd  = _clean(_rget(r, "breach_date"))
        hvt = " ⚑" if getattr(r, "is_hvt", False) or (isinstance(r, dict) and r.get("is_hvt")) else ""
        cred_rows += (
            f"<tr class='{cls}'><td>{em}{hvt}</td>"
            f"<td class='pw'>{pw}</td><td>{src}</td><td>{bd}</td><td>{rs:.0f}</td></tr>"
        )

    # Dork results section
    dork_results = data.get("dork_results", []) or []
    dork_rows = ""
    for h in dork_results:
        url     = h.get("url", "")
        title   = h.get("title", "") or h.get("dork", "")
        snippet = h.get("snippet", "")
        engine  = h.get("engine", "")
        link    = (f'<a href="{_clean(url)}" style="color:#00ff41" target="_blank">{_clean(url[:80])}</a>'
                   if url else _clean(title[:80]))
        dork_rows += (
            f"<tr><td>{link}</td><td>{_clean(snippet[:120])}</td>"
            f"<td>{_clean(h.get('dork','')[:80])}</td><td>{_clean(engine)}</td></tr>"
        )
    dork_section = (
        f'<div class="sec"><h2>Dork Results ({len(dork_results)} hits)</h2>'
        f'<table><thead><tr><th>URL / Title</th><th>Snippet</th><th>Dork Query</th><th>Engine</th></tr></thead>'
        f'<tbody>{dork_rows if dork_rows else "<tr><td colspan=4 style=text-align:center>No dork hits</td></tr>"}</tbody></table></div>'
    )

    # Scrape results section
    scrape_results = data.get("scrape_results", {}) or {}
    pastes   = scrape_results.get("pastes", [])
    creds_sc = scrape_results.get("credentials", [])
    tg_hits  = scrape_results.get("telegram", [])
    mc_hits  = scrape_results.get("dork_misconfigs", [])

    paste_rows = ""
    for p in pastes:
        site = _clean(p.get("site", ""))
        pid  = p.get("id", "")
        pats = _clean(", ".join(f"{k}({len(v)})" for k, v in (p.get("patterns") or {}).items()))
        paste_rows += f"<tr><td>{site}</td><td>{_clean(pid)}</td><td>{pats}</td></tr>"

    cred_sc_rows = ""
    for c in creds_sc:
        cred_sc_rows += (
            f"<tr><td class='pw'>{_clean(c.get('raw','')[:120])}</td>"
            f"<td>{_clean(c.get('source',''))}</td><td>{_clean(c.get('paste_id',''))}</td></tr>"
        )

    tg_rows = ""
    for t in tg_hits:
        ch   = _clean(t.get("channel", ""))
        text = _clean(t.get("text", "")[:200])
        pats = _clean(", ".join(f"{k}({len(v)})" for k, v in (t.get("patterns") or {}).items()))
        link = f'<a href="https://t.me/s/{ch}" style="color:#00ff41" target="_blank">t.me/s/{ch}</a>'
        tg_rows += f"<tr><td>{link}</td><td>{text}</td><td>{pats}</td></tr>"

    mc_rows = ""
    for m in mc_hits:
        url_m   = m.get("url", "")
        title_m = _clean(m.get("title", "")[:80])
        dork_m  = _clean(m.get("dork", "")[:80])
        link_m  = (f'<a href="{_clean(url_m)}" style="color:#ff0040" target="_blank">{_clean(url_m[:80])}</a>'
                   if url_m else title_m)
        mc_rows += f"<tr><td>{link_m}</td><td>{title_m}</td><td>{dork_m}</td></tr>"

    scrape_section = (
        f'<div class="sec"><h2>Scrape Results</h2>'
        f'<h3 style="color:#aaa;margin:10px 0 5px">Pastes ({len(pastes)})</h3>'
        f'<table><thead><tr><th>Site</th><th>Paste ID</th><th>Patterns</th></tr></thead>'
        f'<tbody>{paste_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
        f'<h3 style="color:#aaa;margin:10px 0 5px">Extracted Credentials ({len(creds_sc)})</h3>'
        f'<table><thead><tr><th>Raw Credential</th><th>Source</th><th>Paste ID</th></tr></thead>'
        f'<tbody>{cred_sc_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
        f'<h3 style="color:#aaa;margin:10px 0 5px">Telegram CTI ({len(tg_hits)})</h3>'
        f'<table><thead><tr><th>Channel</th><th>Message</th><th>Patterns</th></tr></thead>'
        f'<tbody>{tg_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
        f'<h3 style="color:#aaa;margin:10px 0 5px">Misconfigurations ({len(mc_hits)})</h3>'
        f'<table><thead><tr><th>URL</th><th>Title</th><th>Dork</th></tr></thead>'
        f'<tbody>{mc_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
        f'</div>'
    )

    page = (
        f'<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>NOX — {target}</title><style>{_CSS}</style></head><body>'
        f'<div class="hdr"><h1>[ NOX ]</h1>'
        f'<p>Target: {target} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; NOX v{_nox_ver()}</p></div>'
        f'<div class="sec"><h2>Executive Summary</h2>'
        f'<div class="kpis">{kpis}</div>'
        f'<table><thead><tr><th>Severity</th><th>Count</th></tr></thead>'
        f'<tbody>{sev_rows}</tbody></table></div>'
        f'<div class="sec"><h2>Pivot Chain</h2>{chain_html}</div>'
        f'{dork_section}'
        f'{scrape_section}'
        f'<div class="sec"><h2>Credential Records (top 500)</h2>'
        f'<table><thead><tr><th>Identity</th><th>Password</th><th>Source</th>'
        f'<th>Date</th><th>Risk</th></tr></thead><tbody>{cred_rows}</tbody></table></div>'
        f'</body></html>'
    )
    Path(path).write_text(page, encoding="utf-8")
    print(f"[+] HTML report saved: {path}")


# ── PDF report (fpdf2) ────────────────────────────────────────────────

def to_pdf(data: dict, path: str, investigator_id: str = "NOX-AUTO") -> None:
    # D1: raise a clear error with install hint if fpdf2 is absent — never silently return.
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        msg = "[!] fpdf2 not installed — PDF report cannot be generated. Run: pip install fpdf2"
        print(msg)
        raise RuntimeError(msg)

    summary = build_exec_summary(data)
    chain   = render_pivot_chain(data)
    target  = _raw(data.get("target", "Unknown"))
    records = data.get("records", [])
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    class _PDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 5, "NOX - FORENSIC INTELLIGENCE REPORT - CONFIDENTIAL", align="R")
            self.ln(3)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 5, _pdf_safe(f"Page {self.page_no()} | {target[:50]}"), align="C")

    pdf = _PDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)

    # ── Cover page ────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(15, 15, 15)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_y(65)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(0, 220, 60)
    pdf.cell(0, 12, "FORENSIC INTELLIGENCE REPORT", align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(200, 200, 200)
    pdf.cell(0, 8, _pdf_safe(f"Target: {target}"), align="C")
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(140, 140, 140)
    for line in [f"Generated: {ts}", f"Investigator: {investigator_id}",
                 f"Framework: NOX v{_nox_ver()}", "Classification: RESTRICTED"]:
        pdf.cell(0, 6, _pdf_safe(line), align="C")
        pdf.ln(5)

    # ── Executive Summary ─────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_draw_color(0, 180, 50)
    pdf.set_line_width(0.4)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(4)

    kpis = [
        ("Total Time",               summary["elapsed"]),
        ("Nodes Discovered",         str(summary["nodes_discovered"])),
        ("Cleartext Passwords Found", str(summary["cleartext_passwords"])),
        ("Pivot Depth",              str(summary["pivot_depth"])),
        ("Total Records",            str(summary["total_records"])),
        ("High-Value Targets",       str(summary["hvt_count"])),
    ]
    pdf.set_font("Helvetica", "B", 10)
    for label, value in kpis:
        pdf.set_fill_color(245, 245, 245)
        pdf.cell(95, 7, _pdf_safe(label), border=1, fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(80, 7, _pdf_safe(value), border=1, ln=True)
        pdf.set_font("Helvetica", "B", 10)
    pdf.ln(4)

    # Severity breakdown
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Severity Breakdown", ln=True)
    _sev_c = {"Critical": (220,0,30), "High": (220,100,0),
               "Medium": (200,180,0), "Low": (0,150,50), "Info": (100,100,100)}
    total_b = max(sum(summary["buckets"].values()), 1)
    for level, count in summary["buckets"].items():
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(35, 6, _pdf_safe(level), border=1)
        pdf.cell(20, 6, str(count), border=1)
        bar_w = int(count / total_b * 120)
        x, y  = pdf.get_x(), pdf.get_y()
        pdf.cell(125, 6, "", border=1)
        if bar_w:
            rc, gc, bc = _sev_c.get(level, (100, 100, 100))
            pdf.set_fill_color(rc, gc, bc)
            pdf.rect(x + 1, y + 1, bar_w, 4, "F")
        pdf.ln()

    # ── Pivot Chain ───────────────────────────────────────────────────
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Pivot Chain Visualization", ln=True)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("Courier", "", 8)
    pdf.set_fill_color(240, 255, 240)
    for c_line in chain:
        # Word-wrap long chains at 100 chars
        for chunk in [c_line[i:i+100] for i in range(0, max(len(c_line), 1), 100)]:
            pdf.set_x(15)
            pdf.cell(180, 5, _pdf_safe(chunk), border=0, ln=True, fill=True)
    pdf.ln(3)

    # ── Credential Findings ───────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 9, "Credential Findings", ln=True)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)

    cols = [("Identity", 60), ("Password", 45), ("Source", 35), ("Date", 25), ("Risk", 15)]

    def _write_col_headers():
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        for col_name, col_w in cols:
            pdf.cell(col_w, 6, col_name, border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)

    _write_col_headers()

    for r in records[:500]:
        pw = _rget(r, "password")
        if not pw and not _rget(r, "email") and not _rget(r, "username"):
            continue  # skip noise rows with no actionable data
        rs = float(_rget(r, "risk_score") or 0)
        if rs >= 90:   pdf.set_fill_color(255, 220, 220)
        elif rs >= 70: pdf.set_fill_color(255, 240, 220)
        else:          pdf.set_fill_color(255, 255, 255)
        pdf.set_font("Helvetica", "", 7)
        # Auto page-break with repeated column headers (§5.1)
        if pdf.get_y() > pdf.h - 25:
            pdf.add_page()
            _write_col_headers()
        vals = [
            _pdf_safe(_rget(r, "email") or _rget(r, "username"), 38),
            _pdf_safe(pw, 28),
            _pdf_safe(_rget(r, "source"), 22),
            _pdf_safe(_rget(r, "breach_date"), 14),
            f"{rs:.0f}",
        ]
        for val, (_, w) in zip(vals, cols):
            pdf.cell(w, 5, val, border=1, fill=True)
        pdf.ln()

    # ── Dork Results ─────────────────────────────────────────────────
    dork_results = data.get("dork_results", []) or []
    if dork_results:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 9, _pdf_safe(f"Dork Results ({len(dork_results)} hits)"), ln=True)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
        for col_name, col_w in [("URL / Title", 95), ("Snippet", 55), ("Engine", 30)]:
            pdf.cell(col_w, 6, col_name, border=1, fill=True)
        pdf.ln(); pdf.set_text_color(0, 0, 0)
        for h in dork_results[:200]:
            pdf.set_fill_color(245, 245, 255); pdf.set_font("Helvetica", "", 7)
            url     = _pdf_safe(h.get("url", h.get("title", "")), 65)
            snippet = _pdf_safe(h.get("snippet", ""), 38)
            engine  = _pdf_safe(h.get("engine", ""), 20)
            for val, w in zip([url, snippet, engine], [95, 55, 30]):
                pdf.cell(w, 5, val, border=1, fill=True)
            pdf.ln()

    # ── Scrape Results ────────────────────────────────────────────────
    scrape_results = data.get("scrape_results", {}) or {}
    pastes      = scrape_results.get("pastes", [])
    creds_sc    = scrape_results.get("credentials", [])
    tg_hits     = scrape_results.get("telegram", [])
    mc_hits     = scrape_results.get("dork_misconfigs", [])

    if pastes or creds_sc or tg_hits or mc_hits:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 9, "Scrape Results", ln=True)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(3)

        if pastes:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, _pdf_safe(f"Pastes ({len(pastes)})"), ln=True)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("Site", 25), ("Paste ID", 80), ("Patterns", 75)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln(); pdf.set_text_color(0, 0, 0)
            for p in pastes[:100]:
                pdf.set_fill_color(245, 245, 245); pdf.set_font("Helvetica", "", 7)
                site = _pdf_safe(p.get("site", ""), 15)
                pid  = _pdf_safe(p.get("id", ""), 55)
                pats = _pdf_safe(", ".join(f"{k}({len(v)})" for k, v in (p.get("patterns") or {}).items()), 50)
                for val, w in zip([site, pid, pats], [25, 80, 75]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()
            pdf.ln(3)

        if creds_sc:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, _pdf_safe(f"Extracted Credentials ({len(creds_sc)})"), ln=True)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("Raw Credential", 120), ("Source", 30), ("Paste ID", 30)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln(); pdf.set_text_color(0, 0, 0)
            for c in creds_sc[:150]:
                pdf.set_fill_color(255, 240, 240); pdf.set_font("Helvetica", "", 7)
                raw = _pdf_safe(c.get("raw", ""), 80)
                src = _pdf_safe(c.get("source", ""), 20)
                pid = _pdf_safe(c.get("paste_id", ""), 20)
                for val, w in zip([raw, src, pid], [120, 30, 30]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()
            pdf.ln(3)

        if tg_hits:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, _pdf_safe(f"Telegram CTI ({len(tg_hits)})"), ln=True)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("Channel", 50), ("Message Excerpt", 100), ("Patterns", 30)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln(); pdf.set_text_color(0, 0, 0)
            for t in tg_hits[:80]:
                pdf.set_fill_color(245, 245, 255); pdf.set_font("Helvetica", "", 7)
                link = _pdf_safe(f"t.me/s/{t.get('channel','')}", 35)
                text = _pdf_safe(t.get("text", ""), 70)
                pats = _pdf_safe(", ".join(f"{k}({len(v)})" for k, v in (t.get("patterns") or {}).items()), 25)
                for val, w in zip([link, text, pats], [50, 100, 30]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()
            pdf.ln(3)

        if mc_hits:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, _pdf_safe(f"Misconfigurations ({len(mc_hits)})"), ln=True)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("URL", 90), ("Title", 60), ("Dork", 30)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln(); pdf.set_text_color(0, 0, 0)
            for m in mc_hits[:80]:
                pdf.set_fill_color(255, 245, 230); pdf.set_font("Helvetica", "", 7)
                url_m   = _pdf_safe(m.get("url", ""), 60)
                title_m = _pdf_safe(m.get("title", ""), 40)
                dork_m  = _pdf_safe(m.get("dork", ""), 25)
                for val, w in zip([url_m, title_m, dork_m], [90, 60, 30]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()

    pdf.output(path)
    print(f"[+] PDF report saved: {path}")
