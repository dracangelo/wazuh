from html import escape
from pathlib import Path

COLORS = {"TP": "#1a7f37", "TN": "#1a7f37", "FN": "#cf222e", "FP": "#bc4c00", "ERROR": "#6e7781"}


def _pct(v):
    return "n/a" if v is None else f"{v:.1%}"


def write(run: dict, rows: list[dict], metrics: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        f"<tr><td>{escape(r['test_id'])}</td><td>{escape(r['name'])}</td><td>{escape(r['technique'])}</td>"
        f"<td style='color:{COLORS.get(r['verdict'], '#000')};font-weight:600'>{r['verdict']}</td>"
        f"<td>{'' if r['latency_seconds'] is None else round(r['latency_seconds'], 1)}</td>"
        f"<td>{escape(', '.join(r['matched_rule_ids']))}</td><td>{escape(r.get('error') or '')}</td></tr>"
        for r in rows)
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Detection validation run {run['id']}</title>
<style>body{{font:14px system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d0d7de;padding:6px 8px;text-align:left}}th{{background:#f6f8fa}}</style></head><body>
<h1>Detection validation - run {run['id']}</h1>
<p>Started {escape(str(run.get('started_at')))} · commit {escape(str(run.get('git_sha') or 'n/a'))}</p>
<p><b>Detection rate:</b> {_pct(metrics['detection_rate'])} · <b>Precision:</b> {_pct(metrics['precision'])} ·
<b>FP rate:</b> {_pct(metrics['false_positive_rate'])} · <b>MTTD:</b> {metrics['mean_time_to_detect_s']}s ·
<b>Errors:</b> {metrics['errors']}</p>
<table><tr><th>ID</th><th>Name</th><th>Technique</th><th>Verdict</th><th>Latency (s)</th><th>Rules</th><th>Error</th></tr>
{body}</table></body></html>"""
    path.write_text(html, encoding="utf-8")
    return path
