from pathlib import Path


def write(run: dict, rows: list[dict], metrics: dict, path: Path) -> Path:
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Table
    except ImportError as exc:
        raise RuntimeError("PDF reports need reportlab: pip install '.[pdf]'") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    s = getSampleStyleSheet()
    dr = metrics["detection_rate"]
    data = [["ID", "Technique", "Verdict", "Latency", "Rules"]] + [
        [r["test_id"], r["technique"], r["verdict"],
         "" if r["latency_seconds"] is None else f"{r['latency_seconds']:.1f}s",
         ", ".join(r["matched_rule_ids"])] for r in rows]
    SimpleDocTemplate(str(path), pagesize=landscape(A4)).build([
        Paragraph(f"Detection validation - run {run['id']}", s["Title"]),
        Paragraph(f"Detection rate: {'n/a' if dr is None else f'{dr:.1%}'} | TP {metrics['tp']} FN {metrics['fn']} "
                  f"TN {metrics['tn']} FP {metrics['fp']} ERR {metrics['errors']}", s["Normal"]),
        Table(data, repeatRows=1)])
    return path
