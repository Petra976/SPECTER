from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    ListFlowable, ListItem, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from datetime import datetime


def risk_score(results):
    weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }
    score = sum(weights.get(r.get("severity", "info").lower(), 1) for r in results)
    return min(score, 100)


def generate_pdf_report(results, path, target):
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Center", alignment=1, fontSize=22, spaceAfter=20))
    styles.add(ParagraphStyle(name="HeadingBig", fontSize=16, spaceAfter=12))

    doc = SimpleDocTemplate(path, pagesize=A4)
    story = []

    story.append(Spacer(1, 120))
    story.append(Paragraph("WordPress Security Assessment Report", styles["Center"]))
    story.append(Spacer(1, 40))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles["Normal"]))
    story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("Executive Summary", styles["HeadingBig"]))
    score = risk_score(results)

    story.append(Paragraph(
        f"This assessment identified <b>{len(results)}</b> findings. "
        f"The calculated risk score for the target is <b>{score}/100</b>.",
        styles["Normal"]
    ))
    story.append(Spacer(1, 20))

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in results:
        sev = r.get("severity", "info").capitalize()
        if sev in sev_counts:
            sev_counts[sev] += 1

    table_data = [["Severity", "Count"]] + [[k, v] for k, v in sev_counts.items()]

    table = Table(table_data, colWidths=[150, 100])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
    ]))

    story.append(table)
    story.append(PageBreak())

    story.append(Paragraph("Technical Findings", styles["HeadingBig"]))

    for r in results:
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>{r.get('title')}</b>", styles["Heading3"]))
        story.append(Paragraph(f"<b>Severity:</b> {r.get('severity')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Module:</b> {r.get('module')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Category:</b> {r.get('category')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Endpoint:</b> {r.get('endpoint')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Description:</b><br/>{r.get('description')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Business Impact:</b><br/>{r.get('business_impact')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Remediation:</b><br/>{r.get('remediation')}", styles["Normal"]))

        evidence = r.get("evidence")
        if evidence:
            ev_list = []
            if isinstance(evidence, dict):
                for k, v in evidence.items():
                    ev_list.append(ListItem(Paragraph(f"{k}: {v}", styles["Normal"])))
            elif isinstance(evidence, list):
                for item in evidence:
                    ev_list.append(ListItem(Paragraph(str(item), styles["Normal"])))

            story.append(ListFlowable(ev_list))
            story.append(Spacer(1, 10))


    doc.build(story)
