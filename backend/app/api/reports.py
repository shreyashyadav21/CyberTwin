import io
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.app.models.database import get_db
from backend.app.services.network_service import NetworkService
from backend.app.security.assessment import SecurityAssessmentEngine

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("/{network_id}")
def download_pdf_report(network_id: str, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    assessment = SecurityAssessmentEngine.assess_network(net)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor("#253443"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor("#397C78"),
        spaceAfter=14
    )
    h2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor("#202E39"),
        spaceBefore=10,
        spaceAfter=6
    )

    story = []
    story.append(Paragraph("CyberTwin – Security Posture & Digital Twin Assessment Report", title_style))
    story.append(Paragraph("ENVIRONMENT: 100% VIRTUAL SIMULATION MODEL | DETERMINISTIC ANALYSIS ONLY", subtitle_style))
    story.append(Spacer(1, 8))

    # Executive Summary Card
    exec_data = [
        ["Network Name", net.name, "Security Score", f"{assessment.security_score} / 100"],
        ["Network ID", net.id, "Risk Score", f"{assessment.risk_score} / 100"],
        ["Total Assets", str(len(net.devices)), "Total Findings", str(assessment.total_findings)]
    ]
    t_exec = Table(exec_data, colWidths=[90, 180, 90, 180])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F5F7F6")),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#253443")),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 12))

    # CIA Triad Assessment
    story.append(Paragraph("1. Security Foundations (CIA Triad Evaluation)", h2_style))
    cia = assessment.cia_triad
    cia_data = [
        ["Principle", "Status", "Evaluation Details"],
        ["Confidentiality", cia.confidentiality_status, cia.confidentiality_desc],
        ["Integrity", cia.integrity_status, cia.integrity_desc],
        ["Availability", cia.availability_status, cia.availability_desc]
    ]
    t_cia = Table(cia_data, colWidths=[90, 90, 360])
    t_cia.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#397C78")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(t_cia)
    story.append(Spacer(1, 12))

    # Identified Vulnerabilities
    story.append(Paragraph("2. Identified Vulnerabilities & Attack Surface", h2_style))
    vuln_data = [["Code", "Severity", "Affected Asset", "Description & Mitigation"]]
    for f in assessment.findings[:6]:
        desc = f"<b>{f.title}</b><br/>{f.evidence}<br/><i>Mitigation: {f.mitigation}</i>"
        vuln_data.append([f.rule_code, f.severity.upper(), f.device_name, Paragraph(desc, styles['Normal'])])

    t_vuln = Table(vuln_data, colWidths=[90, 70, 90, 290])
    t_vuln.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#202E39")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(t_vuln)
    story.append(Spacer(1, 12))

    # Virtual Device Inventory
    story.append(Paragraph("3. Network Asset Inventory", h2_style))
    dev_data = [["Device ID", "Type", "Zone", "IP", "Criticality", "Auth Strength"]]
    for d in net.devices:
        dev_data.append([d.name, d.type, d.zone, d.ip, d.criticality.upper(), d.auth_strength])

    t_dev = Table(dev_data, colWidths=[100, 80, 80, 80, 70, 70])
    t_dev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#80AAA1")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(t_dev)

    doc.build(story)
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cybertwin_assessment_{network_id}.pdf"}
    )

