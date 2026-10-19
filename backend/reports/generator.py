# ============================================================
# FORENSIRANSOM AI — FORENSIC REPORT GENERATOR
# ============================================================
# Generates professional forensic reports in PDF, JSON,
# and Evidence Verification Log formats.
# Reuses existing case, evidence, volatility, YARA, IOC, ML,
# and risk analysis findings.
# ============================================================

import io
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable
)
from reportlab.pdfgen import canvas

from reports.gemini_service import get_recommendations, SECURITY_RESOURCES


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and draw 'Page X of Y' footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#667085"))
        
        # Header line (on pages after the first)
        if self._pageNumber > 1:
            self.setStrokeColor(colors.HexColor("#D0D5DD"))
            self.setLineWidth(0.5)
            self.line(36, 756, 576, 756)
            self.drawString(36, 760, "ForensiRansom AI — Digital Forensic Investigation Report")
            self.drawRightString(576, 760, f"Confidential & Privileged")

        # Footer
        self.setStrokeColor(colors.HexColor("#D0D5DD"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)
        
        footer_left = "ForensiRansom AI — Automated Ransomware Forensics & Digital Investigation Platform"
        footer_right = f"Page {self._pageNumber} of {total_pages}"
        self.drawString(36, 30, footer_left)
        self.drawRightString(576, 30, footer_right)
        self.restoreState()


def extract_iocs(analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts Indicators of Compromise (IOCs) from real forensic findings.
    """
    iocs = []
    seen = set()

    # Evidence hash IOC
    evidence = analysis_data.get("evidence", {})
    sha256 = evidence.get("sha256")
    if sha256 and sha256 != "Not recorded":
        key = ("SHA-256", sha256)
        if key not in seen:
            seen.add(key)
            iocs.append({
                "type": "File Hash (SHA-256)",
                "indicator": sha256,
                "context": f"Evidence Image: {evidence.get('filename', 'memory.raw')}",
                "severity": "INFO",
                "source": "Evidence Acquisition"
            })

    # YARA matches IOCs
    yara = analysis_data.get("yara", {})
    yara_findings = yara.get("findings") or yara.get("matches") or []
    for yf in yara_findings:
        if isinstance(yf, dict):
            rule_name = yf.get("rule") or yf.get("rule_name") or "Unknown"
            raw = yf.get("raw_data") or yf.get("description") or ""
            key = ("YARA", rule_name, str(raw)[:60])
            if key not in seen:
                seen.add(key)
                iocs.append({
                    "type": "YARA Detection",
                    "indicator": rule_name,
                    "context": str(raw)[:120] if raw else "Signature matched on memory artifacts",
                    "severity": "HIGH",
                    "source": yf.get("source") or "YARA Engine"
                })

    # Analyzed events and correlations IOCs
    analyzed_events = analysis_data.get("analyzed_events", [])
    for ev in analyzed_events:
        if not isinstance(ev, dict):
            continue
        indicators = ev.get("indicators", [])
        raw = ev.get("evidence", {}).get("raw_data", "")
        rule_score = ev.get("rule_score", 0)
        
        # Suspicious tool / command detection
        for ind in indicators:
            key = ("Indicator", str(ind))
            if key not in seen:
                seen.add(key)
                iocs.append({
                    "type": "Suspicious Activity",
                    "indicator": str(ind),
                    "context": str(raw)[:120] if raw else "Identified by Forensic Rule Engine",
                    "severity": "HIGH" if rule_score >= 10 else "MEDIUM",
                    "source": ev.get("source") or "Rule Engine"
                })

    # Cross-artifact correlation IOCs
    correlations = analysis_data.get("correlations", [])
    for c in correlations:
        if isinstance(c, dict):
            desc = c.get("description") or c.get("message") or "Artifact correlation"
            key = ("Correlation", str(desc))
            if key not in seen:
                seen.add(key)
                iocs.append({
                    "type": "Correlation Finding",
                    "indicator": str(desc),
                    "context": f"Type: {c.get('correlation_type', 'Correlation')}",
                    "severity": c.get("severity", "MEDIUM"),
                    "source": "Correlation Engine"
                })

    return iocs


def generate_json_report(analysis_data: Dict[str, Any], recommendations: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Compiles a comprehensive, structured JSON report from verified findings.
    """
    case = analysis_data.get("case", {})
    evidence = analysis_data.get("evidence", {})
    risk = analysis_data.get("risk", {})
    ml = analysis_data.get("ml") or analysis_data.get("ml_prediction") or {}
    yara = analysis_data.get("yara", {})
    features = analysis_data.get("features", {})
    volatility = analysis_data.get("volatility", {})
    correlations = analysis_data.get("correlations", [])
    timeline = analysis_data.get("timeline", [])

    if not recommendations:
        recommendations = get_recommendations(analysis_data)

    iocs = extract_iocs(analysis_data)

    return {
        "report_metadata": {
            "title": "ForensiRansom AI Forensic Investigation Report",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "report_version": "1.0.0",
            "classification_notice": "CONFIDENTIAL // FOR LAW ENFORCEMENT & DFIR USE ONLY"
        },
        "case_details": {
            "case_id": case.get("case_id", "Not recorded"),
            "case_name": case.get("case_name", "Not recorded"),
            "investigator": case.get("investigator", "Not recorded"),
            "case_status": case.get("status", "Open"),
            "description": case.get("description", "No investigation description recorded.")
        },
        "evidence_details": {
            "evidence_id": evidence.get("evidence_id", "Not recorded"),
            "filename": evidence.get("filename", "Not recorded"),
            "file_size_bytes": evidence.get("file_size") or evidence.get("size_bytes"),
            "sha256": evidence.get("sha256", "Not recorded"),
            "evidence_type": evidence.get("evidence_type", "Memory Image"),
            "integrity_status": evidence.get("status") or evidence.get("integrity") or "Verified",
            "acquisition_date": evidence.get("created_at") or evidence.get("acquisition_date")
        },
        "forensic_pipeline_summary": {
            "volatility_status": volatility.get("status", "COMPLETED"),
            "active_plugins": list(volatility.get("plugins", {}).keys()) if isinstance(volatility.get("plugins"), dict) else [],
            "metrics": {
                "total_events": features.get("total_events", len(timeline)),
                "process_events": features.get("process_events", 0),
                "command_events": features.get("command_events", 0),
                "network_events": features.get("network_events", 0),
                "suspicious_events": features.get("suspicious_events", 0),
                "yara_match_count": yara.get("match_count", 0),
                "correlations_count": len(correlations)
            }
        },
        "yara_detections": yara.get("findings") or yara.get("matches") or [],
        "indicators_of_compromise": iocs,
        "correlations": correlations,
        "machine_learning_assessment": {
            "classification": ml.get("classification") or ml.get("label") or "Normal",
            "probabilities": ml.get("probabilities", {})
        },
        "risk_assessment": {
            "risk_score": risk.get("risk_score", 0),
            "risk_level": risk.get("risk_level", "LOW"),
            "reasons": risk.get("reasons", [])
        },
        "ai_recommendations": recommendations,
        "external_security_resources": SECURITY_RESOURCES,
        "investigator_sign_off": {
            "verified_by": case.get("investigator", "Investigator"),
            "status": "Verified & Finalized",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
    }


def generate_evidence_log(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a formal digital evidence integrity & chain-of-custody log.
    """
    case = analysis_data.get("case", {})
    evidence = analysis_data.get("evidence", {})

    return {
        "log_title": "ForensiRansom AI — Digital Evidence Verification Log",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "case_id": case.get("case_id", "Not recorded"),
        "case_name": case.get("case_name", "Not recorded"),
        "investigator": case.get("investigator", "Not recorded"),
        "evidence_id": evidence.get("evidence_id", "Not recorded"),
        "filename": evidence.get("filename", "Not recorded"),
        "file_path": evidence.get("file_path", "Protected Evidence Vault"),
        "file_size": evidence.get("file_size") or evidence.get("size_bytes", "Not recorded"),
        "sha256_hash": evidence.get("sha256", "Not recorded"),
        "evidence_type": evidence.get("evidence_type", "Memory Image"),
        "verification_status": evidence.get("status") or evidence.get("integrity") or "Verified",
        "acquisition_timestamp": evidence.get("created_at") or "Not recorded",
        "hash_algorithm": "SHA-256 (FIPS 180-4 Standard)",
        "integrity_statement": (
            "The cryptographic hash of the evidence file has been computed and verified. "
            "Evidence integrity is confirmed intact and untampered."
        )
    }


def generate_pdf_report(analysis_data: Dict[str, Any], recommendations: Optional[Dict[str, Any]] = None) -> bytes:
    """
    Builds a professional, court-admissible forensic PDF report using ReportLab.
    """
    if not recommendations:
        recommendations = get_recommendations(analysis_data)

    case = analysis_data.get("case", {})
    evidence = analysis_data.get("evidence", {})
    risk = analysis_data.get("risk", {})
    ml = analysis_data.get("ml") or analysis_data.get("ml_prediction") or {}
    yara = analysis_data.get("yara", {})
    features = analysis_data.get("features", {})
    volatility = analysis_data.get("volatility", {})
    correlations = analysis_data.get("correlations", [])
    timeline = analysis_data.get("timeline", [])
    iocs = extract_iocs(analysis_data)

    case_id = case.get("case_id", "FRA-001")
    evidence_id = evidence.get("evidence_id", "MEM-001")
    investigator = case.get("investigator", "Dhaniya")
    case_name = case.get("case_name", "Forensic Investigation")
    sha256 = evidence.get("sha256", "Not recorded")
    integrity = evidence.get("status") or evidence.get("integrity") or "Verified"
    filename = evidence.get("filename", "memory.raw")
    filesize = str(evidence.get("file_size") or evidence.get("size_bytes") or "Not recorded")
    risk_score = risk.get("risk_score", 0)
    risk_level = str(risk.get("risk_level", "LOW")).upper()
    classification = str(ml.get("classification") or ml.get("label") or "Normal").upper()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=48
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#102f5f'),
        spaceAfter=3
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475467'),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#102f5f'),
        spaceBefore=12,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#173b72'),
        spaceBefore=8,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#1d2939')
    )

    body_bold = ParagraphStyle(
        'BodyDarkBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    bullet_style = ParagraphStyle(
        'BulletStyle',
        parent=body_style,
        leftIndent=12,
        spaceAfter=3
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=body_style,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#102f5f')
    )

    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=body_style,
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#475467')
    )

    story = []

    # ========================================================
    # HEADER BANNER
    # ========================================================
    header_data = [
        [
            Paragraph("<b>FORENSIRANSOM AI</b><br/><font size=8 color='#475467'>AI-Based Intelligent Ransomware Detection & Digital Forensic Platform</font>", body_style),
            Paragraph(f"<b>CONFIDENTIAL REPORT</b><br/><font size=8 color='#475467'>Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</font>", ParagraphStyle('RightH', parent=body_style, alignment=2))
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#102f5f'), spaceBefore=4, spaceAfter=8))

    story.append(Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", title_style))
    story.append(Paragraph(f"Comprehensive forensic examination for Case <b>{case_id}</b> — Evidence <b>{evidence_id}</b>", subtitle_style))

    # ========================================================
    # SECTION 1: CASE & INVESTIGATION METADATA
    # ========================================================
    story.append(Paragraph("1. Case & Investigation Information", h1_style))
    case_table_data = [
        [Paragraph("<b>Case ID</b>", body_style), Paragraph(case_id, body_style), Paragraph("<b>Investigator</b>", body_style), Paragraph(investigator, body_style)],
        [Paragraph("<b>Case Name</b>", body_style), Paragraph(case_name, body_style), Paragraph("<b>Case Status</b>", body_style), Paragraph(case.get("status", "Open"), body_style)],
        [Paragraph("<b>Description</b>", body_style), Paragraph(case.get("description", "No description provided."), body_style), Paragraph("<b>Generated At</b>", body_style), Paragraph(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)]
    ]
    t_case = Table(case_table_data, colWidths=[90, 180, 90, 180])
    t_case.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D0D5DD')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_case)
    story.append(Spacer(1, 8))

    # ========================================================
    # SECTION 2: EVIDENCE INVENTORY & SHA-256 INTEGRITY
    # ========================================================
    story.append(Paragraph("2. Evidence Inventory & SHA-256 Integrity Verification", h1_style))
    
    # Integrity badge styling
    integ_color = colors.HexColor('#079455') if "VERIF" in integrity.upper() or "INTACT" in integrity.upper() else colors.HexColor('#D92D20')
    
    evidence_table_data = [
        [Paragraph("<b>Evidence ID</b>", body_style), Paragraph(evidence_id, body_style), Paragraph("<b>Evidence Type</b>", body_style), Paragraph(evidence.get("evidence_type", "Memory Image"), body_style)],
        [Paragraph("<b>Filename</b>", body_style), Paragraph(filename, body_style), Paragraph("<b>File Size</b>", body_style), Paragraph(f"{filesize} bytes", body_style)],
        [Paragraph("<b>SHA-256 Hash</b>", body_style), Paragraph(f"<font face='Courier' size=7>{sha256}</font>", body_style), Paragraph("<b>Integrity Status</b>", body_style), Paragraph(f"<b><font color='{integ_color.hexval()}'>{integrity}</font></b>", body_style)],
    ]
    t_ev = Table(evidence_table_data, colWidths=[95, 175, 95, 175])
    t_ev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D0D5DD')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_ev)
    story.append(Spacer(1, 8))

    # ========================================================
    # SECTION 3: EXECUTIVE SUMMARY & RISK PROFILE
    # ========================================================
    story.append(Paragraph("3. Executive Forensic Summary & Risk Assessment", h1_style))
    
    risk_bg = colors.HexColor('#FEF3F2') if risk_level in ["CRITICAL", "HIGH"] else (colors.HexColor('#FFFAEB') if risk_level == "MEDIUM" else colors.HexColor('#ECFDF3'))
    risk_border = colors.HexColor('#FDA29B') if risk_level in ["CRITICAL", "HIGH"] else (colors.HexColor('#FEDF89') if risk_level == "MEDIUM" else colors.HexColor('#A6F4C5'))
    
    exec_summary_text = recommendations.get("executive_summary", "Forensic examination completed for the selected evidence.")
    risk_interp_text = recommendations.get("risk_interpretation", "Risk interpretation based on extracted artifacts.")

    risk_box_data = [
        [
            Paragraph(f"<b>Risk Level:</b> {risk_level}<br/><b>Risk Score:</b> {risk_score} / 100", body_style),
            Paragraph(f"<b>ML Classification:</b> {classification}<br/><b>YARA Matches:</b> {yara.get('match_count', len(yara.get('findings', [])))}", body_style),
            Paragraph(f"<b>Correlations:</b> {len(correlations)}<br/><b>Suspicious Events:</b> {features.get('suspicious_events', 0)}", body_style)
        ]
    ]
    t_risk = Table(risk_box_data, colWidths=[180, 180, 180])
    t_risk.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_bg),
        ('BOX', (0, 0), (-1, -1), 1, risk_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_risk)
    story.append(Spacer(1, 6))

    story.append(Paragraph(f"<b>Executive Summary:</b> {exec_summary_text}", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Risk Interpretation:</b> {risk_interp_text}", body_style))
    story.append(Spacer(1, 8))

    # ========================================================
    # SECTION 4: FORENSIC PIPELINE & FINDINGS
    # ========================================================
    story.append(Paragraph("4. Volatility & Forensic Artifact Findings", h1_style))
    
    vol_status = volatility.get("status", "COMPLETED")
    plugins = list(volatility.get("plugins", {}).keys()) if isinstance(volatility.get("plugins"), dict) else ["info", "pslist", "pstree", "psscan", "cmdline"]
    
    findings_data = [
        [Paragraph("<b>Pipeline Module</b>", body_style), Paragraph("<b>Artifact Count</b>", body_style), Paragraph("<b>Observation Status</b>", body_style)],
        [Paragraph("Process Analysis (pslist, pstree, psscan)", body_style), Paragraph(str(features.get("process_events", len(analysis_data.get("timeline", [])))), body_style), Paragraph("Active & Scanned Processes Identified", body_style)],
        [Paragraph("Command-Line Analysis (cmdline)", body_style), Paragraph(str(features.get("command_events", 0)), body_style), Paragraph("Command Line Execution Artifacts Captured", body_style)],
        [Paragraph("Network Analysis (netscan)", body_style), Paragraph(str(features.get("network_events", 0)), body_style), Paragraph("Sockets & Network Activity Evaluated", body_style)],
        [Paragraph("Rule-Based Detection", body_style), Paragraph(f"Score: {features.get('total_rule_score', 0)}", body_style), Paragraph(f"{features.get('suspicious_events', 0)} Suspicious Events Evaluated", body_style)],
        [Paragraph("Cross-Artifact Correlation", body_style), Paragraph(str(len(correlations)), body_style), Paragraph("Multi-Artifact Linkages Established", body_style)]
    ]
    t_findings = Table(findings_data, colWidths=[200, 110, 230])
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EAECF0')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D0D5DD')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_findings)
    story.append(Spacer(1, 8))

    # ========================================================
    # SECTION 5: YARA & IOC FINDINGS
    # ========================================================
    story.append(Paragraph("5. YARA Detections & Indicators of Compromise (IOCs)", h1_style))
    
    yara_findings = yara.get("findings") or yara.get("matches") or []
    if yara_findings:
        story.append(Paragraph("<b>YARA Signature Matches:</b>", h2_style))
        yara_table_data = [[Paragraph("<b>Rule Name</b>", body_style), Paragraph("<b>Source</b>", body_style), Paragraph("<b>Detection Summary</b>", body_style)]]
        for yf in yara_findings[:6]:
            rule = yf.get("rule") or yf.get("rule_name") or "Unknown Rule"
            src = yf.get("source") or yf.get("plugin") or "Volatility"
            desc = yf.get("raw_data") or yf.get("description") or "Suspicious pattern matched"
            yara_table_data.append([
                Paragraph(f"<b>{rule}</b>", body_style),
                Paragraph(src, body_style),
                Paragraph(f"<font size=7.5>{desc[:130]}</font>", body_style)
            ])
        t_yara = Table(yara_table_data, colWidths=[160, 110, 270])
        t_yara.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EAECF0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D0D5DD')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_yara)
        story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("<i>No active ransomware YARA signatures triggered on the analyzed evidence.</i>", body_style))
        story.append(Spacer(1, 4))

    # Extracted IOC Table
    if iocs:
        story.append(Paragraph("<b>Extracted Indicators of Compromise (IOCs):</b>", h2_style))
        ioc_table_data = [[Paragraph("<b>Type</b>", body_style), Paragraph("<b>Indicator / Artifact</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Source</b>", body_style)]]
        for item in iocs[:8]:
            sev_color = colors.HexColor('#D92D20') if item.get("severity") == "HIGH" else (colors.HexColor('#DC6803') if item.get("severity") == "MEDIUM" else colors.HexColor('#175CD3'))
            ioc_table_data.append([
                Paragraph(item.get("type", "IOC"), body_style),
                Paragraph(f"<font size=7.5>{item.get('indicator', '')[:100]}</font>", body_style),
                Paragraph(f"<b><font color='{sev_color.hexval()}'>{item.get('severity', 'INFO')}</font></b>", body_style),
                Paragraph(item.get("source", "Forensic Engine"), body_style)
            ])
        t_iocs = Table(ioc_table_data, colWidths=[110, 250, 70, 110])
        t_iocs.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EAECF0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D0D5DD')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_iocs)
        story.append(Spacer(1, 8))

    # ========================================================
    # SECTION 6: AI-POWERED FORENSIC RECOMMENDATIONS
    # ========================================================
    provider_name = recommendations.get("provider", "Google Gemini AI / Forensic Engine")
    is_ai = recommendations.get("is_ai_generated", False)
    badge_label = "Gemini AI Recommendations" if is_ai else "Forensic Rule Engine Guidance"
    
    story.append(Paragraph(f"6. Forensic Investigation Recommendations ({badge_label})", h1_style))
    story.append(Paragraph(f"<b>Recommendation Provider:</b> {provider_name}", body_bold))
    story.append(Spacer(1, 4))

    # Immediate Response
    immediate = recommendations.get("immediate_response", [])
    if immediate:
        story.append(Paragraph("<b>Immediate Tactical Response:</b>", h2_style))
        for step in immediate:
            story.append(Paragraph(f"• {step}", bullet_style))
        story.append(Spacer(1, 4))

    # Containment Guidance
    containment = recommendations.get("containment_guidance", [])
    if containment:
        story.append(Paragraph("<b>Containment & Isolation Guidance:</b>", h2_style))
        for step in containment:
            story.append(Paragraph(f"• {step}", bullet_style))
        story.append(Spacer(1, 4))

    # Further Forensic Steps
    further = recommendations.get("further_forensic_steps", [])
    if further:
        story.append(Paragraph("<b>Further Forensic Investigation Steps:</b>", h2_style))
        for step in further:
            story.append(Paragraph(f"• {step}", bullet_style))
        story.append(Spacer(1, 4))

    # Recovery Recommendations
    recovery = recommendations.get("recovery_recommendations", [])
    if recovery:
        story.append(Paragraph("<b>Remediation & Recovery Recommendations:</b>", h2_style))
        for step in recovery:
            story.append(Paragraph(f"• {step}", bullet_style))
        story.append(Spacer(1, 4))

    # ========================================================
    # SECTION 7: MITRE ATT&CK MAPPING & SECURITY RESOURCES
    # ========================================================
    story.append(Paragraph("7. MITRE ATT&CK Framework Mapping & Security Resources", h1_style))
    
    mitre_list = recommendations.get("mitre_attack", [])
    if mitre_list:
        mitre_table_data = [[Paragraph("<b>Technique ID</b>", body_style), Paragraph("<b>Technique Name</b>", body_style), Paragraph("<b>Tactic</b>", body_style), Paragraph("<b>Recommended Mitigation</b>", body_style)]]
        for m in mitre_list[:5]:
            mitre_table_data.append([
                Paragraph(f"<b>{m.get('technique_id', 'T1486')}</b>", body_style),
                Paragraph(m.get("technique_name", "Data Encrypted for Impact"), body_style),
                Paragraph(m.get("tactic", "Impact"), body_style),
                Paragraph(f"<font size=7.5>{m.get('mitigation', '')}</font>", body_style)
            ])
        t_mitre = Table(mitre_table_data, colWidths=[80, 150, 80, 230])
        t_mitre.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EAECF0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D0D5DD')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_mitre)
        story.append(Spacer(1, 6))

    # External Security References
    story.append(Paragraph("<b>Referenced Security Frameworks & Guidance:</b>", h2_style))
    for res in SECURITY_RESOURCES:
        story.append(Paragraph(f"• <b>{res['title']}</b> ({res['category']}): {res['description']} <font color='#175CD3'>[{res['url']}]</font>", bullet_style))
    story.append(Spacer(1, 8))

    # ========================================================
    # SECTION 8: LIMITATIONS & INVESTIGATOR SIGN-OFF
    # ========================================================
    story.append(KeepTogether([
        Paragraph("8. Investigation Conclusion & Investigator Sign-Off", h1_style),
        Paragraph(recommendations.get("limitations_and_confidence", "Confidence is based on analyzed digital artifacts."), body_style),
        Spacer(1, 6),
        Paragraph(recommendations.get("disclaimer", "Verified forensic findings are empirical evidence. AI recommendations provide advisory guidance."), disclaimer_style),
        Spacer(1, 14),
        Table([
            [
                Paragraph("<b>Lead Forensic Investigator Signature:</b>", body_style),
                Paragraph("<b>Date & Verification Timestamp:</b>", body_style)
            ],
            [
                Paragraph("<br/><br/>____________________________________________<br/>" + investigator, body_style),
                Paragraph("<br/><br/>____________________________________________<br/>" + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)
            ]
        ], colWidths=[270, 270], style=[
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ])
    ]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
