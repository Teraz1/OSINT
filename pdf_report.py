"""
reports/pdf_report.py — Generate professional PDF reports from scan results.
Uses ReportLab (pure Python, no wkhtmltopdf needed).
"""

import json
import os
from datetime import datetime
from pathlib import Path

from config import get

REPORTS_DIR = Path(get("reports.output_dir", "reports"))
REPORTS_DIR.mkdir(exist_ok=True)

COMPANY = get("reports.company_name", "OSINT System")

SEV_COLORS_HEX = {
    "CRITICAL": (255, 45, 85),
    "HIGH":     (255, 107, 53),
    "MEDIUM":   (255, 214, 10),
    "LOW":      (48, 209, 88),
    "UNKNOWN":  (100, 100, 100),
}


def _normalize_color(rgb_tuple):
    """Convert 0-255 RGB to 0-1 for ReportLab."""
    return tuple(v / 255 for v in rgb_tuple)


def generate_pdf(scan_id: str, results: dict) -> str:
    """Generate a PDF report and return the file path."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        raise RuntimeError("reportlab not installed. Run: pip3 install reportlab --break-system-packages")

    target = results.get("target", "unknown")
    timestamp = results.get("timestamp", datetime.utcnow().isoformat())
    risk = results.get("risk", {})
    input_type = results.get("input_type", "")

    output_path = REPORTS_DIR / f"report_{scan_id}_{target.replace('.','_')}.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    W = A4[0] - 4*cm

    # Custom styles
    title_style = ParagraphStyle("Title", parent=styles["Heading1"],
        fontSize=22, textColor=colors.HexColor("#00d4ff"), spaceAfter=6)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#00ff9d"), spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("Body", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#c8d8e8"), spaceAfter=4, leading=14)
    mono_style = ParagraphStyle("Mono", parent=styles["Code"],
        fontSize=8, textColor=colors.HexColor("#00d4ff"),
        backColor=colors.HexColor("#0e1822"), spaceAfter=2)
    muted_style = ParagraphStyle("Muted", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#4a6070"), spaceAfter=2)

    BG = colors.HexColor("#060a0f")
    BORDER = colors.HexColor("#1a2d40")
    ACCENT = colors.HexColor("#00d4ff")
    PANEL = colors.HexColor("#0e1822")

    story = []

    # ── HEADER ──
    story.append(Paragraph(f"{COMPANY}", muted_style))
    story.append(Paragraph("OSINT & VULNERABILITY REPORT", title_style))
    story.append(HRFlowable(width=W, thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.3*cm))

    # Meta table
    risk_rgb = SEV_COLORS_HEX.get(risk.get("level", "LOW"), (100,100,100))
    risk_color = colors.Color(*_normalize_color(risk_rgb))
    meta_data = [
        ["Target", target],
        ["Input Type", input_type.upper()],
        ["Scan ID", scan_id],
        ["Timestamp", timestamp],
        ["Risk Level", risk.get("level", "—")],
        ["Risk Score", f"{risk.get('score', 0)}/100"],
    ]
    meta_table = Table(meta_data, colWidths=[3*cm, W-3*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), PANEL),
        ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#4a6070")),
        ("TEXTCOLOR", (1,0), (1,-1), colors.HexColor("#c8d8e8")),
        ("FONTNAME", (0,0), (-1,-1), "Courier"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#0e1822"), colors.HexColor("#0b1117")]),
        ("GRID", (0,0), (-1,-1), 0.5, BORDER),
        ("PADDING", (0,0), (-1,-1), 6),
        ("TEXTCOLOR", (1,4), (1,4), risk_color),
        ("FONTNAME", (1,4), (1,5), "Courier-Bold"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.4*cm))

    # Risk factors
    if risk.get("factors"):
        story.append(Paragraph("Risk Factors", h2_style))
        for f in risk["factors"]:
            story.append(Paragraph(f"▸  {f}", body_style))

    story.append(PageBreak())

    # ── OPEN PORTS ──
    ports = results.get("nmap", {}).get("ports", [])
    if ports:
        story.append(Paragraph("Open Ports & Services", h2_style))
        port_data = [["Port", "Protocol", "Service", "Version"]]
        for p in ports:
            port_data.append([
                str(p.get("port", "")),
                p.get("protocol", ""),
                p.get("service", ""),
                p.get("version", "")[:60] or "—",
            ])
        pt = Table(port_data, colWidths=[1.5*cm, 2*cm, 3*cm, W-6.5*cm])
        pt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), ACCENT),
            ("TEXTCOLOR", (0,0), (-1,0), colors.black),
            ("FONTNAME", (0,0), (-1,0), "Courier-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("FONTNAME", (0,1), (-1,-1), "Courier"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0e1822"), colors.HexColor("#0b1117")]),
            ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor("#c8d8e8")),
            ("GRID", (0,0), (-1,-1), 0.3, BORDER),
            ("PADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(pt)
        story.append(Spacer(1, 0.3*cm))

    # ── NUCLEI VULNERABILITIES ──
    vulns = results.get("nuclei", {}).get("vulnerabilities", [])
    if vulns:
        story.append(Paragraph("Vulnerability Findings (Nuclei)", h2_style))
        for v in vulns:
            sev = v.get("severity", "unknown").upper()
            sev_rgb = SEV_COLORS_HEX.get(sev, (100,100,100))
            sev_color = colors.Color(*_normalize_color(sev_rgb))
            row = [
                [Paragraph(f"<b>{v.get('name','?')}</b>", body_style),
                 Paragraph(f"<font color='#{sev_rgb[0]:02x}{sev_rgb[1]:02x}{sev_rgb[2]:02x}'><b>{sev}</b></font>", body_style)],
            ]
            t = Table([[
                Paragraph(f"<b>{v.get('name','?')}</b>", body_style),
                Paragraph(f"<b>{sev}</b>", ParagraphStyle("S", parent=body_style,
                    textColor=sev_color, alignment=TA_RIGHT))
            ]], colWidths=[W-3*cm, 3*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), PANEL),
                ("GRID", (0,0), (-1,-1), 0.5, BORDER),
                ("PADDING", (0,0), (-1,-1), 6),
            ]))
            story.append(t)
            story.append(Paragraph(v.get("description","")[:300], muted_style))
            story.append(Paragraph(f"URL: {v.get('matched_url','')}", mono_style))
            story.append(Spacer(1, 0.2*cm))

    # ── CVEs ──
    cves = results.get("cve", {}).get("cves", [])
    if cves:
        story.append(Paragraph("CVE Findings (NVD)", h2_style))
        cve_data = [["CVE ID", "Service", "Port", "CVSS", "Severity"]]
        for c in cves[:30]:
            sev = c.get("severity", "UNKNOWN")
            cve_data.append([
                c.get("cve_id", ""), c.get("service", ""),
                str(c.get("port", "")), str(c.get("cvss_score", "")), sev,
            ])
        ct = Table(cve_data, colWidths=[3.5*cm, 2.5*cm, 1.5*cm, 1.5*cm, 2.5*cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), ACCENT),
            ("TEXTCOLOR", (0,0), (-1,0), colors.black),
            ("FONTNAME", (0,0), (-1,0), "Courier-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("FONTNAME", (0,1), (-1,-1), "Courier"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0e1822"), colors.HexColor("#0b1117")]),
            ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor("#c8d8e8")),
            ("GRID", (0,0), (-1,-1), 0.3, BORDER),
            ("PADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(ct)
        story.append(Spacer(1, 0.3*cm))

    # ── SUBDOMAINS ──
    subs = results.get("all_subdomains", [])
    if subs:
        story.append(Paragraph(f"Subdomains ({len(subs)} found)", h2_style))
        # 3-column layout
        cols = [subs[i::3] for i in range(3)]
        max_rows = max(len(c) for c in cols)
        sub_data = []
        for i in range(max_rows):
            sub_data.append([
                cols[0][i] if i < len(cols[0]) else "",
                cols[1][i] if i < len(cols[1]) else "",
                cols[2][i] if i < len(cols[2]) else "",
            ])
        st = Table(sub_data, colWidths=[W/3]*3)
        st.setStyle(TableStyle([
            ("FONTNAME", (0,0), (-1,-1), "Courier"),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor("#00ff9d")),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#0e1822"), colors.HexColor("#060a0f")]),
            ("GRID", (0,0), (-1,-1), 0.2, BORDER),
            ("PADDING", (0,0), (-1,-1), 3),
        ]))
        story.append(st)
        story.append(Spacer(1, 0.3*cm))

    # ── BREACH DATA ──
    hibp = results.get("hibp", {})
    if hibp.get("pwned"):
        story.append(Paragraph("Breach Data (HaveIBeenPwned)", h2_style))
        story.append(Paragraph(
            f"Found in {hibp.get('breach_count', 0)} breach(es)", body_style))
        for b in hibp.get("breaches", [])[:20]:
            story.append(Paragraph(
                f"• <b>{b.get('name','')}</b> ({b.get('date','')}) — {', '.join(b.get('data_classes',[])[:5])}",
                muted_style))

    # ── IP INTEL ──
    geo = results.get("ip_geo", {})
    if geo.get("status") == "ok":
        story.append(Paragraph("IP Intelligence", h2_style))
        geo_data = [[k, str(v)] for k,v in geo.items() if k not in ["status"] and v]
        gt = Table(geo_data, colWidths=[3*cm, W-3*cm])
        gt.setStyle(TableStyle([
            ("FONTNAME", (0,0), (-1,-1), "Courier"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#4a6070")),
            ("TEXTCOLOR", (1,0), (1,-1), colors.HexColor("#c8d8e8")),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#0e1822"), colors.HexColor("#0b1117")]),
            ("GRID", (0,0), (-1,-1), 0.3, BORDER),
            ("PADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(gt)

    # ── FOOTER ──
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width=W, thickness=0.5, color=BORDER))
    story.append(Paragraph(
        f"Generated by {COMPANY} OSINT System · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · Scan {scan_id}",
        muted_style))

    doc.build(story)
    return str(output_path)
