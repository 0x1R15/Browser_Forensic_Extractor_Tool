import os
import json
import csv
import pandas as pd
from datetime import datetime

# Standard ReportLab imports
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
except ImportError:
    # Fallback placeholders in case reportlab is still installing
    pass

class NumberedCanvas(canvas.Canvas):
    """Canvas subclass to dynamically add 'Page X of Y' and headers/footers."""
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

    def draw_page_decorations(self, page_count):
        self.saveState()
        
        # Suppress header/footer on cover page if it is page 1
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#475569"))
            self.drawString(54, 750, "BROWSER FORENSIC EXTRACTOR - CASE REPORT")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 742, letter[0]-54, 742)
            
        # Draw footer on all pages
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(54, 36, "CONFIDENTIAL // EVIDENCE INTEGRITY VERIFIED (READ-ONLY)")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0]-54, 36, page_str)
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 50, letter[0]-54, 50)
        
        self.restoreState()

def export_json(all_data: dict, anomalies: list, case_meta: dict, filepath: str):
    """Exports all parsed data, anomalies, and metadata into a structured JSON file."""
    report = {
        "report_generated_at": datetime.now().isoformat(),
        "case_metadata": case_meta,
        "anomalies": anomalies,
        "browsers_extracted": list(all_data.keys()),
        "artifacts": all_data
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

def export_csv(all_data: dict, filepath: str):
    """Exports a unified, chronological timeline of history, downloads, and autofill to CSV."""
    timeline_records = []
    
    for profile, data in all_data.items():
        # History
        for h in data.get('history', []):
            timeline_records.append({
                'Timestamp': h['timestamp'],
                'Browser': h['browser'],
                'Source Table': h['source'],
                'Event Type': 'Page Visit',
                'Primary Info': h['url'],
                'Secondary Info': h['title'],
                'Detail Value': f"Visit count: {h['visit_count']}, Typed count: {h['typed_count']}, Duration: {h['visit_duration']}s"
            })
        # Downloads
        for dl in data.get('downloads', []):
            timeline_records.append({
                'Timestamp': dl['timestamp'],
                'Browser': dl['browser'],
                'Source Table': dl['source'],
                'Event Type': f"Download ({dl['state']})",
                'Primary Info': dl['file_name'],
                'Secondary Info': dl['target_path'],
                'Detail Value': f"Size: {dl['total_bytes']} bytes, Referrer: {dl['referrer']}"
            })
        # Cookies
        for c in data.get('cookies', []):
            timeline_records.append({
                'Timestamp': c['timestamp'],
                'Browser': c['browser'],
                'Source Table': c['source'],
                'Event Type': 'Cookie Creation',
                'Primary Info': f"{c['host']} (Name: {c['name']})",
                'Secondary Info': c['path'],
                'Detail Value': f"Expiry: {c['expiry']}, Secure: {c['is_secure']}, HttpOnly: {c['is_httponly']}"
            })
        # Autofill
        for af in data.get('autofill', []):
            timeline_records.append({
                'Timestamp': af['timestamp'],
                'Browser': af['browser'],
                'Source Table': af['source'],
                'Event Type': 'Autofill Entry',
                'Primary Info': af['field_name'],
                'Secondary Info': af['value'],
                'Detail Value': f"Used count: {af['count']}"
            })
            
    if not timeline_records:
        # Write empty CSV with headers
        keys = ['Timestamp', 'Browser', 'Source Table', 'Event Type', 'Primary Info', 'Secondary Info', 'Detail Value']
        df = pd.DataFrame(columns=keys)
    else:
        df = pd.DataFrame(timeline_records)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df = df.sort_values(by='Timestamp', ascending=False)
        
    df.to_csv(filepath, index=False, encoding='utf-8')

def generate_pdf_report(all_data: dict, anomalies: list, case_meta: dict, filepath: str):
    """Generates a professional, high-fidelity PDF forensic report using ReportLab."""
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Palette Styling
    dark_slate = colors.HexColor("#0F172A")
    primary_blue = colors.HexColor("#2563EB")
    border_slate = colors.HexColor("#CBD5E1")
    alert_red = colors.HexColor("#EF4444")
    alert_amber = colors.HexColor("#F59E0B")
    bg_light = colors.HexColor("#F8FAFC")
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=dark_slate,
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=primary_blue,
        spaceAfter=15
    )
    
    h1_style = ParagraphStyle(
        'H1Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=dark_slate,
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    
    bold_body_style = ParagraphStyle(
        'BoldBodyStyle',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    table_cell_style = ParagraphStyle(
        'TableCellStyle',
        parent=body_style,
        fontSize=8,
        leading=10
    )
    
    table_header_style = ParagraphStyle(
        'TableHeaderStyle',
        parent=table_cell_style,
        fontName='Helvetica-Bold',
        textColor=colors.white
    )
    
    note_style = ParagraphStyle(
        'NoteStyle',
        parent=body_style,
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#475569")
    )

    story = []
    
    # -------------------- TITLE & COVER HEADER --------------------
    story.append(Spacer(1, 15))
    story.append(Paragraph("BROWSER FORENSIC REPORT", title_style))
    story.append(Paragraph("ACQUISITION & ANALYSIS CASE DOCUMENTATION", subtitle_style))
    story.append(Spacer(1, 5))
    
    # -------------------- CASE METADATA TABLE --------------------
    meta_data = [
        [Paragraph("Case Reference ID:", bold_body_style), Paragraph(case_meta.get('case_id', 'N/A'), body_style),
         Paragraph("Device Name:", bold_body_style), Paragraph(case_meta.get('device_name', 'N/A'), body_style)],
        [Paragraph("Lead Investigator:", bold_body_style), Paragraph(case_meta.get('investigator', 'N/A'), body_style),
         Paragraph("Suspect Name:", bold_body_style), Paragraph(case_meta.get('suspect_name', 'N/A'), body_style)],
        [Paragraph("Extraction Date:", bold_body_style), Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S Local'), body_style),
         Paragraph("Forensic Mode:", bold_body_style), Paragraph("Read-Only (Non-Invasive Copying)", body_style)]
    ]
    
    meta_table = Table(meta_data, colWidths=[110, 140, 90, 160])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('GRID', (0,0), (-1,-1), 0.5, border_slate),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))
    
    # -------------------- EXTRACTION SUMMARY STATS --------------------
    story.append(Paragraph("1. Extraction Summary Statistics", h1_style))
    
    summary_headers = ["Browser Profile", "History Visits", "Downloads", "Cookies", "Autofill Fields", "Logins Found"]
    summary_rows = [[Paragraph(h, table_header_style) for h in summary_headers]]
    
    total_hist = 0
    total_dl = 0
    total_cookies = 0
    total_auto = 0
    total_logins = 0
    
    for profile, data in all_data.items():
        h_len = len(data.get('history', []))
        d_len = len(data.get('downloads', []))
        c_len = len(data.get('cookies', []))
        a_len = len(data.get('autofill', []))
        l_len = len(data.get('logins', []))
        
        total_hist += h_len
        total_dl += d_len
        total_cookies += c_len
        total_auto += a_len
        total_logins += l_len
        
        row = [
            Paragraph(profile, table_cell_style),
            Paragraph(str(h_len), table_cell_style),
            Paragraph(str(d_len), table_cell_style),
            Paragraph(str(c_len), table_cell_style),
            Paragraph(str(a_len), table_cell_style),
            Paragraph(str(l_len), table_cell_style),
        ]
        summary_rows.append(row)
        
    # Add Totals Row
    summary_rows.append([
        Paragraph("<b>Total Extracted</b>", table_cell_style),
        Paragraph(f"<b>{total_hist}</b>", table_cell_style),
        Paragraph(f"<b>{total_dl}</b>", table_cell_style),
        Paragraph(f"<b>{total_cookies}</b>", table_cell_style),
        Paragraph(f"<b>{total_auto}</b>", table_cell_style),
        Paragraph(f"<b>{total_logins}</b>", table_cell_style)
    ])
    
    summary_table = Table(summary_rows, colWidths=[150, 70, 70, 70, 70, 70])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_slate),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, bg_light]),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor("#E2E8F0")),
        ('ALIGN', (1,1), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # -------------------- DIAGNOSTIC FINDINGS / ANOMALIES --------------------
    story.append(Paragraph("2. Forensic Anomalies & Diagnostic Flags", h1_style))
    
    if not anomalies:
        story.append(Paragraph("No major anomalies or deleted history indicators were detected during automatic verification.", body_style))
    else:
        anomaly_table_rows = [
            [Paragraph("Severity", table_header_style), Paragraph("Category", table_header_style), Paragraph("Findings Description", table_header_style)]
        ]
        
        for idx, anom in enumerate(anomalies):
            sev = anom['severity']
            sev_color = alert_red if sev == 'High' else alert_amber
            sev_p = Paragraph(f"<font color='{sev_color.hexval()}'><b>{sev}</b></font>", table_cell_style)
            
            cat_p = Paragraph(anom['category'], table_cell_style)
            msg_p = Paragraph(f"<b>{anom['message']}</b><br/><font color='#64748B'>Evidence: {anom.get('evidence', 'N/A')}</font>", table_cell_style)
            
            anomaly_table_rows.append([sev_p, cat_p, msg_p])
            
        anomaly_table = Table(anomaly_table_rows, colWidths=[60, 100, 340])
        anomaly_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
            ('GRID', (0,0), (-1,-1), 0.5, border_slate),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, bg_light]),
        ]))
        story.append(anomaly_table)
        
    story.append(Spacer(1, 20))
    
    # -------------------- CASE INVESTIGATION NOTES --------------------
    story.append(Paragraph("3. Investigator Forensic Narrative & Notes", h1_style))
    notes_text = case_meta.get('notes', '').strip()
    if not notes_text:
        notes_text = "No narrative notes were recorded by the examiner for this case."
    
    notes_box = [[Paragraph(notes_text.replace('\n', '<br/>'), note_style)]]
    notes_table = Table(notes_box, colWidths=[500])
    notes_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F1F5F9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
        ('PADDING', (0,0), (-1,-1), 12),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(notes_table)
    story.append(Spacer(1, 20))
    
    # -------------------- CHRONOLOGICAL TIMELINE SUMMARY (Latest 150) --------------------
    # Compile latest timeline
    timeline_records = []
    for profile, data in all_data.items():
        for h in data.get('history', []):
            timeline_records.append((h['timestamp'], h['browser'], "History", h['url'][:80], h['title'][:40]))
        for dl in data.get('downloads', []):
            timeline_records.append((dl['timestamp'], dl['browser'], "Download", dl['file_name'], dl['target_path'][:60]))
        for c in data.get('cookies', []):
            timeline_records.append((c['timestamp'], c['browser'], "Cookie", f"Cookie set: {c['host']}", c['name']))
        for af in data.get('autofill', []):
            timeline_records.append((af['timestamp'], af['browser'], "Autofill", af['field_name'], af['value']))
            
    # Sort
    timeline_records.sort(key=lambda x: x[0] or "", reverse=True)
    timeline_summary = timeline_records[:150]
    
    story.append(Paragraph(f"4. Consolidated Forensic Timeline Summary (Latest {len(timeline_summary)} Events)", h1_style))
    story.append(Paragraph("<i>Note: The complete, unfiltered timeline is exported inside the companion CSV and JSON report logs.</i>", body_style))
    story.append(Spacer(1, 8))
    
    timeline_headers = ["Timestamp (UTC)", "Browser Source", "Type", "Details / Value"]
    timeline_rows = [[Paragraph(h, table_header_style) for h in timeline_headers]]
    
    for entry in timeline_summary:
        ts = entry[0]
        browser = entry[1]
        type_str = entry[2]
        detail_1 = entry[3]
        detail_2 = entry[4]
        
        detail_str = f"<b>{detail_1}</b>"
        if detail_2:
            detail_str += f"<br/><font color='#64748B'>{detail_2}</font>"
            
        row = [
            Paragraph(ts, table_cell_style),
            Paragraph(browser, table_cell_style),
            Paragraph(type_str, table_cell_style),
            Paragraph(detail_str, table_cell_style)
        ]
        timeline_rows.append(row)
        
    timeline_table = Table(timeline_rows, colWidths=[105, 95, 55, 245])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_blue),
        ('GRID', (0,0), (-1,-1), 0.5, border_slate),
        ('PADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, bg_light]),
    ]))
    
    story.append(timeline_table)
    
    # Build Document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
