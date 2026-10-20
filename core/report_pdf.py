"""
report_pdf.py - builds the corporate-style PDF security audit report with reportlab.

Report layout
    Page 1   Executive summary (report details, overall risk, statistics, top findings)
    Page 2   Scope and methodology (8 checks, scoring model, limitations)
    Next     Detailed findings (one block per file that triggered at least one indicator)
    Next     File inventory with SHA-256 hashes
    Last     Recommendations and disclaimer

The report uses exactly the same result dictionaries that the GUI shows, so the
screen and the PDF can never disagree.
"""
from __future__ import annotations

from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from core import scanner

NAVY = colors.HexColor("#17233c")
BLUE = colors.HexColor("#2f6fed")
GREY = colors.HexColor("#6b7488")
LIGHT = colors.HexColor("#f1f4fa")
LINE = colors.HexColor("#d5dbe8")
LEVEL_COLORS = {            # (text/strong colour, light background)
    "Low concern": (colors.HexColor("#1b7f3b"), colors.HexColor("#e6f4ea")),
    "Review recommended": (colors.HexColor("#9a6700"), colors.HexColor("#fff4d6")),
    "Elevated concern": (colors.HexColor("#c2410c"), colors.HexColor("#ffe8d9")),
    "High concern": (colors.HexColor("#b42318"), colors.HexColor("#fde7e5")),
    "Could not analyse": (colors.HexColor("#5b6475"), colors.HexColor("#eceff4")),
}
MAX_DETAIL_BLOCKS = 150
MAX_INVENTORY_ROWS = 1500

CHECK_PURPOSES = [
    ("1", "Extension / executable type", "Identifies file types that can run code (.exe, .bat, .ps1, .vbs, .js ...).", "10"),
    ("2", "Double extension", "Detects names such as invoice.pdf.exe that disguise a program as a document.", "20"),
    ("3", "File signature (magic bytes)", "Compares the first bytes of the file with its extension to find disguised files.", "20"),
    ("4", "Metadata / file properties", "Looks for hidden executables and impossible or forged timestamps.", "5"),
    ("5", "Entropy", "Measures how random the data is; very random data may be packed or encrypted.", "10"),
    ("6", "PE header inspection", "Validates the internal structure of Windows executables without running them.", "25"),
    ("7", "File size / empty file", "Flags files above the size threshold and empty executables.", "5"),
    ("8", "SHA-256 fingerprint", "Records a unique fingerprint for later comparison. It does not add risk points.", "0"),
]


# ----------------------------------------------------------------- helpers
def safe(text) -> str:
    """Make any text safe for the PDF: standard PDF fonts only cover Latin-1, and < > & must be escaped."""
    cleaned = []
    for ch in str(text):
        if ch == "‮":
            cleaned.append("<U+202E>")
        elif ord(ch) < 32 and ch not in "\t":
            cleaned.append("?")
        elif ord(ch) > 255:
            cleaned.append("?")
        else:
            cleaned.append(ch)
    return escape("".join(cleaned))


def build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold", fontSize=26,
                                textColor=NAVY, alignment=0, spaceAfter=2, leading=30),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontSize=12, textColor=GREY, spaceAfter=14),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=16,
                             textColor=NAVY, spaceBefore=4, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11.5,
                             textColor=BLUE, spaceBefore=10, spaceAfter=5),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13.5, textColor=colors.HexColor("#1d2433")),
        "small": ParagraphStyle("s", parent=base["Normal"], fontSize=8, leading=10.5, textColor=colors.HexColor("#1d2433")),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8.5, leading=11, textColor=colors.HexColor("#1d2433")),
        "cellb": ParagraphStyle("cb", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11,
                                textColor=colors.HexColor("#1d2433")),
        "head": ParagraphStyle("hd", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11,
                               textColor=colors.white),
        "mono": ParagraphStyle("m", parent=base["Normal"], fontName="Courier", fontSize=7, leading=9),
        "big": ParagraphStyle("big", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=22, leading=26,
                              alignment=TA_CENTER),
        "center": ParagraphStyle("ce", parent=base["Normal"], fontSize=9, alignment=TA_CENTER, textColor=GREY),
        "bullet": ParagraphStyle("bu", parent=base["Normal"], fontSize=9.5, leading=13.5, leftIndent=14,
                                 bulletIndent=2, spaceAfter=3),
    }


def table_style(header: bool = True, zebra: bool = True, extra: list | None = None) -> TableStyle:
    cmds = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]
    if header:
        cmds += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
    if zebra:
        cmds += [("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, LIGHT])]
    return TableStyle(cmds + (extra or []))


def level_badge(level: str, styles: dict) -> Paragraph:
    strong, _ = LEVEL_COLORS.get(level, LEVEL_COLORS["Could not analyse"])
    return Paragraph(f'<font color="{strong.hexval().replace("0x", "#")}"><b>{safe(level)}</b></font>', styles["cell"])


# ---------------------------------------------- page header/footer + "Page X of Y"
class _NumberedCanvas(canvas.Canvas):
    meta: dict = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_pages = []

    def showPage(self):
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            self._decorate(total)
            super().showPage()
        super().save()

    def _decorate(self, total: int):
        width, height = A4
        self.saveState()
        self.setFillColor(NAVY)
        self.rect(0, height - 12 * mm, width, 12 * mm, stroke=0, fill=1)
        self.setFillColor(colors.white)
        self.setFont("Helvetica-Bold", 9)
        self.drawString(18 * mm, height - 7.8 * mm, "USB SECURITY AUDITOR")
        self.setFont("Helvetica", 8.5)
        self.drawRightString(width - 18 * mm, height - 7.8 * mm, f"Report {self.meta.get('report_id', '')}")
        self.setStrokeColor(LINE)
        self.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
        self.setFillColor(GREY)
        self.setFont("Helvetica", 7.5)
        self.drawString(18 * mm, 9.5 * mm, "CONFIDENTIAL - Static analysis results are heuristic indicators, not proof of malware.")
        self.drawRightString(width - 18 * mm, 9.5 * mm, f"Page {self._pageNumber} of {total}")
        self.restoreState()


# ------------------------------------------------------------------ sections
def _distribution_chart(summary: dict) -> Drawing:
    """A small horizontal bar chart of how many files fall in each assessment level."""
    levels = scanner.ALL_LEVELS
    counts = [summary["by_level"].get(level, 0) for level in levels]
    top = max(counts + [1])
    drawing = Drawing(480, 22 * len(levels) + 6)
    for i, (level, count) in enumerate(zip(levels, counts)):
        y = 22 * (len(levels) - 1 - i) + 4
        strong, _ = LEVEL_COLORS[level]
        drawing.add(String(0, y + 4, level, fontName="Helvetica", fontSize=8.5, fillColor=colors.HexColor("#1d2433")))
        drawing.add(Rect(120, y, 330, 14, fillColor=LIGHT, strokeColor=None))
        if count:
            drawing.add(Rect(120, y, max(3, 330 * count / top), 14, fillColor=strong, strokeColor=None))
        drawing.add(String(458, y + 4, str(count), fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    return drawing


def _executive_summary(record: dict, styles: dict) -> list:
    summary = record["summary"]
    overall = summary["overall_level"]
    strong, light = LEVEL_COLORS[overall]
    hexcolor = strong.hexval().replace("0x", "#")
    story = [Paragraph("USB Security Audit Report", styles["title"]),
             Paragraph("Removable media static-analysis assessment", styles["subtitle"])]

    details = [
        [Paragraph("Report ID", styles["cellb"]), Paragraph(safe(record["report_id"]), styles["cell"]),
         Paragraph("Scan date / time", styles["cellb"]), Paragraph(safe(record["scanned_at"]), styles["cell"])],
        [Paragraph("Scanned target", styles["cellb"]), Paragraph(safe(record["root"]), styles["cell"]),
         Paragraph("Scan status", styles["cellb"]), Paragraph(safe(record["status"]), styles["cell"])],
        [Paragraph("Host system", styles["cellb"]), Paragraph(safe(record.get("host", "")), styles["cell"]),
         Paragraph("Tool version", styles["cellb"]), Paragraph(f"USB Security Auditor v{safe(record.get('tool_version', ''))}", styles["cell"])],
    ]
    t = Table(details, colWidths=[28 * mm, 62 * mm, 30 * mm, 52 * mm])
    t.setStyle(table_style(header=False, zebra=False, extra=[
        ("BACKGROUND", (0, 0), (0, -1), LIGHT), ("BACKGROUND", (2, 0), (2, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE)]))
    story += [t, Spacer(1, 10)]

    score_cell = [Paragraph(f'<font color="{hexcolor}">{summary["max_score"]}/100</font>', styles["big"]),
                  Paragraph(f'<font color="{hexcolor}"><b>{safe(overall)}</b></font>', styles["center"]),
                  Paragraph("Overall risk = highest file score", styles["center"])]
    stats = Table([
        [Paragraph("Files scanned", styles["cellb"]), Paragraph(str(summary["total"]), styles["cell"])],
        [Paragraph("Flagged for review (score 20+)", styles["cellb"]), Paragraph(str(summary["flagged"]), styles["cell"])],
        [Paragraph("Elevated or high concern", styles["cellb"]),
         Paragraph(str(summary["by_level"].get("Elevated concern", 0) + summary["by_level"].get("High concern", 0)), styles["cell"])],
        [Paragraph("Could not be analysed", styles["cellb"]), Paragraph(str(summary["errors"]), styles["cell"])],
        [Paragraph("Average file score", styles["cellb"]), Paragraph(str(summary["average_score"]), styles["cell"])],
    ], colWidths=[52 * mm, 20 * mm])
    stats.setStyle(table_style(header=False, zebra=True))
    box = Table([[score_cell, stats]], colWidths=[62 * mm, 82 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), light), ("BOX", (0, 0), (0, 0), 0.8, strong),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (0, 0), 14), ("BOTTOMPADDING", (0, 0), (0, 0), 14),
        ("LEFTPADDING", (1, 0), (1, 0), 12)]))
    story += [box, Spacer(1, 12), Paragraph("Risk distribution", styles["h2"]), _distribution_chart(summary)]

    story.append(Paragraph("Key findings", styles["h2"]))
    ranked = sorted((r for r in record["results"] if not r["error"] and r["score"] >= scanner.FLAG_THRESHOLD),
                    key=lambda r: -r["score"])[:6]
    if ranked:
        rows = [[Paragraph(h, styles["head"]) for h in ("File", "Score", "Assessment")]]
        for r in ranked:
            rows.append([Paragraph(safe(r["relative"]), styles["cell"]), Paragraph(str(r["score"]), styles["cell"]),
                         level_badge(r["level"], styles)])
        t = Table(rows, colWidths=[100 * mm, 18 * mm, 46 * mm], repeatRows=1)
        t.setStyle(table_style())
        story.append(t)
    else:
        story.append(Paragraph("No file reached the review threshold of 20 points. This does not certify the "
                               "scanned files as safe; it means none of the configured indicators was triggered strongly.",
                               styles["body"]))
    if record.get("truncated"):
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Note:</b> the scan stopped at the safety limit of {scanner.MAX_FILES} files; "
                               "remaining files were not analysed.", styles["body"]))
    return story


def _methodology(record: dict, styles: dict) -> list:
    story = [PageBreak(), Paragraph("2. Scope and Methodology", styles["h1"]), Paragraph("Scope", styles["h2"])]
    scope = (f"The assessment covered <b>{record['summary']['total']}</b> file(s) found in "
             f"<b>{safe(record['root'])}</b> ({'including sub-folders' if record['recursive'] else 'top-level folder only'}). "
             f"Files larger than <b>{record['threshold_mb']} MB</b> are flagged for review. Files were opened read-only and "
             "<b>never executed</b>. Operating-system folders such as the recycle bin and system-volume metadata were excluded, "
             "as were symbolic links.")
    story.append(Paragraph(scope, styles["body"]))

    story.append(Paragraph("Security checks performed", styles["h2"]))
    rows = [[Paragraph(h, styles["head"]) for h in ("#", "Check", "Purpose", "Points")]]
    for number, name, purpose, points in CHECK_PURPOSES:
        rows.append([Paragraph(number, styles["cell"]), Paragraph(name, styles["cellb"]),
                     Paragraph(purpose, styles["cell"]), Paragraph(points, styles["cell"])])
    t = Table(rows, colWidths=[8 * mm, 42 * mm, 96 * mm, 18 * mm], repeatRows=1)
    t.setStyle(table_style())
    story.append(t)

    story.append(Paragraph("Scoring methodology", styles["h2"]))
    story.append(Paragraph("Each triggered check adds a fixed number of points. The total is capped at 100. Related findings are "
                           "not counted twice (for example, a missing 'MZ' header on an .exe file is scored once, under the PE "
                           "check). The weights are illustrative design choices, not validated malware probabilities.", styles["body"]))
    rows = [[Paragraph(h, styles["head"]) for h in ("Score", "Assessment", "Meaning")]]
    meanings = {
        "Low concern": "Few indicators. Does not certify the file as safe.",
        "Review recommended": "One or more indicators need attention.",
        "Elevated concern": "Multiple or stronger indicators are present.",
        "High concern": "Isolate and analyse further before opening.",
    }
    ranges = {"Low concern": "0 - 19", "Review recommended": "20 - 49", "Elevated concern": "50 - 74", "High concern": "75 - 100"}
    for level, meaning in meanings.items():
        rows.append([Paragraph(ranges[level], styles["cell"]), level_badge(level, styles), Paragraph(meaning, styles["cell"])])
    t = Table(rows, colWidths=[24 * mm, 44 * mm, 96 * mm], repeatRows=1)
    t.setStyle(table_style())
    story.append(t)

    story.append(Paragraph("Limitations", styles["h2"]))
    for item in ("This is static analysis only. It cannot detect every threat and is not a replacement for antivirus software.",
                 "A file with no indicators is not guaranteed to be safe; a file with indicators is not guaranteed to be malicious.",
                 "Entropy and metadata checks are weak signals and can trigger on legitimate files.",
                 "Only the first 64 KB of each file is sampled for the signature, entropy and PE checks.",
                 "Metadata checks use filesystem properties, not the internal author fields of documents."):
        story.append(Paragraph(item, styles["bullet"], bulletText="•"))

    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Tool:</b> USB Security Auditor v{safe(record.get('tool_version', ''))} &nbsp;|&nbsp; "
                           f"<b>Scan status:</b> {safe(record['status'])} &nbsp;|&nbsp; "
                           f"<b>Duration:</b> {record.get('seconds', 0)} s &nbsp;|&nbsp; <b>Host:</b> {safe(record.get('host', ''))}",
                           styles["small"]))
    return story


def _finding_block(index: int, r: dict, styles: dict) -> KeepTogether:
    strong, light = LEVEL_COLORS.get(r["level"], LEVEL_COLORS["Could not analyse"])
    hexcolor = strong.hexval().replace("0x", "#")
    header = Table([[Paragraph(f"<b>{index}. {safe(r['relative'])}</b>", styles["cell"]),
                     Paragraph(f'<font color="{hexcolor}"><b>{r["score"]}/100 - {safe(r["level"])}</b></font>', styles["cell"])]],
                   colWidths=[100 * mm, 64 * mm])
    header.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), light), ("BOX", (0, 0), (-1, -1), 0.6, strong),
                                ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                                ("ALIGN", (1, 0), (1, 0), "RIGHT")]))
    meta = Table([
        [Paragraph("Detected type", styles["cellb"]), Paragraph(safe(r["detected_type"]), styles["cell"]),
         Paragraph("Size", styles["cellb"]), Paragraph(scanner.human_size(r["size"]), styles["cell"])],
        [Paragraph("Full path", styles["cellb"]), Paragraph(safe(r["path"]), styles["small"]),
         Paragraph("Modified", styles["cellb"]), Paragraph(safe(r["modified"]), styles["cell"])],
        [Paragraph("SHA-256", styles["cellb"]), Paragraph(safe(r["sha256"]) or "-", styles["mono"]), "", ""],
    ], colWidths=[24 * mm, 80 * mm, 18 * mm, 42 * mm])
    meta.setStyle(table_style(header=False, zebra=False, extra=[("SPAN", (1, 2), (3, 2)), ("BOX", (0, 0), (-1, -1), 0.4, LINE)]))

    rows = [[Paragraph(h, styles["head"]) for h in ("Check", "Result", "Pts", "Evidence")]]
    status_text = {"FLAG": "Flagged", "PASS": "Passed", "INFO": "Info", "N/A": "N/A", "ERROR": "Error"}
    for c in r["checks"]:
        if c["number"] == 8:                                  # the hash is already shown above
            continue
        flagged = c["status"] == "FLAG"
        colour = "#b42318" if flagged else "#1d2433"
        rows.append([Paragraph(safe(c["name"]), styles["cell"]),
                     Paragraph(f'<font color="{colour}"><b>{status_text.get(c["status"], c["status"])}</b></font>', styles["cell"]),
                     Paragraph(f'+{c["points"]}' if c["points"] else "0", styles["cell"]),
                     Paragraph(safe(c["evidence"]), styles["small"])])
    checks = Table(rows, colWidths=[38 * mm, 17 * mm, 11 * mm, 98 * mm], repeatRows=1)
    checks.setStyle(table_style(extra=[("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
    action = Paragraph(f"<b>Recommended action:</b> {safe(r['recommendation'])}", styles["small"])
    return KeepTogether([header, meta, Spacer(1, 3), checks, Spacer(1, 3), action, Spacer(1, 14)])


def _findings(record: dict, styles: dict) -> list:
    story = [PageBreak(), Paragraph("3. Detailed Findings", styles["h1"])]
    flagged = sorted((r for r in record["results"] if r["error"] or r["score"] > 0), key=lambda r: (-r["score"], r["relative"].lower()))
    if not flagged:
        story.append(Paragraph("No file triggered any indicator. See the inventory in section 4 for the full list.", styles["body"]))
        return story
    story.append(Paragraph(f"{len(flagged)} file(s) triggered at least one indicator or could not be read, sorted by risk score "
                           "(highest first). Files with no indicators are listed in the inventory.", styles["body"]))
    story.append(Spacer(1, 8))
    for i, r in enumerate(flagged[:MAX_DETAIL_BLOCKS], start=1):
        story.append(_finding_block(i, r, styles))
    if len(flagged) > MAX_DETAIL_BLOCKS:
        story.append(Paragraph(f"... {len(flagged) - MAX_DETAIL_BLOCKS} further file(s) omitted from this section. "
                               "Export the CSV report for the complete list.", styles["body"]))
    return story


def _inventory(record: dict, styles: dict) -> list:
    story = [PageBreak(), Paragraph("4. File Inventory and SHA-256 Hashes", styles["h1"]),
             Paragraph("Every analysed file with its risk score and SHA-256 fingerprint. Use the hash to look the file up on "
                       "a reputation service or to confirm later that the file has not changed.", styles["body"]), Spacer(1, 8)]
    rows = [[Paragraph(h, styles["head"]) for h in ("File", "Size", "Score", "SHA-256")]]
    for r in sorted(record["results"], key=lambda r: r["relative"].lower())[:MAX_INVENTORY_ROWS]:
        rows.append([Paragraph(safe(r["relative"]), styles["small"]), Paragraph(scanner.human_size(r["size"]), styles["small"]),
                     Paragraph("-" if r["error"] else str(r["score"]), styles["small"]),
                     Paragraph(safe(r["sha256"]) or "unreadable", styles["mono"])])
    t = Table(rows, colWidths=[52 * mm, 20 * mm, 12 * mm, 80 * mm], repeatRows=1)
    t.setStyle(table_style())
    story.append(t)
    if len(record["results"]) > MAX_INVENTORY_ROWS:
        story.append(Paragraph(f"... inventory limited to the first {MAX_INVENTORY_ROWS} files.", styles["body"]))
    return story


def _recommendations(record: dict, styles: dict) -> list:
    summary = record["summary"]
    story = [PageBreak(), Paragraph("5. Recommendations and Disclaimer", styles["h1"]), Paragraph("Prioritised follow-up actions", styles["h2"])]
    actions = []
    high = summary["by_level"].get("High concern", 0)
    elevated = summary["by_level"].get("Elevated concern", 0)
    review = summary["by_level"].get("Review recommended", 0)
    if high:
        actions.append(f"<b>Immediate:</b> isolate the {high} high-concern file(s). Do not open or run them; analyse only in a sandbox or virtual machine.")
    if elevated:
        actions.append(f"<b>High priority:</b> scan the {elevated} elevated-concern file(s) with antivirus and check their SHA-256 hashes on a reputation service.")
    if review:
        actions.append(f"<b>Medium priority:</b> confirm the origin of the {review} file(s) marked 'Review recommended' before opening them.")
    if summary["errors"]:
        actions.append(f"<b>Follow-up:</b> {summary['errors']} file(s) could not be read; retry the scan or inspect them manually.")
    actions += ["<b>General:</b> disable Windows AutoRun/AutoPlay for removable media and avoid opening unknown executables from USB drives.",
                "<b>General:</b> keep operating-system and antivirus software up to date and re-scan the drive after copying new files."]
    for a in actions:
        story.append(Paragraph(a, styles["bullet"], bulletText="•"))

    story.append(Paragraph("Files needing manual investigation", styles["h2"]))
    urgent = sorted((r for r in record["results"] if not r["error"] and r["score"] >= scanner.FLAG_THRESHOLD), key=lambda r: -r["score"])
    if urgent:
        rows = [[Paragraph(h, styles["head"]) for h in ("File", "Score", "Assessment")]]
        for r in urgent[:25]:
            rows.append([Paragraph(safe(r["relative"]), styles["cell"]), Paragraph(str(r["score"]), styles["cell"]), level_badge(r["level"], styles)])
        t = Table(rows, colWidths=[100 * mm, 18 * mm, 46 * mm], repeatRows=1)
        t.setStyle(table_style())
        story.append(t)
        if len(urgent) > 25:
            story.append(Paragraph(f"... and {len(urgent) - 25} more (see section 3).", styles["small"]))
    else:
        story.append(Paragraph("None. No file reached the review threshold.", styles["body"]))

    story.append(Paragraph("Disclaimer", styles["h2"]))
    story.append(Paragraph(
        "This report was produced by an automated static-analysis tool created for educational purposes. It examines file names, headers, "
        "properties and statistical characteristics. It does not execute files, query external threat-intelligence services or use "
        "machine learning, so it cannot identify every malicious file and may flag legitimate files. Results are indicators for human review, "
        "not a verdict that any file is malware or is safe. Do not rely on this report as the sole basis for security decisions.", styles["body"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph(f"Report generated {datetime.now():%Y-%m-%d %H:%M:%S} by USB Security Auditor v{safe(record.get('tool_version', ''))}. "
                           f"Report ID: {safe(record['report_id'])}.", styles["small"]))
    return story


# ------------------------------------------------------------------- public
def generate_pdf(record: dict, output_path: str) -> str:
    """Build the PDF for one scan record and save it to output_path."""
    styles = build_styles()
    doc = SimpleDocTemplate(str(output_path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=22 * mm, bottomMargin=20 * mm,
                            title=f"USB Security Audit Report {record['report_id']}", author="USB Security Auditor",
                            subject="Removable media security assessment")
    story = []
    story += _executive_summary(record, styles)
    story += _methodology(record, styles)
    story += _findings(record, styles)
    story += _inventory(record, styles)
    story += _recommendations(record, styles)

    class Canvas(_NumberedCanvas):
        meta = {"report_id": record["report_id"]}

    doc.build(story, canvasmaker=Canvas)
    return str(output_path)
