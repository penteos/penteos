"""Penteos: the deliverable's findings as an Excel sheet (.xlsx), with the standard library only."""
import io
import zipfile
from xml.sax.saxutils import escape

ORDER = ["critical", "high", "medium", "low", "info"]
DELIVERABLE = {"approved", "reported", "fixed", "partially_fixed", "not_fixed", "not_verifiable", "reopened", "wont_fix"}
TEXT = {
    "es": {
        "sheet": "Hallazgos",
        "head": ["ID", "Hallazgo", "Severidad", "CVSS", "Estado", "Activos afectados", "Descripción", "Impacto", "Recomendación"],
        "sev": {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"},
        "status": {"approved": "Aprobado", "reported": "Reportado", "fixed": "Corregido", "partially_fixed": "Corregido en parte", "not_fixed": "No corregido", "not_verifiable": "No verificable", "reopened": "Reabierto", "wont_fix": "No se corregirá"},
        "file": "hallazgos",
    },
    "en": {
        "sheet": "Findings",
        "head": ["ID", "Finding", "Severity", "CVSS", "Status", "Affected assets", "Description", "Impact", "Remediation"],
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"},
        "status": {"approved": "Approved", "reported": "Reported", "fixed": "Fixed", "partially_fixed": "Partially fixed", "not_fixed": "Not fixed", "not_verifiable": "Not verifiable", "reopened": "Reopened", "wont_fix": "Won't fix"},
        "file": "findings",
    },
}
# Style ids in styles.xml: 1 header, 2 wrapped text, 3..7 severities (white on their color).
SEV_STYLE = {"critical": 3, "high": 4, "medium": 5, "low": 6, "info": 7}
WIDTHS = [8, 44, 13, 8, 16, 34, 70, 50, 60]


def col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def cell(ref, value, style=2):
    if isinstance(value, (int, float)):
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    text = escape(str(value or "")).replace("\r", "")
    return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{text[:32000]}</t></is></c>'


def sheet(rows):
    out = []
    for r, row in enumerate(rows, start=1):
        cells = "".join(cell(f"{col(c)}{r}", v, s) for c, (v, s) in enumerate(row))
        out.append(f'<row r="{r}">{cells}</row>')
    last = f"{col(len(WIDTHS) - 1)}{max(len(rows), 1)}"
    cols = "".join(f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>' for i, w in enumerate(WIDTHS))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        f"<cols>{cols}</cols><sheetData>{''.join(out)}</sheetData>"
        f'<autoFilter ref="A1:{last}"/></worksheet>'
    )


STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="3"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
    '<font><b/><sz val="9"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>'
    '<fills count="8"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF1F2933"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF8E1B1B"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFC2410C"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFB7791F"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF2F6FB3"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF5F6B7A"/></patternFill></fill></fills>'
    '<borders count="2"><border/><border><bottom style="thin"><color rgb="FFD5D9E0"/></bottom></border></borders>'
    '<cellStyleXfs count="1"><xf/></cellStyleXfs><cellXfs count="8">'
    '<xf/>'
    '<xf fontId="1" fillId="2" borderId="1" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="center"/></xf>'
    '<xf borderId="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
    + "".join(f'<xf fontId="2" fillId="{f}" borderId="1" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>' for f in range(3, 8))
    + "</cellXfs></styleSheet>"
)


def workbook(name, rows):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="{escape(name)}" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">\'{escape(name)}\'!$A$1:${col(len(WIDTHS) - 1)}${max(len(rows), 1)}</definedName></definedNames></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        z.writestr("xl/styles.xml", STYLES)
        z.writestr("xl/worksheets/sheet1.xml", sheet(rows))
    return buf.getvalue()


def activate(plugin):
    @plugin.operation("excel")
    def excel(input, penteos):
        T = TEXT["en" if (penteos.engagement or {}).get("language") == "en" else "es"]
        findings = [f for f in penteos.graph.query("finding", limit=500) if f["attributes"].get("status") in DELIVERABLE]
        findings.sort(key=lambda f: (ORDER.index(f["attributes"].get("severity", "info")), f["attributes"].get("title", "")))
        names = {}

        def asset(ref):
            eid = (ref or {}).get("id")
            if not eid:
                return ""
            if eid not in names:
                e = penteos.graph.get(eid)
                names[eid] = (e or {}).get("naturalKey", "") if e else ""
                a = (e or {}).get("attributes", {}) if e else {}
                names[eid] = a.get("ip") or a.get("fqdn") or a.get("origin") or a.get("url") or names[eid]
            return names[eid]

        rows = [[(h, 1) for h in T["head"]]]
        for i, f in enumerate(findings, start=1):
            a = f["attributes"]
            sev = a.get("severity", "info")
            cvss = (a.get("cvss") or {}).get("score")
            assets = ", ".join(filter(None, (asset(x.get("entity")) + (f" ({x['location']})" if x.get("location") else "") for x in (a.get("instances") or []))))
            rows.append([
                (f"F-{i:02d}", 2),
                (a.get("title", ""), 2),
                (T["sev"].get(sev, sev), SEV_STYLE.get(sev, 2)),
                (cvss if isinstance(cvss, (int, float)) else "-", 2),
                (T["status"].get(a.get("status"), a.get("status", "")), 2),
                (assets, 2),
                (a.get("description", ""), 2),
                (a.get("impact", ""), 2),
                (a.get("remediation", ""), 2),
            ])
        client = "".join(c if c.isalnum() or c in "-_" else "-" for c in (penteos.engagement or {}).get("clientName", "")).strip("-").lower()
        name = f"{T['file']}{'-' + client if client else ''}.xlsx"
        written = penteos.files.write(name, workbook(T["sheet"], rows))
        return {"name": written["name"], "size": written["size"], "findings": len(findings)}
