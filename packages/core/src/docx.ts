import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  Header,
  HeadingLevel,
  ImageRun,
  Packer,
  PageNumber,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TabStopType,
  TextRun,
  VerticalAlign,
  WidthType,
} from "docx";
import type { Branding } from "./report.js";
import { REPORT_TEXT, confidentialityFor } from "./report-text.js";
import type { Language } from "./language.js";

/**
 * The deliverable as a Word document, from the same markdown the report is built from. Laid out the
 * way a consultancy's report is: a cover with the organization's brand, a running header, a table
 * of contents, numbered sections, findings marked by severity color, readable tables and evidence
 * blocks, "page X of Y". Editable, which is what most clients and QA processes ask for.
 */

const MONO = "Consolas";
const INK = "1F2933";
const MUTED = "6B7280";
const RULE = "D5D9E0";
const ZEBRA = "F5F6F8";
const CODE_BG = "F3F2F7";
/** Severity colors, dark enough for white text on them. */
const SEVERITY_COLOR: Record<string, string> = { critical: "8E1B1B", high: "C2410C", medium: "B7791F", low: "2F6FB3", info: "5F6B7A" };

type RunBase = { bold?: boolean; italics?: boolean; color?: string; size?: number; font?: string };

function inline(text: string, base: RunBase = {}): TextRun[] {
  const runs: TextRun[] = [];
  // **bold**, `code`, _italic_ / *italic*
  const re = /(\*\*[^*]+\*\*|`[^`]+`|_[^_]+_|\*[^*]+\*)/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index! > last) runs.push(new TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) runs.push(new TextRun({ text: t.slice(2, -2), ...base, bold: true }));
    else if (t.startsWith("`")) runs.push(new TextRun({ text: t.slice(1, -1), ...base, font: MONO, size: (base.size ?? 21) - 2 }));
    else runs.push(new TextRun({ text: t.slice(1, -1), ...base, italics: true }));
    last = m.index! + t.length;
  }
  if (last < text.length) runs.push(new TextRun({ text: text.slice(last), ...base }));
  return runs;
}

/** A severity name in the report's language → its key ("Crítica" → critical). */
function severityKeys(language: Language): Map<string, string> {
  return new Map(Object.entries(REPORT_TEXT[language].severities).map(([k, v]) => [v.toLowerCase(), k]));
}

/** A severity as a colored label: white text on its color. */
function severityRun(label: string, key: string, size = 18): TextRun {
  return new TextRun({ text: ` ${label.toUpperCase()} `, bold: true, color: "FFFFFF", size, shading: { type: ShadingType.CLEAR, color: "auto", fill: SEVERITY_COLOR[key] ?? MUTED } });
}

const thin = { style: BorderStyle.SINGLE, size: 4, color: RULE };

function table(rows: string[][], brand: string, severities: Map<string, string>): Table {
  const cells = (r: string[]) => r.map((c) => c.replace(/\\\|/g, "|").trim());
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: thin, bottom: thin, left: thin, right: thin, insideHorizontal: thin, insideVertical: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" } },
    rows: rows.map(
      (r, i) =>
        new TableRow({
          tableHeader: i === 0,
          cantSplit: true,
          children: cells(r).map((c) => {
            const sev = i > 0 ? severities.get(c.toLowerCase()) : undefined;
            const fill = i === 0 ? brand : sev ? undefined : i % 2 === 0 ? ZEBRA : undefined;
            return new TableCell({
              ...(fill ? { shading: { type: ShadingType.CLEAR, color: "auto", fill } } : {}),
              verticalAlign: VerticalAlign.CENTER,
              margins: { top: 70, bottom: 70, left: 110, right: 110 },
              children: [new Paragraph({ children: sev ? [severityRun(c, sev, 16)] : inline(c, i === 0 ? { bold: true, color: "FFFFFF", size: 18 } : { size: 19, color: INK }) })],
            });
          }),
        }),
    ),
  });
}

function logoRun(dataUrl: string | undefined): ImageRun | undefined {
  const m = /^data:image\/(png|jpeg);base64,(.+)$/.exec(dataUrl ?? "");
  if (!m) return undefined; // SVG logos stay out of Word
  const data = Buffer.from(m[2]!, "base64");
  // Keep its proportions inside 170×64 points.
  const size = imageSize(data, m[1] as "png" | "jpeg");
  const scale = size ? Math.min(170 / size.w, 64 / size.h, 1) : 1;
  const width = size ? Math.round(size.w * scale) : 160;
  const height = size ? Math.round(size.h * scale) : 60;
  return new ImageRun({ type: m[1] === "png" ? "png" : "jpg", data, transformation: { width, height } });
}

/** Width and height of a PNG or JPEG, from its header. */
function imageSize(data: Buffer, type: "png" | "jpeg"): { w: number; h: number } | undefined {
  try {
    if (type === "png" && data.length > 24) return { w: data.readUInt32BE(16), h: data.readUInt32BE(20) };
    if (type === "jpeg") {
      let i = 2;
      while (i < data.length) {
        if (data[i] !== 0xff) return undefined;
        const marker = data[i + 1]!;
        const len = data.readUInt16BE(i + 2);
        if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) return { h: data.readUInt16BE(i + 5), w: data.readUInt16BE(i + 7) };
        i += 2 + len;
      }
    }
  } catch {
    /* an odd header: the default box */
  }
  return undefined;
}

export async function reportToDocx(
  markdown: string,
  branding: Branding,
  meta: { client: string; engagement: string; date: string; draft: boolean; language?: Language; image?: (ref: string) => { data: Buffer; mime: string } | undefined },
): Promise<Buffer> {
  const language = meta.language ?? "en";
  const T = REPORT_TEXT[language];
  const brand = branding.primaryColor.replace("#", "").toUpperCase();
  const severities = severityKeys(language);
  const lines = markdown.split("\n");
  const body: Array<Paragraph | Table> = [];
  const contents: string[] = [];
  let i = 0;
  let title = meta.engagement;
  // The meta line under a finding's heading: "**Severidad:** Crítica · **Estado:** …".
  const sevLine = new RegExp(`^\\*\\*${T.severity}:\\*\\* ([^·]+?)( · .*)?$`);
  const severityOf = (line: string | undefined) => {
    const m = line ? sevLine.exec(line.trim()) : null;
    return m ? severities.get(m[1]!.trim().toLowerCase()) : undefined;
  };
  // The headline above the first section (client and date) is on the cover already.
  let firstSection = false;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.startsWith("# ")) {
      title = line.slice(2).trim();
      i++;
      continue;
    }
    if (!firstSection && !line.startsWith("## ")) {
      // The draft banner stays; the client/date line is the cover's.
      if (line.startsWith("> ")) body.push(new Paragraph({ children: inline(line.slice(2), { italics: true, color: "7A2E39" }), border: { left: { style: BorderStyle.SINGLE, size: 12, color: "C94B5A", space: 8 } }, spacing: { after: 200 } }));
      i++;
      continue;
    }
    // Chart markers are for the PDF; a screenshot goes in as an image.
    if (line.trim().startsWith("<!--")) {
      i++;
      continue;
    }
    const shot = /^!\[([^\]]*)\]\(raw:(sha256:[0-9a-f]{64})\)$/.exec(line.trim());
    if (shot) {
      const found = meta.image?.(shot[2]!);
      const type = found?.mime === "image/png" ? "png" : found && /jpe?g/.test(found.mime) ? "jpeg" : undefined;
      if (found && type) {
        const size = imageSize(found.data, type);
        const scale = size ? Math.min(560 / size.w, 380 / size.h, 1) : 1;
        body.push(
          new Paragraph({ children: [new ImageRun({ type: type === "png" ? "png" : "jpg", data: found.data, transformation: { width: size ? Math.round(size.w * scale) : 520, height: size ? Math.round(size.h * scale) : 300 } })], spacing: { after: 60 } }),
          new Paragraph({ children: [new TextRun({ text: shot[1]!, italics: true, size: 16, color: MUTED })], spacing: { after: 160 } }),
        );
      }
      i++;
      continue;
    }
    if (line.startsWith("```")) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.startsWith("```")) code.push(lines[i++]!);
      i++;
      const box = { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 4 };
      for (const [k, c] of (code.length ? code : [""]).entries())
        body.push(
          new Paragraph({
            children: [new TextRun({ text: c || " ", font: MONO, size: 16, color: INK })],
            shading: { type: ShadingType.CLEAR, color: "auto", fill: CODE_BG },
            border: { left: box, right: box, ...(k === 0 ? { top: box } : {}), ...(k === code.length - 1 || code.length === 0 ? { bottom: box } : {}) },
            spacing: { before: 0, after: 0 },
          }),
        );
      body.push(new Paragraph({ text: "", spacing: { after: 60 } }));
      continue;
    }
    if (line.startsWith("|")) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i]!.startsWith("|")) {
        const r = lines[i]!.replace(/^\||\|$/g, "").split(/(?<!\\)\|/);
        if (!r.every((c) => /^\s*:?-+:?\s*$/.test(c))) rows.push(r);
        i++;
      }
      body.push(table(rows, brand, severities), new Paragraph({ text: "", spacing: { after: 120 } }));
      continue;
    }
    if (line.startsWith("## ")) {
      firstSection = true;
      const text = line.slice(3).trim();
      contents.push(text);
      body.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          keepNext: true,
          children: [new TextRun({ text, color: brand, bold: true, size: 30 })],
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: brand, space: 4 } },
          spacing: { before: 420, after: 180 },
        }),
      );
    } else if (line.startsWith("### ")) {
      // A finding's heading takes its severity's color on the left.
      let k = i + 1;
      while (k < lines.length && !lines[k]!.trim()) k++;
      const sev = severityOf(lines[k]);
      body.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_2,
          keepNext: true,
          children: [new TextRun({ text: line.slice(4).trim(), bold: true, size: 24, color: INK })],
          ...(sev ? { border: { left: { style: BorderStyle.SINGLE, size: 24, color: SEVERITY_COLOR[sev]!, space: 8 } } } : {}),
          spacing: { before: 320, after: 100 },
        }),
      );
    } else if (severityOf(line)) {
      const m = sevLine.exec(line.trim())!;
      body.push(new Paragraph({ children: [new TextRun({ text: `${T.severity}  `, bold: true, size: 18, color: MUTED }), severityRun(m[1]!.trim(), severityOf(line)!), ...inline(m[2] ?? "", { size: 18, color: MUTED })], spacing: { after: 160 } }));
    } else if (/^\*\*[^*]+\*\*$/.test(line.trim())) {
      // A label on its own line ("**Descripción**"): a small heading for what follows.
      body.push(new Paragraph({ keepNext: true, children: [new TextRun({ text: line.trim().slice(2, -2).toUpperCase(), bold: true, size: 17, color: brand, characterSpacing: 20 })], spacing: { before: 180, after: 60 } }));
    } else if (/^\s*[-*] /.test(line)) body.push(new Paragraph({ children: inline(line.replace(/^\s*[-*] /, ""), { color: INK }), bullet: { level: 0 }, spacing: { after: 60 } }));
    else if (/^\d+\. /.test(line)) body.push(new Paragraph({ children: inline(line, { color: INK }), indent: { left: 360, hanging: 360 }, spacing: { after: 60 } }));
    else if (line.startsWith("> ")) body.push(new Paragraph({ children: inline(line.slice(2), { italics: true, color: "7A2E39" }), border: { left: { style: BorderStyle.SINGLE, size: 12, color: "C94B5A", space: 8 } } }));
    else if (line.trim()) body.push(new Paragraph({ children: inline(line, { color: INK }), spacing: { after: 140, line: 288 } }));
    i++;
  }

  // Cover: logo, a band in the brand's color with the title, who and when, and the confidentiality note.
  const logo = logoRun(branding.logo);
  const none = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  const band = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: none, bottom: none, left: none, right: none, insideHorizontal: none, insideVertical: none },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            shading: { type: ShadingType.CLEAR, color: "auto", fill: brand },
            margins: { top: 480, bottom: 480, left: 360, right: 360 },
            children: [
              new Paragraph({ children: [new TextRun({ text: title, bold: true, size: 52, color: "FFFFFF" })], spacing: { after: 160 } }),
              new Paragraph({ children: [new TextRun({ text: meta.client, size: 30, color: "FFFFFF" })] }),
            ],
          }),
        ],
      }),
    ],
  });
  const fact = (label: string, value: string) =>
    new Paragraph({ tabStops: [{ type: TabStopType.LEFT, position: 2200 }], children: [new TextRun({ text: label, size: 19, color: MUTED }), new TextRun({ text: `\t${value}`, size: 21, color: INK })], spacing: { after: 80 } });
  const cover: Array<Paragraph | Table> = [
    logo ? new Paragraph({ children: [logo], spacing: { after: 900 } }) : new Paragraph({ text: "", spacing: { after: 1800 } }),
    band,
    new Paragraph({ text: "", spacing: { after: 420 } }),
    ...(meta.draft ? [new Paragraph({ children: [new TextRun({ text: ` ${T.draft} `, bold: true, color: "FFFFFF", size: 22, shading: { type: ShadingType.CLEAR, color: "auto", fill: "C94B5A" } })], spacing: { after: 260 } })] : []),
    fact(T.client, meta.client),
    fact(T.issued, meta.date),
    ...(branding.companyName ? [fact(T.preparedBy("").replace(/\s+$/, ""), branding.companyName)] : []),
    ...(branding.authors ? [fact(T.authors, branding.authors)] : []),
    new Paragraph({ text: "", spacing: { after: 2400 } }),
    new Paragraph({
      children: [new TextRun({ text: confidentialityFor(branding.confidentiality, language), italics: true, size: 17, color: MUTED })],
      border: { left: { style: BorderStyle.SINGLE, size: 12, color: brand, space: 8 } },
    }),
  ];

  // Contents: the sections, in order (Word's own field would need updating by hand to show).
  const toc: Paragraph[] = contents.length
    ? [
        new Paragraph({ children: [new TextRun({ text: T.contents, bold: true, size: 30, color: brand })], border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: brand, space: 4 } }, spacing: { after: 240 } }),
        ...contents.map((c) => new Paragraph({ children: [new TextRun({ text: c, size: 21, color: INK })], spacing: { after: 100 } })),
      ]
    : [];

  const grey = { size: 15, color: "8A8F98" };
  const header = new Header({
    children: [
      new Paragraph({
        alignment: AlignmentType.RIGHT,
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 4 } },
        children: [
          new TextRun({ text: [branding.companyName, meta.client, title].filter(Boolean).join("  ·  "), ...grey }),
          ...(meta.draft ? [new TextRun({ text: `   ${T.draft}`, bold: true, size: 15, color: "C94B5A" })] : []),
        ],
      }),
    ],
  });
  const footer = new Footer({
    children: [
      new Paragraph({
        tabStops: [{ type: TabStopType.RIGHT, position: 9000 }],
        children: [
          new TextRun({ text: `${T.confidential}${branding.footer ? ` · ${branding.footer}` : ""}`, ...grey }),
          new TextRun({ children: [`\t${T.page} `, PageNumber.CURRENT, ` ${T.of} `, PageNumber.TOTAL_PAGES], ...grey }),
        ],
      }),
    ],
  });

  const margins = { top: 1300, bottom: 1200, left: 1300, right: 1300 };
  const doc = new Document({
    creator: branding.companyName || "Penteos",
    title,
    styles: {
      default: { document: { run: { font: "Calibri", size: 21, color: INK } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", run: { font: "Calibri", color: brand } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", run: { font: "Calibri", color: INK } },
      ],
    },
    sections: [
      { properties: { page: { margin: margins } }, children: cover },
      ...(toc.length ? [{ properties: { page: { margin: margins } }, headers: { default: header }, footers: { default: footer }, children: toc }] : []),
      { properties: { page: { margin: margins } }, headers: { default: header }, footers: { default: footer }, children: body },
    ],
  });
  return Packer.toBuffer(doc);
}
