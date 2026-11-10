import type { Branding } from "./report.js";
import { confidentialityFor, REPORT_TEXT } from "./report-text.js";
import { FULL_TEXT } from "./report-text-full.js";
import type { Language } from "./language.js";

/**
 * The deliverable as a print-ready HTML document, from the same markdown as every other format:
 * a cover with the brand, a contents page whose page numbers the paginator fills in, a running
 * header and "page X of Y", numbered sections, findings marked by severity, a severity chart,
 * evidence as request and response, screenshots. Shown as the preview and printed to PDF.
 */

export interface HtmlReportMeta {
  client: string;
  engagement: string;
  date: string;
  draft: boolean;
  language?: Language;
  /** Raw artifacts the markdown points to (`raw:sha256:…` images): their bytes and type. */
  image?: (ref: string) => { data: Buffer; mime: string } | undefined;
}

const SEV_COLOR: Record<string, string> = { critical: "#8e1b1b", high: "#c2410c", medium: "#b7791f", low: "#2f6fb3", info: "#5f6b7a" };
const ORDER = ["critical", "high", "medium", "low", "info"] as const;

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** **bold**, `code`, _italic_, [text](url) - on already-escaped text. */
function inline(text: string): string {
  let t = esc(text);
  t = t.replace(/`([^`]+)`/g, (_m, c: string) => `<code>${c}</code>`);
  t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  t = t.replace(/(^|[\s(])_([^_]+)_(?=[\s).,;:]|$)/g, "$1<em>$2</em>");
  t = t.replace(/(^|[\s(])\*([^*]+)\*(?=[\s).,;:]|$)/g, "$1<em>$2</em>");
  t = t.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_m, label: string, url: string) => `<a href="${url}">${label}</a>`);
  t = t.replace(/(^|[\s(])(https?:\/\/[^\s<)]+)/g, (_m, pre: string, url: string) => `${pre}<a href="${url}">${url}</a>`);
  return t;
}

function slug(text: string, used: Set<string>): string {
  let base = text.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "s";
  base = `s-${base}`;
  let id = base;
  for (let i = 2; used.has(id); i++) id = `${base}-${i}`;
  used.add(id);
  return id;
}

/** A request or response, with its first line and header names marked. */
function httpBlock(text: string): string {
  const lines = text.split("\n");
  let inBody = false;
  return lines
    .map((l, i) => {
      if (i === 0) return `<span class="h-start">${esc(l)}</span>`;
      if (!inBody && !l.trim()) {
        inBody = true;
        return "";
      }
      if (!inBody) {
        const m = /^([A-Za-z0-9-]+):(.*)$/.exec(l);
        if (m) return `<span class="h-name">${esc(m[1]!)}</span>:${esc(m[2]!)}`;
      }
      return esc(l);
    })
    .join("\n");
}

function severityChart(counts: Record<string, number>, labels: Record<string, string>): string {
  const max = Math.max(1, ...ORDER.map((s) => counts[s] ?? 0));
  const row = 26;
  const width = 460;
  const bars = ORDER.map((s, i) => {
    const n = counts[s] ?? 0;
    const w = Math.round((n / max) * (width - 170));
    const y = i * row + 4;
    return `<text x="0" y="${y + 13}" class="c-l">${esc(labels[s] ?? s)}</text><rect x="110" y="${y}" width="${Math.max(w, n ? 4 : 0)}" height="17" rx="3" fill="${SEV_COLOR[s]}"/><text x="${118 + w}" y="${y + 13}" class="c-n">${n}</text>`;
  }).join("");
  return `<figure class="chart"><svg viewBox="0 0 ${width} ${ORDER.length * row + 4}" width="${width}" role="img" aria-label="severity">${bars}</svg></figure>`;
}

export function reportToHtml(markdown: string, branding: Branding, meta: HtmlReportMeta): string {
  const language = meta.language ?? "en";
  const T = REPORT_TEXT[language];
  const F = FULL_TEXT[language];
  const brand = branding.primaryColor;
  const sevByLabel = new Map(Object.entries(T.severities).map(([k, v]) => [v.toLowerCase(), k]));
  const lines = markdown.replace(/\r\n?/g, "\n").split("\n");
  const body: string[] = [];
  const toc: Array<{ id: string; text: string }> = [];
  const used = new Set<string>();
  let title = meta.engagement;
  let i = 0;
  let started = false;
  const sevLine = new RegExp(`^\\*\\*${T.severity}:\\*\\* ([^·]+?)( · .*)?$`);
  const severityOf = (line: string | undefined) => {
    const m = line ? sevLine.exec(line.trim()) : null;
    return m ? sevByLabel.get(m[1]!.trim().toLowerCase()) : undefined;
  };
  let list: "ul" | "ol" | undefined;
  let breakNext = false;
  let firstH2 = true;
  const closeList = () => {
    if (list) body.push(`</${list}>`);
    list = undefined;
  };
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.startsWith("# ")) {
      title = line.slice(2).trim();
      i++;
      continue;
    }
    // The client/date line above the first section is on the cover.
    if (!started && !line.startsWith("## ")) {
      if (line.startsWith("> ")) body.push(`<p class="draft-banner">${inline(line.slice(2))}</p>`);
      i++;
      continue;
    }
    const chart = /^<!-- chart:severity (\{.*\}) -->$/.exec(line.trim());
    if (chart) {
      closeList();
      try {
        body.push(severityChart(JSON.parse(chart[1]!) as Record<string, number>, T.severities));
      } catch {
        /* a chart that does not parse is left out */
      }
      i++;
      continue;
    }
    // The major sections start on a new page.
    if (line.trim() === "<!-- pagebreak -->") {
      breakNext = true;
      i++;
      continue;
    }
    if (line.trim().startsWith("<!--")) {
      i++;
      continue;
    }
    if (line.startsWith("```")) {
      closeList();
      const fenceLen = /^`+/.exec(line)![0].length;
      const lang = line.slice(fenceLen).trim();
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.startsWith("`".repeat(fenceLen))) code.push(lines[i++]!);
      i++;
      body.push(`<pre class="code${lang ? ` ${esc(lang)}` : ""}">${lang === "http" ? httpBlock(code.join("\n")) : esc(code.join("\n"))}</pre>`);
      continue;
    }
    if (line.startsWith("|")) {
      closeList();
      const rows: string[][] = [];
      while (i < lines.length && lines[i]!.startsWith("|")) {
        const r = lines[i]!.replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.replace(/\\\|/g, "|").trim());
        if (!r.every((c) => /^:?-+:?$/.test(c))) rows.push(r);
        i++;
      }
      const [head, ...rest] = rows;
      // Only the severity column shows badges ("Baja" is also a CVSS value).
      const sevCol = (head ?? []).findIndex((h) => h.toLowerCase() === T.severity.toLowerCase());
      const cellHtml = (c: string, col: number) => {
        const sev = col === sevCol ? sevByLabel.get(c.toLowerCase()) : undefined;
        return sev ? `<span class="sev sev-${sev}">${esc(c)}</span>` : inline(c);
      };
      body.push(`<table><thead><tr>${(head ?? []).map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>${rest.map((r) => `<tr>${r.map((c, k) => `<td>${cellHtml(c, k)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
      continue;
    }
    const img = /^!\[([^\]]*)\]\(raw:(sha256:[0-9a-f]{64})\)$/.exec(line.trim());
    if (img) {
      closeList();
      const found = meta.image?.(img[2]!);
      if (found) body.push(`<figure class="shot"><img src="data:${found.mime};base64,${found.data.toString("base64")}" alt="${esc(img[1]!)}"/><figcaption>${esc(img[1]!)}</figcaption></figure>`);
      i++;
      continue;
    }
    if (line.startsWith("## ")) {
      closeList();
      started = true;
      const text = line.slice(3).trim();
      const id = slug(text, used);
      toc.push({ id, text });
      // The first section follows the contents page, which already ends with a page break.
      body.push(`<h2 id="${id}"${breakNext && !firstH2 ? ' class="brk"' : ""}>${inline(text)}</h2>`);
      breakNext = false;
      firstH2 = false;
    } else if (line.startsWith("### ")) {
      closeList();
      let k = i + 1;
      while (k < lines.length && !lines[k]!.trim()) k++;
      const sev = severityOf(lines[k]);
      const text = line.slice(4).trim();
      body.push(`<h3 id="${slug(text, used)}"${sev ? ` class="finding" style="--sev:${SEV_COLOR[sev]}"` : ""}>${inline(text)}</h3>`);
    } else if (severityOf(line)) {
      closeList();
      const m = sevLine.exec(line.trim())!;
      const sev = severityOf(line)!;
      body.push(`<p class="meta"><span class="sev sev-${sev}">${esc(m[1]!.trim())}</span>${inline(m[2] ?? "")}</p>`);
    } else if (/^\*\*[^*]+\*\*$/.test(line.trim())) {
      closeList();
      body.push(`<h4>${esc(line.trim().slice(2, -2))}</h4>`);
    } else if (/^\s*[-*] /.test(line)) {
      if (list !== "ul") {
        closeList();
        body.push("<ul>");
        list = "ul";
      }
      body.push(`<li>${inline(line.replace(/^\s*[-*] /, ""))}</li>`);
    } else if (/^\d+\. /.test(line)) {
      if (list !== "ol") {
        closeList();
        body.push("<ol>");
        list = "ol";
      }
      body.push(`<li>${inline(line.replace(/^\d+\. /, ""))}</li>`);
    } else if (line.startsWith("> ")) {
      closeList();
      body.push(`<blockquote>${inline(line.slice(2))}</blockquote>`);
    } else if (line.trim()) {
      closeList();
      body.push(`<p>${inline(line)}</p>`);
    } else closeList();
    i++;
  }
  closeList();

  const logo = branding.logo ? `<img class="logo" src="${branding.logo}" alt=""/>` : "";
  const fact = (k: string, v: string) => `<div class="fact"><span>${esc(k)}</span><b>${esc(v)}</b></div>`;
  const cover = `<section class="cover">
  ${logo}
  <div class="band"><h1>${inline(title)}</h1><p>${esc(meta.client)}</p></div>
  ${meta.draft ? `<p class="draft-stamp">${esc(T.draft)}</p>` : ""}
  <div class="facts">${fact(T.client, meta.client)}${fact(T.issued, meta.date)}${branding.companyName ? fact(T.preparedBy("").trim(), branding.companyName) : ""}${branding.authors ? fact(F.dc.team, branding.authors) : ""}</div>
  <p class="confidential">${esc(confidentialityFor(branding.confidentiality, language))}</p>
</section>`;
  const contents = `<section class="toc"><h2 class="toc-title">${esc(T.contents)}</h2><ol>${toc.map((t) => `<li><a href="#${t.id}">${inline(t.text)}</a></li>`).join("")}</ol></section>`;
  const runningTitle = [branding.companyName, meta.client].filter(Boolean).join(" · ");
  const footer = `${T.confidential}${branding.footer ? ` · ${branding.footer}` : ""}`;
  return `<!doctype html>
<html lang="${language}">
<head>
<meta charset="utf-8"/>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline' file:"/>
<title>${esc(title)}</title>
<style>
@page { size: A4; margin: 24mm 18mm 22mm 18mm;
  @top-left { content: string(doctitle); font: 8pt Inter, "Segoe UI", Arial, sans-serif; color: #8a8f98; }
  @top-right { content: "${esc(runningTitle).replace(/"/g, "")}"; font: 8pt Inter, "Segoe UI", Arial, sans-serif; color: #8a8f98; }
  @bottom-left { content: "${esc(footer).replace(/"/g, "")}"; font: 8pt Inter, "Segoe UI", Arial, sans-serif; color: #8a8f98; }
  @bottom-right { content: "${esc(T.page)} " counter(page) " ${esc(T.of)} " counter(pages); font: 8pt Inter, "Segoe UI", Arial, sans-serif; color: #8a8f98; }
}
@page :first { margin: 0; @top-left { content: none; } @top-right { content: none; } @bottom-left { content: none; } @bottom-right { content: none; } }
:root { --brand: ${brand}; --ink: #1f2933; --muted: #6b7280; --rule: #d5d9e0; --zebra: #f5f6f8; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font: 10pt/1.55 Inter, "Segoe UI", Calibri, Arial, sans-serif; color: var(--ink); background: #fff; }
h1 { string-set: doctitle content(); }
.cover { page: cover; break-after: page; height: 297mm; padding: 34mm 22mm 24mm; display: flex; flex-direction: column; gap: 14mm; }
.cover .logo { max-width: 60mm; max-height: 22mm; object-fit: contain; align-self: flex-start; }
.cover .band { background: var(--brand); color: #fff; padding: 14mm 12mm; border-radius: 3mm; margin-top: auto; }
.cover .band h1 { margin: 0 0 4mm; font-size: 26pt; line-height: 1.15; font-weight: 700; }
.cover .band p { margin: 0; font-size: 14pt; opacity: .95; }
.cover .facts { display: grid; gap: 2.5mm; }
.cover .fact { display: grid; grid-template-columns: 45mm 1fr; font-size: 10.5pt; }
.cover .fact span { color: var(--muted); }
.cover .draft-stamp { align-self: flex-start; background: #c94b5a; color: #fff; font-weight: 700; padding: 1.5mm 4mm; border-radius: 1.5mm; letter-spacing: .08em; margin: 0; }
.cover .confidential { margin-top: auto; font-size: 8.5pt; font-style: italic; color: var(--muted); border-left: 2px solid var(--brand); padding-left: 4mm; }
.toc { break-after: page; }
.toc-title, h2 { color: var(--brand); font-size: 16pt; border-bottom: 1.5px solid var(--brand); padding-bottom: 2mm; margin: 0 0 5mm; }
.toc ol { list-style: none; padding: 0; margin: 0; }
.toc li { margin: 0 0 2mm; border-bottom: 1px dotted var(--rule); padding-bottom: 1mm; }
.toc a { color: var(--ink); text-decoration: none; display: block; }
.toc a::after { content: target-counter(attr(href), page); float: right; color: var(--muted); }
h2 { margin-top: 9mm; }
h2.brk { break-before: page; margin-top: 0; }
h3 { font-size: 12pt; margin: 8mm 0 2mm; break-after: avoid; }
h3.finding { border-left: 4px solid var(--sev); padding-left: 3mm; break-before: auto; }
h4 { font-size: 8pt; letter-spacing: .08em; text-transform: uppercase; color: var(--brand); margin: 4mm 0 1.5mm; break-after: avoid; }
p { margin: 0 0 2.5mm; orphans: 3; widows: 3; }
a { color: var(--brand); word-break: break-word; }
code { font: 8.5pt "JetBrains Mono", Consolas, monospace; background: #f1f0f6; padding: .2mm 1mm; border-radius: 1mm; }
pre.code { font: 7.8pt/1.45 "JetBrains Mono", Consolas, monospace; background: #f6f6f9; border: 1px solid var(--rule); border-radius: 1.5mm; padding: 3mm; white-space: pre-wrap; word-break: break-all; margin: 0 0 3mm; }
pre.code .h-start { font-weight: 700; color: #1f2933; }
pre.code .h-name { color: #6a4bd6; }
table { width: 100%; border-collapse: collapse; margin: 0 0 4mm; font-size: 9pt; break-inside: auto; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th { background: var(--brand); color: #fff; text-align: left; font-weight: 600; padding: 1.8mm 2.5mm; }
td { padding: 1.6mm 2.5mm; border-bottom: 1px solid var(--rule); vertical-align: top; }
tbody tr:nth-child(even) td { background: var(--zebra); }
.sev { display: inline-block; color: #fff; font-weight: 700; font-size: 7.5pt; letter-spacing: .05em; text-transform: uppercase; padding: .4mm 2mm; border-radius: 1mm; }
${ORDER.map((s) => `.sev-${s} { background: ${SEV_COLOR[s]}; }`).join("\n")}
p.meta { color: var(--muted); font-size: 9pt; line-height: 1.8; }
p.meta .sev { margin-right: 1.5mm; }
p.meta code { font-size: 7.5pt; }
ul, ol { margin: 0 0 3mm; padding-left: 6mm; }
li { margin-bottom: 1mm; }
blockquote, .draft-banner { margin: 0 0 3mm; padding: 2mm 4mm; border-left: 3px solid #c94b5a; background: #fdf2f3; color: #7a2e39; font-style: italic; }
figure.chart { margin: 2mm 0 5mm; }
figure.chart .c-l { font: 9px Inter, Arial, sans-serif; fill: #6b7280; }
figure.chart .c-n { font: 600 10px Inter, Arial, sans-serif; fill: #1f2933; }
figure.shot { margin: 0 0 4mm; break-inside: avoid; }
figure.shot img { max-width: 100%; max-height: 120mm; border: 1px solid var(--rule); border-radius: 1.5mm; }
figure.shot figcaption { font-size: 8pt; color: var(--muted); margin-top: 1mm; }
/* On screen (the preview), sheets on a grey table; the PDF is laid out by the paginator (html.paged). */
@media screen {
  html:not(.paged) body { background: #e9e9ee; padding: 18px 0; }
  html:not(.paged) .cover, html:not(.paged) .toc, html:not(.paged) main { width: 210mm; margin: 0 auto 18px; background: #fff; box-shadow: 0 2px 14px rgba(0,0,0,.18); }
  html:not(.paged) .toc, html:not(.paged) main { padding: 20mm 18mm; }
  html:not(.paged) .cover { height: auto; min-height: 297mm; }
  html:not(.paged) h2 { break-before: auto; margin-top: 10mm; }
  html:not(.paged) .toc a::after { content: ""; }
}
</style>
</head>
<body>
${cover}
${contents}
<main>
${body.join("\n")}
</main>
</body>
</html>`;
}
