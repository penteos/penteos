import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { extname } from "node:path";
import { unzipSync } from "fflate";
import type { Actor } from "@penteos/schema";
import type { Engagement } from "./engagement.js";

/**
 * A previous assessment of the same client, done elsewhere (another team, another tool), as the
 * baseline of this one: its findings are read from the document by the agent, each one gets a
 * status here (still open, fixed, not re-tested) and the report says what was fixed, what remains
 * and what is new. Retests between Penteos projects already do this (engagement.retest); this is
 * for the report that came from outside.
 */

export interface BaselineFinding {
  /** The previous report's own reference ("M1", "A3", "F4-2"). */
  ref: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  asset?: string;
  summary?: string;
  status?: "still_open" | "fixed" | "not_retested";
  /** The finding of this assessment that confirms it is still there. */
  findingId?: string;
  note?: string;
  decidedBy?: Actor;
}

export interface Baseline {
  source: string;
  date?: string;
  findings: BaselineFinding[];
  at: string;
}

const KEY = "externalBaseline";

export function getBaseline(e: Engagement): Baseline | undefined {
  return e.getState<Baseline>(KEY);
}

export function setBaseline(e: Engagement, b: Omit<Baseline, "at">, by: Actor): Baseline {
  const prev = getBaseline(e);
  // Statuses already given survive a re-import of the same references.
  const findings = b.findings.map((f) => {
    const old = prev?.findings.find((x) => x.ref === f.ref);
    return old?.status ? { ...f, status: old.status, ...(old.findingId ? { findingId: old.findingId } : {}), ...(old.note ? { note: old.note } : {}), ...(old.decidedBy ? { decidedBy: old.decidedBy } : {}) } : f;
  });
  const out = { ...b, findings, at: new Date().toISOString() };
  e.setState(KEY, out);
  e.audit(by, "baseline.set", { source: b.source }, { findings: findings.length });
  return out;
}

export function linkBaseline(e: Engagement, ref: string, patch: Pick<BaselineFinding, "status" | "findingId" | "note">, by: Actor): BaselineFinding {
  const b = getBaseline(e);
  const f = b?.findings.find((x) => x.ref === ref);
  if (!b || !f) throw new Error(`no baseline finding ${ref}`);
  Object.assign(f, patch, { decidedBy: by });
  if (!patch.findingId) delete f.findingId;
  e.setState(KEY, b);
  e.audit(by, "baseline.link", { ref }, patch);
  return f;
}

/** Baseline findings nobody gave a status yet. */
export function undecidedBaseline(e: Engagement): BaselineFinding[] {
  return getBaseline(e)?.findings.filter((f) => !f.status) ?? [];
}

/** The text of a previous report: Markdown or text as is, Word from its XML, PDF with pdftotext. */
export function readDocumentText(file: string): { text: string; method: string } {
  const size = statSync(file).size;
  if (size > 60 * 1024 * 1024) throw new Error("the document is larger than 60 MB");
  const ext = extname(file).toLowerCase();
  if (ext === ".md" || ext === ".txt" || ext === ".markdown") return { text: readFileSync(file, "utf8"), method: "text" };
  if (ext === ".docx") {
    const files = unzipSync(readFileSync(file));
    const xml = files["word/document.xml"];
    if (!xml) throw new Error("not a Word document (no word/document.xml)");
    const text = Buffer.from(xml)
      .toString("utf8")
      .replace(/<w:tab\/>/g, "\t")
      .replace(/<\/w:p>/g, "\n")
      .replace(/<w:br\/>/g, "\n")
      .replace(/<[^>]+>/g, "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&amp;/g, "&");
    return { text, method: "docx" };
  }
  if (ext === ".pdf") {
    const r = spawnSync("pdftotext", ["-layout", "-enc", "UTF-8", file, "-"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 60_000 });
    if (r.status === 0 && r.stdout.trim()) return { text: r.stdout, method: "pdftotext" };
    throw new Error(r.error ? "pdftotext is not installed (poppler-utils on Linux, poppler with Homebrew): install it, or save the report as Word or text" : "the PDF has no extractable text (a scan?): save it as Word or text, or paste its findings");
  }
  throw new Error(`unsupported document type ${ext}: use PDF, Word (.docx), Markdown or text`);
}
