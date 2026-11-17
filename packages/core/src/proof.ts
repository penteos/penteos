/**
 * Textual proof: a finding is backed by what the target actually answered, not by what the model
 * says it answered. Evidence can carry quotes (the leaked hash, another user's e-mail, the SQL
 * error), and each quote is checked against the stored output it points to before the evidence is
 * accepted. A model that misremembers or invents a response cannot turn it into proof.
 *
 * The model reads the client's data masked («email:3»), so a quote is matched with the markers put
 * back to their real values; secrets it only ever saw redacted are matched against the redacted
 * output. Compressed HTTP bodies are decoded first. Whitespace runs count as one space.
 */
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import type { Engagement } from "./engagement.js";
import { restore } from "./privacy/vault.js";

/** The shortest quote that proves anything (shorter ones match by chance). */
export const MIN_QUOTE = 8;

const norm = (s: string) => s.replace(/\s+/g, " ").trim();

/** HTTP bodies stored compressed, decoded so a quote of what the page said can be found. */
function decodedBodies(text: string, raw: Buffer): string[] {
  const out: string[] = [];
  const re = /content-encoding:\s*(gzip|br|deflate)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const headersEnd = text.indexOf("\r\n\r\n", m.index);
    if (headersEnd < 0) continue;
    // The body as bytes: the same offset in the buffer (headers are ASCII).
    const start = Buffer.byteLength(text.slice(0, headersEnd + 4), "utf8");
    const body = raw.subarray(start);
    for (const decode of m[1]!.toLowerCase() === "gzip" ? [gunzipSync] : m[1]!.toLowerCase() === "br" ? [brotliDecompressSync] : [inflateSync]) {
      try {
        out.push(decode(body).toString("utf8"));
      } catch {
        /* not a whole compressed body (cut, or several messages): the plain text is all there is */
      }
    }
  }
  return out;
}

/** The text of a stored output (or of its byte range), with compressed bodies decoded. */
export function rawText(e: Engagement, rawId: string, range?: { start: number; end: number }): string[] {
  const all = e.readRaw(rawId);
  const raw = range ? all.subarray(range.start, Math.max(range.start, range.end)) : all;
  const text = raw.toString("utf8");
  // A range inside a compressed body cannot be decoded alone: decode the whole message instead.
  return [text, ...decodedBodies(text, raw), ...(range ? decodedBodies(all.toString("utf8"), all) : [])];
}

export interface QuoteCheck {
  found: string[];
  missing: string[];
}

/** Which quotes are really in the output. */
export function checkQuotes(e: Engagement, rawId: string, range: { start: number; end: number } | undefined, quotes: string[]): QuoteCheck {
  const texts = rawText(e, rawId, range).flatMap((t) => [norm(t), norm(e.redact(t))]);
  const found: string[] = [];
  const missing: string[] = [];
  for (const q of quotes) {
    const real = norm(restore(e, q).text);
    const asWritten = norm(q);
    if (real.length >= MIN_QUOTE && texts.some((t) => t.includes(real) || t.includes(asWritten))) found.push(q);
    else missing.push(q);
  }
  return { found, missing };
}

/** Severities a proposal to the operator needs textual proof for. */
export const NEEDS_PROOF = new Set(["critical", "high", "medium"]);

/**
 * Whether a finding is proven by quotes checked in the output (its own evidence, or the verifier's),
 * or declared proven by an absence (a header, a lockout, a limit that is not there).
 */
export function proofOf(e: Engagement, finding: { attributes: Record<string, unknown> }): { quoted: number; absence: boolean } {
  const ids = [...((finding.attributes.evidenceIds as string[] | undefined) ?? []), ...(((finding.attributes.verification as { evidenceIds?: string[] } | undefined)?.evidenceIds) ?? [])];
  let quoted = 0;
  for (const id of ids) {
    const ev = e.get(id);
    if (ev?.kind === "evidence") quoted += ((ev.attributes.quotes as unknown[] | undefined) ?? []).length;
  }
  return { quoted, absence: Boolean(String(finding.attributes.absenceProof ?? "").trim()) };
}
