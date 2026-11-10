import { INGEST_FORMAT, type IngestBatch, type IngestItem } from "@penteos/schema";

/**
 * Proxy history into the graph: Burp Suite "Save items" XML and HAR (browsers, Caido, ZAP,
 * mitmproxy). Each request becomes an endpoint of its application, with methods, statuses and
 * parameter names; the exchanges themselves are kept as raw, to be used as evidence.
 */

export interface Exchange {
  url: URL;
  method: string;
  status?: number;
  /** Request and response, as raw HTTP text when the source has it. */
  raw: string;
  params: Array<{ name: string; location: "query" | "body" | "cookie" }>;
}

export function isBurpXml(text: string): boolean {
  return /<items[^>]*burpVersion/i.test(text);
}

export function isHar(text: string): boolean {
  return /^\s*\{[\s\S]{0,200}"log"\s*:/.test(text) && text.includes('"entries"');
}

function bodyParams(body: string, contentType: string): Array<{ name: string; location: "body" }> {
  if (!body) return [];
  if (contentType.includes("json")) {
    try {
      const j = JSON.parse(body) as unknown;
      return j && typeof j === "object" && !Array.isArray(j) ? Object.keys(j).map((name) => ({ name, location: "body" as const })) : [];
    } catch {
      return [];
    }
  }
  if (!contentType || contentType.includes("urlencoded")) return [...new Set(new URLSearchParams(body).keys())].map((name) => ({ name, location: "body" as const }));
  return [];
}

function queryParams(url: URL) {
  return [...new Set(url.searchParams.keys())].map((name) => ({ name, location: "query" as const }));
}

function cdata(item: string, tag: string): { text: string; base64: boolean } | undefined {
  const m = new RegExp(`<${tag}(\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "i").exec(item);
  if (!m) return undefined;
  const text = m[2]!.replace(/^<!\[CDATA\[/, "").replace(/\]\]>$/, "");
  return { text, base64: /base64="true"/i.test(m[1] ?? "") };
}

export function parseBurpXml(xml: string): Exchange[] {
  const out: Exchange[] = [];
  for (const m of xml.matchAll(/<item>([\s\S]*?)<\/item>/gi)) {
    const item = m[1]!;
    const urlText = cdata(item, "url")?.text;
    if (!urlText) continue;
    let url: URL;
    try {
      url = new URL(urlText);
    } catch {
      continue;
    }
    const decode = (v?: { text: string; base64: boolean }) => (v ? (v.base64 ? Buffer.from(v.text, "base64").toString("utf8") : v.text) : "");
    const request = decode(cdata(item, "request"));
    const response = decode(cdata(item, "response"));
    const method = (cdata(item, "method")?.text ?? request.split(" ")[0] ?? "GET").toUpperCase();
    const status = Number(cdata(item, "status")?.text) || undefined;
    const split = request.replace(/\r\n/g, "\n").indexOf("\n\n");
    const reqHead = split === -1 ? request : request.slice(0, split);
    const reqBody = split === -1 ? "" : request.replace(/\r\n/g, "\n").slice(split + 2);
    const ct = /content-type:\s*([^\n]+)/i.exec(reqHead)?.[1] ?? "";
    out.push({ url, method, ...(status ? { status } : {}), raw: `${request}\r\n\r\n${response}`, params: [...queryParams(url), ...bodyParams(reqBody, ct.toLowerCase())] });
  }
  return out;
}

interface HarEntry {
  request: { method: string; url: string; httpVersion?: string; headers?: Array<{ name: string; value: string }>; postData?: { mimeType?: string; text?: string } };
  response: { status: number; statusText?: string; headers?: Array<{ name: string; value: string }>; content?: { text?: string; encoding?: string } };
}

export function parseHar(json: string): Exchange[] {
  const har = JSON.parse(json) as { log?: { entries?: HarEntry[] } };
  const out: Exchange[] = [];
  for (const e of har.log?.entries ?? []) {
    let url: URL;
    try {
      url = new URL(e.request.url);
    } catch {
      continue;
    }
    if (!/^https?:$/.test(url.protocol)) continue;
    const reqBody = e.request.postData?.text ?? "";
    const resBody = e.response.content?.encoding === "base64" ? "[binario]" : (e.response.content?.text ?? "");
    const raw = [
      `${e.request.method} ${url.pathname}${url.search} HTTP/1.1`,
      ...(e.request.headers ?? []).map((h) => `${h.name}: ${h.value}`),
      "",
      reqBody,
      "",
      `HTTP/1.1 ${e.response.status} ${e.response.statusText ?? ""}`,
      ...(e.response.headers ?? []).map((h) => `${h.name}: ${h.value}`),
      "",
      resBody,
    ].join("\r\n");
    out.push({
      url,
      method: e.request.method.toUpperCase(),
      ...(e.response.status ? { status: e.response.status } : {}),
      raw,
      params: [...queryParams(url), ...bodyParams(reqBody, (e.request.postData?.mimeType ?? "").toLowerCase())],
    });
  }
  return out;
}

/** The graph side of a proxy history. */
export function exchangesToBatch(exchanges: Exchange[], rawIds: string[], tool: string): IngestBatch {
  const items: IngestItem[] = [];
  const origins = new Set<string>();
  for (const x of exchanges) {
    if (!origins.has(x.url.origin)) {
      origins.add(x.url.origin);
      items.push({ op: "upsert", kind: "webapp", key: { origin: x.url.origin }, confidence: 1 });
    }
    items.push({
      op: "upsert",
      kind: "endpoint",
      key: { origin: x.url.origin, path: x.url.pathname },
      attributes: { methods: [x.method], ...(x.status ? { statusesSeen: [x.status] } : {}), ...(x.params.length ? { params: x.params } : {}) },
      confidence: 1,
    } as IngestItem);
  }
  return { format: INGEST_FORMAT, source: { parser: `${tool}-import@0.1.0`, tool }, rawIds, observedAt: new Date().toISOString(), items };
}
