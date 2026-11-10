/**
 * Web search and page reading through Parallel's public search server (MCP over HTTP: JSON-RPC,
 * no key). Penteos speaks to it directly, so the Maestro has it whatever model it runs on.
 * https://search.parallel.ai/mcp - terms: https://parallel.ai/customer-terms
 */

export const PARALLEL_URL = "https://search.parallel.ai/mcp";
const PROTOCOL = "2025-03-26";

export interface WebResult {
  url: string;
  title: string;
  date?: string;
  excerpts: string[];
}

export interface FetchedPage {
  url: string;
  title?: string;
  /** The parts of the page relevant to the objective (or its text). */
  excerpts: string[];
  error?: string;
}

export class ResearchError extends Error {}

/** Reads a JSON-RPC answer that may come as JSON or as server-sent events. */
async function rpcBody(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text();
  if ((res.headers.get("content-type") ?? "").includes("event-stream")) {
    const data = text
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .filter(Boolean);
    for (const d of data.reverse()) {
      try {
        const parsed = JSON.parse(d) as Record<string, unknown>;
        if ("result" in parsed || "error" in parsed) return parsed;
      } catch {
        /* a keep-alive or a partial line */
      }
    }
    throw new ResearchError("the search service sent no answer");
  }
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new ResearchError(`the search service answered something that is not JSON (${res.status})`);
  }
}

export class ParallelClient {
  private session: string | undefined;
  private seq = 0;

  constructor(
    private readonly fetchImpl: typeof fetch = (...a) => fetch(...a),
    private readonly url = PARALLEL_URL,
    private readonly timeoutMs = 60_000,
  ) {}

  private headers(): Record<string, string> {
    return {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": PROTOCOL,
      "user-agent": "Penteos",
      ...(this.session ? { "mcp-session-id": this.session } : {}),
    };
  }

  private async post(body: Record<string, unknown>): Promise<Response> {
    return this.fetchImpl(this.url, { method: "POST", headers: this.headers(), body: JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs) });
  }

  private async open(): Promise<void> {
    this.session = undefined;
    const res = await this.post({ jsonrpc: "2.0", id: ++this.seq, method: "initialize", params: { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: "penteos", version: "1" } } });
    if (!res.ok) throw new ResearchError(`the search service is not available (${res.status})`);
    this.session = res.headers.get("mcp-session-id") ?? undefined;
    await rpcBody(res);
    await this.post({ jsonrpc: "2.0", method: "notifications/initialized" }).then((r) => r.text()).catch(() => undefined);
  }

  /** One tool call; a lapsed session is opened again once. */
  private async call(name: string, args: Record<string, unknown>, retry = true): Promise<unknown> {
    if (!this.session) await this.open();
    const res = await this.post({ jsonrpc: "2.0", id: ++this.seq, method: "tools/call", params: { name, arguments: args } });
    if ((res.status === 404 || res.status === 400) && retry) {
      this.session = undefined;
      return this.call(name, args, false);
    }
    if (res.status === 429) throw new ResearchError("the search service is limiting requests: wait a minute, or use research_github for code and exploits");
    if (!res.ok) throw new ResearchError(`the search service failed (${res.status})`);
    const body = await rpcBody(res);
    if (body.error) {
      const e = body.error as { message?: string };
      if (retry && /session/i.test(String(e.message))) {
        this.session = undefined;
        return this.call(name, args, false);
      }
      throw new ResearchError(`the search service refused: ${e.message ?? "unknown error"}`);
    }
    const result = body.result as { content?: Array<{ type: string; text?: string }>; isError?: boolean } | undefined;
    const text = result?.content?.find((c) => c.type === "text")?.text ?? "";
    if (result?.isError) throw new ResearchError(`the search service could not do it: ${text.slice(0, 300)}`);
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  async search(objective: string, queries: string[]): Promise<WebResult[]> {
    const out = (await this.call("web_search", { objective, search_queries: queries })) as { results?: Array<{ url?: string; title?: string; publish_date?: string | null; excerpts?: string[] }> };
    return (out?.results ?? [])
      .filter((r) => typeof r.url === "string")
      .map((r) => ({ url: r.url!, title: String(r.title ?? r.url), ...(r.publish_date ? { date: r.publish_date } : {}), excerpts: (r.excerpts ?? []).map(String) }));
  }

  async fetchPages(urls: string[], objective?: string): Promise<FetchedPage[]> {
    const out = (await this.call("web_fetch", { urls, ...(objective ? { objective } : {}) })) as {
      results?: Array<{ url?: string; title?: string | null; excerpts?: string[]; full_content?: string | null }>;
      errors?: Array<{ url?: string; error_type?: string; content?: string }>;
    };
    const pages: FetchedPage[] = (out?.results ?? []).map((r) => ({
      url: String(r.url),
      ...(r.title ? { title: r.title } : {}),
      excerpts: r.excerpts?.length ? r.excerpts.map(String) : r.full_content ? [String(r.full_content)] : [],
    }));
    for (const e of out?.errors ?? []) pages.push({ url: String(e.url), excerpts: [], error: String(e.error_type ?? e.content ?? "could not read it") });
    return pages;
  }
}
