import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Network and cache for the vulnerability sources. Per-query APIs (OSV) go
 * through `json`; bulk feeds (KEV, EPSS, ExploitDB index, Wordfence) go through `feed`, which keeps
 * a dated copy on disk and reuses it within a TTL. Everything degrades: a source that fails falls
 * back to the cached copy, and the "as of" date travels with the data so stale intel is visible.
 */
export interface Net {
  json<T>(url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }): Promise<T>;
  text(url: string, init?: { headers?: Record<string, string> }): Promise<string>;
}

/** Default Net over global fetch, with a timeout. */
export function httpNet(timeoutMs = 15_000): Net {
  const call = async (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(url, { method: init?.method ?? "GET", headers: init?.headers, body: init?.body, signal: ac.signal });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
      return res;
    } finally {
      clearTimeout(timer);
    }
  };
  return {
    async json<T>(url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) {
      const res = await call(url, init);
      return (await res.json()) as T;
    },
    async text(url: string, init?: { headers?: Record<string, string> }) {
      const res = await call(url, init);
      return await res.text();
    },
  };
}

export interface FeedResult<T> {
  data: T;
  asOf: string;
  /** True when it came from the cache because the network failed or the TTL had not expired. */
  cached: boolean;
}

/**
 * Cached bulk feeds. A feed is fetched at most once per TTL; on a network error the last good copy
 * is used. The parsed value and its "as of" date are what callers see.
 */
export class Feeds {
  constructor(
    private readonly dir: string,
    private readonly net: Net = httpNet(),
  ) {
    mkdirSync(dir, { recursive: true });
  }

  private pathFor(name: string): string {
    return join(this.dir, `${name}.json`);
  }

  private readCache<T>(name: string): { data: T; asOf: string } | undefined {
    try {
      const raw = readFileSync(this.pathFor(name), "utf8");
      const { data, asOf } = JSON.parse(raw) as { data: T; asOf: string };
      return { data, asOf };
    } catch {
      return undefined;
    }
  }

  private ageMs(name: string): number {
    try {
      return Date.now() - statSync(this.pathFor(name)).mtimeMs;
    } catch {
      return Infinity;
    }
  }

  status(name: string): { asOf?: string; ageMs: number } {
    const cached = this.readCache<unknown>(name);
    return { ...(cached ? { asOf: cached.asOf } : {}), ageMs: this.ageMs(name) };
  }

  /**
   * Returns the feed, fetching and re-parsing only when the cache is older than `ttlMs`. `fetch`
   * gets the raw text; `parse` turns it into the stored value. A failed fetch falls back to cache.
   */
  async get<T>(name: string, ttlMs: number, fetchRaw: (net: Net) => Promise<string>, parse: (raw: string) => T): Promise<FeedResult<T>> {
    const fresh = this.ageMs(name) < ttlMs;
    const cached = this.readCache<T>(name);
    if (fresh && cached) return { data: cached.data, asOf: cached.asOf, cached: true };
    try {
      const raw = await fetchRaw(this.net);
      const data = parse(raw);
      const asOf = new Date().toISOString();
      writeFileSync(this.pathFor(name), JSON.stringify({ data, asOf }));
      return { data, asOf, cached: false };
    } catch (e) {
      if (cached) return { data: cached.data, asOf: cached.asOf, cached: true };
      throw e;
    }
  }
}
