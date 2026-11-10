import { Feeds, httpNet, type Net } from "./net.js";
import { epssEnricher, euvdEnricher, exploitDbEnricher, kevEnricher, metasploitEnricher, nvdFinder, osvFinder, wpVulnerabilityFinder } from "./providers.js";
import type { Enricher, FeedStatus, Finder } from "./types.js";

export * from "./types.js";
export { lookup, rankOf, tierOf, type LookupResult } from "./engine.js";
export { Feeds, httpNet, type Net } from "./net.js";
export { compareVersions, toCpe23 } from "./providers.js";

/**
 * The base providers: all keyless and HTTP, nothing to install. OSV covers
 * ecosystem packages, WPVulnerability covers WordPress core/plugins/themes (free community API, no
 * key), NVD covers generic products with a CPE (network services from nmap). An NVD key (env
 * PENTEOS_NVD_API_KEY) only raises the rate limit; no source requires a key.
 */
export function defaultProviders(cacheDir: string, net?: Net): { finders: Finder[]; enrichers: Enricher[]; feeds: Feeds } {
  // Bulk feeds (KEV, ExploitDB, Wordfence) can be tens of MB, so they get a generous timeout;
  // per-query APIs (OSV, NVD, EPSS) use the short one. A test may inject one net for both.
  const feedNet = net ?? httpNet(90_000);
  const queryNet = net ?? httpNet(15_000);
  const feeds = new Feeds(cacheDir, feedNet);
  const nvdKey = process.env.PENTEOS_NVD_API_KEY || undefined;
  return {
    finders: [osvFinder(queryNet), wpVulnerabilityFinder(queryNet), nvdFinder(queryNet, nvdKey)],
    enrichers: [kevEnricher(feeds), euvdEnricher(feeds), epssEnricher(queryNet), exploitDbEnricher(feeds), metasploitEnricher(feeds)],
    feeds,
  };
}

// Cached bulk feeds (downloaded and kept with an "as of" date).
const FEED_LABELS: Record<string, string> = { kev: "CISA KEV", euvd: "EUVD (ENISA)", exploitdb: "ExploitDB", metasploit: "Metasploit" };
const FEED_TTL: Record<string, number> = { kev: 1, euvd: 1, exploitdb: 7, metasploit: 7 };
// Per-query APIs: nothing to download, always current.
const LIVE_SOURCES = ["OSV", "WPVulnerability", "NVD", "EPSS"];

/** Freshness of the cached feeds (with a date) plus the live sources (no download), for the indicator. */
export function feedStatuses(cacheDir: string): FeedStatus[] {
  const feeds = new Feeds(cacheDir);
  const cached = Object.keys(FEED_LABELS).map((name) => {
    const s = feeds.status(name);
    const days = s.ageMs / (24 * 60 * 60 * 1000);
    return {
      name: FEED_LABELS[name]!,
      ...(s.asOf ? { asOf: s.asOf } : {}),
      ok: Number.isFinite(s.ageMs),
      ...(s.asOf === undefined ? { note: "not downloaded yet" } : days > (FEED_TTL[name] ?? 1) + 1 ? { note: "stale" } : {}),
    };
  });
  return [...cached, ...LIVE_SOURCES.map((name) => ({ name, ok: true, live: true }))];
}
