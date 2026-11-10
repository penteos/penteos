import type { Enricher, Finder, RawVuln, VulnQuery } from "./types.js";
import { preferCve } from "./types.js";
import type { Feeds, Net } from "./net.js";

/** Loose version compare for dotted versions (plugins, servers): numeric parts, left to right. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[^0-9]+/).filter(Boolean).map(Number);
  const pb = b.split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Base score out of a CVSS vector or a numeric field, when present. */
function scoreFrom(v: unknown): { version: string; vector?: string; score: number } | undefined {
  if (typeof v === "number" && v >= 0 && v <= 10) return { version: "3.1", score: v };
  if (typeof v === "string") {
    const m = /CVSS:(\d\.\d)/.exec(v);
    const base = /\/(?:base[sS]core|score)[:=](\d+(?:\.\d+)?)/i.exec(v);
    if (base) return { version: m?.[1] ?? "3.1", vector: v, score: Number(base[1]) };
    if (m) return { version: m[1]!, vector: v, score: NaN };
  }
  return undefined;
}

const TTL_DAY = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------------------------
// OSV - libraries and packages (finder). Per-query API, no key.
// ---------------------------------------------------------------------------------------------

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  references?: Array<{ url: string }>;
  affected?: Array<{ ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }> }>;
}

export function osvFinder(net: Net): Finder {
  return {
    name: "osv",
    available: () => true,
    async find(q: VulnQuery): Promise<RawVuln[]> {
      if (!q.ecosystem || !q.product) return [];
      const body = JSON.stringify({ ...(q.version ? { version: q.version } : {}), package: { name: q.product, ecosystem: q.ecosystem } });
      const res = await net.json<{ vulns?: OsvVuln[] }>("https://api.osv.dev/v1/query", { method: "POST", headers: { "Content-Type": "application/json" }, body });
      return (res.vulns ?? []).map((v) => {
        const cvss = v.severity?.map((s) => scoreFrom(s.score)).find((x) => x && !Number.isNaN(x.score));
        const fixed = v.affected?.flatMap((a) => a.ranges?.flatMap((r) => r.events?.map((e) => e.fixed).filter(Boolean) ?? []) ?? []) ?? [];
        return {
          id: preferCve(v.id, v.aliases),
          aliases: v.aliases,
          ...(v.summary || v.details ? { summary: (v.summary ?? v.details ?? "").slice(0, 600) } : {}),
          ...(cvss ? { cvss } : {}),
          ...(fixed.length ? { affected: `fixed in ${[...new Set(fixed)].join(", ")}` } : {}),
          ...(v.references?.length ? { references: v.references.map((r) => r.url).slice(0, 8) } : {}),
          source: "osv",
        } satisfies RawVuln;
      });
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Wordfence - WordPress core, plugins and themes (finder). Bulk feed, no key.
// ---------------------------------------------------------------------------------------------

interface WfSoftware {
  type: string;
  slug: string;
  affected_versions?: Record<string, { from_version?: string; from_inclusive?: boolean; to_version?: string; to_inclusive?: boolean }>;
}
interface WfVuln {
  id: string;
  title?: string;
  cve?: string;
  cvss?: { score?: number; vector?: string };
  software?: WfSoftware[];
  references?: string[];
}

function inRange(version: string, r: { from_version?: string; from_inclusive?: boolean; to_version?: string; to_inclusive?: boolean }): boolean {
  if (r.from_version && r.from_version !== "*") {
    const c = compareVersions(version, r.from_version);
    if (c < 0 || (c === 0 && r.from_inclusive === false)) return false;
  }
  if (r.to_version && r.to_version !== "*") {
    const c = compareVersions(version, r.to_version);
    if (c > 0 || (c === 0 && r.to_inclusive === false)) return false;
  }
  return true;
}

// Wordfence Intelligence (WordPress) made its feed licensed: optional, only with an API key
// (env PENTEOS_WORDFENCE_API_KEY). Without a key it stays off - the base sources still cover a lot.
export function wordfenceFinder(feeds: Feeds, apiKey?: string): Finder {
  const load = () =>
    feeds.get<WfVuln[]>(
      "wordfence",
      TTL_DAY,
      (net) => net.text("https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner/", { headers: { Authorization: `Bearer ${apiKey}` } }),
      (raw) => Object.values(JSON.parse(raw) as Record<string, WfVuln>),
    );
  return {
    name: "wordfence",
    available: () => Boolean(apiKey),
    async find(q: VulnQuery): Promise<RawVuln[]> {
      if (!apiKey) return [];
      if (q.ecosystem && !/wordpress/i.test(q.ecosystem)) return [];
      const slug = q.product.toLowerCase();
      const { data } = await load();
      const out: RawVuln[] = [];
      for (const v of data) {
        const match = (v.software ?? []).find((s) => s.slug?.toLowerCase() === slug || (s.type === "core" && slug === "wordpress"));
        if (!match) continue;
        if (q.version && match.affected_versions && !Object.values(match.affected_versions).some((r) => inRange(q.version!, r))) continue;
        out.push({
          id: preferCve(v.cve ?? v.id, v.cve ? [v.cve] : []),
          ...(v.title ? { title: v.title } : {}),
          ...(v.cvss?.score !== undefined ? { cvss: { version: "3.1", ...(v.cvss.vector ? { vector: v.cvss.vector } : {}), score: v.cvss.score } } : {}),
          ...(v.references?.length ? { references: v.references.slice(0, 8) } : {}),
          source: "wordfence",
        });
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// CISA KEV - exploited in the wild (enricher). Bulk feed, no key.
// ---------------------------------------------------------------------------------------------

export function kevEnricher(feeds: Feeds): Enricher {
  const load = () =>
    feeds.get<Record<string, string>>(
      "kev",
      TTL_DAY,
      (net) => net.text("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
      (raw) => {
        const parsed = JSON.parse(raw) as { vulnerabilities?: Array<{ cveID: string; dueDate?: string }> };
        return Object.fromEntries((parsed.vulnerabilities ?? []).map((v) => [v.cveID.toUpperCase(), v.dueDate ?? ""]));
      },
    );
  return {
    name: "kev",
    async enrich(ids) {
      const { data } = await load();
      const out = new Map<string, Partial<import("./types.js").VulnMatch>>();
      for (const id of ids) if (id.toUpperCase() in data) out.set(id, { kev: true, ...(data[id.toUpperCase()] ? { kevDueDate: data[id.toUpperCase()] } : {}) });
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// EPSS - probability of exploitation (enricher). Per-query API, no key.
// ---------------------------------------------------------------------------------------------

export function epssEnricher(net: Net): Enricher {
  return {
    name: "epss",
    async enrich(ids) {
      const cves = ids.filter((id) => /^CVE-/i.test(id)).slice(0, 100);
      const out = new Map<string, Partial<import("./types.js").VulnMatch>>();
      if (!cves.length) return out;
      const res = await net.json<{ data?: Array<{ cve: string; epss: string }> }>(`https://api.first.org/data/v1/epss?cve=${cves.join(",")}`);
      for (const row of res.data ?? []) {
        const p = Number(row.epss);
        if (!Number.isNaN(p)) out.set(row.cve.toUpperCase(), { epss: p });
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// ExploitDB - is there a public exploit (enricher). Bulk CSV index, no install, no key.
// ---------------------------------------------------------------------------------------------

export function exploitDbEnricher(feeds: Feeds): Enricher {
  const load = () =>
    feeds.get<Record<string, number[]>>(
      "exploitdb",
      7 * TTL_DAY,
      (net) => net.text("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"),
      (raw) => {
        const lines = raw.split(/\r?\n/);
        const header = (lines[0] ?? "").split(",");
        const idCol = header.indexOf("id");
        const codesCol = header.indexOf("codes");
        const map: Record<string, number[]> = {};
        if (idCol < 0 || codesCol < 0) return map;
        for (const line of lines.slice(1)) {
          const cols = splitCsv(line);
          const edbId = Number(cols[idCol]);
          const codes = cols[codesCol] ?? "";
          if (!edbId) continue;
          for (const code of codes.split(";")) {
            const cve = code.trim().toUpperCase();
            if (/^CVE-\d{4}-\d+$/.test(cve)) (map[cve] ??= []).push(edbId);
          }
        }
        return map;
      },
    );
  return {
    name: "exploitdb",
    async enrich(ids) {
      const { data } = await load();
      const out = new Map<string, Partial<import("./types.js").VulnMatch>>();
      for (const id of ids) {
        const edb = data[id.toUpperCase()];
        if (edb?.length) out.set(id, { hasExploit: true, exploitRefs: edb.slice(0, 5).map((n) => `https://www.exploit-db.com/exploits/${n}`) });
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Metasploit - is there a weaponised module (enricher). Bulk module metadata, no install, no key.
// ---------------------------------------------------------------------------------------------

export function metasploitEnricher(feeds: Feeds): Enricher {
  const load = () =>
    feeds.get<Record<string, string[]>>(
      "metasploit",
      7 * TTL_DAY,
      (net) => net.text("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"),
      (raw) => {
        const mods = JSON.parse(raw) as Record<string, { fullname?: string; references?: string[] }>;
        const map: Record<string, string[]> = {};
        for (const m of Object.values(mods)) {
          const name = m.fullname;
          if (!name || !m.references) continue;
          for (const ref of m.references) {
            const cve = ref.trim().toUpperCase();
            if (/^CVE-\d{4}-\d+$/.test(cve)) (map[cve] ??= []).push(name);
          }
        }
        return map;
      },
    );
  return {
    name: "metasploit",
    async enrich(ids) {
      const { data } = await load();
      const out = new Map<string, Partial<import("./types.js").VulnMatch>>();
      for (const id of ids) {
        const mods = data[id.toUpperCase()];
        if (mods?.length) out.set(id, { hasExploit: true, exploitRefs: mods.slice(0, 3).map((n) => `Metasploit: ${n}`) });
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// EUVD - ENISA's EU exploited list (enricher), the European KEV. Public API, no key.
// ---------------------------------------------------------------------------------------------

export function euvdEnricher(feeds: Feeds): Enricher {
  const load = () =>
    feeds.get<Record<string, true>>(
      "euvd",
      TTL_DAY,
      (net) => net.text("https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities?size=2000"),
      (raw) => {
        const rows = JSON.parse(raw) as Array<{ aliases?: string }>;
        const map: Record<string, true> = {};
        for (const r of rows) for (const alias of (r.aliases ?? "").split(/\s+/)) if (/^CVE-\d{4}-\d+$/i.test(alias)) map[alias.toUpperCase()] = true;
        return map;
      },
    );
  return {
    name: "euvd",
    async enrich(ids) {
      const { data } = await load();
      const out = new Map<string, Partial<import("./types.js").VulnMatch>>();
      for (const id of ids) if (data[id.toUpperCase()]) out.set(id, { kev: true });
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// WPVulnerability - WordPress core, plugins and themes (finder). Free community API, no key.
// ---------------------------------------------------------------------------------------------

interface WpvOperator {
  min_version?: string | null;
  min_operator?: string | null;
  max_version?: string | null;
  max_operator?: string | null;
}
interface WpvVuln {
  uuid: string;
  name: string;
  operator?: WpvOperator;
  source?: Array<{ id: string; link?: string }>;
  impact?: { cvss?: { version?: string; vector?: string; score?: string | number } };
}

function wpvInRange(op: WpvOperator, version: string): boolean {
  if (op.min_version) {
    const c = compareVersions(version, op.min_version);
    if (op.min_operator === "gt" ? c <= 0 : c < 0) return false;
  }
  if (op.max_version) {
    const c = compareVersions(version, op.max_version);
    if (op.max_operator === "le" ? c > 0 : c >= 0) return false;
  }
  return true;
}

export function wpVulnerabilityFinder(net: Net): Finder {
  return {
    name: "wpvulnerability",
    available: () => true,
    async find(q: VulnQuery): Promise<RawVuln[]> {
      const core = q.product.toLowerCase() === "wordpress";
      if (!core && q.ecosystem && !/wordpress/i.test(q.ecosystem)) return [];
      if (q.ecosystem === undefined && !core) return []; // only query for products tagged WordPress
      if (core && !q.version) return [];
      const url = core
        ? `https://www.wpvulnerability.net/core/${encodeURIComponent(q.version!)}/`
        : `https://www.wpvulnerability.net/plugin/${encodeURIComponent(q.product.toLowerCase())}/`;
      let res: { data?: { vulnerability?: WpvVuln[] } };
      try {
        res = await net.json(url);
      } catch {
        return [];
      }
      const out: RawVuln[] = [];
      for (const v of res.data?.vulnerability ?? []) {
        if (q.version && v.operator && !wpvInRange(v.operator, q.version)) continue;
        const sources = v.source ?? [];
        const cves = sources.map((s) => s.id).filter((id) => /^CVE-\d/i.test(id));
        const sc = v.impact?.cvss;
        const score = sc?.score != null ? Number(sc.score) : NaN;
        const refs = sources.map((s) => s.link).filter((l): l is string => Boolean(l));
        out.push({
          id: preferCve(cves[0] ?? v.uuid, cves),
          ...(cves.length ? { aliases: cves } : {}),
          ...(v.name ? { title: v.name } : {}),
          ...(sc && !Number.isNaN(score) ? { cvss: { version: sc.version ?? "3.1", ...(sc.vector ? { vector: sc.vector } : {}), score } } : {}),
          ...(v.operator?.max_version ? { affected: `fixed in ${v.operator.max_version}` } : {}),
          ...(refs.length ? { references: refs.slice(0, 6) } : {}),
          source: "wpvulnerability",
        });
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// NVD - generic products by CPE (finder). Network services (nginx, OpenSSH…) that no ecosystem
// covers. Keyless (rate-limited to ~5 req/30s; an optional key raises it). Precise: it needs a CPE.
// ---------------------------------------------------------------------------------------------

/** nmap's CPE 2.2 URI (cpe:/a:v:p:ver) or a 2.3 string → an NVD virtualMatchString (2.3). */
export function toCpe23(cpe: string): string | undefined {
  if (cpe.startsWith("cpe:2.3:")) return cpe;
  const m = /^cpe:\/([aoh]):([^:]*):([^:]*)(?::([^:]*))?/.exec(cpe);
  if (!m) return undefined;
  const [, part, vendor, product, version] = m;
  const field = (v: string | undefined) => (v && v !== "" ? v.replace(/ /g, "_").toLowerCase() : "*");
  return `cpe:2.3:${part}:${field(vendor)}:${field(product)}:${field(version)}:*:*:*:*:*:*:*`;
}

interface CpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}
interface NvdItem {
  cve: {
    id: string;
    descriptions?: Array<{ lang: string; value: string }>;
    metrics?: Record<string, Array<{ cvssData?: { baseScore?: number; vectorString?: string; version?: string }; baseSeverity?: string }>>;
    references?: Array<{ url: string }>;
    configurations?: Array<{ nodes?: Array<{ cpeMatch?: CpeMatch[] }> }>;
  };
}

/** The product and version fields of a 2.3 CPE string. */
function cpeParts(cpe: string): { product?: string; version?: string } {
  const f = cpe.split(":");
  return { product: f[4], version: f[5] };
}

/** Whether the detected version actually falls in a CVE's cpeMatch range (the real applicability). */
function versionInMatch(version: string, m: CpeMatch): boolean {
  const has = m.versionStartIncluding || m.versionStartExcluding || m.versionEndIncluding || m.versionEndExcluding;
  if (!has) {
    // No range: the match pins an exact version in its CPE, so require equality (ignore "*").
    const cv = m.criteria ? cpeParts(m.criteria).version : undefined;
    return Boolean(cv && cv !== "*" && compareVersions(version, cv) === 0);
  }
  if (m.versionStartIncluding && compareVersions(version, m.versionStartIncluding) < 0) return false;
  if (m.versionStartExcluding && compareVersions(version, m.versionStartExcluding) <= 0) return false;
  if (m.versionEndIncluding && compareVersions(version, m.versionEndIncluding) > 0) return false;
  if (m.versionEndExcluding && compareVersions(version, m.versionEndExcluding) >= 0) return false;
  return true;
}

export function nvdFinder(net: Net, apiKey?: string): Finder {
  return {
    name: "nvd",
    available: () => true,
    async find(q: VulnQuery): Promise<RawVuln[]> {
      const cpe = q.cpe ? toCpe23(q.cpe) : undefined;
      if (!cpe) return []; // NVD here is precise by CPE; without one, other finders cover it.
      const product = cpeParts(cpe).product;
      const version = (q.version ?? cpeParts(cpe).version)?.trim();
      // Without a precise version NVD returns the product's whole CVE history - noise. Require one.
      if (!version || version === "*" || !/\d/.test(version)) return [];
      const headers = apiKey ? { apiKey } : undefined;
      const res = await net.json<{ vulnerabilities?: NvdItem[] }>(`https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encodeURIComponent(cpe)}&resultsPerPage=500`, headers ? { headers } : {});
      const out: RawVuln[] = [];
      for (const { cve } of res.vulnerabilities ?? []) {
        // Only the cpeMatch entries for THIS product, and only those the detected version is in.
        const matches = (cve.configurations ?? []).flatMap((c) => c.nodes?.flatMap((n) => n.cpeMatch ?? []) ?? [])
          .filter((m) => m.vulnerable !== false && (!m.criteria || !product || cpeParts(m.criteria).product === product));
        const applicable = matches.filter((m) => versionInMatch(version, m));
        if (matches.length && !applicable.length) continue; // product matched but this version is not affected
        const metric = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0] ?? cve.metrics?.cvssMetricV2?.[0];
        const data = metric?.cvssData;
        const fixed = applicable.map((m) => m.versionEndExcluding).filter((v): v is string => Boolean(v));
        out.push({
          id: cve.id.toUpperCase(),
          ...(cve.descriptions?.find((d) => d.lang === "en")?.value ? { summary: cve.descriptions.find((d) => d.lang === "en")!.value.slice(0, 600) } : {}),
          ...(data?.baseScore !== undefined ? { cvss: { version: data.version ?? "3.1", ...(data.vectorString ? { vector: data.vectorString } : {}), score: data.baseScore } } : {}),
          ...(fixed.length ? { affected: `fixed in ${[...new Set(fixed)].join(", ")}` } : {}),
          ...(cve.references?.length ? { references: cve.references.map((r) => r.url).slice(0, 8) } : {}),
          source: "nvd",
        });
      }
      return out;
    },
  };
}

/** A CSV line split that honours simple double-quoted fields. */
function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else inQuotes = !inQuotes;
    } else if (c === "," && !inQuotes) {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}
