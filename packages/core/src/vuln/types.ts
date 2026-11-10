/**
 * Known-vulnerability intelligence. The engine matches a product+version
 * against several sources and ranks the result, so the agent gets a few decision-ready leads, not
 * a dump of CVEs. Sources are of two kinds: finders (product/version → CVE ids) and enrichers
 * (CVE id → extra signal: exploited in the wild, exploit probability, public exploit).
 */

/** What to look up: a technology detected on the target. */
export interface VulnQuery {
  product: string;
  version?: string;
  /** For library lookups (OSV): npm, PyPI, composer, Go, WordPress… */
  ecosystem?: string;
  /** cpe:2.3:a:vendor:product:version:… when known. */
  cpe?: string;
  /** The host's distribution when known (e.g. "ubuntu", "debian", "ubuntu:22.04"): enables backport awareness. */
  distro?: string;
}

export interface Cvss {
  version: string;
  vector?: string;
  score: number;
}

/** A vulnerability as a finder reports it, before enrichment and ranking. */
export interface RawVuln {
  /** Preferred CVE id (CVE-YYYY-NNNN); a GHSA/other id if no CVE alias. */
  id: string;
  aliases?: string[];
  title?: string;
  summary?: string;
  cvss?: Cvss;
  /** Human text of the affected range, for the applicability step. */
  affected?: string;
  references?: string[];
  source: string;
}

/** A ranked vulnerability as the engine returns it. */
export interface VulnMatch extends RawVuln {
  sources: string[];
  /** Exploited in the wild (CISA KEV). */
  kev?: boolean;
  kevDueDate?: string;
  /** EPSS probability of exploitation in the next 30 days (0-1). */
  epss?: number;
  /** A public exploit exists (ExploitDB / searchsploit). */
  hasExploit?: boolean;
  exploitRefs?: string[];
  /** Composite priority (higher first) and a one-line reason. */
  rank: number;
  why: string;
  /** Deterministic triage tier: dangerous now / warning / cold. */
  tier?: "fire" | "smoke" | "ice";
  /**
   * The host runs a distribution that may have backported the fix. The banner shows the UPSTREAM
   * version, which can't confirm the patch level, so this lowers confidence (caps the tier at smoke
   * and makes applicability "unknown") instead of asserting the host is patched - a missed real
   * vulnerability is worse than a lead to confirm.
   */
  backportSuspect?: boolean;
  /** Whether it applies to THIS deployment (version range, attack vector), with the reasons. */
  applies?: "yes" | "unlikely" | "unknown";
  applyReasons?: string[];
}

export interface Finder {
  name: string;
  available(): boolean | Promise<boolean>;
  find(q: VulnQuery): Promise<RawVuln[]>;
}

export interface Enricher {
  name: string;
  /** CVE id → partial signal to merge (kev, epss, hasExploit…). */
  enrich(ids: string[]): Promise<Map<string, Partial<VulnMatch>>>;
}

/** Freshness of a cached bulk feed. */
export interface FeedStatus {
  name: string;
  asOf?: string;
  ok: boolean;
  note?: string;
  /** A per-query API (OSV, NVD, EPSS), not a cached file: always available, nothing to download. */
  live?: boolean;
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
export const isCve = (id: string): boolean => CVE_RE.test(id);

/** The CVE id among a primary id and its aliases, if any (CVE is the lingua franca). */
export function preferCve(id: string, aliases: string[] = []): string {
  if (isCve(id)) return id.toUpperCase();
  const cve = aliases.find(isCve);
  return cve ? cve.toUpperCase() : id;
}

/** CVSS 0-10 to a severity band. */
export function severityOf(score: number | undefined): "critical" | "high" | "medium" | "low" | "info" {
  if (score === undefined) return "info";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}
