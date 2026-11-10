import type { Enricher, Finder, RawVuln, VulnMatch, VulnQuery } from "./types.js";
import { preferCve, severityOf } from "./types.js";
import { compareVersions } from "./providers.js";

/**
 * Does this match apply to THIS deployment, or is it noise? It
 * cuts what a version list over-reports - a CVE already patched in the detected version, or one that
 * needs local access when we are testing over the network - and keeps the reason, so "60 CVEs" becomes
 * "5 that matter, and here is why the rest were set aside". It never silences an exploited-in-the-wild
 * one; that gets decided when recording, not here.
 */
export function applicability(m: VulnMatch, q: VulnQuery): { applies: "yes" | "unlikely" | "unknown"; reasons: string[] } {
  const reasons: string[] = [];
  let applies: "yes" | "unlikely" | "unknown" = "yes";
  const av = /AV:([NALP])/.exec(m.cvss?.vector ?? "")?.[1];
  if (av === "L" || av === "P") {
    applies = "unlikely";
    reasons.push(av === "L" ? "local attack vector, not reachable over the network" : "physical attack vector");
  }
  if (q.version && m.affected) {
    const fixes = [...m.affected.matchAll(/fixed in ([\w.]+)/g)].map((x) => x[1]!);
    if (fixes.length && fixes.every((f) => compareVersions(q.version!, f) >= 0)) {
      applies = "unlikely";
      reasons.push(`the detected version ${q.version} is at or past the fixed version (${fixes.join(", ")})`);
    }
  }
  if (/\b(authenticated|requires? (an? )?(admin|login|account|valid|privileg)|logged.?in)\b/i.test(`${m.title ?? ""} ${m.summary ?? ""}`)) reasons.push("may need authentication");
  if (m.backportSuspect) {
    if (applies === "yes") applies = "unknown";
    reasons.push(`${q.distro} may have backported the fix; the banner shows the upstream version, so confirm directly before treating it as present`);
  }
  if (applies === "yes" && !m.cvss?.vector && !m.affected && !q.version) applies = "unknown";
  return { applies, reasons };
}

/**
 * The ranking: it decides what matters, not how many CVEs exist. Exploited-in-the-wild (KEV) is the
 * strongest signal, then EPSS probability, then CVSS, then "a public exploit exists". The score
 * only orders the list; the human `why` says why each is where it is.
 */
export function rankOf(v: VulnMatch): { rank: number; why: string } {
  const reasons: string[] = [];
  let rank = 0;
  if (v.kev) {
    rank += 100;
    reasons.push("exploited in the wild (KEV)");
  }
  if (v.epss !== undefined) {
    rank += v.epss * 40;
    if (v.epss >= 0.1) reasons.push(`EPSS ${(v.epss * 100).toFixed(1)}%`);
  }
  const score = v.cvss && !Number.isNaN(v.cvss.score) ? v.cvss.score : undefined;
  if (score !== undefined) {
    rank += (score / 10) * 30;
    reasons.push(`CVSS ${score} (${severityOf(score)})`);
  }
  if (v.hasExploit) {
    rank += 15;
    reasons.push("public exploit");
  }
  if (!reasons.length) reasons.push("no exploitation signal yet");
  return { rank: Math.round(rank * 10) / 10, why: reasons.join(" · ") };
}

/**
 * The triage tier (fire/smoke/ice), deterministic and computed before any AI. "fire" is
 * dangerous now, "smoke" is a warning, "ice" is cold. A distro backport forces ice (the fix is in,
 * whatever the CVE's own tier).
 */
export function tierOf(v: VulnMatch): "fire" | "smoke" | "ice" {
  const cvss = v.cvss && !Number.isNaN(v.cvss.score) ? v.cvss.score : 0;
  const epss = v.epss ?? 0;
  const base = v.kev || v.hasExploit || cvss >= 9 || (epss >= 0.1 && cvss >= 7) ? "fire" : cvss >= 7 || epss >= 0.1 ? "smoke" : "ice";
  // A suspected distro backport can't be "fire": we can't confirm the host is still vulnerable.
  if (v.backportSuspect && base === "fire") return "smoke";
  return base;
}

export interface LookupResult {
  matches: VulnMatch[];
  /** Finders and enrichers that ran, and any that failed (for honesty about coverage). */
  used: string[];
  failed: Array<{ name: string; error: string }>;
}

/** Runs the available finders, merges by CVE id, enriches and ranks. Never throws for one bad source. */
export async function lookup(q: VulnQuery, finders: Finder[], enrichers: Enricher[]): Promise<LookupResult> {
  const used: string[] = [];
  const failed: Array<{ name: string; error: string }> = [];
  const byId = new Map<string, VulnMatch>();

  const merge = (raw: RawVuln) => {
    const id = preferCve(raw.id, raw.aliases);
    const prev = byId.get(id);
    if (!prev) {
      byId.set(id, { ...raw, id, sources: [raw.source], rank: 0, why: "" });
      return;
    }
    prev.sources = [...new Set([...prev.sources, raw.source])];
    prev.title ??= raw.title;
    prev.summary ??= raw.summary;
    prev.affected ??= raw.affected;
    if (!prev.cvss && raw.cvss) prev.cvss = raw.cvss;
    if (raw.references?.length) prev.references = [...new Set([...(prev.references ?? []), ...raw.references])].slice(0, 10);
  };

  for (const f of finders) {
    try {
      if (!(await f.available())) continue;
      const found = await f.find(q);
      used.push(f.name);
      for (const r of found) merge(r);
    } catch (e) {
      failed.push({ name: f.name, error: (e as Error).message });
    }
  }

  const ids = [...byId.keys()];
  if (ids.length) {
    for (const en of enrichers) {
      try {
        const got = await en.enrich(ids);
        used.push(en.name);
        for (const [id, patch] of got) {
          const m = byId.get(id);
          if (!m) continue;
          // Several sources can carry an exploit reference: keep them all, don't let one overwrite another.
          if (patch.exploitRefs && m.exploitRefs) patch.exploitRefs = [...new Set([...m.exploitRefs, ...patch.exploitRefs])];
          Object.assign(m, patch);
        }
      } catch (e) {
        failed.push({ name: en.name, error: (e as Error).message });
      }
    }
  }

  const matches = [...byId.values()];
  for (const m of matches) {
    Object.assign(m, rankOf(m));
    // Distro backport suspicion: an upstream version-range match (NVD/OSV generic) on a host with a
    // known distribution can't be confirmed from the banner, which shows the upstream version. KEV and
    // public-exploit matches are never softened this way - too important to defer on a guess.
    if (q.distro && !m.kev && !m.hasExploit && m.sources.some((s) => s === "NVD" || s === "OSV")) m.backportSuspect = true;
    const ap = applicability(m, q);
    m.applies = ap.applies;
    if (ap.reasons.length) m.applyReasons = ap.reasons;
    m.tier = tierOf(m);
  }
  matches.sort((a, b) => b.rank - a.rank || a.id.localeCompare(b.id));
  return { matches, used: [...new Set(used)], failed };
}
