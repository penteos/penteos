import { parse as parseDomain } from "tldts";
import type { Actor } from "@penteos/schema";
import type { Engagement } from "./engagement.js";

/**
 * Attack surface found outside the scope. Reconnaissance turns up hosts nobody listed (an
 * automation server, a QA environment, a payments site); left there, they are silently untested
 * and the report reads as if the client had nothing else. Each one waits for a decision: propose
 * including it (a person approves the scope change) or set it aside with a reason. A round does not
 * close while any is undecided.
 *
 * Only the client's own names count: hosts under the registrable domain of something in scope
 * (third parties named in JavaScript, CDNs and the like are not the client's surface).
 */

export interface SurfaceDecision {
  decision: "proposed" | "set_aside";
  reason: string;
  at: string;
  by: Actor;
}

export interface SurfaceAsset {
  host: string;
  /** Where it was seen: its origins (when it serves the web) and what is known of it. */
  origins: string[];
  title?: string;
  technologies: string[];
  decision?: SurfaceDecision;
}

const KEY = "surfaceDecisions";

const hostOf = (name: string) => name.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[:/].*$/, "").toLowerCase();

/** The registrable domains of what is in scope (example.com for https://app.example.com). */
function clientDomains(e: Engagement): Set<string> {
  const out = new Set<string>();
  for (const r of e.scopeRules()) {
    if (r.effect !== "include") continue;
    const t = r.target;
    const v = t.type === "url" || t.type === "domain" || t.type === "wildcard" ? hostOf(t.value.replace(/^\*\./, "")) : undefined;
    const d = v ? parseDomain(v).domain : undefined;
    if (d) out.add(d);
  }
  return out;
}

export function surfaceDecisions(e: Engagement): Record<string, SurfaceDecision> {
  return e.getState<Record<string, SurfaceDecision>>(KEY) ?? {};
}

/** Every out-of-scope asset of the client's own domains, with its decision if any. */
export function outOfScopeSurface(e: Engagement): SurfaceAsset[] {
  const domains = clientDomains(e);
  if (!domains.size) return [];
  const decisions = surfaceDecisions(e);
  const byHost = new Map<string, SurfaceAsset>();
  for (const kind of ["webapp", "domain"] as const) {
    for (const ent of e.query({ kind, limit: 5000 })) {
      if (!ent.outOfScope) continue;
      const a = ent.attributes as Record<string, unknown>;
      const host = hostOf(String(a.origin ?? a.fqdn ?? ""));
      const reg = host ? parseDomain(host).domain : undefined;
      if (!host || !reg || !domains.has(reg)) continue;
      const asset = byHost.get(host) ?? { host, origins: [], technologies: [], ...(decisions[host] ? { decision: decisions[host] } : {}) };
      if (a.origin) asset.origins.push(String(a.origin));
      if (a.title && !asset.title) asset.title = String(a.title);
      if (Array.isArray(a.technologies)) for (const t of a.technologies as Array<{ name?: string }>) if (t.name && !asset.technologies.includes(t.name)) asset.technologies.push(t.name);
      byHost.set(host, asset);
    }
  }
  return [...byHost.values()].sort((x, y) => x.host.localeCompare(y.host));
}

/** What still waits for a decision. */
export function undecidedSurface(e: Engagement): SurfaceAsset[] {
  return outOfScopeSurface(e).filter((s) => !s.decision);
}

export function recordSurfaceDecision(e: Engagement, hosts: string[], decision: SurfaceDecision["decision"], reason: string, by: Actor): void {
  const all = surfaceDecisions(e);
  const at = new Date().toISOString();
  for (const h of hosts) all[hostOf(h)] = { decision, reason, at, by };
  e.setState(KEY, all);
  e.audit(by, "surface.decide", { hosts: hosts.map(hostOf) }, { decision, reason });
}
