import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RiskLevel, ulid } from "@penteos/schema";
import { z } from "zod";
import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import type { RunOutcome } from "../../tools/runner.js";
import { engagementId, outcome, settle, wait } from "./shared.js";
import { defaultProviders, type Enricher, feedStatuses, type Finder, lookup, severityOf, type VulnMatch, type VulnQuery } from "../../vuln/index.js";
import { canonicalOrigin } from "../../tools/runner.js";

/** How vuln_lookup gets its sources. Overridable in tests so no real network is touched. */
let makeProviders: (cacheDir: string) => { finders: Finder[]; enrichers: Enricher[] } = (dir) => defaultProviders(dir);
export function __setVulnProviders(fn: ((cacheDir: string) => { finders: Finder[]; enrichers: Enricher[] }) | undefined): void {
  makeProviders = fn ?? ((dir) => defaultProviders(dir));
}

// ---------------------------------------------------------------------------------------------
// Known-vulnerability intelligence: fingerprint → lookup → rank → observations.
// ---------------------------------------------------------------------------------------------

const cacheDir = (ctx: OperationContext) => join(ctx.workspace.dataDir, "vuln-cache");

interface Tech {
  id: string;
  where: string;
  product: string;
  version?: string;
  ecosystem?: string;
  cpe?: string;
  distro?: string;
  affects: Array<{ kind: string; id: string }>;
}

function technologiesOf(ctx: OperationContext, e: ReturnType<OperationContext["engagement"]>): Tech[] {
  return e.query({ kind: "technology", limit: 5000 }).map((t) => ({
    id: t.id,
    where: String(t.attributes.where),
    product: String(t.attributes.product),
    ...(t.attributes.version ? { version: String(t.attributes.version) } : {}),
    ...(t.attributes.ecosystem ? { ecosystem: String(t.attributes.ecosystem) } : {}),
    ...(t.attributes.cpe ? { cpe: String(t.attributes.cpe) } : {}),
    ...(t.attributes.distro ? { distro: String(t.attributes.distro) } : {}),
    affects: (t.attributes.affects as Array<{ kind: string; id: string }> | undefined) ?? [],
  }));
}

defineOperation({
  name: "tech.scan",
  title: "Collect technologies from the graph",
  description:
    "Turns the products and versions already in the graph (a web app's detected technologies, a service's product/version from nmap) into technology entities, the unit that known vulnerabilities are matched against. Run it after recon/harvest; then vuln_lookup. For a product read elsewhere (a version in the API contract or a JS bundle), use tech_add with its ecosystem.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const items: unknown[] = [];
    let found = 0;
    for (const w of e.query({ kind: "webapp", limit: 2000 })) {
      const origin = String(w.attributes.origin);
      for (const t of (w.attributes.technologies as Array<{ name: string; version?: string; confidence?: number }> | undefined) ?? []) {
        if (!t.name) continue;
        found++;
        items.push({ op: "upsert", kind: "technology", key: { where: origin, product: t.name, ...(t.version ? { version: t.version } : {}) }, attributes: { where: origin, product: t.name, ...(t.version ? { version: t.version } : {}), source: "fingerprint", confidence: t.confidence ?? 0.6, affects: [{ kind: "webapp", id: w.id }] }, confidence: t.confidence ?? 0.6 });
      }
    }
    for (const s of e.query({ kind: "service", limit: 5000 })) {
      const product = s.attributes.product ? String(s.attributes.product) : undefined;
      if (!product) continue;
      found++;
      const host = e.get(String(s.attributes.hostId));
      const where = host ? String(host.naturalKey) : String(s.id);
      const cpe = s.attributes.cpe ? String(s.attributes.cpe) : undefined;
      items.push({ op: "upsert", kind: "technology", key: { where, product, ...(s.attributes.version ? { version: String(s.attributes.version) } : {}) }, attributes: { where, product, ...(s.attributes.version ? { version: String(s.attributes.version) } : {}), ...(cpe ? { cpe } : {}), part: "a", source: "nmap", confidence: 0.8, affects: [{ kind: "service", id: s.id }] }, confidence: 0.8 });
    }
    if (items.length) e.ingest({ format: "penteos.ingest/v0", source: { parser: "tech-scan", tool: "tech-scan" }, rawIds: [], observedAt: new Date().toISOString(), items } as never, ctx.caller.actor);
    return { status: "scanned", found, technologies: technologiesOf(ctx, e).length, note: found ? "Now run vuln_lookup to match known vulnerabilities. Add an ecosystem with tech_add where you know it (a JS library is npm; a plugin read from the API is WordPress), so the library sources can search it." : "No products with a name in the graph yet: harvest or scan the surface first." };
  },
});

defineOperation({
  name: "tech.add",
  title: "Register a technology",
  description:
    "Records a product and version you identified (from the API contract, a JS bundle, a banner), so vuln_lookup can match it. ecosystem routes the library sources: npm, PyPI, Packagist, Go, crates.io, WordPress… where is the origin or host it runs on.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    where: z.string().min(1).describe("The origin (https://x) or host it runs on"),
    product: z.string().min(1),
    version: z.string().optional(),
    ecosystem: z.string().optional(),
    cpe: z.string().optional(),
    distro: z.string().optional().describe("The host's distribution if known (ubuntu, debian, ubuntu:22.04): enables backport awareness"),
    source: z.string().optional(),
    confidence: z.number().min(0).max(1).optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const where = input.where;
    const webapp = /^https?:\/\//.test(where) ? e.query({ kind: "webapp", limit: 2000 }).find((w) => String(w.attributes.origin) === where) : undefined;
    const attributes = { where, product: input.product, ...(input.version ? { version: input.version } : {}), ...(input.ecosystem ? { ecosystem: input.ecosystem } : {}), ...(input.cpe ? { cpe: input.cpe } : {}), ...(input.distro ? { distro: input.distro } : {}), source: input.source ?? "manual", confidence: input.confidence ?? 0.7, ...(webapp ? { affects: [{ kind: "webapp", id: webapp.id }] } : {}) };
    e.ingest({ format: "penteos.ingest/v0", source: { parser: "tech-add", tool: "tech-add" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "technology", key: { where, product: input.product, ...(input.version ? { version: input.version } : {}) }, attributes, confidence: attributes.confidence }] } as never, ctx.caller.actor);
    return { status: "added", product: input.product, version: input.version ?? null };
  },
});

defineOperation({
  name: "web.detect_versions",
  title: "Detect exact technology versions",
  description:
    "Reads the EXACT installed version of the technologies on a web app from reliable sources, not a guess: response headers (Server, X-Powered-By, X-Generator), the generator meta tag, WordPress plugin/theme files (readme.txt 'Stable tag', style.css 'Version'), version comments in the scripts, and exposed composer.json / package.json. Read-only GETs. The versions found become technologies, ready for vuln_lookup. Always prefer this over an asset's ?ver= query (often a cache-buster) or a guessed number - a wrong version makes the CVE match miss real vulnerabilities or report ones that do not apply. slugs: extra WordPress plugin/theme slugs to check beyond the ones seen on the page.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, origin: z.string().url(), slugs: z.array(z.string().min(1).max(80)).max(30).optional(), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).detectVersions({ origin: input.origin, ...(input.slugs?.length ? { slugs: input.slugs } : {}), risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "tech.list",
  title: "Technologies in the graph",
  description: "The products and versions identified on the target, with where they run and whether they carry an ecosystem for library lookups.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    return { technologies: technologiesOf(ctx, e).map((t) => ({ id: t.id, where: t.where, product: t.product, version: t.version ?? null, ecosystem: t.ecosystem ?? null })) };
  },
});

/** Where an observation about this technology should hang (as a key ref the ingest can resolve). */
function affectRef(t: Tech): { kind: string; key: Record<string, string> } {
  if (/^https?:\/\//.test(t.where)) return { kind: "webapp", key: { origin: t.where } };
  return { kind: "technology", key: { where: t.where, product: t.product, ...(t.version ? { version: t.version } : {}) } };
}

const summarize = (m: VulnMatch) => ({
  id: m.id,
  ...(m.tier ? { tier: m.tier } : {}),
  severity: severityOf(m.cvss && !Number.isNaN(m.cvss.score) ? m.cvss.score : undefined),
  ...(m.backportSuspect ? { backportSuspect: true } : {}),
  ...(m.cvss && !Number.isNaN(m.cvss.score) ? { cvss: m.cvss.score } : {}),
  ...(m.kev ? { kev: true } : {}),
  ...(m.epss !== undefined ? { epss: Math.round(m.epss * 1000) / 1000 } : {}),
  ...(m.hasExploit ? { exploit: true } : {}),
  why: m.why,
  ...(m.title || m.summary ? { about: (m.title ?? m.summary ?? "").slice(0, 200) } : {}),
  ...(m.affected ? { affected: m.affected } : {}),
  ...(m.applyReasons?.length ? { caveat: m.applyReasons.join("; ") } : {}),
});

const CVE = z.string().regex(/^CVE-\d{4}-\d+$/i, "a CVE id like CVE-2024-1234");

/** A nuclei observation on this origin whose template is the CVE, i.e. a confirmation already on record. */
function nucleiConfirmation(e: ReturnType<OperationContext["engagement"]>, cve: string, origin: string): string | undefined {
  const rule = `nuclei:${cve.toLowerCase()}`;
  const hit = e.query({ kind: "observation", limit: 5000 }).find((o) => {
    if (String(o.attributes.sourceRule).toLowerCase() !== rule) return false;
    return ((o.attributes.affects as Array<{ id: string }> | undefined) ?? []).some((ref) => {
      const w = e.get(ref.id);
      // The origin lives in the attributes when set, otherwise in the natural key.
      return w?.kind === "webapp" && canonicalOrigin(String(w.attributes.origin ?? w.naturalKey)) === canonicalOrigin(origin);
    });
  });
  return hit?.id;
}

defineOperation({
  name: "vuln.confirm",
  title: "Confirm a known vulnerability without exploiting it",
  description:
    "The non-invasive step: tells whether THIS deployment is really affected by a CVE, not just running a matching version, without firing a destructive payload. If a nuclei detection template for the CVE is installed, it runs just that one template against the origin (it inherits nuclei's risk, so it may ask for approval) and the hit lands as evidence. When no template exists for the CVE, you (the agent) may draft a READ-ONLY detection template and pass it as `template` (a nuclei YAML whose id is the CVE, a matcher that tells a patched server from a vulnerable one WITHOUT an exploitation payload); it is saved as evidence and run behind approval - never auto-fired. If nuclei is not installed and no template is given, it returns how to confirm by hand with http_send. A version match is a lead; this is what turns it into a finding. A real proof-of-concept (reading a file, a callback) is a separate, approval-gated step.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    cve: CVE,
    origin: z.string().url(),
    template: z
      .string()
      .min(20)
      .max(8000)
      .refine((t) => /\bid\s*:/.test(t) && /\b(http|dns|tcp|headless|javascript)\s*:/.test(t), "a nuclei template needs an id and a protocol block like http:")
      .optional()
      .describe("A read-only nuclei detection template (YAML) you drafted when no built-in one exists; id must be the CVE. Saved as evidence and run behind approval."),
    wait,
  }),
  handler: async (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const cve = input.cve.toUpperCase();
    const already = nucleiConfirmation(e, cve, input.origin);
    if (already) return { status: "confirmed", by: "nuclei", observation: already, note: `${cve} is already confirmed on ${input.origin} by a nuclei template. Promote the finding (observation_promote) with the nuclei observation and its evidence; its impact goes through deepening.` };

    const runner = ctx.runner(input.engagementId);
    const manifest = runner.registry.get("nuclei");
    const status = manifest ? await runner.registry.binaryFor(manifest) : undefined;
    if (!manifest || !status?.installed) {
      return {
        status: "no_engine",
        note: `nuclei is not installed, so Penteos will not auto-confirm ${cve}. Confirm it by hand: craft an http_send that tells a patched server from a vulnerable one for this CVE (a version-specific file or path, a behavioural difference) WITHOUT firing the payload, save the exchange as evidence, and only then promote the finding. The CVE's references (from vuln_lookup) describe the check. Installing nuclei lets Penteos run the detection template for you.`,
      };
    }

    const caller = { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? ("agent_tool" as const) : ("runner" as const) };
    // A drafted template (no built-in one for this CVE): save it as evidence and run that file; the
    // run is approval-gated like any active action, so a person sees it before it touches the target.
    let argv = ["nuclei", "-u", input.origin, "-id", cve];
    if (input.template) {
      e.putRaw(input.template, { type: "stdin", mime: "application/yaml", originalName: `${cve}-drafted-template.yaml` });
      const file = join(tmpdir(), `penteos-tpl-${ulid()}.yaml`);
      writeFileSync(file, input.template, { mode: 0o600 });
      argv = ["nuclei", "-u", input.origin, "-t", file];
    }
    // One template, one origin: the narrowest possible run. nuclei floors the risk to its own.
    const result = await runner.runExec({ argv, targets: [input.origin], risk: "active" }, caller);
    if (result.status !== "started") return outcome(result, ctx);

    if (!input.wait) return { ...(outcome(result, ctx) as object), note: `Running the ${cve} detection template against ${input.origin}. If it matches, the hit lands as an observation and the lead is confirmed; check with vuln_confirm again or run_output.` };
    const settled = (await settle(ctx, input.engagementId, result.run.id, input.wait)) as { status: string; runId: string };
    const confirmed = nucleiConfirmation(e, cve, input.origin);
    if (confirmed) return { status: "confirmed", by: "nuclei", observation: confirmed, runId: settled.runId, note: `Confirmed: the ${cve} template matched on ${input.origin}. Promote the finding with its evidence; its impact goes through deepening.` };
    if (settled.status === "running") return { status: "running", runId: settled.runId, note: "The template is still running; you will be told when it finishes." };
    return { status: "not_confirmed", runId: settled.runId, note: `The ${cve} template did not match on ${input.origin}. The version match may be a false positive (a backported patch, a WAF, the wrong component): treat it as potential, or confirm another way, before writing a finding.` };
  },
});

defineOperation({
  name: "vuln.sources",
  title: "Vulnerability data freshness",
  description: "Which vulnerability feeds are cached locally and how old they are (CISA KEV, EPSS, ExploitDB, Wordfence). Does not touch the network.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (_input, ctx) => ({ feeds: feedStatuses(cacheDir(ctx)).map((f) => ({ source: f.name, asOf: f.asOf ?? null, ok: f.ok, ...(f.live ? { live: true } : {}), ...(f.note ? { note: f.note } : {}) })) }),
});

defineOperation({
  name: "vuln.refresh",
  title: "Refresh the vulnerability feeds",
  description: "Downloads or updates the cached vulnerability feeds (KEV, ExploitDB, Wordfence) so later lookups are fresh and work offline. Reaches third-party sites over the internet.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: async (_input, ctx) => {
    const { finders, enrichers } = makeProviders(cacheDir(ctx));
    const failed: string[] = [];
    // A touch of each source that caches a bulk feed makes it fetch and store it. Per-query APIs
    // (OSV, NVD, EPSS) are live, so warming them is harmless but optional.
    await Promise.all([
      ...finders.map(async (f) => { try { if (await f.available()) await f.find({ product: "wordpress", ecosystem: "WordPress" }); } catch (e) { failed.push(`${f.name}: ${(e as Error).message}`); } }),
      ...enrichers.map(async (en) => { try { await en.enrich(["CVE-2021-44228"]); } catch (e) { failed.push(`${en.name}: ${(e as Error).message}`); } }),
    ]);
    return { status: "refreshed", feeds: feedStatuses(cacheDir(ctx)).map((f) => ({ source: f.name, asOf: f.asOf ?? null, ...(f.live ? { live: true } : {}), ...(f.note ? { note: f.note } : {}) })), ...(failed.length ? { failed } : {}) };
  },
});

defineOperation({
  name: "vuln.lookup",
  title: "Match known vulnerabilities",
  description:
    "Matches a technology (or all of them) against the vulnerability sources (OSV, NVD, WordPress; enriched with CISA KEV and ENISA EUVD for exploited-in-the-wild, EPSS for probability, ExploitDB and Metasploit for public exploits), ranks by real-world signal into fire/smoke/ice tiers and records the top ones as observations. It queries third-party databases over the internet (the product and version leave the machine). This gives leads, not proof: confirm a serious one with a non-invasive probe before calling it a finding. Give id for one technology, or product/version/ecosystem for an ad-hoc check, or neither to look up every technology in the graph.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    id: z.string().optional().describe("A technology id (from tech_list); omit to look up all of them"),
    product: z.string().optional(),
    version: z.string().optional(),
    ecosystem: z.string().optional(),
    cpe: z.string().optional(),
    distro: z.string().optional().describe("The host's distribution if known (ubuntu, debian…): for an ad-hoc check with backport awareness"),
    max: z.number().int().min(1).max(30).default(10).describe("Top N per technology recorded as observations"),
  }),
  handler: async (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const { finders, enrichers } = makeProviders(cacheDir(ctx));
    let targets: Array<{ q: VulnQuery; tech?: Tech }>;
    if (input.product) targets = [{ q: { product: input.product, ...(input.version ? { version: input.version } : {}), ...(input.ecosystem ? { ecosystem: input.ecosystem } : {}), ...(input.cpe ? { cpe: input.cpe } : {}), ...(input.distro ? { distro: input.distro } : {}) } }];
    else {
      const all = technologiesOf(ctx, e);
      const chosen = input.id ? all.filter((t) => t.id === input.id) : all;
      if (input.id && !chosen.length) throw new OperationError("NOT_FOUND", `technology not found: ${input.id}. Run tech_scan or tech_list.`);
      if (!chosen.length) return { status: "no_technologies", note: "No technologies in the graph. Run tech_scan, or pass product/version/ecosystem for an ad-hoc check." };
      targets = chosen.map((t) => ({ q: { product: t.product, ...(t.version ? { version: t.version } : {}), ...(t.ecosystem ? { ecosystem: t.ecosystem } : {}), ...(t.cpe ? { cpe: t.cpe } : {}), ...(t.distro ? { distro: t.distro } : {}) }, tech: t }));
    }

    const items: unknown[] = [];
    const results: unknown[] = [];
    const failedSources = new Set<string>();
    for (const { q, tech } of targets) {
      const r = await lookup(q, finders, enrichers);
      for (const f of r.failed) failedSources.add(`${f.name}: ${f.error}`);
      // Applicability trims the noise: an "unlikely" match (patched version, local-only vector) is
      // not recorded unless it is exploited in the wild or has a public exploit (too important to drop).
      const applicable = r.matches.filter((m) => m.applies !== "unlikely" || m.kev || m.hasExploit);
      const setAside = r.matches.filter((m) => m.applies === "unlikely" && !m.kev && !m.hasExploit);
      const top = applicable.slice(0, input.max);
      if (tech) {
        for (const m of top) {
          const severe = m.tier === "fire" || m.kev || (m.cvss && !Number.isNaN(m.cvss.score) && m.cvss.score >= 7);
          const baseSev = severityOf(m.cvss?.score);
          // A "fire" lead (exploited/public exploit/critical) is at least high even when the CVSS is thin.
          const severityHint = m.tier === "fire" && (baseSev === "info" || baseSev === "low") ? "high" : baseSev;
          items.push({
            op: "observe",
            title: `[${m.tier ?? "ice"}] ${m.id} - ${tech.product}${tech.version ? ` ${tech.version}` : ""}: ${(m.title ?? m.summary ?? "known vulnerability").slice(0, 90)}`,
            sourceRule: "vuln:known",
            affects: [affectRef(tech)],
            location: m.id,
            severityHint,
            detail: `Tier ${m.tier ?? "ice"}. ${m.why}. ${m.affected ?? ""}${m.applyReasons?.length ? ` Caveat: ${m.applyReasons.join("; ")}.` : ""}${m.exploitRefs?.length ? ` Public exploit: ${m.exploitRefs[0]}.` : ""} Sources: ${m.sources.join(", ")}. This is a lead from a version match: confirm with vuln_confirm before treating it as a finding.${severe ? "" : " Low signal; weigh before spending time on it."}`,
          });
        }
      }
      results.push({
        ...(tech ? { technology: tech.id, product: tech.product, version: tech.version ?? null } : { product: q.product, version: q.version ?? null }),
        searched: r.used,
        found: r.matches.length,
        recorded: tech ? top.length : 0,
        top: top.map(summarize),
        ...(setAside.length ? { setAside: setAside.slice(0, 10).map((m) => ({ id: m.id, reason: (m.applyReasons ?? []).join("; ") || "does not apply" })) } : {}),
      });
    }
    if (items.length) e.ingest({ format: "penteos.ingest/v0", source: { parser: "vuln@0.1.0", tool: "vuln" }, rawIds: [], observedAt: new Date().toISOString(), items } as never, ctx.caller.actor);

    const feeds = feedStatuses(cacheDir(ctx));
    return {
      status: "done",
      results,
      feeds: feeds.map((f) => ({ source: f.name, asOf: f.asOf ?? null, ...(f.live ? { live: true } : {}), ...(f.note ? { note: f.note } : {}) })),
      ...(failedSources.size ? { unavailable: [...failedSources] } : {}),
      note: "Each match carries a tier - fire (dangerous now: exploited, public exploit, or critical), smoke (warning), ice (cold, or patched by a distro backport) - and is ranked by real-world signal within it. Each top item is an observation. Confirm a fire/smoke one with a non-invasive probe and only then promote it; its impact goes through deepening.",
    };
  },
});
