import type { Actor, ImpactQuestionKey } from "@penteos/schema";
import type { Engagement, Entity } from "./engagement.js";
import { pseudonym } from "./privacy/vault.js";
import { canonicalOrigin } from "./tools/runner.js";

/**
 * Deepening a finding. Detecting "this answers without credentials" is half the job; the report a
 * client acts on says how far it reaches, what the exposed data lets an attacker do and what it
 * chains with. Penteos opens those three questions on serious findings and computes leads from the
 * evidence and the graph, so the agent starts from concrete next steps instead of moving on.
 */

export const IMPACT_KEYS: ImpactQuestionKey[] = ["reach", "exposed", "chain"];

export interface ImpactQuestion {
  key: ImpactQuestionKey;
  status: "open" | "answered" | "not_applicable";
  answer?: string;
  evidenceIds: string[];
  by?: Actor;
  at?: string;
}

export interface Deepening {
  reason: string;
  openedAt: string;
  questions: ImpactQuestion[];
}

export interface ImpactLead {
  text: string;
  /** The Penteos tool that answers it, with the arguments ready. */
  tool?: string;
  args?: Record<string, unknown>;
}

export type ImpactLeads = Record<ImpactQuestionKey, ImpactLead[]>;

/** Weaknesses whose impact depends on what they reach and expose. */
const EXPOSURE_CWE = new Set([
  "CWE-22", "CWE-78", "CWE-89", "CWE-94", "CWE-200", "CWE-201", "CWE-284", "CWE-285", "CWE-287", "CWE-288", "CWE-306", "CWE-312", "CWE-359",
  "CWE-425", "CWE-502", "CWE-522", "CWE-532", "CWE-538", "CWE-548", "CWE-552", "CWE-611", "CWE-639", "CWE-798", "CWE-862", "CWE-863", "CWE-918",
]);
const EXPOSURE_TITLE = /sin autenticaci|sin credencial|without (auth|credential)|unauthenticated|expuest|exposed|exposure|enumera|idor|bola|autorizaci[oó]n por objeto|acceso no autorizado|unauthori[sz]ed access|leak|filtraci|fuga|inyecci|injection|ssrf|ejecuci[oó]n remota|remote code/i;

/** Why a finding deserves deepening, or undefined. */
export function deepeningReason(a: Record<string, unknown>): string | undefined {
  const severity = String(a.severity ?? "");
  if (severity === "critical" || severity === "high") return `severity ${severity}`;
  if (severity !== "medium") return undefined;
  if (((a.cwe as string[] | undefined) ?? []).some((c) => EXPOSURE_CWE.has(c))) return "exposure or access control (CWE)";
  if (EXPOSURE_TITLE.test(String(a.title ?? ""))) return "exposure or access control";
  return undefined;
}

export function deepeningOf(f: Entity): Deepening | undefined {
  return f.attributes.deepening as Deepening | undefined;
}

export function openQuestions(f: Entity): ImpactQuestionKey[] {
  return (deepeningOf(f)?.questions ?? []).filter((q) => q.status === "open").map((q) => q.key);
}

const CLOSED = new Set(["fixed", "wont_fix", "not_verifiable"]);

/**
 * Opens the impact questions on a finding that deserves them (or when asked to, with `reason`).
 * Idempotent: a finding that already has them keeps its answers. Returns whether it opened them.
 */
export function openDeepening(e: Engagement, findingId: string, actor: Actor, reason?: string): boolean {
  const f = e.get(findingId);
  if (!f || f.kind !== "finding" || deepeningOf(f) || CLOSED.has(String(f.attributes.status))) return false;
  const why = reason ?? deepeningReason(f.attributes);
  if (!why) return false;
  const deepening: Deepening = { reason: why, openedAt: new Date().toISOString(), questions: IMPACT_KEYS.map((key) => ({ key, status: "open", evidenceIds: [] })) };
  e.editEntity(findingId, { deepening }, actor);
  e.emit({ type: "finding.deepen", findingId, title: String(f.attributes.title), severity: String(f.attributes.severity), open: [...IMPACT_KEYS] });
  return true;
}

/** Findings of the project with impact questions still open (not closed findings). */
export function findingsToDeepen(e: Engagement): Array<{ id: string; title: string; severity: string; open: ImpactQuestionKey[] }> {
  return e
    .query({ kind: "finding", limit: 5000 })
    .filter((f) => !CLOSED.has(String(f.attributes.status)) && openQuestions(f).length)
    .map((f) => ({ id: f.id, title: String(f.attributes.title), severity: String(f.attributes.severity), open: openQuestions(f) }));
}

// ---------------------------------------------------------------------------------------------
// What the finding touches: its endpoints and the raw outputs that show it
// ---------------------------------------------------------------------------------------------

interface Touched {
  origin: string;
  /** Path templates ("/api/tenants/{id}"), concrete numbers turned into {id}. */
  templates: string[];
}

const templateOf = (path: string) =>
  path
    .split("?")[0]!
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}")
    .replace(/\/\d+(?=\/|$)/g, "/{id}")
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, "/{uuid}");

function touched(e: Engagement, f: Entity): Touched[] {
  const byOrigin = new Map<string, Set<string>>();
  const add = (origin: string, path: string) => {
    if (!origin || !path.startsWith("/")) return;
    const set = byOrigin.get(origin) ?? new Set<string>();
    set.add(templateOf(path));
    byOrigin.set(origin, set);
  };
  const instances = (f.attributes.instances as Array<{ entity: { kind: string; id: string }; location?: string }> | undefined) ?? [];
  for (const i of instances) {
    const x = e.get(i.entity.id);
    if (!x) continue;
    let origin = "";
    if (x.kind === "endpoint") {
      const app = e.get(String(x.attributes.webappId));
      origin = app ? String(app.attributes.origin) : "";
      add(origin, String(x.attributes.pathTemplate));
    } else if (x.kind === "webapp") origin = String(x.attributes.origin);
    // "GET /api/tenants/{id}" or a full URL in the location.
    const loc = i.location ?? "";
    const url = /https?:\/\/[^\s"'<>]+/.exec(loc)?.[0];
    if (url) {
      try {
        const u = new URL(url);
        add(u.origin, u.pathname);
      } catch {
        /* not a URL */
      }
    } else {
      const path = /(?:^|\s)(\/[^\s"'<>]*)/.exec(loc)?.[1];
      if (path && origin) add(origin, path);
    }
  }
  return [...byOrigin].map(([origin, set]) => ({ origin, templates: [...set] }));
}

/** Raw outputs that show the finding: its evidence, the verifier's, and its observations'. */
function rawsOf(e: Engagement, f: Entity): string[] {
  const ids = new Set<string>();
  const evidence = [...((f.attributes.evidenceIds as string[] | undefined) ?? []), ...(((f.attributes.verification as { evidenceIds?: string[] } | undefined)?.evidenceIds) ?? [])];
  for (const id of evidence) {
    const ev = e.get(id);
    const raw = (ev?.attributes.source as { rawId?: string } | undefined)?.rawId;
    if (raw) ids.add(raw);
  }
  const instances = (f.attributes.instances as Array<{ observationIds?: string[] }> | undefined) ?? [];
  for (const i of instances) for (const o of i.observationIds ?? []) {
    const raw = e.get(o)?.attributes.rawId;
    if (typeof raw === "string") ids.add(raw);
  }
  return [...ids].slice(0, 8);
}

/** The JSON documents inside a raw output (a response body, an HTTP exchange, a log). */
export function jsonBodies(text: string): unknown[] {
  const out: unknown[] = [];
  const tryParse = (s: string) => {
    const t = s.trim();
    if (t.length < 2 || !/^[[{]/.test(t)) return;
    try {
      out.push(JSON.parse(t));
    } catch {
      /* not JSON */
    }
  };
  tryParse(text);
  if (!out.length) for (const part of text.split(/\r?\n\r?\n/)) tryParse(part);
  return out;
}

// ---------------------------------------------------------------------------------------------
// What the data exposes
// ---------------------------------------------------------------------------------------------

export interface Exposed {
  kind: "secret" | "emails" | "storage" | "hosts";
  /** Where in the document (keys only, never values). */
  path: string;
  /** For a secret, the vault marker the model knows it by (restored at the target). */
  marker?: string;
  count?: number;
  hosts?: string[];
}

const SECRET_KEY = /(token|secret|api_?key|apikey|passw|pwd|private|credential|client_?secret|access_?key|webhook|dsn|signing|hmac|bearer|session_?id|auth_?key)/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const STORAGE = /(amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|supabase\.co|firebasestorage|cloudinary\.com|digitaloceanspaces\.com|r2\.cloudflarestorage\.com)/i;
const SECRETISH_VALUE = (v: string) => v.length >= 8 && !/^(true|false|null|none|optional|required|disabled|enabled|header|query|body|cookie|bearer|basic)$/i.test(v) && /[A-Za-z0-9]/.test(v) && !/\s/.test(v);

/** Secrets, e-mail lists, storage buckets and hosts in a JSON document (values become markers). */
export function exposedIn(e: Engagement, doc: unknown): { exposed: Exposed[]; records?: number; declaredTotal?: number } {
  const exposed: Exposed[] = [];
  const emails = new Map<string, number>();
  const storage = new Set<string>();
  const hosts = new Set<string>();
  let records: number | undefined;
  let declaredTotal: number | undefined;
  const walk = (v: unknown, path: string, depth: number) => {
    if (depth > 12) return;
    if (Array.isArray(v)) {
      if (records === undefined && v.length && v.every((x) => x && typeof x === "object" && !Array.isArray(x))) records = v.length;
      v.slice(0, 200).forEach((x) => walk(x, `${path}[]`, depth + 1));
      return;
    }
    if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (declaredTotal === undefined && typeof x === "number" && /^(total|count|total_?count|total_?items|totalElements|recordsTotal)$/i.test(k)) declaredTotal = x;
        walk(x, path ? `${path}.${k}` : k, depth + 1);
      }
      return;
    }
    if (typeof v !== "string" || !v) return;
    const key = path.split(".").pop()!.replace(/\[\]$/, "");
    if (SECRET_KEY.test(key) && !/(name|type|header|field|param|policy|mode|scheme|url|expir|length|ttl|enabled|required)$/i.test(key) && SECRETISH_VALUE(v)) {
      exposed.push({ kind: "secret", path, marker: pseudonym(e, "secret", v) });
      return;
    }
    if (EMAIL.test(v)) {
      const p = path.replace(/\[\]/g, "[]");
      emails.set(p, (emails.get(p) ?? 0) + 1);
      return;
    }
    if (/^https?:\/\//.test(v)) {
      try {
        const u = new URL(v);
        if (STORAGE.test(u.hostname)) storage.add(u.hostname);
        else hosts.add(u.hostname);
      } catch {
        /* not a URL */
      }
    }
  };
  walk(doc, "", 0);
  for (const [path, count] of emails) exposed.push({ kind: "emails", path, count });
  if (storage.size) exposed.push({ kind: "storage", path: "(URLs)", hosts: [...storage].slice(0, 8) });
  if (hosts.size) exposed.push({ kind: "hosts", path: "(URLs)", hosts: [...hosts].slice(0, 12) });
  return { exposed: exposed.slice(0, 30), ...(records !== undefined ? { records } : {}), ...(declaredTotal !== undefined ? { declaredTotal } : {}) };
}

// ---------------------------------------------------------------------------------------------
// Where an exposed value could be used: routes whose words match the value's place in the data
// ---------------------------------------------------------------------------------------------

const GENERIC = new Set(["config", "configuration", "settings", "setting", "module", "modules", "data", "value", "values", "token", "key", "secret", "id", "api", "v1", "v2", "public", "custom", "default", "item", "items", "attributes", "meta", "info", "field", "fields"]);
const SYNONYM: Record<string, string> = {
  incidencia: "incident", incidente: "incident", reporte: "report", formulario: "form", publico: "public", tramite: "procedure", turno: "appointment", usuario: "user",
  organismo: "tenant", municipio: "tenant", documento: "document", archivo: "file", pago: "payment", notificacion: "notification", geocodificacion: "geocoding", firma: "signature",
};
const stem = (w: string) => {
  const plain = w.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
  const base = plain.length > 4 ? plain.replace(/(es|s)$/, "") : plain;
  return SYNONYM[base] ?? SYNONYM[plain] ?? base;
};
const wordsOf = (s: string) =>
  s
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-zÀ-ÿ0-9]+/)
    .filter((w) => w.length > 2)
    .map(stem);

/** Routes of the origin (graph, the app's calls, the contract) ranked by words shared with `path`. */
function routesLike(e: Engagement, origin: string, path: string, extra: RegExp, limit = 5): string[] {
  const want = new Set(wordsOf(path).filter((w) => !GENERIC.has(w)));
  if (!want.size) return [];
  const routes = new Set<string>();
  const o = canonicalOrigin(origin);
  for (const app of e.query({ kind: "webapp", limit: 500 }).filter((a) => canonicalOrigin(String(a.attributes.origin)) === o)) {
    for (const ep of e.query({ kind: "endpoint", limit: 50_000 })) if (ep.attributes.webappId === app.id) routes.add(String(ep.attributes.pathTemplate));
  }
  for (const calls of Object.values(e.getState<Record<string, string[]>>("apiCalls") ?? {})) for (const c of calls) routes.add(c);
  const scored = [...routes]
    .map((r) => {
      const words = new Set(wordsOf(r));
      const shared = [...want].filter((w) => words.has(w)).length;
      return { r, score: shared + (extra.test(r) ? 0.5 : 0) };
    })
    .filter((x) => x.score >= 1)
    .sort((a, b) => b.score - a.score || a.r.length - b.r.length);
  return scored.slice(0, limit).map((x) => x.r);
}

// ---------------------------------------------------------------------------------------------
// Leads
// ---------------------------------------------------------------------------------------------

/** Concrete next steps for each impact question, from the finding's evidence and the graph. */
export function impactLeads(e: Engagement, f: Entity): ImpactLeads {
  const leads: ImpactLeads = { reach: [], exposed: [], chain: [] };
  const where = touched(e, f);
  const origin = where[0]?.origin;

  // What the evidence shows.
  const found: Exposed[] = [];
  let records: number | undefined;
  let declaredTotal: number | undefined;
  for (const raw of rawsOf(e, f)) {
    let text: string;
    try {
      text = e.readRaw(raw).subarray(0, 600_000).toString("utf8");
    } catch {
      continue;
    }
    for (const doc of jsonBodies(text)) {
      const x = exposedIn(e, doc);
      found.push(...x.exposed);
      records ??= x.records;
      declaredTotal ??= x.declaredTotal;
    }
  }
  const seen = new Set<string>();
  const exposed = found.filter((x) => {
    const k = `${x.kind}|${x.path}|${x.marker ?? ""}`;
    return !seen.has(k) && seen.add(k);
  });

  // --- Reach: how many records, organisations or users it opens.
  for (const t of where) {
    for (const template of t.templates.filter((p) => /\{[^}]+\}/.test(p)).slice(0, 3)) {
      leads.reach.push({
        text: `Measure how many records ${template} opens: web_measure_enumeration probes the identifiers (bounded, read-only) and estimates the total, the highest id and the density.`,
        tool: "web_measure_enumeration",
        args: { origin: t.origin, template },
      });
    }
  }
  if (declaredTotal !== undefined) leads.reach.push({ text: `The response itself declares a total of ${declaredTotal}: cite it (with the evidence) as the reach.` });
  else if (records !== undefined) leads.reach.push({ text: `The response lists ${records} record(s) in one page: check whether paging (page, limit, offset, size) returns all of them, and cite the total.` });
  if (!leads.reach.length && where.length) {
    leads.reach.push({ text: `No identifier in the route: check whether other records or organisations are selectable another way (?id=, ?tenant=, ?slug=, an X-Tenant header, the Host) and say who can reach it (anyone on the Internet?).` });
  }

  // --- Exposed: what each exposed value lets an attacker do.
  for (const x of exposed.filter((x) => x.kind === "secret").slice(0, 4)) {
    const candidates = origin ? routesLike(e, origin, x.path, /public|token|webhook|callback|form|submit|upload|report|incident/i) : [];
    leads.exposed.push({
      text: `${x.marker} sits at ${x.path}. What does it allow? ${
        candidates.length ? `Routes that may take it: ${candidates.join(", ")}.` : "No route of the app names it yet: look for it in the JavaScript (web_harvest_scripts) or the contract."
      } Use it as the parameter, header or body field those routes expect (the marker is restored at the target) with a harmless request, and record what it opens.`,
      ...(candidates.length && origin ? { tool: "http_send", args: { origin, candidates } } : {}),
    });
  }
  for (const x of exposed.filter((x) => x.kind === "emails").slice(0, 2)) {
    leads.exposed.push({ text: `${x.count} e-mail address(es) at ${x.path}: real accounts of the platform. Say whose they are (role) and whether they are valid usernames; never try passwords on them without the operator's approval.` });
  }
  for (const x of exposed.filter((x) => x.kind === "storage")) {
    leads.exposed.push({ text: `Storage buckets referenced: ${x.hosts!.join(", ")}. Check (read-only) whether the bucket lists its files or serves other organisations' files by changing the name in the URL.` });
  }
  if (!exposed.some((x) => x.kind === "secret" || x.kind === "emails") && rawsOf(e, f).length) {
    leads.exposed.push({ text: "No secrets or e-mails detected in the evidence. Read the fields (names only) and say which are sensitive for this client: configuration that reveals security posture (2FA policy, allowed modules), personal data, internal URLs." });
  }

  // --- Chain: what it combines with.
  if (origin) {
    const o = canonicalOrigin(origin);
    const sameOrigin = (obs: Entity) =>
      ((obs.attributes.affects as Array<{ id: string }> | undefined) ?? []).some((ref) => {
        const ep = e.get(ref.id);
        const app = ep?.kind === "endpoint" ? e.get(String(ep.attributes.webappId)) : ep;
        return app?.kind === "webapp" && canonicalOrigin(String(app.attributes.origin)) === o;
      });
    const observations = e.query({ kind: "observation", limit: 5000 }).filter((x) => x.attributes.triage !== "false_positive" && sameOrigin(x));
    const noLimit = observations.filter((x) => x.attributes.sourceRule === "ratelimit:none").map((x) => String(x.attributes.title).replace(/^No rate limiting on /, "").replace(/:.*$/, ""));
    if (noLimit.length && exposed.some((x) => x.kind === "emails")) {
      leads.chain.push({ text: `Exposed e-mails + no rate limit on ${noLimit.join(", ")}: an attacker gets the usernames here and guesses passwords (or floods resets) there. State the chain; test it only with a test account and the operator's approval.` });
    }
    // Sub-routes of the same resource, reachable with an id this finding gives away.
    for (const t of where) for (const template of t.templates.filter((p) => /\{[^}]+\}/.test(p)).slice(0, 2)) {
      const prefix = template.replace(/\{[^}]+\}.*$/, "");
      const subs = new Set<string>();
      for (const app of e.query({ kind: "webapp", limit: 500 }).filter((a) => canonicalOrigin(String(a.attributes.origin)) === canonicalOrigin(t.origin))) {
        for (const ep of e.query({ kind: "endpoint", limit: 50_000 })) {
          const p = String(ep.attributes.pathTemplate);
          if (ep.attributes.webappId === app.id && p.startsWith(prefix) && templateOf(p) !== template && p.length > template.length) subs.add(p);
        }
      }
      if (subs.size) {
        const paths = [...subs].slice(0, 40);
        leads.chain.push({
          text: `${subs.size} other route(s) under ${prefix}…: with the identifiers this finding gives away, check which answer without credentials too (one sweep).`,
          tool: "web_probe_endpoints",
          args: { origin: t.origin, paths: paths.map((p) => p.replace(/\{[^}]+\}|:[A-Za-z_]\w*/g, "1")) },
        });
      }
    }
    for (const x of exposed.filter((x) => x.kind === "secret").slice(0, 2)) {
      const gated = e
        .query({ kind: "endpoint", limit: 50_000 })
        .filter((ep) => ep.attributes.requiresAuth === true && ((ep.attributes.params as Array<{ location: string; name: string }> | undefined) ?? []).some((p) => p.location === "header" && /key|token|auth/i.test(p.name)))
        .map((ep) => String(ep.attributes.pathTemplate))
        .slice(0, 5);
      if (gated.length) leads.chain.push({ text: `Routes that require a key or token header (${gated.join(", ")}): does ${x.marker} open any of them?` });
    }
    const hosts = exposed.filter((x) => x.kind === "hosts").flatMap((x) => x.hosts ?? []);
    if (hosts.length) leads.chain.push({ text: `Hosts named in the data: ${hosts.slice(0, 8).join(", ")}. If they belong to the client and are not in scope, propose them (scope_propose_rule); never test them before.` });
    const others = e
      .query({ kind: "finding", limit: 5000 })
      .filter((x) => x.id !== f.id && !CLOSED.has(String(x.attributes.status)) && touched(e, x).some((t) => canonicalOrigin(t.origin) === o))
      .map((x) => `«${String(x.attributes.title)}»`)
      .slice(0, 4);
    if (others.length) leads.chain.push({ text: `Other findings on the same origin: ${others.join(", ")}. Does one make the other worse (what this exposes is the input the other needs)?` });
  }
  if (!leads.chain.length) leads.chain.push({ text: "Nothing in the graph combines with it yet. If nothing does, answer not_applicable saying what you checked." });
  return leads;
}

/** A short line of leads for a notice: the first of each question. */
export function leadsLine(leads: ImpactLeads): string {
  return IMPACT_KEYS.map((k) => (leads[k][0] ? `${k}: ${leads[k][0]!.text}` : "")).filter(Boolean).join(" | ");
}
