import { type Actor, type RiskLevel, ulid } from "@penteos/schema";
import type { Engagement } from "../engagement.js";
import type { ActorPolicy } from "../scope/evaluate.js";

/**
 * Capabilities and gaps.
 *
 * The agent asks for a capability ("discover subdomains"), not a tool. Penteos uses the best tool
 * installed for it; without one, its own fallback (tools/builtins.ts); without that either, nothing
 * runs. Whatever could not be done at full quality is a GAP: recorded by Penteos (never left to the
 * agent's memory), resumed by itself when the tool appears, shown when the phase closes, and, if the
 * operator moves on without it, written in the report as a limitation of the test.
 */

export type CapabilityId = "dns_resolve" | "subdomains" | "http_probe" | "crawl" | "content_discovery" | "port_scan" | "vuln_templates" | "sqli" | "oob" | "internal_services";

export interface CapabilityDef {
  id: CapabilityId;
  title: { es: string; en: string };
  /** Tools that do it fully, best first (names of manifests or catalog entries). */
  providers: string[];
  /** What the targets are. */
  targets: "domain" | "host" | "origin";
  risk: RiskLevel;
  /** Penteos's own way, when it has one: which tool's output it writes, and how it compares. */
  builtin?: {
    name: string;
    writes: "dnsx" | "subfinder" | "httpx" | "katana" | "nmap";
    quality: "full" | "degraded";
    /** What the tool would add over the fallback: shown in the gap and to the agent. */
    lacks: { es: string; en: string };
  };
  /** What is missing when nothing can do it (no builtin). */
  missing?: { es: string; en: string };
  /** Phases whose central work this is: without any source for it, the phase cannot close. */
  centralIn: string[];
}

export const CAPABILITIES: Record<CapabilityId, CapabilityDef> = {
  dns_resolve: {
    id: "dns_resolve",
    title: { es: "Resolver nombres DNS", en: "Resolve DNS names" },
    providers: ["dnsx"],
    targets: "domain",
    risk: "passive",
    builtin: { name: "dns", writes: "dnsx", quality: "full", lacks: { es: "dnsx resuelve miles de nombres en paralelo y prueba listas de subdominios", en: "dnsx resolves thousands of names in parallel and brute-forces subdomain lists" } },
    centralIn: ["recon"],
  },
  subdomains: {
    id: "subdomains",
    title: { es: "Descubrir subdominios (pasivo)", en: "Discover subdomains (passive)" },
    providers: ["subfinder"],
    targets: "domain",
    risk: "passive",
    builtin: { name: "ct", writes: "subfinder", quality: "degraded", lacks: { es: "subfinder consulta decenas de fuentes; lo propio solo usa certificados públicos (crt.sh, certspotter)", en: "subfinder queries dozens of sources; the fallback only uses public certificates (crt.sh, certspotter)" } },
    centralIn: [],
  },
  http_probe: {
    id: "http_probe",
    title: { es: "Sondear servicios web", en: "Probe web services" },
    providers: ["httpx"],
    targets: "host",
    risk: "active",
    builtin: { name: "http-probe", writes: "httpx", quality: "degraded", lacks: { es: "httpx detecta cientos de tecnologías más y prueba muchos hosts en paralelo", en: "httpx detects hundreds more technologies and probes many hosts in parallel" } },
    centralIn: ["recon"],
  },
  crawl: {
    id: "crawl",
    title: { es: "Rastrear enlaces de la aplicación", en: "Crawl the application" },
    providers: ["katana"],
    targets: "origin",
    risk: "active",
    builtin: { name: "crawl", writes: "katana", quality: "degraded", lacks: { es: "katana ejecuta JavaScript, llega más profundo y encuentra rutas en los scripts", en: "katana runs JavaScript, goes deeper and finds routes inside scripts" } },
    centralIn: ["mapping"],
  },
  content_discovery: {
    id: "content_discovery",
    title: { es: "Buscar rutas y archivos expuestos", en: "Discover exposed paths and files" },
    // ffuf and gobuster need a wordlist the operator chooses: Penteos's own short list is the default.
    providers: [],
    targets: "origin",
    risk: "active",
    builtin: { name: "common-paths", writes: "katana", quality: "full", lacks: { es: "con ffuf y una lista grande se prueban miles de rutas", en: "ffuf with a large wordlist tries thousands of paths" } },
    centralIn: [],
  },
  port_scan: {
    id: "port_scan",
    title: { es: "Escanear puertos", en: "Scan ports" },
    providers: ["nmap"],
    targets: "host",
    risk: "active",
    builtin: { name: "tcp-connect", writes: "nmap", quality: "degraded", lacks: { es: "nmap identifica versiones con precisión, corre scripts y escanea UDP; lo propio prueba los 100 puertos TCP más comunes y lee banners", en: "nmap identifies versions precisely, runs scripts and scans UDP; the fallback tries the 100 most common TCP ports and reads banners" } },
    centralIn: ["recon"],
  },
  vuln_templates: {
    id: "vuln_templates",
    title: { es: "Plantillas de vulnerabilidades conocidas", en: "Known-vulnerability templates" },
    providers: ["nuclei"],
    targets: "origin",
    risk: "intrusive",
    missing: { es: "No se ejecutaron plantillas de vulnerabilidades conocidas (CVE, configuraciones expuestas)", en: "Known-vulnerability templates (CVEs, exposed configurations) were not run" },
    centralIn: [],
  },
  sqli: {
    id: "sqli",
    title: { es: "Inyección SQL automatizada", en: "Automated SQL injection" },
    providers: ["sqlmap"],
    targets: "origin",
    risk: "intrusive",
    missing: { es: "No se automatizó la prueba de inyección SQL (se puede probar a mano con http_send)", en: "SQL injection was not automated (it can be tested by hand with http_send)" },
    centralIn: [],
  },
  oob: {
    id: "oob",
    title: { es: "Detección fuera de banda", en: "Out-of-band detection" },
    providers: ["interactsh-client"],
    targets: "origin",
    risk: "active",
    missing: { es: "No se probaron vulnerabilidades que solo se ven fuera de banda (SSRF ciega, XXE, inyecciones ciegas)", en: "Vulnerabilities only visible out of band (blind SSRF, XXE, blind injections) were not tested" },
    centralIn: [],
  },
  internal_services: {
    id: "internal_services",
    title: { es: "Enumerar servicios internos (SMB, LDAP, WinRM)", en: "Enumerate internal services (SMB, LDAP, WinRM)" },
    providers: ["netexec"],
    targets: "host",
    risk: "active",
    missing: { es: "No se enumeraron SMB, LDAP ni WinRM", en: "SMB, LDAP and WinRM were not enumerated" },
    centralIn: ["enumeration"],
  },
};

export const CAPABILITY_IDS = Object.keys(CAPABILITIES) as CapabilityId[];

/** What each phase usually needs (the kit offered once when it starts). */
export const PHASE_CAPABILITIES: Record<string, CapabilityId[]> = {
  recon: ["dns_resolve", "subdomains", "http_probe", "port_scan"],
  mapping: ["crawl", "content_discovery"],
  analysis: ["vuln_templates", "oob"],
  enumeration: ["internal_services"],
  exploitation: ["sqli", "oob"],
  verification: ["vuln_templates"],
  monitoring: ["port_scan", "http_probe"],
};

/** The project's permission to install from the verified catalog without asking (off by default). */
export interface AutoInstall {
  enabled: boolean;
  /** Most it may install this way, in MB, all together. */
  maxMB: number;
}
export const AUTO_INSTALL_DEFAULT: AutoInstall = { enabled: false, maxMB: 300 };

// ---------------------------------------------------------------------------------------------
// Gaps

export interface Gap {
  id: string;
  capability: CapabilityId;
  /** degraded: done with Penteos's own fallback; blocked: not done at all. */
  severity: "degraded" | "blocked";
  /** Tools that would fill it. */
  tools: string[];
  phase?: string;
  targets: string[];
  status: "open" | "resolving" | "resolved" | "accepted";
  createdAt: string;
  updatedAt: string;
  /** Who asked (the agent, usually) and with what policy: a resume runs as they would. */
  requestedBy: Actor;
  policy: ActorPolicy;
  options?: Record<string, unknown>;
  /** How many times it came up (the same gap is merged, not repeated). */
  count: number;
  resolvedRun?: string;
  /** While resuming it waits for the operator: the card that decides it. */
  approvalId?: string;
  accepted?: { by: Actor; reason: string; at: string };
}

const KEY = "toolgaps";

export function listGaps(e: Engagement): Gap[] {
  return e.getState<Gap[]>(KEY) ?? [];
}

function saveGaps(e: Engagement, gaps: Gap[]): void {
  e.setState(KEY, gaps.slice(-500));
}

/**
 * Records that a capability could not be done fully. The same capability still open (same
 * severity) gathers the new targets instead of opening another gap: no repeats, no noise.
 */
export function openGap(e: Engagement, g: Omit<Gap, "id" | "status" | "createdAt" | "updatedAt" | "count">): { gap: Gap; isNew: boolean } {
  const gaps = listGaps(e);
  const now = new Date().toISOString();
  const same = gaps.find((x) => x.capability === g.capability && x.severity === g.severity && x.status === "open");
  if (same) {
    same.targets = [...new Set([...same.targets, ...g.targets])];
    same.count += 1;
    same.updatedAt = now;
    if (g.options) same.options = g.options;
    saveGaps(e, gaps);
    return { gap: same, isNew: false };
  }
  const gap: Gap = { ...g, id: ulid(), status: "open", createdAt: now, updatedAt: now, count: 1 };
  gaps.push(gap);
  saveGaps(e, gaps);
  e.events.emit("change", { type: "gap.changed", id: gap.id });
  return { gap, isNew: true };
}

export function updateGap(e: Engagement, id: string, patch: Partial<Gap>): Gap | undefined {
  const gaps = listGaps(e);
  const g = gaps.find((x) => x.id === id);
  if (!g) return undefined;
  Object.assign(g, patch, { updatedAt: new Date().toISOString() });
  saveGaps(e, gaps);
  e.events.emit("change", { type: "gap.changed", id });
  return g;
}

/** OWASP WSTG categories each capability feeds: a gap there makes "tested" only partial. */
const WSTG_OF: Partial<Record<CapabilityId, string[]>> = {
  crawl: ["INFO", "APIT"],
  content_discovery: ["INFO", "CONF"],
  http_probe: ["INFO"],
  vuln_templates: ["CONF", "INPV"],
  sqli: ["INPV"],
  oob: ["INPV"],
};

/** Gaps (open or accepted) that limit a WSTG category on a web application. */
export function gapsLimiting(e: Engagement, origin: string, category: string): Gap[] {
  const host = (() => {
    try {
      return new URL(origin).hostname;
    } catch {
      return origin;
    }
  })();
  return listGaps(e).filter(
    (g) =>
      (g.status === "open" || g.status === "accepted" || g.status === "resolving") &&
      (WSTG_OF[g.capability] ?? []).includes(category) &&
      g.targets.some((t) => t === origin || t.replace(/\/+$/, "") === origin || t.startsWith(`${origin}/`) || t === host || t.split(":")[0] === host || (() => { try { return new URL(t).hostname === host; } catch { return false; } })()),
  );
}

/** A gap is critical when it leaves its phase without any source for that phase's central work. */
export function isCritical(g: Gap): boolean {
  return g.severity === "blocked" && Boolean(g.phase && CAPABILITIES[g.capability].centralIn.includes(g.phase));
}

/** One line for people (phase card, report): what was not done, on what, and why. */
export function gapLine(g: Gap, lang: "es" | "en"): string {
  const def = CAPABILITIES[g.capability];
  const on = g.targets.slice(0, 4).join(", ") + (g.targets.length > 4 ? (lang === "en" ? ` and ${g.targets.length - 4} more` : ` y ${g.targets.length - 4} más`) : "");
  const tools = g.tools.join(lang === "en" ? " or " : " o ");
  if (g.severity === "blocked") {
    const what = def.missing?.[lang] ?? def.title[lang];
    return lang === "en" ? `${what} on ${on} (${tools} not available)` : `${what} en ${on} (${tools} no disponible)`;
  }
  return lang === "en" ? `${def.title[lang]} on ${on} done with Penteos's own method: ${def.builtin!.lacks[lang]}` : `${def.title[lang]} en ${on} se hizo con el método propio de Penteos: ${def.builtin!.lacks[lang]}`;
}
