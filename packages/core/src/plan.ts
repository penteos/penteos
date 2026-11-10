import { listGaps, updateGap } from "./tools/capabilities.js";
import type { Actor } from "@penteos/schema";
import type { Engagement } from "./engagement.js";

/**
 * The phases of the work: where the engagement is, what the plan is for each
 * phase and what came out of it. The phase is also a rule: an agent cannot run
 * exploitation-level actions before a human moves the engagement to a phase that allows them.
 */

export interface Phase {
  id: string;
  title: string;
  /** What is done in this phase, for the operator and the agent. */
  goal: string;
  status: "pending" | "current" | "done";
  /** The agent's (or operator's) plan for this phase, in markdown. */
  plan?: string;
  /** What came out of it, written when the phase closes. */
  summary?: string;
  /** Agents may run exploitation-level actions in this phase. */
  exploitation: boolean;
}

export interface Plan {
  /** The mode the phases were made for: changing the engagement's mode starts a new plan. */
  mode: string;
  phases: Phase[];
  current: string | null;
  updatedAt: string;
}

type Template = Array<Pick<Phase, "id" | "title" | "goal" | "exploitation">>;

const WEB: Template = [
  { id: "recon", title: "Reconocimiento", goal: "Qué hay: hosts, puertos, tecnologías, subdominios. Sin atacar.", exploitation: false },
  { id: "mapping", title: "Mapeo", goal: "Cómo funciona la aplicación: rutas, parámetros, roles, autenticación y flujos.", exploitation: false },
  { id: "analysis", title: "Análisis de vulnerabilidades", goal: "Qué puede fallar: pruebas por categoría (OWASP), scanners y verificación manual, sin explotar.", exploitation: false },
  { id: "exploitation", title: "Explotación", goal: "Demostrar el impacto de lo encontrado, con el mínimo daño posible.", exploitation: true },
  { id: "reporting", title: "Reporte", goal: "Hallazgos revisados, dónde estamos y qué caminos quedan; el entregable, cuando el operador lo pida.", exploitation: false },
];

const INFRA: Template = [
  { id: "recon", title: "Reconocimiento", goal: "Qué hay en la red: hosts vivos, servicios y versiones.", exploitation: false },
  { id: "enumeration", title: "Enumeración", goal: "Usuarios, recursos compartidos, Active Directory (BloodHound) y configuraciones.", exploitation: false },
  { id: "analysis", title: "Análisis de vulnerabilidades", goal: "Qué puede fallar en cada servicio, sin explotar.", exploitation: false },
  { id: "exploitation", title: "Explotación y escalada", goal: "Demostrar acceso, escalar privilegios y moverse lateralmente.", exploitation: true },
  { id: "reporting", title: "Reporte", goal: "Hallazgos por activo, dónde estamos y qué caminos quedan; el entregable, cuando el operador lo pida.", exploitation: false },
];

const RETEST: Template = [
  { id: "verification", title: "Verificación", goal: "Reproducir cada hallazgo original y ver si sigue presente.", exploitation: true },
  { id: "reporting", title: "Reporte de retest", goal: "Estado de cada hallazgo y comparación con el original.", exploitation: false },
];

const CONTINUOUS: Template = [
  { id: "monitoring", title: "Monitoreo", goal: "Escaneos programados e instantáneas de la superficie.", exploitation: false },
  { id: "analysis", title: "Análisis de cambios", goal: "Investigar lo nuevo: servicios, versiones, hallazgos.", exploitation: false },
  { id: "reporting", title: "Reporte", goal: "Qué cambió y qué hay que corregir.", exploitation: false },
];

const TEMPLATES: Record<string, Template> = { web: WEB, infra: INFRA, retest: RETEST, continuous: CONTINUOUS };

/** The same phases for projects whose deliverable is in English. */
const EN: Record<string, Template> = {
  infra: [
    { id: "recon", title: "Reconnaissance", goal: "What is on the network: live hosts, services and versions.", exploitation: false },
    { id: "enumeration", title: "Enumeration", goal: "Users, shares, Active Directory (BloodHound) and configurations.", exploitation: false },
    { id: "analysis", title: "Vulnerability analysis", goal: "What can fail in each service, without exploitation.", exploitation: false },
    { id: "exploitation", title: "Exploitation and escalation", goal: "Demonstrate access, escalate privileges and move laterally.", exploitation: true },
    { id: "reporting", title: "Reporting", goal: "Findings by asset, where things stand and which paths remain; the deliverable when the operator asks for it.", exploitation: false },
  ],
  web: [
    { id: "recon", title: "Reconnaissance", goal: "What is there: hosts, ports, technologies, subdomains. No attacks.", exploitation: false },
    { id: "mapping", title: "Mapping", goal: "How the application works: routes, parameters, roles, authentication and flows.", exploitation: false },
    { id: "analysis", title: "Vulnerability analysis", goal: "What can fail: tests by category (OWASP), scanners and manual verification, without exploitation.", exploitation: false },
    { id: "exploitation", title: "Exploitation", goal: "Demonstrate the impact of what was found, with the least possible damage.", exploitation: true },
    { id: "reporting", title: "Reporting", goal: "Reviewed findings, where things stand and which paths remain; the deliverable when the operator asks for it.", exploitation: false },
  ],
  retest: [
    { id: "verification", title: "Verification", goal: "Reproduce each original finding and check whether it is still present.", exploitation: true },
    { id: "reporting", title: "Retest report", goal: "Status of each finding and comparison with the original.", exploitation: false },
  ],
  continuous: [
    { id: "monitoring", title: "Monitoring", goal: "Scheduled scans and snapshots of the surface.", exploitation: false },
    { id: "analysis", title: "Change analysis", goal: "Investigate what is new: services, versions, findings.", exploitation: false },
    { id: "reporting", title: "Reporting", goal: "What changed and what needs fixing.", exploitation: false },
  ],
};


/**
 * The plan with its standard phases' titles and goals in `lang`. A plan stores them in the language
 * the project had when it started; a phase still carrying a template's text (in either language) is
 * shown in the one asked for, while a phase someone renamed keeps its own words.
 */
export function localizePlan(plan: Plan, lang: "es" | "en"): Plan {
  const es = TEMPLATES[plan.mode];
  const en = EN[plan.mode];
  if (!es || !en) return plan;
  const target = lang === "en" ? en : es;
  return {
    ...plan,
    phases: plan.phases.map((p) => {
      const standard = [es, en].some((t) => t.some((x) => x.id === p.id && x.title === p.title));
      const to = target.find((x) => x.id === p.id);
      return standard && to ? { ...p, title: to.title, goal: to.goal } : p;
    }),
  };
}

/** Free mode has no phases: nothing is gated. */
export function getPlan(engagement: Engagement): Plan {
  const info = engagement.info;
  // The round mode drives the phases for retest/continuous; otherwise the target type does.
  const mode = info.roundMode !== "pentest" ? info.roundMode : info.mode;
  const stored = engagement.getMeta<Plan>("plan");
  // The deliverable's language can change mid-project: the standard phases follow it.
  if (stored && stored.mode === mode) return localizePlan(stored, info.language ?? "en");
  const template = (info.language === "en" ? EN : TEMPLATES)[mode];
  if (!template) return { mode, phases: [], current: null, updatedAt: new Date().toISOString() };
  return {
    mode,
    phases: template.map((p, i) => ({ ...p, status: i === 0 ? "current" : "pending" })),
    current: template[0]!.id,
    updatedAt: new Date().toISOString(),
  };
}

function save(engagement: Engagement, plan: Plan, actor: Actor): Plan {
  const next = { ...plan, updatedAt: new Date().toISOString() };
  engagement.setMeta("plan", next, actor);
  return next;
}

export function currentPhase(engagement: Engagement): Phase | undefined {
  const plan = getPlan(engagement);
  return plan.phases.find((p) => p.id === plan.current);
}

/** Whether agents may run exploitation-level actions now. */
export function exploitationAllowed(engagement: Engagement): { allowed: boolean; phase?: Phase; next?: Phase } {
  const plan = getPlan(engagement);
  if (plan.phases.length === 0) return { allowed: true };
  const phase = plan.phases.find((p) => p.id === plan.current);
  const next = plan.phases.find((p) => p.exploitation);
  return { allowed: Boolean(phase?.exploitation), ...(phase ? { phase } : {}), ...(next ? { next } : {}) };
}

export function setPhase(engagement: Engagement, to: string, actor: Actor, summary?: string): Plan {
  const plan = getPlan(engagement);
  const target = plan.phases.findIndex((p) => p.id === to);
  if (target < 0) throw new Error(`unknown phase: ${to}`);
  const from = plan.phases.findIndex((p) => p.id === plan.current);
  const phases = plan.phases.map((p, i) => {
    if (i === target) return { ...p, status: "current" as const };
    if (i === from) return { ...p, status: (i < target ? "done" : "pending") as Phase["status"], ...(summary ? { summary } : {}) };
    if (i < target && p.status !== "done") return { ...p, status: "done" as const };
    if (i > target && p.status === "current") return { ...p, status: "pending" as const };
    return p;
  });
  engagement.audit(actor, "phase.set", { phase: to }, { from: plan.current, to, summary });
  // Leaving a phase with gaps still open is the operator going on without them: recorded as such
  // (who, and that it was this move), and the report lists them as limitations of the test.
  if (actor.type === "human" && plan.current && plan.current !== to) {
    const title = plan.phases[target]!.title;
    const lang = engagement.info.language ?? "en";
    for (const g of listGaps(engagement)) {
      if (g.status !== "open" || (g.phase && g.phase !== plan.current)) continue;
      updateGap(engagement, g.id, { status: "accepted", accepted: { by: actor, reason: lang === "en" ? `Moved on to «${title}» without it` : `Se pasó a «${title}» sin resolverlo`, at: new Date().toISOString() } });
    }
  }
  return save(engagement, { ...plan, phases, current: to }, actor);
}

export function setPhasePlan(engagement: Engagement, phase: string, text: string, actor: Actor): Plan {
  const plan = getPlan(engagement);
  if (!plan.phases.some((p) => p.id === phase)) throw new Error(`unknown phase: ${phase}`);
  return save(engagement, { ...plan, phases: plan.phases.map((p) => (p.id === phase ? { ...p, plan: text } : p)) }, actor);
}

export function setPhaseSummary(engagement: Engagement, phase: string, text: string, actor: Actor): Plan {
  const plan = getPlan(engagement);
  if (!plan.phases.some((p) => p.id === phase)) throw new Error(`unknown phase: ${phase}`);
  return save(engagement, { ...plan, phases: plan.phases.map((p) => (p.id === phase ? { ...p, summary: text } : p)) }, actor);
}
