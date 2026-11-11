import type { Language } from "./language.js";

/**
 * The fixed text of the complete technical report and the executive one (2026-11), in the project's
 * language. Kept apart from report-text.ts so the original deliverable's text stays as it was.
 */
export interface FullReportText {
  executiveKind: (kind: string) => string;
  documentControl: string;
  dc: { version: string; date: string; preparedBy: string; team: string; distribution: string; classification: string; testType: string; period: string };
  testTypes: Record<"black" | "grey" | "white", string>;
  overallRisk: string;
  riskLevels: Record<"critical" | "high" | "medium" | "low" | "none", string>;
  /** The overall risk when coverage does not allow saying more than the worst finding found. */
  riskUndetermined: string;
  riskAtLeast: (level: string) => string;
  riskLine: (level: string, total: number, top: string) => string;
  /** Why the overall risk is not determined: what was not done and what was not tested. */
  coverageCaveat: (c: { phases: string[]; untested: number; applicable: number; apps: Array<{ origin: string; untested: number; applicable: number }> }) => string;
  /** Assets found during the work that were outside this round's scope (not tested). */
  discoveredTitle: string;
  discoveredIntro: string;
  /** The limitations a person accepted to issue the report as final. */
  acceptedLimitations: string;
  /** In a report, a saved credential is named, never shown (nor its internal marker). */
  secretRef: string;
  topRisks: string;
  rulesOfEngagement: string;
  window: (from: string, to: string) => string;
  methodology: string;
  methodologyIntro: Record<"web" | "network" | "other", string>;
  standards: string;
  phasesHead: string;
  phaseStatus: Record<"done" | "current" | "pending", string>;
  operatorNotes: string;
  timeline: string;
  timelineIntro: (from: string, to: string, days: number) => string;
  timelineHead: string;
  timelineNone: string;
  remediationPlan: string;
  remediationIntro: string;
  horizons: Record<"now" | "short" | "mid", string>;
  planHead: string;
  inventory: string;
  hostsTitle: string;
  hostsHead: string;
  servicesTitle: string;
  servicesHead: string;
  appsTitle: string;
  appsHead: string;
  techTitle: string;
  techHead: string;
  trimmed: (shown: number, total: number) => string;
  limitations: string;
  /** Heading of the list of what missing tools left undone. */
  toolGaps: string;
  defaultLimitations: string;
  tools: string;
  toolsHead: string;
  commandsTitle: string;
  commandsHead: string;
  reproduction: string;
  cvssDetail: string;
  cwe: string;
  request: string;
  response: string;
  screenshot: string;
  verified: (by: string, at: string) => string;
  cvssMetric: Record<string, string>;
  cvssValue: Record<string, Record<string, string>>;
  none: string;
}

const CVSS_VALUES_ES: Record<string, Record<string, string>> = {
  AV: { N: "Red", A: "Red adyacente", L: "Local", P: "Física" },
  AC: { L: "Baja", H: "Alta" },
  AT: { N: "Ninguno", P: "Presente" },
  PR: { N: "Ninguno", L: "Bajos", H: "Altos" },
  UI: { N: "Ninguna", R: "Requerida", P: "Pasiva", A: "Activa" },
  S: { U: "Sin cambio", C: "Con cambio" },
  C: { N: "Ninguno", L: "Bajo", H: "Alto" },
  I: { N: "Ninguno", L: "Bajo", H: "Alto" },
  A: { N: "Ninguno", L: "Bajo", H: "Alto" },
  VC: { N: "Ninguno", L: "Bajo", H: "Alto" },
  VI: { N: "Ninguno", L: "Bajo", H: "Alto" },
  VA: { N: "Ninguno", L: "Bajo", H: "Alto" },
  SC: { N: "Ninguno", L: "Bajo", H: "Alto" },
  SI: { N: "Ninguno", L: "Bajo", H: "Alto" },
  SA: { N: "Ninguno", L: "Bajo", H: "Alto" },
};
const CVSS_VALUES_EN: Record<string, Record<string, string>> = {
  AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  AC: { L: "Low", H: "High" },
  AT: { N: "None", P: "Present" },
  PR: { N: "None", L: "Low", H: "High" },
  UI: { N: "None", R: "Required", P: "Passive", A: "Active" },
  S: { U: "Unchanged", C: "Changed" },
  C: { N: "None", L: "Low", H: "High" },
  I: { N: "None", L: "Low", H: "High" },
  A: { N: "None", L: "Low", H: "High" },
  VC: { N: "None", L: "Low", H: "High" },
  VI: { N: "None", L: "Low", H: "High" },
  VA: { N: "None", L: "Low", H: "High" },
  SC: { N: "None", L: "Low", H: "High" },
  SI: { N: "None", L: "Low", H: "High" },
  SA: { N: "None", L: "Low", H: "High" },
};

const es: FullReportText = {
  executiveKind: (kind) => `${kind} · Resumen ejecutivo`,
  documentControl: "Control del documento",
  dc: { version: "Versión", date: "Fecha", preparedBy: "Elaborado por", team: "Equipo", distribution: "Destinatarios", classification: "Clasificación", testType: "Tipo de prueba", period: "Período de pruebas" },
  testTypes: { black: "Caja negra (sin información previa)", grey: "Caja gris (con información o credenciales parciales)", white: "Caja blanca (con acceso completo a la información)" },
  overallRisk: "Nivel de riesgo general",
  riskLevels: { critical: "Crítico", high: "Alto", medium: "Medio", low: "Bajo", none: "Sin riesgos relevantes" },
  riskUndetermined: "No determinado",
  riskAtLeast: (level) => `al menos ${level}`,
  coverageCaveat: (c) =>
    `**La cobertura alcanzada no permite determinar el riesgo general.**${c.phases.length ? ` Quedó sin realizar: ${c.phases.join(", ")}.` : ""}${c.applicable ? ` Sin probar: ${c.untested} de ${c.applicable} categorías aplicables de OWASP WSTG${c.apps.length ? ` (${c.apps.map((a) => `${a.origin}: ${a.untested} de ${a.applicable}`).join("; ")})` : ""}.` : ""} Lo informado describe lo encontrado en lo que sí se probó; no indica la ausencia de otros problemas.`,
  acceptedLimitations: "Limitaciones aceptadas para esta entrega",
  discoveredTitle: "Activos descubiertos fuera del alcance de esta ronda",
  discoveredIntro: "Aparecieron durante el reconocimiento y no se probaron porque no estaban incluidos en el alcance. Se recomienda evaluar su inclusión en una próxima ronda:",
  secretRef: "[credencial de prueba]",
  riskLine: (level, total, top) => `**Nivel de riesgo general: ${level}.** Se informan ${total} hallazgos${top ? `; el más grave: ${top}` : ""}.`,
  topRisks: "Riesgos principales",
  rulesOfEngagement: "Reglas de compromiso",
  window: (from, to) => `Las pruebas se realizaron entre el ${from} y el ${to}.`,
  methodology: "Metodología",
  methodologyIntro: {
    web: "La evaluación siguió la Guía de Pruebas de Seguridad Web de OWASP (WSTG) y el estándar PTES: reconocimiento de la superficie, análisis de la aplicación, pruebas de autenticación, autorización, manejo de sesiones, validación de entradas y lógica de negocio, y verificación de cada hallazgo con evidencia.",
    network: "La evaluación siguió el estándar PTES y la guía NIST SP 800-115: descubrimiento de activos y servicios, identificación de versiones y vulnerabilidades conocidas, verificación controlada y análisis del impacto, con evidencia de cada hallazgo.",
    other: "La evaluación siguió el estándar PTES: reconocimiento, análisis de vulnerabilidades, verificación controlada e informe, con evidencia de cada hallazgo.",
  },
  standards: "Marcos de referencia",
  phasesHead: "| Fase | Estado | Resumen |",
  phaseStatus: { done: "Completada", current: "En curso", pending: "No realizada" },
  operatorNotes: "Notas del equipo",
  timeline: "Cronología",
  timelineIntro: (from, to, days) => `Actividad registrada entre el ${from} y el ${to} (${days} ${days === 1 ? "día" : "días"} con actividad).`,
  timelineHead: "| Fecha | Ejecuciones | Herramientas | Hallazgos registrados |",
  timelineNone: "_No hay actividad registrada._",
  remediationPlan: "Plan de remediación",
  remediationIntro: "Orden sugerido para corregir, según la severidad de cada hallazgo. Los plazos son una referencia y pueden ajustarse al riesgo propio de la organización.",
  horizons: { now: "Inmediato (0 a 7 días)", short: "Corto plazo (hasta 30 días)", mid: "Mediano plazo (hasta 90 días)" },
  planHead: "| ID | Hallazgo | Activos | Acción principal |",
  inventory: "Inventario relevado",
  hostsTitle: "Hosts",
  hostsHead: "| Dirección | Nombres | Sistema | Estado |",
  servicesTitle: "Servicios",
  servicesHead: "| Host | Puerto | Servicio | Producto y versión |",
  appsTitle: "Aplicaciones web",
  appsHead: "| Origen | Tecnologías |",
  techTitle: "Tecnologías identificadas",
  techHead: "| Tecnología | Versión | Dónde |",
  trimmed: (shown, total) => `_Se muestran ${shown} de ${total}; el inventario completo está en el proyecto de Penteos._`,
  limitations: "Limitaciones",
  toolGaps: "Pruebas que no se pudieron completar por falta de herramientas",
  defaultLimitations:
    "Las pruebas se realizaron durante un período acotado y sobre el alcance acordado; los resultados reflejan el estado de los sistemas en ese momento. La ausencia de hallazgos en un componente no garantiza que esté libre de vulnerabilidades. No se realizaron pruebas que pudieran afectar la disponibilidad de los servicios salvo autorización expresa.",
  tools: "Anexo · Herramientas utilizadas",
  toolsHead: "| Herramienta | Ejecuciones | Primera | Última |",
  commandsTitle: "Comandos ejecutados",
  commandsHead: "| Fecha | Herramienta | Comando |",
  reproduction: "Pasos para reproducir",
  cvssDetail: "Detalle CVSS",
  cwe: "CWE",
  request: "Pedido",
  response: "Respuesta",
  screenshot: "Captura",
  verified: (by, at) => `Reproducido de forma independiente por ${by} el ${at}.`,
  cvssMetric: { AV: "Vector de ataque", AC: "Complejidad", AT: "Requisitos del ataque", PR: "Privilegios requeridos", UI: "Interacción del usuario", S: "Alcance", C: "Confidencialidad", I: "Integridad", A: "Disponibilidad", VC: "Confidencialidad", VI: "Integridad", VA: "Disponibilidad", SC: "Confidencialidad (sistemas siguientes)", SI: "Integridad (sistemas siguientes)", SA: "Disponibilidad (sistemas siguientes)" },
  cvssValue: CVSS_VALUES_ES,
  none: "-",
};

const en: FullReportText = {
  executiveKind: (kind) => `${kind} · Executive summary`,
  documentControl: "Document control",
  dc: { version: "Version", date: "Date", preparedBy: "Prepared by", team: "Team", distribution: "Distribution", classification: "Classification", testType: "Test type", period: "Testing period" },
  testTypes: { black: "Black box (no prior information)", grey: "Grey box (partial information or credentials)", white: "White box (full access to information)" },
  overallRisk: "Overall risk",
  riskLevels: { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "No relevant risks" },
  riskUndetermined: "Not determined",
  riskAtLeast: (level) => `at least ${level}`,
  coverageCaveat: (c) =>
    `**The coverage reached does not allow determining the overall risk.**${c.phases.length ? ` Not carried out: ${c.phases.join(", ")}.` : ""}${c.applicable ? ` Untested: ${c.untested} of ${c.applicable} applicable OWASP WSTG categories${c.apps.length ? ` (${c.apps.map((a) => `${a.origin}: ${a.untested} of ${a.applicable}`).join("; ")})` : ""}.` : ""} What is reported describes what was found in what was tested; it does not indicate the absence of other problems.`,
  acceptedLimitations: "Limitations accepted for this delivery",
  discoveredTitle: "Assets discovered outside this round's scope",
  discoveredIntro: "They appeared during reconnaissance and were not tested because they were not in scope. Including them in a next round is recommended:",
  secretRef: "[test credential]",
  riskLine: (level, total, top) => `**Overall risk: ${level}.** ${total} findings are reported${top ? `; the most serious: ${top}` : ""}.`,
  topRisks: "Main risks",
  rulesOfEngagement: "Rules of engagement",
  window: (from, to) => `Testing took place between ${from} and ${to}.`,
  methodology: "Methodology",
  methodologyIntro: {
    web: "The assessment followed the OWASP Web Security Testing Guide (WSTG) and PTES: surface reconnaissance, application analysis, testing of authentication, authorization, session management, input validation and business logic, and verification of every finding with evidence.",
    network: "The assessment followed PTES and NIST SP 800-115: discovery of assets and services, identification of versions and known vulnerabilities, controlled verification and impact analysis, with evidence for every finding.",
    other: "The assessment followed PTES: reconnaissance, vulnerability analysis, controlled verification and reporting, with evidence for every finding.",
  },
  standards: "Reference frameworks",
  phasesHead: "| Phase | Status | Summary |",
  phaseStatus: { done: "Completed", current: "In progress", pending: "Not performed" },
  operatorNotes: "Team notes",
  timeline: "Timeline",
  timelineIntro: (from, to, days) => `Activity recorded between ${from} and ${to} (${days} ${days === 1 ? "day" : "days"} with activity).`,
  timelineHead: "| Date | Executions | Tools | Findings recorded |",
  timelineNone: "_No activity recorded._",
  remediationPlan: "Remediation plan",
  remediationIntro: "Suggested order to fix, by each finding's severity. The time frames are a reference and can be adjusted to the organization's own risk.",
  horizons: { now: "Immediate (0 to 7 days)", short: "Short term (up to 30 days)", mid: "Medium term (up to 90 days)" },
  planHead: "| ID | Finding | Assets | Main action |",
  inventory: "Inventory",
  hostsTitle: "Hosts",
  hostsHead: "| Address | Names | System | State |",
  servicesTitle: "Services",
  servicesHead: "| Host | Port | Service | Product and version |",
  appsTitle: "Web applications",
  appsHead: "| Origin | Technologies |",
  techTitle: "Technologies identified",
  techHead: "| Technology | Version | Where |",
  trimmed: (shown, total) => `_${shown} of ${total} shown; the full inventory is in the Penteos project._`,
  limitations: "Limitations",
  toolGaps: "Tests that could not be completed for lack of tools",
  defaultLimitations:
    "Testing took place during a limited period and within the agreed scope; the results reflect the state of the systems at that time. The absence of findings in a component does not guarantee it is free of vulnerabilities. No tests that could affect the availability of services were performed unless expressly authorized.",
  tools: "Annex · Tools used",
  toolsHead: "| Tool | Executions | First | Last |",
  commandsTitle: "Commands executed",
  commandsHead: "| Date | Tool | Command |",
  reproduction: "Steps to reproduce",
  cvssDetail: "CVSS detail",
  cwe: "CWE",
  request: "Request",
  response: "Response",
  screenshot: "Screenshot",
  verified: (by, at) => `Independently reproduced by ${by} on ${at}.`,
  cvssMetric: { AV: "Attack vector", AC: "Complexity", AT: "Attack requirements", PR: "Privileges required", UI: "User interaction", S: "Scope", C: "Confidentiality", I: "Integrity", A: "Availability", VC: "Confidentiality", VI: "Integrity", VA: "Availability", SC: "Confidentiality (subsequent systems)", SI: "Integrity (subsequent systems)", SA: "Availability (subsequent systems)" },
  cvssValue: CVSS_VALUES_EN,
  none: "-",
};

export const FULL_TEXT: Record<Language, FullReportText> = { es, en };

/** A CVSS vector's base metrics, readable ("Attack vector: Network"). */
export function cvssBreakdown(vector: string, T: FullReportText): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (!k || !v || !T.cvssMetric[k]) continue;
    out.push([T.cvssMetric[k]!, T.cvssValue[k]?.[v] ?? v]);
  }
  return out;
}
