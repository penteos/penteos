import type { Language } from "./language.js";

/**
 * Fixed text of the deliverable, in the project's language. What the
 * operator and the agents wrote goes in as written; only the frame around it is translated here.
 */
export interface ReportText {
  pending: string;
  kind: Record<"pentest" | "retest" | "continuous", string>;
  client: string;
  issued: string;
  period: (from: string, to: string) => string;
  draftBanner: string;
  executiveSummary: string;
  scope: string;
  included: string;
  excluded: string;
  ports: (p: string) => string;
  noRules: string;
  paths: string;
  retest: string;
  retestSummary: (n: { total: number; fixed: number; partial: number; notFixed: number; notVerifiable: number; unverified: number }) => string;
  retestHead: string;
  retestNone: string;
  comparison: (n: { resolved: number; persisting: number; added: number; servicesAdded: number; servicesRemoved: number }) => string;
  findings: string;
  findingsSummary: string;
  noFindings: string;
  noApprovedFindings: string;
  severityHead: string;
  findingsHead: string;
  detailed: string;
  severity: string;
  status: string;
  description: string;
  impact: string;
  demonstrated: string;
  impactKeys: Record<"reach" | "exposed" | "chain", string>;
  affected: string;
  evidence: string;
  evidenceMissing: string;
  remediation: string;
  references: string;
  surface: string;
  surfaceLine: (c: Record<string, number>) => string;
  appsHead: string;
  coverage: string;
  coverageHead: string;
  conclusion: string;
  traces: string;
  tracesIntro: string;
  tracesHead: string;
  traceStatus: Record<"pending" | "cleaned" | "accepted", string>;
  annex: string;
  annexText: (runs: number) => string;
  auditOk: (events: number) => string;
  auditBroken: (at: number | undefined) => string;
  deletedAsset: string;
  severities: Record<string, string>;
  statuses: Record<string, string>;
  via: Record<string, string>;
  coverageStatus: Record<string, string>;
  /** Word document: cover and footer. */
  draft: string;
  preparedBy: (company: string) => string;
  confidential: string;
  page: string;
  /** "Página 3 de 12". */
  of: string;
  contents: string;
  authors: string;
  confidentiality: string;
  fileName: string;
  draftSuffix: string;
}

const es: ReportText = {
  pending: "_Pendiente de redacción._",
  kind: { pentest: "Informe de pentest", retest: "Informe de retest", continuous: "Informe de monitoreo" },
  client: "Cliente",
  issued: "Fecha de emisión",
  period: (from, to) => `**Período:** ${from} a ${to}`,
  draftBanner: "> **BORRADOR**: incluye hallazgos que todavía no fueron aprobados por un revisor.",
  executiveSummary: "Resumen ejecutivo",
  scope: "Alcance",
  included: "Incluido",
  excluded: "Excluido",
  ports: (p) => `puertos ${p}`,
  noRules: "_(sin reglas)_",
  paths: "Caminos de ataque",
  retest: "Resultado del retest",
  retestSummary: (n) =>
    `De ${n.total} hallazgos verificados: **${n.fixed} corregidos**, ${n.partial} parcialmente corregidos, **${n.notFixed} no corregidos**, ${n.notVerifiable} no verificables y ${n.unverified} sin verificar todavía.`,
  retestHead: "| Hallazgo | Severidad | Resultado |",
  retestNone: "_Este retest no tiene hallazgos heredados del proyecto original._",
  comparison: (n) =>
    `**Comparación con el original:** ${n.resolved} resueltos, ${n.persisting} siguen abiertos, ${n.added} nuevos; ${n.servicesAdded} servicios nuevos y ${n.servicesRemoved} cerrados.`,
  findings: "Hallazgos",
  findingsSummary: "Resumen de hallazgos",
  noFindings: "_No hay hallazgos registrados._",
  noApprovedFindings: "_No hay hallazgos aprobados. Los borradores se revisan antes de incluirse._",
  severityHead: "| Severidad | Cantidad |",
  findingsHead: "| ID | Hallazgo | Severidad | CVSS | Estado |",
  detailed: "Hallazgos detallados",
  severity: "Severidad",
  status: "Estado",
  description: "Descripción",
  impact: "Impacto",
  demonstrated: "Impacto demostrado",
  impactKeys: { reach: "Alcance", exposed: "Qué permite lo expuesto", chain: "Encadenamiento" },
  affected: "Activos afectados",
  evidence: "Evidencia",
  evidenceMissing: "_(contenido de evidencia no disponible)_",
  remediation: "Recomendación",
  references: "Referencias",
  surface: "Superficie observada",
  surfaceLine: (c) =>
    `${c.host ?? 0} hosts · ${c.domain ?? 0} dominios · ${c.service ?? 0} servicios · ${c.webapp ?? 0} aplicaciones web · ${c.endpoint ?? 0} endpoints · ${c.observation ?? 0} observaciones.`,
  appsHead: "| Aplicación | Tecnologías |",
  coverage: "Cobertura de pruebas (OWASP WSTG)",
  coverageHead: "| Categoría | Estado | Nota |",
  conclusion: "Conclusión",
  traces: "Rastros en el entorno",
  tracesIntro: "Elementos que las pruebas dejaron en los sistemas del cliente y su estado de limpieza.",
  tracesHead: "| Qué | Dónde | Cómo retirarlo | Estado |",
  traceStatus: { pending: "pendiente de limpieza", cleaned: "retirado", accepted: "aceptado por el cliente" },
  annex: "Anexo · Trazabilidad",
  annexText: (runs) =>
    `Cada hallazgo, activo y evidencia de este informe está registrado en Penteos con su procedencia (herramienta, ejecución y salida cruda). Se registraron ${runs} ejecuciones de herramientas. `,
  auditOk: (events) => `La cadena de auditoría (${events} eventos) se verificó íntegra al emitir este informe.`,
  auditBroken: (at) => `ATENCIÓN: la cadena de auditoría está alterada (evento #${at}).`,
  deletedAsset: "(activo eliminado)",
  severities: { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", info: "Informativa" },
  statuses: {
    draft: "Borrador",
    in_review: "En revisión",
    approved: "Aprobado",
    reported: "Reportado",
    fixed: "Corregido",
    partially_fixed: "Parcialmente corregido",
    not_fixed: "No corregido",
    not_verifiable: "No verificable",
    reopened: "Reabierto",
    wont_fix: "No se corregirá",
  },
  via: { member_of: "miembro de", admin_to: "administrador local en", session: "sesión de" },
  coverageStatus: { untested: "Sin probar", in_progress: "En curso", tested: "Probado", partial: "Probado en parte", vulnerable: "**Vulnerable**", "n/a": "No aplica" },
  draft: "BORRADOR",
  preparedBy: (c) => `Elaborado por ${c}`,
  confidential: "Confidencial",
  page: "Página",
  of: "de",
  contents: "Contenido",
  authors: "Equipo",
  confidentiality: "Documento confidencial. Contiene información sensible sobre la seguridad del cliente; su distribución está restringida a las personas autorizadas.",
  fileName: "informe",
  draftSuffix: "borrador",
};

const en: ReportText = {
  pending: "_Pending._",
  kind: { pentest: "Penetration test report", retest: "Retest report", continuous: "Monitoring report" },
  client: "Client",
  issued: "Issued",
  period: (from, to) => `**Period:** ${from} to ${to}`,
  draftBanner: "> **DRAFT**: includes findings that a reviewer has not approved yet.",
  executiveSummary: "Executive summary",
  scope: "Scope",
  included: "In scope",
  excluded: "Out of scope",
  ports: (p) => `ports ${p}`,
  noRules: "_(no rules)_",
  paths: "Attack paths",
  retest: "Retest results",
  retestSummary: (n) =>
    `Of ${n.total} verified findings: **${n.fixed} fixed**, ${n.partial} partially fixed, **${n.notFixed} not fixed**, ${n.notVerifiable} not verifiable and ${n.unverified} not verified yet.`,
  retestHead: "| Finding | Severity | Result |",
  retestNone: "_This retest has no findings carried over from the original project._",
  comparison: (n) =>
    `**Compared with the original:** ${n.resolved} resolved, ${n.persisting} still open, ${n.added} new; ${n.servicesAdded} new services and ${n.servicesRemoved} closed.`,
  findings: "Findings",
  findingsSummary: "Summary of findings",
  noFindings: "_No findings recorded._",
  noApprovedFindings: "_No approved findings. Drafts are reviewed before they are included._",
  severityHead: "| Severity | Count |",
  findingsHead: "| ID | Finding | Severity | CVSS | Status |",
  detailed: "Detailed findings",
  severity: "Severity",
  status: "Status",
  description: "Description",
  impact: "Impact",
  demonstrated: "Demonstrated impact",
  impactKeys: { reach: "Reach", exposed: "What the exposed data allows", chain: "Chaining" },
  affected: "Affected assets",
  evidence: "Evidence",
  evidenceMissing: "_(evidence content not available)_",
  remediation: "Recommendation",
  references: "References",
  surface: "Observed surface",
  surfaceLine: (c) =>
    `${c.host ?? 0} hosts · ${c.domain ?? 0} domains · ${c.service ?? 0} services · ${c.webapp ?? 0} web applications · ${c.endpoint ?? 0} endpoints · ${c.observation ?? 0} observations.`,
  appsHead: "| Application | Technologies |",
  coverage: "Test coverage (OWASP WSTG)",
  coverageHead: "| Category | Status | Note |",
  conclusion: "Conclusion",
  traces: "Traces left in the environment",
  tracesIntro: "Items the tests left in the client's systems and whether they were cleaned up.",
  tracesHead: "| What | Where | How to remove it | Status |",
  traceStatus: { pending: "pending cleanup", cleaned: "removed", accepted: "accepted by the client" },
  annex: "Appendix · Traceability",
  annexText: (runs) =>
    `Every finding, asset and piece of evidence in this report is recorded in Penteos with its provenance (tool, run and raw output). ${runs} tool runs were recorded. `,
  auditOk: (events) => `The audit chain (${events} events) was verified intact when this report was issued.`,
  auditBroken: (at) => `WARNING: the audit chain has been altered (event #${at}).`,
  deletedAsset: "(deleted asset)",
  severities: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" },
  statuses: {
    draft: "Draft",
    in_review: "In review",
    approved: "Approved",
    reported: "Reported",
    fixed: "Fixed",
    partially_fixed: "Partially fixed",
    not_fixed: "Not fixed",
    not_verifiable: "Not verifiable",
    reopened: "Reopened",
    wont_fix: "Won't fix",
  },
  via: { member_of: "member of", admin_to: "local admin on", session: "session on" },
  coverageStatus: { untested: "Not tested", in_progress: "In progress", tested: "Tested", partial: "Partly tested", vulnerable: "**Vulnerable**", "n/a": "Not applicable" },
  draft: "DRAFT",
  preparedBy: (c) => `Prepared by ${c}`,
  confidential: "Confidential",
  page: "Page",
  of: "of",
  contents: "Contents",
  authors: "Team",
  confidentiality: "Confidential document. It contains sensitive information about the client's security; distribution is restricted to authorized persons.",
  fileName: "report",
  draftSuffix: "draft",
};

export const REPORT_TEXT: Record<Language, ReportText> = { es, en };

/** The confidentiality notice: the organization's own, or the default in the report's language. */
export function confidentialityFor(custom: string, lang: Language): string {
  const isDefault = !custom.trim() || Object.values(REPORT_TEXT).some((t) => t.confidentiality === custom.trim());
  return isDefault ? REPORT_TEXT[lang].confidentiality : custom;
}
