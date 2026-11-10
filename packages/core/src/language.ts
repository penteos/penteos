/**
 * Languages. Three on purpose: the operator's (interface and the
 * conversation with the Maestro), the project's (everything that ends up in the deliverable) and
 * English for the models' own instructions. Agents get explicit rules, never a guess.
 */

export type Language = "es" | "en";

export const LANGUAGE_NAMES: Record<Language, string> = { es: "Spanish", en: "English" };

/** The terms the interface uses, so agents and screens say the same thing. */
export const GLOSSARY: Array<[en: string, es: string]> = [
  ["scope", "alcance"],
  ["scope rule", "regla de alcance"],
  ["finding", "hallazgo"],
  ["observation", "observación"],
  ["evidence", "evidencia"],
  ["project", "proyecto"],
  ["deliverable / report", "entregable / informe"],
  ["executive summary", "resumen ejecutivo"],
  ["phase", "fase"],
  ["approval", "aprobación"],
  ["verifier", "verificador"],
  ["verdict: reproduced / not reproduced / inconclusive", "veredicto: reproducido / no reproducido / no concluyente"],
  ["board / task", "tablero / tarea"],
  ["coverage", "cobertura"],
  ["credential", "credencial"],
  ["run", "ejecución"],
  ["severity: critical / high / medium / low / informational", "severidad: crítica / alta / media / baja / informativa"],
  ["risk: passive / active / intrusive / exploitation", "riesgo: pasivo / activo / intrusivo / explotación"],
];

const STYLE: Record<Language, string> = {
  es: "neutral Spanish: no voseo and no regionalisms (write «puede», «revise», «se requiere», never «podés», «revisá», «vos»), serious and direct, no exclamation marks, no chatty or marketing phrasing, no emoji",
  en: "American English, serious and direct, no exclamation marks, no chatty or marketing phrasing, no emoji",
};

function glossaryFor(lang: Language): string {
  return GLOSSARY.map(([en, es]) => (lang === "es" ? `${en} → ${es}` : en)).join("; ");
}

/**
 * The language rules every agent gets. `operator` is who it talks to (null for agents that never
 * talk to anyone: the verifier); `project` is the deliverable's.
 */
export function languageRules(operator: Language | null, project: Language): string {
  const lines = [
    "Languages (follow exactly):",
    ...(operator
      ? [
          `- Talk to the operator in ${LANGUAGE_NAMES[operator]} (${STYLE[operator]}) by default, from your very first line: even a short "let me look at the brief" before a tool call is written in ${LANGUAGE_NAMES[operator]}.`,
          "- The conversation follows the operator: if their latest message is written in another language, answer in that language (Spanish always neutral, formal «usted»). Messages you send on your own (autopilot, news) use the language of the operator's latest message. This never changes the deliverable's language below.",
        ]
      : []),
    `- Write everything that ends up in the deliverable in ${LANGUAGE_NAMES[project]} (${STYLE[project]}): findings (title, description, impact, remediation), evidence captions, report sections, CVSS rationale, task titles and descriptions, questions to the operator, notes, memories, phase plans and summaries and verification verdicts.`,
    ...(operator && operator !== project ? [`- So the operator and the deliverable use different languages here: answer the operator in ${LANGUAGE_NAMES[operator]} even while you write findings in ${LANGUAGE_NAMES[project]}.`] : []),
    `- Use these terms: ${glossaryFor(project)}${operator && operator !== project ? `; with the operator: ${glossaryFor(operator)}` : ""}.`,
    "- Technical tokens stay as they are (HTTP, CVSS, OWASP, command names, paths, parameters).",
    "- Never write the long dash (U+2014) or the en dash (U+2013), in any language or text: use a comma, a colon, parentheses or a plain hyphen (-) instead.",
  ];
  return lines.join("\n");
}
