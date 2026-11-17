/**
 * How a finding was reached: the chain from the asset being discovered to the operator's approval,
 * rebuilt from what Penteos already keeps, so it works for every finding, old ones included:
 *
 *   discovered  the affected asset, first seen (by which tool or request)
 *   lead        the observations that pointed at it
 *   action      the agent actions on those assets and outputs, with the intent they stated
 *   proof       each piece of evidence: the output it quotes, and how that output was obtained
 *   finding     when the finding was written, and by whom
 *   verified    the independent verifier's verdict
 *   approved    the operator's approval
 *
 * Steps carry facts (times, commands, ids, the agent's own words), never prose written here: the
 * app and the report put them into the reader's language.
 */
import type { Actor } from "@penteos/schema";
import type { Engagement, Entity } from "./engagement.js";

export type LineageKind = "discovered" | "lead" | "action" | "proof" | "finding" | "verified" | "approved";

export interface LineageStep {
  at: string;
  kind: LineageKind;
  /** Who did it: a tool run, an agent, the verifier, a person. */
  by: "tool" | "agent" | "verifier" | "human";
  /** The thing itself: the asset, the observation, the caption, the verdict. */
  title: string;
  /** How: the command, the request, the operation. */
  how?: string;
  /** Why, in the agent's own words (the intent it gave with the action). */
  why?: string;
  /** Ids to open it in the app. */
  refs: string[];
  /** For a proof: how many quotes were checked in its output. */
  quotes?: number;
}

const VERIFIER_ID = "01JA0000000000000000VRFYR0";
const TARGET_OPS = /^(http\.send|run\.exec|tool\.run|capability\.run|fuzz\.start|web\.|ws\.|browser\.|graphql\.|dns\.|oob\.)/;
const MAX_STEPS = 16;

function who(actor: Actor | undefined): LineageStep["by"] {
  if (!actor) return "tool";
  if (actor.type === "agent") return actor.id === VERIFIER_ID ? "verifier" : "agent";
  return actor.type === "human" ? "human" : "tool";
}

function label(e: Entity): string {
  const a = e.attributes;
  const base = String(a.title ?? a.caption ?? a.origin ?? a.fqdn ?? a.ip ?? a.name ?? e.naturalKey ?? "").trim();
  return a.pathTemplate ? `${base} ${String(a.pathTemplate)}`.trim() : base;
}

const short = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

export function findingLineage(e: Engagement, findingId: string): LineageStep[] {
  const f = e.get(findingId);
  if (!f || f.kind !== "finding") throw new Error(`finding not found: ${findingId}`);
  const a = f.attributes;
  const steps: LineageStep[] = [];
  const runCommand = (runId: string | undefined) => (runId ? e.getRun(runId)?.command : undefined);

  // The affected assets: when each was first seen, and by what.
  const instances = (a.instances as Array<{ entity: { id: string }; observationIds?: string[] }> | undefined) ?? [];
  const assets = instances.map((i) => e.get(i.entity.id)).filter((x): x is Entity => Boolean(x));
  for (const asset of assets.slice(0, 3)) {
    const first = e.sightingsOf(asset.id)[0];
    const how = runCommand(first?.runId) ?? (first?.rawId ? e.rawInfo(first.rawId)?.originalName : undefined);
    steps.push({ at: first?.observedAt ?? asset.createdAt, kind: "discovered", by: first?.runId ? "tool" : who(first?.source ?? asset.createdBy), title: `${asset.kind} ${label(asset)}`, ...(how ? { how: short(how, 220) } : {}), refs: [asset.id, ...(first?.runId ? [first.runId] : [])] });
  }

  // The observations that pointed at it.
  const obsIds = new Set(instances.flatMap((i) => i.observationIds ?? []));
  for (const o of e.query({ kind: "observation", limit: 5000 })) if (o.attributes.findingId === findingId) obsIds.add(o.id);
  const observations = [...obsIds].map((id) => e.get(id)).filter((x): x is Entity => Boolean(x));
  for (const o of observations.slice(0, 4)) {
    const rule = o.attributes.sourceRule ? String(o.attributes.sourceRule) : undefined;
    steps.push({ at: o.createdAt, kind: "lead", by: who(o.createdBy), title: label(o), ...(rule ? { how: rule } : {}), refs: [o.id] });
  }

  // The evidence: what it quotes, and how its output was obtained.
  const evidence = ((a.evidenceIds as string[] | undefined) ?? []).map((id) => e.get(id)).filter((x): x is Entity => Boolean(x));
  const proofRefs: string[] = [];
  for (const ev of evidence) {
    const src = ev.attributes.source as { rawId?: string } | undefined;
    const raw = src?.rawId ? e.rawInfo(src.rawId) : undefined;
    const how = runCommand(raw?.runId) ?? raw?.originalName;
    proofRefs.push(...[src?.rawId, raw?.runId].filter((x): x is string => Boolean(x)));
    // Why that output was asked for: the action that produced it.
    const making = src?.rawId ? e.stepsTouching([src.rawId, ...(raw?.runId ? [raw.runId] : [])], 20).find((s) => TARGET_OPS.test(s.op) && s.intent) : undefined;
    const quotes = ((ev.attributes.quotes as string[] | undefined) ?? []).length;
    steps.push({
      at: ev.createdAt,
      kind: "proof",
      by: who(ev.createdBy),
      title: String(ev.attributes.caption ?? ""),
      ...(how ? { how: short(how, 220) } : {}),
      ...(making?.intent ? { why: making.intent } : {}),
      refs: [ev.id, ...(src?.rawId ? [src.rawId] : [])],
      ...(quotes ? { quotes } : {}),
    });
  }

  // The agent's actions on those assets and outputs, with the intent it gave (before the finding).
  const touched = e.stepsTouching([...assets.map((x) => x.id), ...observations.map((o) => o.id), ...proofRefs], 300);
  const actions = touched.filter((s) => TARGET_OPS.test(s.op) && s.at <= f.createdAt && s.actor.id !== VERIFIER_ID);
  // The ones that said why come first; at most six, the latest.
  for (const s of [...actions.filter((x) => x.intent), ...actions.filter((x) => !x.intent)].slice(-6).sort((x, y) => x.at.localeCompare(y.at))) {
    steps.push({ at: s.at, kind: "action", by: who(s.actor), title: s.op, ...(s.intent ? { why: s.intent } : {}), refs: s.refs.slice(0, 6) });
  }

  // The finding itself, with why it was written (the promote or create call).
  const written = e.stepsTouching([findingId], 50).find((s) => /^(finding\.create|observation\.promote|finding\.from_template)$/.test(s.op));
  steps.push({ at: f.createdAt, kind: "finding", by: who(f.createdBy), title: `${String(a.severity ?? "")} · ${String(a.title ?? "")}`.trim(), ...(written?.intent ? { why: written.intent } : {}), refs: [findingId] });

  const v = a.verification as { verdict?: string; summary?: string; at?: string; by?: Actor; evidenceIds?: string[] } | undefined;
  if (v?.verdict && v.at) steps.push({ at: v.at, kind: "verified", by: "verifier", title: v.verdict, ...(v.summary ? { how: short(v.summary, 300) } : {}), refs: v.evidenceIds ?? [] });

  if (["approved", "reported"].includes(String(a.status)) && a.reviewer) steps.push({ at: f.updatedAt, kind: "approved", by: "human", title: String((a.reviewer as Actor & { name?: string }).name ?? ""), refs: [] });

  // Oldest first; a duplicate (the same thing at the same moment) once.
  const seen = new Set<string>();
  const ordered = steps
    .sort((x, y) => x.at.localeCompare(y.at))
    .filter((s) => {
      const key = `${s.kind}|${s.title}|${s.at}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  if (ordered.length <= MAX_STEPS) return ordered;
  // Too long: keep the ends of the story (discovery, proof, verdict) and thin out the middle actions.
  const keep = ordered.filter((s) => s.kind !== "action");
  const room = Math.max(0, MAX_STEPS - keep.length);
  const actionsKept = new Set(ordered.filter((s) => s.kind === "action").slice(-room));
  return ordered.filter((s) => s.kind !== "action" || actionsKept.has(s));
}
