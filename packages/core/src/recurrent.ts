import { type Actor, ulid } from "@penteos/schema";
import type { Engagement, Entity } from "./engagement.js";
import type { ToolRunner } from "./tools/runner.js";

/**
 * Recurrent mode: photos of what an engagement knows at a moment, and the
 * differences between two photos - of the same engagement over time, or of a retest against
 * the original. Everything is keyed by real-world identity (IP, port, FQDN, finding
 * fingerprint), never by ULIDs, so photos of different engagements compare.
 */

export interface SnapshotFinding {
  fingerprint: string;
  title: string;
  severity: string;
  status: string;
  assets: string[];
}

export interface Snapshot {
  id: string;
  engagementId: string;
  label: string;
  takenAt: string;
  hosts: Array<{ key: string; hostnames: string[] }>;
  services: Array<{ key: string; product?: string; version?: string }>;
  domains: string[];
  webapps: string[];
  findings: SnapshotFinding[];
}

export interface SnapshotSummary {
  id: string;
  label: string;
  takenAt: string;
  counts: { hosts: number; services: number; domains: number; webapps: number; findings: number };
}

/** Same weakness, whoever wrote it: the library template when there is one, else the normalized title. */
export function fingerprint(f: Entity): string {
  if (f.attributes.templateRef) return `tpl:${f.attributes.templateRef}`;
  return `title:${String(f.attributes.title).toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, " ").trim()}`;
}

function assetLabel(engagement: Engagement, id: string): string {
  const e = engagement.get(id);
  if (!e) return id;
  if (e.kind === "service") return `${e.naturalKey.split("|").slice(-3).join("|")}`;
  return e.naturalKey;
}

export function takeSnapshot(engagement: Engagement, label = ""): Snapshot {
  const all = (kind: Parameters<Engagement["query"]>[0]["kind"]) => engagement.query({ kind, limit: 1_000_000 });
  const findings = all("finding");
  return {
    id: ulid(),
    engagementId: engagement.info.id,
    label,
    takenAt: new Date().toISOString(),
    hosts: all("host").map((h) => ({ key: h.naturalKey, hostnames: (h.attributes.hostnames as string[] | undefined) ?? [] })),
    services: all("service")
      .filter((s) => s.attributes.state === "open")
      .map((s) => ({
        key: s.naturalKey,
        ...(s.attributes.product ? { product: String(s.attributes.product) } : {}),
        ...(s.attributes.version ? { version: String(s.attributes.version) } : {}),
      })),
    domains: all("domain").map((d) => d.naturalKey),
    webapps: all("webapp").map((w) => w.naturalKey),
    findings: findings.map((f) => ({
      fingerprint: fingerprint(f),
      title: String(f.attributes.title),
      severity: String(f.attributes.severity),
      status: String(f.attributes.status),
      assets: ((f.attributes.instances as Array<{ entity: { id: string } }> | undefined) ?? []).map((i) => assetLabel(engagement, i.entity.id)).sort(),
    })),
  };
}

export const summarize = (s: Snapshot): SnapshotSummary => ({
  id: s.id,
  label: s.label,
  takenAt: s.takenAt,
  counts: { hosts: s.hosts.length, services: s.services.length, domains: s.domains.length, webapps: s.webapps.length, findings: s.findings.length },
});

export function saveSnapshot(engagement: Engagement, snapshot: Snapshot, actor: Actor): SnapshotSummary {
  engagement.setMeta(`snapshot:${snapshot.id}`, snapshot, actor);
  const index = engagement.getMeta<SnapshotSummary[]>("snapshots") ?? [];
  const summary = summarize(snapshot);
  engagement.setMeta("snapshots", [...index, summary], actor);
  return summary;
}

export const listSnapshots = (engagement: Engagement): SnapshotSummary[] => engagement.getMeta<SnapshotSummary[]>("snapshots") ?? [];
export const getSnapshot = (engagement: Engagement, id: string): Snapshot | undefined => engagement.getMeta<Snapshot>(`snapshot:${id}`);

export interface SnapshotDiff {
  from: { label: string; takenAt: string; engagementId: string };
  to: { label: string; takenAt: string; engagementId: string };
  hosts: { added: string[]; removed: string[] };
  services: { added: string[]; removed: string[]; changed: Array<{ key: string; before: string; after: string }> };
  domains: { added: string[]; removed: string[] };
  webapps: { added: string[]; removed: string[] };
  findings: {
    /** Present now, not before. */
    new: SnapshotFinding[];
    /** Present before, gone now (or marked fixed). */
    resolved: SnapshotFinding[];
    /** Still there. */
    persisting: Array<SnapshotFinding & { severityBefore?: string }>;
  };
}

function setDiff(before: string[], after: string[]) {
  const b = new Set(before);
  const a = new Set(after);
  return { added: after.filter((x) => !b.has(x)), removed: before.filter((x) => !a.has(x)) };
}

const FIXED = new Set(["fixed", "wont_fix"]);
const describeService = (s: { product?: string; version?: string }) => [s.product, s.version].filter(Boolean).join(" ") || "-";

export function diffSnapshots(from: Snapshot, to: Snapshot): SnapshotDiff {
  const servicesBefore = new Map(from.services.map((s) => [s.key, s]));
  const changed: SnapshotDiff["services"]["changed"] = [];
  for (const s of to.services) {
    const prev = servicesBefore.get(s.key);
    if (prev && describeService(prev) !== describeService(s) && (prev.product || prev.version)) changed.push({ key: s.key, before: describeService(prev), after: describeService(s) });
  }
  const live = (fs: SnapshotFinding[]) => new Map(fs.filter((f) => !FIXED.has(f.status)).map((f) => [f.fingerprint, f]));
  const before = live(from.findings);
  const after = live(to.findings);
  return {
    from: { label: from.label, takenAt: from.takenAt, engagementId: from.engagementId },
    to: { label: to.label, takenAt: to.takenAt, engagementId: to.engagementId },
    hosts: setDiff(from.hosts.map((h) => h.key), to.hosts.map((h) => h.key)),
    services: { ...setDiff(from.services.map((s) => s.key), to.services.map((s) => s.key)), changed },
    domains: setDiff(from.domains, to.domains),
    webapps: setDiff(from.webapps, to.webapps),
    findings: {
      new: [...after.values()].filter((f) => !before.has(f.fingerprint)),
      resolved: [...before.values()].filter((f) => !after.has(f.fingerprint)),
      persisting: [...after.values()]
        .filter((f) => before.has(f.fingerprint))
        .map((f) => {
          const prev = before.get(f.fingerprint)!;
          return prev.severity !== f.severity ? { ...f, severityBefore: prev.severity } : f;
        }),
    },
  };
}

/** One line for notices and the activity feed. */
export function diffHeadline(d: SnapshotDiff): string {
  const parts = [
    d.hosts.added.length ? `${d.hosts.added.length} new hosts` : "",
    d.services.added.length ? `${d.services.added.length} new open services` : "",
    d.services.removed.length ? `${d.services.removed.length} closed services` : "",
    d.services.changed.length ? `${d.services.changed.length} services changed version` : "",
    d.domains.added.length ? `${d.domains.added.length} new domains` : "",
    d.findings.new.length ? `${d.findings.new.length} new findings` : "",
    d.findings.resolved.length ? `${d.findings.resolved.length} resolved findings` : "",
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : "no changes";
}

// ---------------------------------------------------------------------------------------------
// Scheduled scans

export interface Schedule {
  id: string;
  label: string;
  argv: string[];
  targets: string[];
  risk: "passive" | "active" | "intrusive";
  everyHours: number;
  /** Who set it up: the scan runs with their authority, inside the scope like any other run. */
  createdBy: Actor;
  createdAt: string;
  enabled: boolean;
  nextAt: string;
  last?: { at: string; runId?: string; status: string; headline?: string; snapshotId?: string };
}

export const listSchedules = (engagement: Engagement): Schedule[] => engagement.getMeta<Schedule[]>("schedules") ?? [];

export function saveSchedules(engagement: Engagement, schedules: Schedule[], actor: Actor): void {
  engagement.setMeta("schedules", schedules, actor);
}

const addHours = (iso: string, hours: number) => new Date(Date.parse(iso) + hours * 3_600_000).toISOString();

/**
 * Runs the schedules that are due. After each scan finishes, a photo is taken and compared with
 * the previous one; the headline lands in the schedule and in the audit log.
 */
export async function runDueSchedules(
  engagement: Engagement,
  runner: ToolRunner,
  options: { now?: Date; waitSeconds?: number; onDone?: (schedule: Schedule, diff: SnapshotDiff | undefined) => void } = {},
): Promise<Schedule[]> {
  const now = (options.now ?? new Date()).toISOString();
  if (engagement.info.stopWork?.active) return [];
  const due = listSchedules(engagement).filter((s) => s.enabled && s.nextAt <= now);
  const done: Schedule[] = [];
  for (const schedule of due) {
    const actor = schedule.createdBy;
    // Claim it first, so a slow scan is not started twice.
    const claim = (patch: Partial<Schedule>) =>
      saveSchedules(engagement, listSchedules(engagement).map((s) => (s.id === schedule.id ? { ...s, ...patch } : s)), actor);
    claim({ nextAt: addHours(now, schedule.everyHours) });
    const outcome = await runner.runExec({ argv: schedule.argv, targets: schedule.targets, risk: schedule.risk }, { actor, policy: { type: "human" }, origin: "runner" });
    if (outcome.status !== "started") {
      const status = outcome.status === "denied" ? `bloqueado: ${outcome.reason}` : outcome.status;
      claim({ last: { at: now, status } });
      done.push({ ...schedule, last: { at: now, status } });
      continue;
    }
    const run = await runner.waitForRun(outcome.run.id, options.waitSeconds ?? 6 * 3600);
    const previous = listSnapshots(engagement).at(-1);
    const snapshot = takeSnapshot(engagement, `programado: ${schedule.label}`);
    const summary = saveSnapshot(engagement, snapshot, actor);
    const before = previous ? getSnapshot(engagement, previous.id) : undefined;
    const diff = before ? diffSnapshots(before, snapshot) : undefined;
    const last = { at: now, runId: outcome.run.id, status: run?.status ?? "running", headline: diff ? diffHeadline(diff) : "primera foto", snapshotId: summary.id };
    claim({ last });
    engagement.audit(actor, "schedule.completed", { scheduleId: schedule.id }, last);
    engagement.emit({ type: "schedule.completed", id: schedule.id, label: schedule.label, headline: last.headline });
    done.push({ ...schedule, last });
    options.onDone?.({ ...schedule, last }, diff);
  }
  return done;
}

export { addHours };
