import { defineOperation, OperationError } from "../registry.js";
import { ulid } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { addHours, diffSnapshots, getSnapshot, listSchedules, listSnapshots, saveSchedules, saveSnapshot, type Schedule, type Snapshot, takeSnapshot } from "../../recurrent.js";
import { join } from "node:path";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Recurrent mode: photos, differences, retest, scheduled scans

defineOperation({
  name: "snapshot.create",
  title: "Take a photo",
  description: "Saves a photo of what the engagement knows now (hosts, open services, domains, web apps, findings) to compare later.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, label: z.string().default("") }),
  handler: (input, ctx) => saveSnapshot(ctx.engagement(input.engagementId), takeSnapshot(ctx.engagement(input.engagementId), input.label), ctx.caller.actor),
});

defineOperation({
  name: "snapshot.list",
  title: "List photos",
  description: "Lists the saved photos of the engagement, oldest first, and the retest baseline if there is one.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    return { snapshots: listSnapshots(e), baseline: e.getMeta<string>("baseline") ?? null, previousEngagementId: e.info.previousEngagementId ?? null };
  },
});

defineOperation({
  name: "snapshot.diff",
  title: "What changed",
  description:
    "Compares two photos: new and closed services, version changes, new domains, and findings that are new, resolved or persisting. 'from' defaults to the retest baseline or the latest photo; 'to' defaults to the current state. 'fromEngagementId' compares against a photo of another engagement (e.g. last year's).",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, from: z.string().optional(), to: z.string().optional(), fromEngagementId: z.string().optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const source = input.fromEngagementId ? ctx.engagement(input.fromEngagementId) : e;
    const fromId = input.from ?? (input.fromEngagementId ? undefined : e.getMeta<string>("baseline")) ?? listSnapshots(source).at(-1)?.id;
    let from: Snapshot | undefined = fromId ? getSnapshot(source, fromId) : undefined;
    // Another engagement without photos: compare with what it knows now.
    if (!from && input.fromEngagementId && !input.from) from = takeSnapshot(source, "estado actual");
    if (!from) throw new OperationError("VALIDATION_ERROR", "there is no photo to compare with yet: take one with snapshot.create");
    const to = input.to ? getSnapshot(e, input.to) : takeSnapshot(e, "ahora");
    if (!to) throw new OperationError("NOT_FOUND", `photo ${input.to} not found`);
    return diffSnapshots(from, to);
  },
});

defineOperation({
  name: "engagement.retest",
  title: "Start a retest",
  description:
    "Creates a retest engagement from a previous one: same client and scope, and every reported finding copied to be verified again. The original becomes the baseline to compare with.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ sourceEngagementId: z.string(), name: z.string().optional() }),
  handler: (input, ctx) => {
    const source = ctx.engagement(input.sourceEngagementId);
    const info = source.info;
    const actor = ctx.caller.actor;
    const target = ctx.workspace.create({ clientName: info.clientName, name: input.name ?? `Retest · ${info.name}`, mode: info.mode, roundMode: "retest", maxRisk: info.maxRisk, language: info.language ?? "en" }, actor);
    target.setInfo({ ...target.info, previousEngagementId: info.id }, actor, "engagement.retest");
    for (const { id: _id, ...rule } of source.scopeRules()) target.addScopeRule(rule, actor);
    const delivered = (status: unknown) => !["draft", "wont_fix"].includes(String(status));
    const photo = takeSnapshot(source, `original: ${info.name}`);
    // The baseline is what was delivered, not drafts nobody reported.
    const baseline = { ...photo, findings: photo.findings.filter((f) => delivered(f.status)) };
    saveSnapshot(target, baseline, actor);
    target.setMeta("baseline", baseline.id, actor);
    let copied = 0;
    for (const f of source.query({ kind: "finding", limit: 100_000 })) {
      if (!delivered(f.attributes.status)) continue;
      const assets = baseline.findings.find((b) => b.title === f.attributes.title)?.assets ?? [];
      const { instances: _i, reviewer: _r, status: _s, ...rest } = f.attributes;
      target.createEntity(
        "finding",
        {
          ...rest,
          status: "reported",
          description: `${String(f.attributes.description ?? "")}${assets.length ? `\n\n**Activos afectados en el engagement original:** ${assets.map((a) => `\`${a}\``).join(", ")}` : ""}`,
        },
        actor,
      );
      copied++;
    }
    const created = target.query({ kind: "finding", limit: 100_000 });
    for (const f of created) target.tag(f.id, ["retest"], [], actor);
    return { ...target.info, findingsToVerify: copied };
  },
});

const scheduleInput = {
  label: z.string().min(1),
  argv: z.array(z.string()).min(1),
  targets: z.array(z.string()),
  risk: z.enum(["passive", "active", "intrusive"]),
  everyHours: z.number().min(1).max(24 * 90),
};

defineOperation({
  name: "schedule.create",
  title: "Schedule a scan",
  description:
    "Repeats a command every N hours inside the scope (with the authority of who scheduled it). After each run a photo is taken and compared with the previous one.",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, ...scheduleInput, startNow: z.boolean().default(false) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const now = new Date().toISOString();
    const schedule: Schedule = {
      id: ulid(),
      label: input.label,
      argv: input.argv,
      targets: input.targets,
      risk: input.risk,
      everyHours: input.everyHours,
      createdBy: ctx.caller.actor,
      createdAt: now,
      enabled: true,
      nextAt: input.startNow ? now : addHours(now, input.everyHours),
    };
    saveSchedules(e, [...listSchedules(e), schedule], ctx.caller.actor);
    return schedule;
  },
});

defineOperation({
  name: "schedule.list",
  title: "List scheduled scans",
  description: "Lists the scheduled scans, when they run next and what the last run changed.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => listSchedules(ctx.engagement(input.engagementId)),
});

defineOperation({
  name: "schedule.update",
  title: "Change a scheduled scan",
  description: "Pauses, resumes, deletes or runs a scheduled scan right away.",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string(), enabled: z.boolean().optional(), runNow: z.boolean().optional(), delete: z.boolean().optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const list = listSchedules(e);
    if (!list.some((s) => s.id === input.id)) throw new OperationError("NOT_FOUND", `schedule ${input.id} not found`);
    const next = input.delete
      ? list.filter((s) => s.id !== input.id)
      : list.map((s) =>
          s.id === input.id
            ? { ...s, ...(input.enabled !== undefined ? { enabled: input.enabled } : {}), ...(input.runNow ? { nextAt: new Date().toISOString(), enabled: true } : {}) }
            : s,
        );
    saveSchedules(e, next, ctx.caller.actor);
    return next.find((s) => s.id === input.id) ?? { deleted: input.id };
  },
});
