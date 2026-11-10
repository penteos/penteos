import { defineOperation } from "../registry.js";
import { z } from "zod";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// The operator log: every execution, in order
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "log.timeline",
  title: "Operator log",
  description:
    "Chronological log of every execution (who, from where, against what, ATT&CK technique, result), including denied ones: the record to share with the client or to deconflict with their security team. format=csv returns it ready to share.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, limit: z.number().int().min(1).max(100_000).default(5000), format: z.enum(["json", "csv"]).default("json") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const names = new Map(ctx.workspace.operators().map((o) => [o.id, o.name]));
    const who = (a: { type: string; id: string }) =>
      a.type === "human" ? (names.get(a.id) ?? "local operator") : a.type === "agent" ? (a.id.endsWith("MSTR") ? "Maestro" : "external agent") : a.id;
    const rows = e
      .runs(input.limit)
      .reverse()
      .map((r) => ({
        startedAt: r.startedAt,
        endedAt: r.endedAt ?? "",
        operator: who(r.actor),
        actorType: r.actor.type,
        origin: r.origin,
        runner: r.runner,
        tool: r.tool ?? "",
        command: r.command ?? "",
        targets: r.targets.join(" "),
        attack: (r.attack ?? []).join(" "),
        status: r.status,
        policy: r.policy.result,
        reason: r.policy.reason ?? "",
      }));
    if (input.format === "json") return rows;
    const cols = Object.keys(rows[0] ?? { startedAt: "" }) as Array<keyof (typeof rows)[number]>;
    const cell = (v: string) => (/[",\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v);
    return { csv: [cols.join(","), ...rows.map((r) => cols.map((c) => cell(String(r[c] ?? ""))).join(","))].join("\n") };
  },
});
