import type { RunOutcome } from "../../tools/runner.js";
import { defineOperation, OperationError } from "../registry.js";
import { RiskLevel } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { BUILTIN } from "../../fuzz.js";
import { engagementId, outcome } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Fuzzer (Intruder-style)

const PayloadSourceInput = z.discriminatedUnion("type", [
  z.object({ type: z.literal("list"), items: z.array(z.string()).max(200_000) }),
  z.object({ type: z.literal("numbers"), from: z.number().int(), to: z.number().int(), step: z.number().int().optional(), pad: z.number().int().min(0).max(20).optional() }),
  z.object({ type: z.literal("file"), path: z.string().min(1) }),
  z.object({ type: z.literal("builtin"), name: z.enum(Object.keys(BUILTIN) as [keyof typeof BUILTIN, ...Array<keyof typeof BUILTIN>]) }),
]);

defineOperation({
  name: "fuzz.start",
  title: "Start a fuzzing attack",
  description:
    "Sends many variants of a raw HTTP request (like Burp Intruder). Mark positions in the template with § (e.g. 'GET /item?id=§1§ HTTP/1.1'). attack: sniper (one list, each position in turn), battering_ram (same payload everywhere), pitchfork (lists in parallel), cluster_bomb (every combination). The first request is the baseline with the original values; results that differ (status, size, time, grep matches) are flagged as anomalies. Runs in the background: follow it with fuzz_results. Prefer small, targeted lists.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    origin: z.string().describe("http(s)://host:port"),
    template: z.string().min(1),
    attack: z.enum(["sniper", "battering_ram", "pitchfork", "cluster_bomb"]).default("sniper"),
    sets: z.array(PayloadSourceInput).min(1).max(20),
    processing: z.array(z.object({ prefix: z.string().optional(), suffix: z.string().optional(), encode: z.enum(["none", "url", "url_all", "base64", "hex", "html"]).optional() })).optional(),
    grep: z.array(z.string()).max(50).optional(),
    extract: z.string().max(500).optional(),
    concurrency: z.number().int().min(1).max(20).default(5),
    delayMs: z.number().int().min(0).max(60_000).default(0),
    maxRequests: z.number().int().min(1).max(100_000).default(10_000),
    risk: RiskLevel.default("intrusive"),
  }),
  handler: (input, ctx) => {
    const { engagementId: id, ...rest } = input;
    let result: RunOutcome;
    try {
      result = ctx.runner(id).runFuzz(rest as never, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "fuzz.results",
  title: "Fuzzing results",
  description:
    "Results of a fuzzing run: payloads, status, length, words, time, grep matches, extracted values and why each one is an anomaly. onlyAnomalies=true gives what is worth a look. Also returns progress.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    runId: z.string(),
    onlyAnomalies: z.boolean().default(false),
    sort: z.enum(["index", "status", "length", "time"]).default("index"),
    limit: z.number().int().min(1).max(5000).default(200),
    offset: z.number().int().min(0).default(0),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const run = e.getRun(input.runId);
    if (!run || run.tool !== "fuzz") throw new OperationError("NOT_FOUND", `fuzzing run ${input.runId} not found`);
    const page = e.queryFuzz(input.runId, { onlyAnomalies: input.onlyAnomalies, sort: input.sort, limit: input.limit, offset: input.offset });
    const done = input.onlyAnomalies ? e.queryFuzz(input.runId, { limit: 1 }).total : page.total;
    const summary = (run.summary as { fuzz?: { total: number } } | undefined)?.fuzz;
    return { status: run.status, command: run.command, done, total: summary?.total ?? null, anomalies: page.anomalies, matching: page.total, rows: page.rows };
  },
});
