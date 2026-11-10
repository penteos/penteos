import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import { RiskLevel } from "@penteos/schema";
import { z } from "zod";
import { manifestInvocation, parseWithManifest, validateManifest } from "../../tools/manifest.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { NMAP_PRESETS } from "../../tools/nmap.js";
import { ToolboxError } from "../../tools/toolbox.js";
import { canAskPassword, captureGrantable, captureState, forgetCaptureState, MAC_CAPTURE_NOTE, setcapCommand, which, withPassword } from "../../tools/system.js";
import { CAPABILITIES, CAPABILITY_IDS, type CapabilityId, gapLine, isCritical, listGaps, updateGap } from "../../tools/capabilities.js";
import { engagementId, outcome, settle, untrusted, wait } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// tools / runs
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "tool.list",
  title: "List tools",
  description:
    "Lists the tools Penteos knows (verified by their version output, so homonyms are detected): whether they are installed, whether their output is mapped into the graph (integrated), their risk and install recipe.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, refresh: z.boolean().default(false) }),
  handler: async (input, ctx) => ({
    tools: await (async () => {
      const runner = ctx.runner(input.engagementId);
      const tools = await runner.registry.status(input.refresh);
      // A tool that appeared on the system (installed by hand) takes up what was left for it.
      if (input.refresh) void runner.resumeGaps().catch(() => undefined);
      return tools;
    })(),
    presets: { nmap: NMAP_PRESETS },
    note: "Run known tools with tool_run (targets) or run_exec (explicit argv); integrated ones land in the graph automatically. A missing tool can be proposed for installation (tool_propose_install). An installed tool Penteos does not know can be taught with a manifest (tool_test_manifest, then tool_propose_manifest).",
  }),
});

defineOperation({
  name: "tool.manifest",
  title: "Tool manifest",
  description: "Returns the manifest of a known tool: how its targets are read, its risk, install recipe and output mapping. Useful as an example when writing a new one.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, tool: z.string() }),
  handler: (input, ctx) => {
    const manifest = ctx.runner(input.engagementId).registry.get(input.tool);
    if (!manifest) throw new OperationError("NOT_FOUND", `no manifest for ${input.tool}`);
    return manifest;
  },
});

defineOperation({
  name: "tool.test_manifest",
  title: "Test a manifest",
  description:
    "Dry run of a manifest: validates it and maps a sample of the tool's real output (e.g. from run_output) without touching the graph. Returns the items it would ingest and how many lines were skipped. Iterate until the mapping is right, then propose it.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, manifest: z.unknown(), sampleOutput: z.string().max(200_000) }),
  handler: (input) => {
    let manifest;
    try {
      manifest = validateManifest(input.manifest);
    } catch (error) {
      throw new OperationError("VALIDATION_ERROR", `invalid manifest: ${(error as Error).message}`);
    }
    if (!manifest.output) return { valid: true, note: "no output mapping: the tool will run with scope checks but its output stays raw" };
    const { batch, skipped } = parseWithManifest(manifest, input.sampleOutput, { rawIds: [] });
    return { valid: true, items: batch.items.length, skipped, preview: batch.items.slice(0, 25) };
  },
});

defineOperation({
  name: "tool.propose_manifest",
  title: "Propose a tool manifest",
  description:
    "Proposes a manifest so Penteos can use a tool safely and map its output into the graph. A human approves it. Test it first with tool_test_manifest on real output. Manifests are declarative data (templates and regexes), never code.",
  kind: "write",
  actors: ["agent"],
  input: z.object({ engagementId, manifest: z.unknown(), reason: z.string().min(1) }),
  handler: (input, ctx) => {
    try {
      const approval = ctx.runner(input.engagementId).proposeManifest(input.manifest, input.reason, ctx.caller.actor);
      return { status: "pending_approval", approvalId: approval.id, summary: approval.summary };
    } catch (error) {
      if (error instanceof OperationError) throw error;
      throw new OperationError("VALIDATION_ERROR", `invalid manifest: ${(error as Error).message}`);
    }
  },
});

defineOperation({
  name: "tool.propose_install",
  title: "Propose installing a tool",
  description:
    "Proposes installing a tool. When Penteos's verified catalog has it (tool_list shows `catalog`), it is downloaded, checked against a fixed SHA-256 and installed without root in Penteos's own tool box; otherwise its manifest's recipe is shown to the operator. A human approves (one proposal per tool: asking again returns the one waiting). Keep working on something else meanwhile; never retry the tool until it is installed.",
  kind: "write",
  actors: ["agent"],
  input: z.object({ engagementId, tool: z.string(), reason: z.string().min(1) }),
  handler: (input, ctx) => {
    const approval = ctx.runner(input.engagementId).proposeInstall(input.tool, input.reason, ctx.caller.actor);
    return { status: "pending_approval", approvalId: approval.id, summary: approval.summary };
  },
});

defineOperation({
  name: "tool.install",
  title: "Install a tool",
  description: "Installs a known tool with its manifest's recipe.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, tool: z.string() }),
  handler: (input, ctx) => outcome(ctx.runner(input.engagementId).install(input.tool, ctx.caller.actor)),
});

// Capabilities and gaps.

const capabilityId = z.enum(CAPABILITY_IDS as [CapabilityId, ...CapabilityId[]]);

defineOperation({
  name: "capability.run",
  title: "Do a capability",
  description:
    "Asks for a job, not a tool: dns_resolve, subdomains, http_probe, crawl, content_discovery, port_scan, vuln_templates, sqli, oob, internal_services. Penteos runs the best tool installed for it; if none is, its own method (quality 'degraded' when that is lesser), and if there is no way at all, nothing runs. Whatever could not be done fully is recorded by Penteos as a GAP and resumed by itself when the tool is installed (it proposes the install once). Never retry a gap or ask for the same tool again: keep working on something else. port_scan takes options.preset (quick, service-scan, full, scripts) when nmap is there.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, capability: capabilityId, targets: z.array(z.string().min(1)).min(1), options: z.record(z.string(), z.unknown()).optional(), wait }),
  handler: async (input, ctx) => {
    const runner = ctx.runner(input.engagementId);
    const caller = { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? ("agent_tool" as const) : ("runner" as const) };
    const r = await runner.runCapability({ capability: input.capability, targets: input.targets, ...(input.options ? { options: input.options } : {}) }, caller);
    const def = CAPABILITIES[input.capability];
    const base = input.wait && r.outcome.status === "started" ? await settle(ctx, input.engagementId, r.outcome.run.id, input.wait) : outcome(r.outcome, ctx);
    const how =
      r.quality === "full"
        ? r.provider.startsWith("penteos:")
          ? `Done with Penteos's own method (as good as a tool for this).`
          : `Done with ${r.provider}.`
        : r.quality === "degraded"
          ? `No tool for this is installed: done with Penteos's own method, which is lesser (${def.builtin!.lacks.en}). Recorded as gap ${r.gap?.id ?? ""}; it is redone with ${def.providers.join("/")} by itself once installed${r.install ? " (install card waiting for the operator)" : ""}. Use these results now; do not retry.`
          : "";
    return { capability: input.capability, provider: r.provider, quality: r.quality, ...(base as object), ...(how ? { how } : {}), ...(r.gap ? { gapId: r.gap.id } : {}), ...(r.install ? { installApprovalId: r.install.id } : {}) };
  },
});

defineOperation({
  name: "capability.list",
  title: "Capabilities",
  description: "What Penteos can do for each capability on this machine right now: the tool that would run (and whether it is installed), its own fallback and how it compares, and what the verified catalog can install without root.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: async (input, ctx) => {
    const runner = ctx.runner(input.engagementId);
    const status = await runner.registry.status();
    const box = runner.registry.toolbox;
    return {
      capabilities: CAPABILITY_IDS.map((id) => {
        const def = CAPABILITIES[id];
        const installed = def.providers.find((t) => status.find((s) => s.name === t)?.installed);
        const installable = def.providers.find((t) => box?.asset(t));
        // Only the system has it (netexec; nmap on ARM): its package, with the password window.
        const systemOnly = !installable && !installed ? def.providers.map((t) => status.find((s) => s.name === t)).find((s) => s?.install && s.install.method !== "catalog") : undefined;
        const nmapBin = installed === "nmap" ? (box?.binaryPath("nmap") ?? which("nmap")) : undefined;
        return {
          id,
          title: def.title,
          risk: def.risk,
          now: installed ? { provider: installed, quality: "full" } : def.builtin ? { provider: `penteos:${def.builtin.name}`, quality: def.builtin.quality } : { provider: "none", quality: "blocked" },
          providers: def.providers,
          ...(def.builtin ? { fallback: { name: def.builtin.name, quality: def.builtin.quality, lacks: def.builtin.lacks } } : {}),
          ...(installable && !installed ? { installable: { tool: installable, version: box!.entry(installable)!.version, size: box!.asset(installable)!.size } } : {}),
          ...(systemOnly ? { system: { tool: systemOnly.name, command: systemOnly.install!.command, password: canAskPassword() } } : {}),
          ...(nmapBin ? { capture: { state: captureState(nmapBin), password: canAskPassword(), grantable: captureGrantable() } } : {}),
        };
      }),
    };
  },
});

defineOperation({
  name: "gap.list",
  title: "Gaps",
  description: "What could not be done fully for lack of a tool (open), what was taken up again once it appeared (resolved) and what the operator chose to go on without (accepted). Open gaps resume by themselves: do not redo them by hand.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, status: z.enum(["open", "resolving", "resolved", "accepted", "all"]).default("all") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const lang = e.info.language ?? "en";
    return {
      gaps: listGaps(e)
        .filter((g) => input.status === "all" || g.status === input.status)
        .map((g) => ({ ...g, text: gapLine(g, lang), critical: isCritical(g) })),
    };
  },
});

defineOperation({
  name: "gap.accept",
  title: "Go on without it",
  description: "The operator decides to go on without what a gap left undone. It stays recorded with who and why, and the report lists it among the test's limitations.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string(), reason: z.string().min(1).max(500) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const g = listGaps(e).find((x) => x.id === input.id);
    if (!g) throw new OperationError("NOT_FOUND", `no gap ${input.id}`);
    if (g.status !== "open") throw new OperationError("VALIDATION_ERROR", `gap ${input.id} is ${g.status}, not open`);
    const accepted = updateGap(e, g.id, { status: "accepted", accepted: { by: ctx.caller.actor, reason: input.reason, at: new Date().toISOString() } });
    e.audit(ctx.caller.actor, "gap.accepted", { gap: g.id }, { capability: g.capability, reason: input.reason });
    return accepted;
  },
});

// The tool box: Penteos's own verified tools.

const requireBox = (ctx: OperationContext, engagementId: string | undefined) => {
  const box = ctx.runner(engagementId).registry.toolbox;
  if (!box) throw new OperationError("VALIDATION_ERROR", "this core has no tool box");
  return box;
};
const boxError = (e: unknown): never => {
  if (e instanceof ToolboxError) throw new OperationError("VALIDATION_ERROR", `${e.message}${e.hint ? ` - ${e.hint}` : ""}`);
  throw e;
};

defineOperation({
  name: "tool.toolbox",
  title: "Tool box",
  description: "Penteos's own tool box: what the verified catalog offers for this machine, what is installed (version, size, last used, previous version), the space it takes and its limit.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const box = requireBox(ctx, input.engagementId);
    const installed = new Map(box.installed().map((t) => [t.name, t]));
    return {
      dir: box.dir,
      usage: box.usage(),
      quota: box.quotaBytes,
      autoInstall: ctx.runner(input.engagementId).autoInstall(),
      tools: box.available().map(({ entry, asset }) => {
        const t = installed.get(entry.name);
        return {
          name: entry.name,
          version: entry.version,
          size: asset.size,
          license: entry.license,
          homepage: entry.homepage,
          ...(t ? { installed: { version: t.version, bytes: t.bytes, installedAt: t.installedAt, ...(t.lastUsedAt ? { lastUsedAt: t.lastUsedAt } : {}), ...(t.previous ? { previous: t.previous.version } : {}) }, update: t.version !== entry.version } : {}),
        };
      }),
    };
  },
});

defineOperation({
  name: "tool.set_auto_install",
  title: "Install tools without asking",
  description: "The project's permission to install tools from Penteos's verified catalog without asking (no root, checked against a fixed SHA-256), up to a size in MB. Off by default.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, enabled: z.boolean(), maxMB: z.number().int().min(10).max(5000).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const runner = ctx.runner(input.engagementId);
    const next = { ...runner.autoInstall(), enabled: input.enabled, ...(input.maxMB ? { maxMB: input.maxMB } : {}) };
    e.setMeta("toolbox.autoInstall", next, ctx.caller.actor);
    return next;
  },
});

defineOperation({
  name: "tool.diagnose",
  title: "Diagnose the tool box",
  description: "What could keep tools from installing here: a data folder that cannot run programs (noexec), little free space, no route to GitHub, nmap.org or PyPI, nothing to unpack nmap's package with, whether the desktop can ask for a password.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: async (input, ctx) => {
    const box = requireBox(ctx, input.engagementId);
    return { checks: [...(await box.diagnose()), { id: "password", ok: canAskPassword(), level: "info" as const }] };
  },
});

defineOperation({
  name: "tool.export_kit",
  title: "Export a tool kit",
  description: "Writes the verified catalog's tools for a platform (linux-x64 or linux-arm64) into one .penteos-tools file, to install them where there is no internet. Each is downloaded and checked here first.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, dest: z.string().min(1), platform: z.enum(["linux-x64", "linux-arm64"]).optional(), tools: z.array(z.string()).optional() }),
  handler: (input, ctx) => {
    const runner = ctx.runner(input.engagementId);
    const box = requireBox(ctx, input.engagementId);
    return outcome(
      runner.trackJob("penteos-toolbox", `exportar kit ${input.platform ?? ""} → ${input.dest}`.replace(/\s+/g, " "), ctx.caller.actor, async (say) => {
        const r = await box.exportKit(input.dest, { onProgress: say, ...(input.platform ? { platform: input.platform } : {}), ...(input.tools ? { names: input.tools } : {}) });
        return { kit: r };
      }),
    );
  },
});

defineOperation({
  name: "tool.import_kit",
  title: "Import a tool kit",
  description: "Installs the tools of a .penteos-tools kit without internet. Each file is checked against this Penteos's own verified catalog; whatever does not match is left out and said so.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, file: z.string().min(1) }),
  handler: (input, ctx) => {
    const runner = ctx.runner(input.engagementId);
    const box = requireBox(ctx, input.engagementId);
    return outcome(
      runner.trackJob("penteos-toolbox", `importar kit ${input.file}`, ctx.caller.actor, async (say) => {
        const r = await box.importKit(input.file, { onProgress: say });
        runner.registry.invalidate();
        for (const t of r.installed) ctx.engagement(input.engagementId).events.emit("change", { type: "tool.installed", tool: t.name, version: t.version });
        void runner.resumeGaps().catch(() => undefined);
        return { installed: r.installed.map((t) => `${t.name} ${t.version}`), skipped: r.skipped };
      }),
    );
  },
});

defineOperation({
  name: "tool.capture_status",
  title: "nmap's capture permission",
  description: "Whether nmap may send raw packets here (SYN scans, OS detection, UDP): as root, with the file capability, or neither (then it scans with connect, which needs no permission). Says how to give it.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const box = ctx.runner(input.engagementId).registry.toolbox;
    const nmap = box?.binaryPath("nmap") ?? which("nmap");
    if (!nmap) return { nmap: null, state: "none", note: "nmap is not installed" };
    if (!captureGrantable()) return { nmap, state: captureState(nmap), canAskPassword: false, note: MAC_CAPTURE_NOTE };
    return { nmap, state: captureState(nmap), canAskPassword: canAskPassword(), command: `sudo ${setcapCommand(nmap).join(" ")}` };
  },
});

defineOperation({
  name: "tool.grant_capture",
  title: "Give nmap the capture permission",
  description: "Gives nmap the packet capture permission once (setcap), through the desktop's password window, so SYN scans, OS detection and UDP work without running anything as root. Without a desktop it returns the command to run.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId }),
  handler: async (input, ctx) => {
    const box = ctx.runner(input.engagementId).registry.toolbox;
    const nmap = box?.binaryPath("nmap") ?? which("nmap");
    if (!nmap) throw new OperationError("NOT_FOUND", "nmap is not installed");
    if (!captureGrantable()) return { status: "unsupported", note: MAC_CAPTURE_NOTE };
    const argv = setcapCommand(nmap);
    if (!canAskPassword()) return { status: "manual", command: `sudo ${argv.join(" ")}` };
    const r = await withPassword(argv, 3 * 60_000);
    forgetCaptureState();
    if (!r.ok) return { status: r.dismissed ? "dismissed" : "failed", error: r.error, command: `sudo ${argv.join(" ")}` };
    const state = captureState(nmap);
    ctx.engagement(input.engagementId).audit(ctx.caller.actor, "tool.capture_granted", { tool: "nmap" }, { binary: argv[2], state });
    // Given but still without effect: the folder is mounted nosuid (file capabilities are ignored there).
    return state === "none" ? { status: "no_effect", note: "The permission was set but has no effect: the folder is mounted nosuid. Install nmap with the system instead." } : { status: "granted", state };
  },
});

defineOperation({
  name: "tool.remove",
  title: "Remove a tool",
  description: "Removes a tool Penteos installed in its tool box, with every version kept of it. Tools found on the system are never touched.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, tool: z.string() }),
  handler: (input, ctx) => {
    const box = requireBox(ctx, input.engagementId);
    const r = box.remove(input.tool);
    ctx.runner(input.engagementId).registry.invalidate();
    ctx.engagement(input.engagementId).audit(ctx.caller.actor, "tool.removed", { tool: input.tool }, r);
    return r;
  },
});

defineOperation({
  name: "tool.rollback",
  title: "Go back to the previous version",
  description: "Switches a tool in the tool box back to the version it had before its last install.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, tool: z.string() }),
  handler: (input, ctx) => {
    const box = requireBox(ctx, input.engagementId);
    let t;
    try {
      t = box.rollback(input.tool);
    } catch (e) {
      boxError(e);
    }
    ctx.runner(input.engagementId).registry.invalidate();
    ctx.engagement(input.engagementId).audit(ctx.caller.actor, "tool.rollback", { tool: input.tool }, { version: t!.version });
    return { tool: input.tool, version: t!.version };
  },
});

defineOperation({
  name: "tool.run",
  title: "Run a known tool",
  description:
    "Runs a tool Penteos knows against targets; integrated tools ingest their results into the graph. nmap takes a preset (quick, service-scan, full, scripts). Other tools (subfinder, dnsx, dig, httpx, nuclei, katana…) build their command from `targets`; `args` adds extra flags to it (or, without targets, is the whole command line). See tool_list.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    tool: z.string(),
    preset: z.string().optional(),
    targets: z.array(z.string()).optional(),
    args: z.array(z.string()).optional(),
    wait,
  }),
  handler: async (input, ctx) => {
    const runner = ctx.runner(input.engagementId);
    const caller = { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? ("agent_tool" as const) : ("runner" as const) };
    let result;
    if (input.tool === "nmap") {
      result = runner.runNmap(runner.nmapArgs(input), caller);
    } else {
      const manifest = runner.registry.get(input.tool);
      if (!manifest) throw new OperationError("NOT_FOUND", `unknown tool "${input.tool}"; see tool_list`);
      if (!input.args && !input.targets?.length) throw new OperationError("VALIDATION_ERROR", "pass targets (or explicit args)");
      // With targets, args are extra flags added to the manifest's invocation; without targets,
      // args are the whole command line.
      const argv = input.targets?.length && manifest.invoke ? [...manifestInvocation(manifest, input.targets), ...(input.args ?? [])] : (input.args ?? []);
      result = await runner.runExec({ argv: [manifest.name, ...argv], targets: input.targets ?? [], risk: manifest.risk }, caller);
    }
    if (input.wait && result.status === "started") return settle(ctx, input.engagementId, result.run.id, input.wait);
    return outcome(result);
  },
});

defineOperation({
  name: "run.exec",
  title: "Run any installed tool",
  description:
    "Runs any installed command (argv array, no shell). Declare every target the command will touch and its risk; the command is rejected if it contains undeclared targets. For HTTP requests to a target prefer http_send, web_probe_rate_limit, web_probe_endpoints or fuzz_start: their exchanges are kept as evidence.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, argv: z.array(z.string().min(1, "empty argument")).min(1), targets: z.array(z.string()), risk: RiskLevel, wait }),
  handler: async (input, ctx) => {
    const { wait: seconds, ...request } = input;
    const result = await ctx.runner(input.engagementId).runExec(request, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    if (seconds && result.status === "started") return settle(ctx, input.engagementId, result.run.id, seconds);
    return outcome(result);
  },
});

defineOperation({
  name: "run.list",
  title: "List runs",
  description: "Lists recent tool executions, including denied ones.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, limit: z.number().int().min(1).max(1000).default(100) }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).runs(input.limit),
});

defineOperation({
  name: "run.get",
  title: "Get run",
  description: "Status, targets, policy decision and ingest summary of a run.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, runId: z.string() }),
  handler: (input, ctx) => {
    const run = ctx.engagement(input.engagementId).getRun(input.runId);
    if (!run) throw new OperationError("NOT_FOUND", `run not found: ${input.runId}`);
    return run;
  },
});

defineOperation({
  name: "run.output",
  title: "Run output",
  description: "Output of a run (stdout and stderr), live while it is still running. Content comes from the target and is untrusted.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, runId: z.string(), offset: z.number().int().min(0).default(0), length: z.number().int().min(1).max(1_000_000).default(65_536) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const run = e.getRun(input.runId);
    if (!run) throw new OperationError("NOT_FOUND", `run not found: ${input.runId}`);
    if (run.status === "running") {
      const live = ctx.runner(input.engagementId).liveOutput(run.id) ?? "";
      return { runId: run.id, status: run.status, live: true, size: live.length, content: untrusted(ctx, live.slice(input.offset, input.offset + input.length)) };
    }
    const raw = run.rawIds.find((r) => r.startsWith("sha256:"));
    if (!raw) return { runId: run.id, status: run.status, content: "" };
    const data = e.readRaw(raw);
    return { runId: run.id, status: run.status, rawId: raw, size: data.length, content: untrusted(ctx, data.subarray(input.offset, input.offset + input.length).toString("utf8")) };
  },
});

defineOperation({
  name: "run.wait",
  title: "Wait for run",
  description: "Waits until a run finishes (or the timeout passes) and returns its status, ingest summary and output. Use instead of polling run_get.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, runId: z.string(), seconds: z.number().int().min(1).max(600).default(120) }),
  handler: (input, ctx) => settle(ctx, input.engagementId, input.runId, input.seconds),
});

defineOperation({
  name: "run.cancel",
  title: "Cancel run",
  description: "Cancels a running tool.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, runId: z.string() }),
  handler: (input, ctx) => ({ cancelled: ctx.runner(input.engagementId).cancel(input.runId) }),
});
