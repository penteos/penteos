import { z } from "zod";
import { join } from "node:path";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { installPackage } from "../../plugins/package.js";
import { pluginFiles } from "../../plugins/files.js";
import { PluginCatalog } from "../../plugins/catalog.js";
import { DRAFT_ID_RE, type PluginDrafts } from "../../plugins/drafts.js";
import { pluginGuide } from "../../plugins/guide.js";
import { testDraft } from "../../plugins/sandbox.js";
import type { PluginData } from "../../plugins/data.js";
import type { PluginHost } from "../../plugins/host.js";
import type { PluginRuntime } from "../../plugins/runtime.js";
import { PluginId, renderValue, SecretValue } from "@penteos/schema";
import { changedOutputs, deleteOutput, listOutputs, OutputError, outputDir, outputPath, readOutput } from "../../plugins/outputs.js";
import { defineOperation, executeOperation, OperationError, type OperationContext } from "../registry.js";

// ---------------------------------------------------------------------------------------------
// Plugins: what is installed, why something is off, and the switches.
// Only humans: a plugin is never approved, enabled or widened by an agent.
// ---------------------------------------------------------------------------------------------

const hostOf = (ctx: OperationContext): PluginHost => {
  if (!ctx.plugins) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not load plugins");
  return ctx.plugins;
};

const pluginId = z.string().min(1).max(120);

/** The host's own refusals (not valid, not installed, changed) as a conflict the operator can read. */
async function act<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (e) {
    throw new OperationError("CONFLICT", e instanceof Error ? e.message : String(e));
  }
}

defineOperation({
  name: "plugin.list",
  title: "Installed plugins",
  description: "Every plugin found, with its status (active, disabled, pending approval, invalid, incompatible, modified, slow, safe mode), why it is not running, its permissions and its recent failures.",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => {
    const host = hostOf(ctx);
    const isolation = (id: string) => ctx.pluginRuntime?.isolationOf(id);
    return { safeMode: host.safeMode, dir: host.pluginsDir, plugins: host.list().map((p) => (isolation(p.id) ? { ...p, isolation: isolation(p.id) } : p)) };
  },
});

defineOperation({
  name: "plugin.files",
  title: "A plugin's files",
  description: "The files of an installed plugin, with the text of each one (to review a code plugin before approving it).",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId }),
  handler: (input, ctx) => {
    const info = hostOf(ctx).get(input.id);
    if (!info) throw new OperationError("NOT_FOUND", `plugin not installed: ${input.id}`);
    return { id: input.id, files: pluginFiles(join(hostOf(ctx).pluginsDir, info.folder)) };
  },
});

defineOperation({
  name: "plugin.notices",
  title: "Plugin notices",
  description: "What the operator should know at start: plugins the host disabled on its own and why, and whether this start is in safe mode.",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => hostOf(ctx).notices(),
});

defineOperation({
  name: "plugin.dismiss_notices",
  title: "Dismiss plugin notices",
  description: "Marks the plugin notices as seen.",
  kind: "write",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => {
    hostOf(ctx).dismissNotices();
    return { dismissed: true };
  },
});

defineOperation({
  name: "plugin.approve",
  title: "Approve a plugin",
  description: "Approves a plugin as its files are now (they are hashed: a later change stops it until approved again) and activates it.",
  kind: "admin",
  actors: ["human"],
  input: z.object({
    id: pluginId,
    reviewedCode: z.boolean().default(false).describe("A code plugin: whoever approves says they reviewed its code"),
    trust: z.enum(["free", "isolated"]).optional().describe("A code plugin: free (a normal program, watched) or isolated"),
  }),
  handler: (input, ctx) => act(() => hostOf(ctx).approve(input.id, { reviewedCode: input.reviewedCode, ...(input.trust ? { trust: input.trust } : {}) })),
});

defineOperation({
  name: "plugin.set_trust",
  title: "Free or isolate a plugin",
  description: "A code plugin runs free (a normal program: network, files, processes; Penteos watches and warns) or isolated (no network of its own, only its folder). It starts again under the new one.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId, trust: z.enum(["free", "isolated"]) }),
  handler: (input, ctx) => act(() => hostOf(ctx).setTrust(input.id, input.trust)),
});

defineOperation({
  name: "plugin.enable",
  title: "Enable a plugin",
  description: "Turns an installed plugin back on; its failure history starts over.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId }),
  handler: (input, ctx) => act(() => hostOf(ctx).enable(input.id)),
});

defineOperation({
  name: "plugin.disable",
  title: "Disable a plugin",
  description: "Turns a plugin off. Its data and settings are kept.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId }),
  handler: (input, ctx) => act(() => hostOf(ctx).disable(input.id)),
});

defineOperation({
  name: "plugin.log",
  title: "Plugin log",
  description: "The last lines of a plugin's log: activations, failures and why it was disabled.",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId, lines: z.number().int().min(1).max(500).default(100) }),
  handler: (input, ctx) => ({ id: input.id, lines: hostOf(ctx).logOf(input.id, input.lines) }),
});

// ---------------------------------------------------------------------------------------------
// Data: what a plugin keeps, and taking it away. Uninstalling keeps the data; purging is a
// separate, explicit step.
// ---------------------------------------------------------------------------------------------

const dataOf = (ctx: OperationContext): PluginData => {
  if (!ctx.pluginData) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not load plugins");
  return ctx.pluginData;
};

defineOperation({
  name: "plugin.uninstall",
  title: "Uninstall a plugin",
  description: "Removes a plugin's package. Its data is kept: entities of its types stay in the graph (read only) and its databases stay on disk, so installing it again picks them up. purgeGlobal also deletes its global database.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId, purgeGlobal: z.boolean().default(false) }),
  handler: (input, ctx) =>
    act(async () => {
      const result = await hostOf(ctx).uninstall(input.id);
      dataOf(ctx).close(input.id);
      if (input.purgeGlobal) dataOf(ctx).purgeGlobal(input.id);
      return { id: input.id, ...result, purgedGlobal: input.purgeGlobal };
    }),
});

defineOperation({
  name: "plugin.storage",
  title: "Plugin data",
  description: "What a plugin keeps: size and rows of its databases against its quota and, for a project, the entities and annotations it left in the graph. With only engagementId: every plugin with data in that project, installed or not.",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId.optional(), engagementId: z.string().optional() }),
  handler: (input, ctx) => {
    const data = dataOf(ctx);
    const engagement = input.engagementId ? ctx.engagement(input.engagementId) : undefined;
    if (!input.id) {
      if (!engagement) throw new OperationError("VALIDATION_ERROR", "give a plugin id, an engagementId, or both");
      return { plugins: data.projectPlugins(engagement.dir).map((p) => ({ ...p, footprint: engagement.pluginFootprint(p.pluginId) })) };
    }
    return { id: input.id, ...data.stats(input.id, engagement) };
  },
});

defineOperation({
  name: "plugin.purge_project",
  title: "Delete a plugin's data from a project",
  description: "Deletes what a plugin keeps in one project: its database and, with graph, the entities of its types (and their relations) and its annotations. Cannot be undone.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId, engagementId: z.string(), graph: z.boolean().default(false) }),
  handler: (input, ctx) => {
    const engagement = ctx.engagement(input.engagementId);
    dataOf(ctx).purgeProject(input.id, engagement);
    const graph = input.graph ? engagement.purgePluginData(input.id, ctx.caller.actor) : { entities: 0, annotations: 0 };
    return { id: input.id, database: "deleted", ...graph };
  },
});

// ---------------------------------------------------------------------------------------------
// What running plugins offer, their settings, and where they run. Enabling a plugin in a
// project is the operator's consent for it to act there (and, with net:, to send data out).
// ---------------------------------------------------------------------------------------------

const runtimeOf = (ctx: OperationContext): PluginRuntime => {
  if (!ctx.pluginRuntime) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not run plugins");
  return ctx.pluginRuntime;
};

defineOperation({
  name: "plugin.catalog",
  title: "What plugins offer",
  description: "The running plugins with their operations (forms), menus, settings, providers and the hosts they send data to; with engagementId, which of them are enabled in that project.",
  kind: "read",
  actors: ["human"],
  input: z.object({ engagementId: z.string().optional() }),
  handler: (input, ctx) => {
    const plugins = runtimeOf(ctx).catalog();
    let enabled: string[] = [];
    if (input.engagementId) enabled = ctx.engagement(input.engagementId).info.plugins;
    return { plugins: plugins.map((p) => ({ ...p, enabled: enabled.includes(p.id) })) };
  },
});

defineOperation({
  name: "plugin.set_project",
  title: "Enable a plugin in a project",
  description: "Turns a plugin on or off in one project. Plugins run only in the projects where they are enabled; one that sends data to third parties takes this project's data to them.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId, engagementId: z.string(), enabled: z.boolean() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    if (input.enabled && hostOf(ctx).get(input.id)?.status !== "active") throw new OperationError("PLUGIN_UNAVAILABLE", `the plugin ${input.id} is not active`);
    const info = e.info;
    const plugins = input.enabled ? [...new Set([...info.plugins, input.id])] : info.plugins.filter((p) => p !== input.id);
    if (plugins.length !== info.plugins.length || plugins.some((p, i) => p !== info.plugins[i])) {
      e.setInfo({ ...info, plugins }, ctx.caller.actor, input.enabled ? "plugin.enable_project" : "plugin.disable_project");
      e.emit({ type: "engagement.updated" });
    }
    return { id: input.id, engagementId: input.engagementId, enabled: input.enabled, plugins };
  },
});

const settingsFields = (ctx: OperationContext, id: string) => {
  const manifest = hostOf(ctx).manifest(id);
  if (!manifest) throw new OperationError("NOT_FOUND", `plugin not installed: ${id}`);
  return manifest.contributes.settings ?? [];
};

defineOperation({
  name: "plugin.settings",
  title: "Plugin settings",
  description: "A plugin's settings: the fields it declares, their values, and which secrets are set (secret values are never returned).",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId }),
  handler: (input, ctx) => {
    if (!ctx.pluginSettings) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not run plugins");
    const fields = settingsFields(ctx, input.id);
    return { id: input.id, fields, ...ctx.pluginSettings.view(input.id, fields) };
  },
});

defineOperation({
  name: "plugin.set_settings",
  title: "Change plugin settings",
  description: "Sets some of a plugin's settings. A secret given as an empty text is cleared; one left out keeps its value.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId, values: z.record(z.string(), z.unknown()) }),
  handler: (input, ctx) => {
    if (!ctx.pluginSettings) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not run plugins");
    const fields = settingsFields(ctx, input.id);
    try {
      return { id: input.id, fields, ...ctx.pluginSettings.update(input.id, fields, input.values) };
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", e instanceof Error ? e.message : String(e));
    }
  },
});

defineOperation({
  name: "plugin.run",
  title: "Run a plugin operation from its form",
  description: "Runs one of a plugin's operations (same checks as calling it directly) and returns its result with its view's message already written.",
  kind: "write",
  actors: ["human"],
  input: z.object({ name: z.string().regex(/^plugin\./), input: z.record(z.string(), z.unknown()).default({}), engagementId: z.string().optional() }),
  handler: async (input, ctx) => {
    const runtime = runtimeOf(ctx);
    const op = runtime.catalog().flatMap((p) => p.operations).find((o) => o.name === input.name);
    if (!op) throw new OperationError("PLUGIN_UNAVAILABLE", `${input.name} is not available (its plugin is off or not installed)`);
    // The files it wrote in this run (through the core or, a free plugin, by itself) come with the result.
    const owner = input.name.split(".").slice(1, -1).join(".");
    const dir = outputDir(ctx.engagement(input.engagementId).dir, owner);
    const before = listOutputs(dir).files;
    const result = await executeOperation(input.name, { ...input.input, ...(input.engagementId ? { engagementId: input.engagementId } : {}) }, ctx);
    const files = changedOutputs(before, listOutputs(dir).files);
    let message: string | undefined;
    if (op.view?.type === "message") {
      try {
        message = String(renderValue(op.view.text, { result, input: input.input }) ?? "");
      } catch {
        /* a message that does not fit the result: the result is still shown */
      }
    }
    return { result, ...(message !== undefined ? { message } : {}), ...(files.length ? { plugin: owner, files } : {}) };
  },
});

defineOperation({
  name: "plugin.prefill",
  title: "Form values for a plugin menu",
  description: "The values a plugin menu puts in its form, taken from an entity (an entity menu) or from the project.",
  kind: "read",
  actors: ["human"],
  input: z.object({ plugin: pluginId, menu: z.string().max(40), entityId: z.string().optional(), engagementId: z.string().optional() }),
  handler: (input, ctx) => {
    const p = runtimeOf(ctx).catalog().find((x) => x.id === input.plugin);
    const menu = p?.menus.find((m) => m.id === input.menu);
    if (!p || !menu) throw new OperationError("PLUGIN_UNAVAILABLE", `${input.plugin} has no menu ${input.menu} running`);
    const e = ctx.engagement(input.engagementId);
    const entity = input.entityId ? e.get(input.entityId) : undefined;
    const info = e.info;
    const scope = {
      engagement: { id: info.id, name: info.name, clientName: info.clientName, mode: info.mode },
      ...(entity ? { entity: { id: entity.id, kind: entity.kind, naturalKey: entity.naturalKey, attributes: entity.attributes, ...(entity.ext ? { ext: entity.ext } : {}) } } : {}),
    };
    const values: Record<string, unknown> = {};
    for (const [field, tpl] of Object.entries(menu.prefill ?? {})) {
      try {
        const v = renderValue(tpl, scope);
        if (v !== undefined && v !== null && v !== "") values[field] = v;
      } catch {
        /* a value that cannot be taken from this entity: the operator fills it in */
      }
    }
    return { values };
  },
});

defineOperation({
  name: "plugin.rescan",
  title: "Look for new plugins",
  description: "Looks at the plugins folder again: new plugins show up waiting for approval, changed ones stop until approved again, removed ones stop. Running plugins that did not change are not touched.",
  kind: "admin",
  actors: ["human"],
  input: z.object({}),
  handler: async (_input, ctx) => {
    const host = hostOf(ctx);
    return { safeMode: host.safeMode, dir: host.pluginsDir, plugins: await host.rescan() };
  },
});

// ---------------------------------------------------------------------------------------------
// The plugins that ship with Penteos.
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "plugin.bundled",
  title: "Plugins that ship with Penteos",
  description: "The ready-made plugins: what each does, its permissions, where it sends data, and whether it is installed or has an update.",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => ({ plugins: new PluginCatalog(hostOf(ctx)).list() }),
});

defineOperation({
  name: "plugin.install",
  title: "Install a ready-made plugin",
  description: "Installs (or updates) a plugin that ships with Penteos and, with approve, approves it as installed. An update keeps its data and settings.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: pluginId, approve: z.boolean().default(true) }),
  handler: (input, ctx) => act(async () => ({ id: input.id, plugin: await new PluginCatalog(hostOf(ctx)).install(input.id, { approve: input.approve }) })),
});

// ---------------------------------------------------------------------------------------------
// The Maestro builds plugins. It writes drafts, tests them in a sandbox with recorded
// responses, and proposes them; only the operator's approval installs one (in this project).
// ---------------------------------------------------------------------------------------------

const draftsOf = (ctx: OperationContext): PluginDrafts => {
  if (!ctx.pluginDrafts) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not build plugins");
  return ctx.pluginDrafts;
};
const draftId = z.string().regex(DRAFT_ID_RE, "expected maestro.<name>");
function draftState(ctx: OperationContext, id: string, withTests: boolean): string | undefined {
  const drafts = ctx.pluginDrafts;
  if (!drafts) return undefined;
  try {
    const v = drafts.view(id);
    if (!v) return undefined;
    const given = ctx.pluginSettings ? ctx.pluginSettings.view(id, drafts.settingFields(id)).secretsSet.join(",") : "";
    return [v.hash, (v.meta.needs ?? []).length, given, ...(withTests ? [v.meta.lastTest?.at, v.meta.lastLive?.at] : [])].join("|");
  } catch {
    return undefined;
  }
}
const asValidation = <T>(work: () => T): T => {
  try {
    return work();
  } catch (e) {
    throw new OperationError("VALIDATION_ERROR", e instanceof Error ? e.message : String(e));
  }
};

defineOperation({
  name: "plugin.guide",
  title: "How to build a plugin",
  description: "The plugin language in one page (manifest, permissions, steps, templates, tests) with a complete example. Read it before writing a plugin draft.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({}),
  handler: () => ({ guide: pluginGuide() }),
});

defineOperation({
  name: "plugin.draft_write",
  title: "Write a plugin draft",
  description:
    "Creates or replaces a plugin draft from a full manifest (JSON object). It is not loaded or installed: it returns the validation (issues with their exact path, warnings, what it would be allowed to do). The id becomes maestro.<name>. A code plugin (level: code) also takes files: { \"main.mjs\": \"…\" } adds or replaces files, remove deletes some; send only the files that change.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ manifest: z.record(z.string(), z.unknown()), files: z.record(z.string(), z.string()).optional(), remove: z.array(z.string()).max(40).optional() }),
  handler: (input, ctx) => asValidation(() => draftsOf(ctx).write(input.manifest, ctx.caller.actor, input.files ?? {}, input.remove ?? [])),
});

defineOperation({
  name: "plugin.drafts",
  title: "Plugin drafts",
  description: "The plugin drafts with their validation, last test and whether they are installed.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({}),
  handler: (_input, ctx) => ({ drafts: draftsOf(ctx).list() }),
});

defineOperation({
  name: "plugin.draft_get",
  title: "Read a plugin draft",
  description: "One draft: its manifest as saved, its validation and its last test.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ id: draftId }),
  handler: (input, ctx) => {
    const drafts = draftsOf(ctx);
    const view = drafts.view(input.id);
    if (!view) throw new OperationError("NOT_FOUND", `no draft ${input.id}`);
    return { ...view, manifest: drafts.manifest(input.id), ...(view.level === "code" ? { code: drafts.files(input.id) } : {}) };
  },
});

defineOperation({
  name: "plugin.draft_from_installed",
  title: "Start a new version of a Maestro plugin",
  description: "Copies an installed plugin built by the Maestro (maestro.*) into a draft, to change it. Raise its version before proposing it.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ id: draftId }),
  handler: (input, ctx) => asValidation(() => draftsOf(ctx).fromInstalled(input.id, ctx.caller.actor)),
});

defineOperation({
  name: "plugin.draft_test",
  title: "Test a plugin draft",
  description: "Runs one operation of a draft in a throwaway sandbox: a lab project with the fixtures given and a fake internet that answers only with the recorded responses given (nothing leaves the machine). Returns the result or the error, each step with its output, the requests it made and what it wrote. A draft can be proposed only once its current version passed a test.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    id: draftId,
    operation: z.string().max(40),
    input: z.record(z.string(), z.unknown()).default({}),
    live: z.boolean().default(false).describe("Against the real services (only the hosts the plugin declares, through Penteos) with the operator's settings. Required before proposing a plugin that talks to the internet."),
    expect: z
      .object({
        fields: z.array(z.string().max(120)).max(20).optional(),
        contains: z.array(z.string().max(200)).max(20).optional(),
        absent: z.array(z.string().max(200)).max(20).optional(),
        fails: z.boolean().optional(),
      })
      .optional()
      .describe("The acceptance criteria: paths that must hold a value, texts it must (not) contain; fails: true for a failure-path test that must end with a clear message. The test passes only if they hold."),
    settings: z.record(z.string(), z.unknown()).optional(),
    responses: z
      .array(
        z.union([
          z.object({ fromProbe: z.string().min(10).max(40), url: z.string().max(2000).optional() }),
          z.object({ method: z.string().max(10).optional(), url: z.string().min(9).max(2000), status: z.number().int().min(100).max(599).optional(), body: z.unknown().optional(), headers: z.record(z.string(), z.string()).optional() }),
        ]),
      )
      .max(50)
      .default([]),
    fixtures: z
      .object({
        hosts: z.array(z.string()).max(50).optional(),
        domains: z.array(z.string()).max(50).optional(),
        webapps: z.array(z.string()).max(50).optional(),
        findings: z.array(z.object({ title: z.string().min(1), severity: z.enum(["critical", "high", "medium", "low", "info"]), description: z.string().optional() })).max(20).optional(),
      })
      .optional(),
  }),
  // Testing again after a fix is not a loop: the draft's content is part of what is repeated.
  // The draft's content and what the operator gave since are part of what is repeated.
  guardState: (input, ctx) => draftState(ctx, input.id, false),
  handler: async (input, ctx) => {
    const drafts = draftsOf(ctx);
    const hash = asValidation(() => drafts.hash(input.id));
    const { id, ...test } = input;
    // A recorded answer taken from a probe is exactly what the real service said.
    const responses = test.responses.map((r) => {
      if (!("fromProbe" in r)) return r;
      const p = drafts.prober.get(r.fromProbe);
      if (!p) throw new OperationError("NOT_FOUND", `no probe ${r.fromProbe} (probes are kept a while: probe again)`);
      return { method: p.method, url: r.url ?? p.url, status: p.status, body: p.body, fromProbe: r.fromProbe };
    });
    const fields = drafts.settingFields(id);
    const settings = test.live && ctx.pluginSettings ? Object.fromEntries(Object.entries(ctx.pluginSettings.scope(id, fields)).map(([k, v]) => [k, v instanceof SecretValue ? v.value : v])) : undefined;
    const report = await testDraft(drafts.manifest(id), { ...test, responses } as never, { ...(drafts.view(id)?.level === "code" ? { sourceDir: drafts.sourceDir(id) } : {}), ...(settings ? { settings } : {}), liveFetch: drafts.fetch });
    drafts.recordTest(id, hash, report, test.input);
    const view = drafts.view(id);
    const live = view?.meta.lastLive?.hash === view?.hash;
    return {
      ...report,
      canPropose: Boolean(view?.tested && (live || !view.summary.sendsTo.length)),
      ...(report.invented ? { warning: `${report.invented} recorded answer(s) were written by you, not taken from a probe: they prove nothing about the real service` } : {}),
      // What to ask oneself before going on (the way a careful engineer would).
      review: REVIEW,
    };
  },
});

defineOperation({
  name: "plugin.draft_propose",
  title: "Propose a plugin to the operator",
  description: "Asks the operator to approve a tested draft: they see what it does, its permissions and where it sends data. If approved, exactly this version is installed and enabled in this project only. Fails if the draft is invalid or its current version has not passed a test.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId: z.string().optional(),
    id: draftId,
    reason: z.string().min(1).max(1000),
    evidence: z.string().min(20).max(2000).describe("For the operator, in their language: what you checked and what the live test showed (the input you used, what came back), and any limit they should know (needs a key, rate limit, what it does not cover)."),
  }),
  // Testing again after a fix is not a loop: the draft's content is part of what is repeated.
  // A new test (live, or after the operator gave a key) is a new situation, not a repetition.
  guardState: (input, ctx) => draftState(ctx, input.id, true),
  handler: (input, ctx) => {
    const drafts = draftsOf(ctx);
    const proposal = { ...asValidation(() => drafts.proposal(input.id)), evidence: input.evidence };
    const approval = ctx.runner(input.engagementId).proposePlugin(proposal, input.reason, ctx.caller.actor);
    drafts.markProposed(input.id, proposal.hash, approval.id);
    return { status: "pending_approval", approvalId: approval.id, plugin: proposal.pluginId, version: proposal.version };
  },
});

defineOperation({
  name: "plugin.draft_delete",
  title: "Delete a plugin draft",
  description: "Deletes a draft (not an installed plugin).",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ id: draftId }),
  handler: (input, ctx) => {
    draftsOf(ctx).remove(input.id);
    return { deleted: input.id };
  },
});

// ---------------------------------------------------------------------------------------------
// Panels of code plugins (an isolated frame, opened with a short-lived ticket).
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "plugin.panel_open",
  title: "Open a plugin panel",
  description: "A short-lived address for one of a plugin's panels (an isolated frame with no network), for the interface to show.",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId, panel: z.string().max(40), entityId: z.string().optional(), engagementId: z.string().optional() }),
  handler: (input, ctx) => {
    if (!ctx.pluginPanels) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not show plugin panels");
    const host = hostOf(ctx);
    const info = host.get(input.id);
    const manifest = host.manifest(input.id);
    const panel = manifest?.contributes.panels?.find((p) => p.id === input.panel);
    if (!info || !manifest || !panel) throw new OperationError("NOT_FOUND", `${input.id} has no panel ${input.panel}`);
    const engagement = ctx.engagement(input.engagementId);
    const usable = runtimeOf(ctx).usableIn(input.id, engagement);
    if (!usable.ok) throw new OperationError("PLUGIN_UNAVAILABLE", usable.reason);
    const entity = input.entityId ? engagement.get(input.entityId) : undefined;
    const ticket = act(async () => ctx.pluginPanels!.issue(input.id, panel.id, join(host.pluginsDir, info.folder), panel.file, entity ? { entityId: entity.id, kind: entity.kind } : {}, info.trust !== "isolated"));
    return ticket.then((t) => ({ path: `/v0/plugin-panel/${t}`, height: panel.height, title: panel.title }));
  },
});

// ---------------------------------------------------------------------------------------------
// Installing a plugin from its file (.penteos-plugin).
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "plugin.install_file",
  title: "Install a plugin from its file",
  description: "Installs a .penteos-plugin file: checked (names, size, manifest) and unpacked into the plugins folder, where it waits for approval like any other. Replaces an earlier copy of the same plugin, which then needs approval again.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ filename: z.string().min(1).max(200), contentBase64: z.string().max(70_000_000) }),
  handler: (input, ctx) =>
    act(async () => {
      const host = hostOf(ctx);
      const bytes = new Uint8Array(Buffer.from(input.contentBase64, "base64"));
      const manifest = installPackage(bytes, host.pluginsDir);
      // A hand-copied folder of the same plugin goes: one package per plugin.
      const previous = host.get(manifest.id)?.folder;
      if (previous && previous !== manifest.id) rmSync(join(host.pluginsDir, previous), { recursive: true, force: true });
      await host.rescan();
      return { id: manifest.id, name: manifest.name, version: manifest.version, plugin: host.get(manifest.id) };
    }),
});

// ---------------------------------------------------------------------------------------------
// What a plugin did (destinations, programs, alerts), for its card.
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "plugin.activity",
  title: "What a plugin did",
  description: "A plugin's recent activity as Penteos saw it: hosts it reached (inside the scope, declared, or elsewhere), connections around the proxy, programs it started, and alerts.",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId }),
  handler: (input, ctx) => ({ id: input.id, activity: runtimeOf(ctx).activityOf(input.id) }),
});

// ---------------------------------------------------------------------------------------------
// Files plugins make for the operator: in the project's
// folder, under plugins/<id>/files/. Also for plugins no longer installed (their files stay).
// ---------------------------------------------------------------------------------------------

const outputs = (ctx: OperationContext, id: string, engagementId?: string) => {
  if (!PluginId.safeParse(id).success) throw new OperationError("VALIDATION_ERROR", `not a plugin id: ${id}`);
  return outputDir(ctx.engagement(engagementId).dir, id);
};
const fileOp = <T>(work: () => T): T => {
  try {
    return work();
  } catch (e) {
    if (e instanceof OutputError) throw new OperationError("NOT_FOUND", e.message);
    throw e;
  }
};

defineOperation({
  name: "plugin.outputs",
  title: "Files plugins made",
  description: "The files plugins saved in this project (reports, exports, images…), newest first: one plugin's, or every plugin's.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ id: pluginId.optional(), engagementId: z.string().optional() }),
  handler: (input, ctx) => {
    const root = join(ctx.engagement(input.engagementId).dir, "plugins");
    const ids = input.id ? [input.id] : existsSync(root) ? readdirSync(root).filter((d) => PluginId.safeParse(d).success).sort() : [];
    return {
      plugins: ids
        .map((id) => ({ id, ...listOutputs(outputs(ctx, id, input.engagementId)) }))
        .filter((p) => p.total > 0 || p.id === input.id),
      root,
    };
  },
});

defineOperation({
  name: "plugin.output_read",
  title: "Read a file a plugin made",
  description: "The bytes of one file a plugin saved in this project (base64), to download or preview it.",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId, name: z.string().min(1).max(200), engagementId: z.string().optional() }),
  handler: (input, ctx) =>
    fileOp(() => {
      const { bytes, file } = readOutput(outputs(ctx, input.id, input.engagementId), input.name);
      return { ...file, base64: bytes.toString("base64") };
    }),
});

defineOperation({
  name: "plugin.output_delete",
  title: "Delete a file a plugin made",
  description: "Deletes one file a plugin saved in this project.",
  kind: "write",
  actors: ["human"],
  input: z.object({ id: pluginId, name: z.string().min(1).max(200), engagementId: z.string().optional() }),
  handler: (input, ctx) =>
    fileOp(() => {
      const engagement = ctx.engagement(input.engagementId);
      deleteOutput(outputs(ctx, input.id, input.engagementId), input.name);
      engagement.audit(ctx.caller.actor, "plugin.file_deleted", { plugin: input.id, name: input.name }, {});
      return { deleted: input.name };
    }),
});

defineOperation({
  name: "plugin.output_path",
  title: "Where a plugin's files are",
  description: "The absolute path of a plugin's files folder in this project, or of one file in it (to open it or show it in the file manager).",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: pluginId, name: z.string().min(1).max(200).optional(), engagementId: z.string().optional() }),
  handler: (input, ctx) =>
    fileOp(() => {
      const dir = outputs(ctx, input.id, input.engagementId);
      if (!input.name) return { path: dir };
      return outputPath(dir, input.name);
    }),
});

// ---------------------------------------------------------------------------------------------
// How the Maestro builds a plugin the way a careful engineer would: look at the real service first,
// test against it, ask the operator for what only they can give.
// ---------------------------------------------------------------------------------------------

const REVIEW = [
  "Did the live test use the operator's own example, and does the result answer what they asked for (not just 'no error')?",
  "Did you try an edge case: a subdomain or odd input, something that does not exist, an empty answer?",
  "Is every error message true and useful (a missing key is not 'not found')?",
  "Does the service need a key or account, have a rate limit, redirect to another host? Is that handled or said?",
  "Will the result read well in its view (a card or table with the useful fields, not raw JSON)?",
  "Is there anything only the operator can decide or give? Ask them (task with question, or plugin_draft_request_setting for a key) instead of guessing.",
];

defineOperation({
  name: "plugin.probe",
  title: "Look at a real service",
  description:
    "One real request to a third-party service you are building a plugin for (an API, a public lookup), to see what it really answers: status, headers, body, redirects, whether it needs a key, rate limits. Do this BEFORE writing the plugin, and again when something fails. Never a project target (use the usual tools) nor a private network. With draft, {{settings.<name>}} in the url or headers is filled with the operator's value (never shown to you). Returns a probeId: use it as a recorded answer in plugin_draft_test ({ fromProbe }).",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({
    engagementId: z.string().optional(),
    url: z.string().min(8).max(4000),
    method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
    headers: z.record(z.string().regex(/^[A-Za-z0-9-]{1,64}$/), z.string().max(4000)).optional(),
    body: z.unknown().optional(),
    draft: draftId.optional(),
  }),
  handler: async (input, ctx) => {
    const drafts = draftsOf(ctx);
    const engagement = ctx.engagement(input.engagementId);
    let secrets: string[] = [];
    let fill = (t: string) => t;
    if (input.draft && ctx.pluginSettings) {
      const scope = ctx.pluginSettings.scope(input.draft, drafts.settingFields(input.draft));
      secrets = Object.values(scope).filter((v): v is SecretValue => v instanceof SecretValue).map((v) => v.value).filter((v) => v.length >= 4);
      fill = (t) =>
        t.replace(/\{\{\s*settings\.([a-zA-Z0-9_]+)\s*\}\}/g, (_m, name: string) => {
          const v = scope[name];
          if (v === undefined) throw new OperationError("VALIDATION_ERROR", `the operator has not given ${name} yet: ask with plugin_draft_request_setting`);
          return v instanceof SecretValue ? v.value : String(v);
        });
    }
    const redact = (t: string) => secrets.reduce((acc, sec) => acc.split(sec).join("[secret]").split(encodeURIComponent(sec)).join("[secret]"), t);
    try {
      const result = await drafts.prober.probe(
        { method: input.method, url: fill(input.url), ...(input.headers ? { headers: Object.fromEntries(Object.entries(input.headers).map(([k, v]) => [k, fill(v)])) } : {}), ...(input.body !== undefined ? { body: input.body } : {}) },
        { inScope: (host) => engagement.inScope(host), redact },
      );
      engagement.audit(ctx.caller.actor, "plugin.probe", { url: redact(result.url) }, { method: result.method, status: result.status, bytes: result.bytes });
      return { ...result, url: redact(result.url) };
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", `probe failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  },
});

defineOperation({
  name: "plugin.draft_request_setting",
  title: "Ask the operator for a plugin setting",
  description:
    "When a plugin you are building needs something only the operator can give - an API key, an account, a site - declare it as a setting of the draft (secret: true for a key) and ask for it here, saying why. The operator types it in a protected field; you never see a secret, and you hear when it is given. Never ask for keys in the chat or in a task answer.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId: z.string().optional(), id: draftId, setting: z.string().min(1).max(40), reason: z.string().min(5).max(500) }),
  handler: (input, ctx) => {
    const drafts = draftsOf(ctx);
    const f = asValidation(() => drafts.requestSetting(input.id, input.setting, input.reason));
    const name = drafts.view(input.id)?.name ?? input.id;
    ctx.engagement(input.engagementId).emit({ type: "plugin.setting_requested", draftId: input.id, name, setting: f.setting, label: f.label, secret: f.secret, reason: input.reason });
    return { status: "asked", setting: f.setting, note: "The operator sees the request in Plugins (and as a notice). Tell them in one line what you need and why; keep working on what does not depend on it. You will hear when they give it." };
  },
});

defineOperation({
  name: "plugin.draft_settings",
  title: "A draft's settings",
  description: "The settings a plugin draft declares, which ones are set (never a secret's value) and what the Maestro asked for.",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: draftId }),
  handler: (input, ctx) => {
    const drafts = draftsOf(ctx);
    const fields = drafts.settingFields(input.id);
    const view = ctx.pluginSettings ? ctx.pluginSettings.view(input.id, fields) : { values: {}, secretsSet: [] };
    return { id: input.id, fields, ...view, needs: drafts.view(input.id)?.meta.needs ?? [] };
  },
});

defineOperation({
  name: "plugin.draft_set_settings",
  title: "Give a draft's settings",
  description: "The operator gives what a plugin draft needs (a key, an account). Secrets are encrypted and never reach the Maestro; it hears that they were given.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId: z.string().optional(), id: draftId, values: z.record(z.string(), z.unknown()) }),
  handler: (input, ctx) => {
    const drafts = draftsOf(ctx);
    if (!ctx.pluginSettings) throw new OperationError("PLUGIN_UNAVAILABLE", "this core does not run plugins");
    const fields = drafts.settingFields(input.id);
    const view = asValidation(() => ctx.pluginSettings!.update(input.id, fields, input.values));
    const given = Object.entries(input.values).filter(([, v]) => v !== "" && v !== null).map(([k]) => k);
    drafts.settingGiven(input.id, given);
    const engagement = ctx.engagement(input.engagementId);
    engagement.audit(ctx.caller.actor, "plugin.draft_settings", { plugin: input.id }, { settings: given });
    if (given.length) engagement.emit({ type: "plugin.setting_given", draftId: input.id, name: drafts.view(input.id)?.name ?? input.id, settings: given });
    return { id: input.id, ...view };
  },
});
