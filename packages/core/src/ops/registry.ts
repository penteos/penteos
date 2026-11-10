import type { Actor, RiskLevel } from "@penteos/schema";
import { z } from "zod";
import type { Engagement } from "../engagement.js";
import type { ActorPolicy } from "../scope/evaluate.js";
import type { FindingLibrary } from "../library.js";
import type { PluginHost } from "../plugins/host.js";
import type { PluginData } from "../plugins/data.js";
import type { PluginRuntime } from "../plugins/runtime.js";
import type { PluginSettings } from "../plugins/settings.js";
import type { PluginDrafts } from "../plugins/drafts.js";
import type { PanelTickets } from "../plugins/panels.js";
import type { ToolRunner } from "../tools/runner.js";
import type { Workspace } from "../workspace.js";
import { guardCall, repeatNote } from "./guard.js";
import { describeIssues, normalizeKeys, repairInput } from "./repair.js";
import { recordCall } from "../metrics.js";
import { restoreDeep } from "../privacy/vault.js";

/**
 * The operation catalog. One definition per operation; the API, the
 * CLI, MCP tools and the command palette are all generated from it, so humans and agents always
 * go through the same validation, permissions and audit.
 */

export type OperationKind = "read" | "write" | "target" | "admin";

export type ErrorCode =
  | "VALIDATION_ERROR"
  | "PHASE"
  | "UNKNOWN_SECRET"
  | "SUBDOMAINS_EXCLUDED"
  | "PERMISSION_DENIED"
  | "OUT_OF_SCOPE"
  | "RISK_EXCEEDED"
  | "STOP_WORK_ACTIVE"
  | "OUTSIDE_WINDOW"
  | "UNCHECKED_TARGETS"
  | "UNDECLARED_TARGETS"
  | "INVALID_TARGET"
  | "NOT_FOUND"
  | "CONFLICT"
  | "TOOL_NOT_INSTALLED"
  | "HOST_BUSY"
  | "REPEATED"
  | "UNKNOWN_OPERATION"
  | "PLUGIN_UNAVAILABLE"
  /** A third-party service is limiting requests: wait. */
  | "RATE_LIMITED"
  /** A third-party service failed or is not reachable. */
  | "UPSTREAM_ERROR"
  | "INTERNAL";

export class OperationError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "OperationError";
  }
}

/** Team roles, from least to most privileged. */
export const ROLES = ["observer", "reviewer", "operator", "lead"] as const;
export type Role = (typeof ROLES)[number];

export interface Caller {
  actor: Actor;
  policy: ActorPolicy;
  /** For human operators in team mode. Absent means the local owner (solo mode): lead. */
  role?: Role;
  name?: string;
}

/** Admin operations that an operator (not only the lead) may perform. */
const OPERATOR_ADMIN = new Set(["approval.approve", "approval.reject", "engagement.stop_work", "tool.install", "agents.pause", "agents.resume"]);

/** The minimum role an operation needs. */
/** Operations about one's own preferences: anyone connected may call them. */
const PERSONAL = new Set(["operator.set_language"]);

export function requiredRole(op: { name: string; kind: OperationKind }): Role {
  if (op.kind === "read" || PERSONAL.has(op.name)) return "observer";
  if (op.kind === "write") return "reviewer";
  if (op.kind === "target") return "operator";
  return OPERATOR_ADMIN.has(op.name) ? "operator" : "lead";
}

/** The intercepting proxy as operations see it (only where the core runs one). */
export interface ProxyControl {
  status(): { running: boolean; host: string; port: number; requestedPort?: number; token: string; caFingerprint: string; upstream?: string };
  ca(): { pem: string; derBase64: string; fingerprint: string };
  setUpstream(url: string | undefined): void;
  interceptor: import("../proxy/intercept.js").Interceptor;
  /** Lets one out-of-scope host through the operator's browser for a while, without a scope rule. */
  letThrough(engagementId: string, host: string, minutes?: number): { host: string; until: string };
}

/** Starts an independent verification of a finding. */
export interface VerifierControl {
  /** auto: asked because the finding went to review (stay quiet if no verifier is available). */
  request(engagementId: string, findingId: string, by: Actor, auto: boolean): { ok: true } | { ok: false; reason: string };
}

/**
 * The agent runtime as operations see it (only where the core runs the agents): the team's state
 * and the controls of the Team panel and the panic button. Through the catalog so roles and the
 * audit apply like to everything else.
 */
export interface AgentControl {
  teamStatus(engagementId: string): unknown;
  pauseAll(engagementId: string, by: Caller): void;
  resumeAll(engagementId: string, by: Caller): void;
}

export interface OperationContext {
  workspace: Workspace;
  caller: Caller;
  /** The model reading the results runs on this machine: nothing leaves it, so nothing is masked. */
  modelIsLocal?: boolean;
  /** Engagement used when the input does not name one. */
  defaultEngagementId?: string;
  engagement(id?: string): Engagement;
  runner(id?: string): ToolRunner;
  /** The findings library; built-in templates only when not provided. */
  proxy?: ProxyControl;
  /** The independent verifier (only where the core runs the agents). */
  verifier?: VerifierControl;
  /** The agent runtime (only where the core runs the agents). */
  agents?: AgentControl;
  /** The plugin host: only where the core loads plugins. */
  plugins?: PluginHost;
  /** Where plugins keep data (their databases, types and annotations). */
  pluginData?: PluginData;
  /** Runs declarative plugins (their operations, menus, events, providers). */
  pluginRuntime?: PluginRuntime;
  pluginSettings?: PluginSettings;
  /** The plugins the Maestro is building. */
  pluginDrafts?: PluginDrafts;
  /** Tickets for plugin panels (served by the core on its own origin). */
  pluginPanels?: PanelTickets;
  library?: FindingLibrary;
  /** Operators connected right now (team server). */
  presence?: () => Array<{ id: string; name: string; role: Role }>;
  /** Called when operators are disabled, so their live sessions can be closed. */
  onOperatorsChanged?: () => void;
}

export interface OperationDefinition<I extends z.ZodType = z.ZodType, O = unknown> {
  name: string;
  title: string;
  /** Written for humans and for models: what it does and when to use it. */
  description: string;
  kind: OperationKind;
  /** Only for kind "target": the risk when the operation does not compute its own. */
  risk?: RiskLevel;
  input: I;
  /** Who may call it. Agents can never call admin operations. */
  actors: Array<"human" | "agent">;
  /**
   * For the repetition guard: the state the outcome depends on besides the input (a draft's hash).
   * The same call on a changed state is a new call, not a loop.
   */
  guardState?(input: z.infer<I>, ctx: OperationContext): string | undefined;
  handler(input: z.infer<I>, ctx: OperationContext): O | Promise<O>;
}

const registry = new Map<string, OperationDefinition>();

export function defineOperation<I extends z.ZodType, O>(definition: OperationDefinition<I, O>): OperationDefinition<I, O> {
  if (definition.kind === "admin" && definition.actors.includes("agent")) {
    throw new Error(`${definition.name}: admin operations cannot be exposed to agents`);
  }
  registry.set(definition.name, definition as unknown as OperationDefinition);
  return definition;
}

/** Removes an operation (a plugin's, when the plugin stops). Official operations are never removed. */
export function undefineOperation(name: string): boolean {
  if (!name.startsWith("plugin.")) throw new Error(`only plugin operations can be removed (${name})`);
  return registry.delete(name);
}

export function listOperations(): OperationDefinition[] {
  return [...registry.values()];
}

export function getOperation(name: string): OperationDefinition | undefined {
  return registry.get(name);
}

export async function executeOperation(name: string, rawInput: unknown, ctx: OperationContext): Promise<unknown> {
  const op = registry.get(name);
  if (!op) throw new OperationError("UNKNOWN_OPERATION", `Unknown operation "${name}"`);

  const actorType = ctx.caller.actor.type === "agent" ? "agent" : "human";
  if (!op.actors.includes(actorType)) {
    throw new OperationError("PERMISSION_DENIED", `"${name}" cannot be called by ${actorType}s`);
  }
  if (actorType === "human") {
    const role = ctx.caller.role ?? "lead";
    const needed = requiredRole(op);
    if (ROLES.indexOf(role) < ROLES.indexOf(needed)) {
      throw new OperationError("PERMISSION_DENIED", `"${name}" needs the ${needed} role (you are ${role})`);
    }
  }

  // People read the real values behind the vault's markers (what the agents wrote stays masked
  // in storage; only the model never sees the real values).
  if (actorType !== "agent") {
    const result = await perform(name, op, rawInput, ctx, actorType, {});
    return withRealValues(ctx, rawInput, result);
  }
  // Agents' calls are counted per engagement (how the run went: errors, loops, repairs).
  const flags: CallFlags = {};
  try {
    const result = await perform(name, op, rawInput, ctx, actorType, flags);
    count(ctx, name, flags);
    return result;
  } catch (error) {
    count(ctx, name, { ...flags, error: error instanceof OperationError ? error.code : "INTERNAL" });
    throw error;
  }
}

/** Writes whose value must be the real one (a credential saved from a response). */
const RESTORE_ON_WRITE = new Set(["secret.save"]);

function engagementFor(ctx: OperationContext, input: unknown) {
  try {
    return ctx.engagement((input as { engagementId?: string } | undefined)?.engagementId);
  } catch {
    return undefined;
  }
}

function restoreInput(ctx: OperationContext, input: unknown): unknown {
  if (!JSON.stringify(input ?? null).includes("«")) return input;
  const e = engagementFor(ctx, input);
  if (!e) return input;
  const unknown: string[] = [];
  const restored = restoreDeep(e, input, unknown);
  if (unknown.length) {
    throw new OperationError("VALIDATION_ERROR", `unknown masked value${unknown.length > 1 ? "s" : ""} ${[...new Set(unknown)].slice(0, 5).join(", ")}: use the markers exactly as Penteos wrote them in a result (copy them whole); do not invent or edit them. Nothing was sent.`);
  }
  return restored;
}

function withRealValues(ctx: OperationContext, input: unknown, result: unknown): unknown {
  if (result === undefined || !JSON.stringify(result).includes("«")) return result;
  const e = engagementFor(ctx, input);
  return e ? restoreDeep(e, result) : result;
}

interface CallFlags {
  repaired?: boolean;
  echoed?: boolean;
  refused?: boolean;
  engagementId?: string;
  error?: string;
}

function count(ctx: OperationContext, op: string, f: CallFlags): void {
  try {
    const e = ctx.engagement(f.engagementId);
    recordCall(e, op, { ...(f.error ? { error: f.error } : {}), ...(f.echoed ? { echoed: true } : {}), ...(f.refused ? { refused: true } : {}), ...(f.repaired ? { repaired: true } : {}) });
  } catch {
    /* no engagement (workspace-level call): nothing to count */
  }
}

async function perform(name: string, op: OperationDefinition, rawInput: unknown, ctx: OperationContext, actorType: "agent" | "human", flags: CallFlags): Promise<unknown> {
  // An agent may say in one line what it is after (shown to people); the operation never sees it.
  let input: unknown = rawInput ?? {};
  if (actorType === "agent" && input && typeof input === "object" && !Array.isArray(input) && "intent" in input) {
    const { intent: _intent, ...rest } = input as Record<string, unknown>;
    input = rest;
  }
  if (actorType === "agent") input = normalizeKeys(input, knownKeys(op));
  // On the way to the target the real values go back in: markers issued by the vault become the
  // values they stand for. One Penteos never issued (invented or garbled) is refused, never sent.
  if (actorType === "agent" && (op.kind === "target" || RESTORE_ON_WRITE.has(name))) input = restoreInput(ctx, input);

  let parsed: { success: true; data: unknown } | { success: false; error: z.ZodError } = op.input.safeParse(input);
  if (!parsed.success && actorType === "agent") {
    const repaired = repairInput(op.input, input);
    if (repaired) {
      parsed = { success: true, data: repaired.data };
      flags.repaired = true;
    }
  }
  if (!parsed.success) {
    const issues = actorType === "agent" ? describeIssues(parsed.error.issues, inputJsonSchema(op)) : parsed.error.issues.map((i) => `${i.path.join(".") || "(input)"}: ${i.message}`);
    throw new OperationError("VALIDATION_ERROR", `Invalid input for "${name}": ${issues.join("; ")}`, issues);
  }

  flags.engagementId = (parsed.data as { engagementId?: string } | undefined)?.engagementId;
  // Loops: an agent repeating the same action gets its previous outcome back instead of a new run.
  if (actorType === "agent" && op.kind !== "read") {
    let state: string | undefined;
    try {
      state = op.guardState?.(parsed.data, ctx);
    } catch {
      state = undefined;
    }
    const decision = guardCall(`${ctx.caller.actor.id}:${ctx.defaultEngagementId ?? ""}`, name, state === undefined ? parsed.data : { input: parsed.data, state });
    if (decision.action === "refuse") {
      flags.refused = true;
      throw new OperationError("REPEATED", `This exact call was made ${decision.times - 1} times recently. Penteos will not run it again: change approach or close the task with what you have.`);
    }
    if (decision.action === "echo") {
      flags.echoed = true;
      const note = repeatNote(decision.times);
      if (!decision.previous.ok) {
        const e = decision.previous.error;
        if (e instanceof OperationError) throw new OperationError(e.code, `${e.message} - ${note}`, e.details);
        throw new OperationError("INTERNAL", `${(e as Error).message} - ${note}`);
      }
      const r = decision.previous.result;
      return r && typeof r === "object" && !Array.isArray(r) ? { ...(r as Record<string, unknown>), repeatedCall: note } : { result: r, repeatedCall: note };
    }
    try {
      const result = await run(op, parsed.data, ctx);
      decision.record({ ok: true, result });
      return result;
    } catch (error) {
      decision.record({ ok: false, error });
      throw error;
    }
  }
  return run(op, parsed.data, ctx);
}

const keysCache = new WeakMap<OperationDefinition, Set<string>>();
function knownKeys(op: OperationDefinition): Set<string> {
  let keys = keysCache.get(op);
  if (!keys) {
    try {
      keys = new Set(Object.keys((inputJsonSchema(op).properties ?? {}) as Record<string, unknown>));
    } catch {
      keys = new Set();
    }
    keysCache.set(op, keys);
  }
  return keys;
}

async function run(op: OperationDefinition, data: unknown, ctx: OperationContext): Promise<unknown> {
  try {
    return await op.handler(data, ctx);
  } catch (error) {
    if (error instanceof OperationError) throw error;
    const message = (error as Error).message ?? String(error);
    const errorName = (error as Error).name;
    if (errorName === "IngestError" || errorName === "NormalizationError" || errorName === "ZodError") {
      throw new OperationError("VALIDATION_ERROR", message);
    }
    // A plugin that is off (or a dormant type of one): the caller learns which and why.
    if (errorName === "DormantTypeError" || (error as { code?: string }).code === "PLUGIN_UNAVAILABLE") {
      throw new OperationError("PLUGIN_UNAVAILABLE", message);
    }
    if (errorName === "PluginStorageError") {
      const code = (error as { code?: string }).code;
      throw new OperationError(code === "QUOTA_EXCEEDED" || code === "NO_KEY" ? "CONFLICT" : code === "NOT_FOUND" ? "NOT_FOUND" : "VALIDATION_ERROR", message);
    }
    if (/not found/i.test(message)) throw new OperationError("NOT_FOUND", message);
    throw new OperationError("INTERNAL", message);
  }
}

/** JSON Schema of an operation's input, for MCP tool definitions and API docs. */
export function inputJsonSchema(op: OperationDefinition): Record<string, unknown> {
  return z.toJSONSchema(op.input, { io: "input", unrepresentable: "any" }) as Record<string, unknown>;
}

/** An operation's input as an agent's tool sees it: the same, plus an optional one-line intent. */
export function agentInputJsonSchema(op: OperationDefinition): Record<string, unknown> {
  const schema = inputJsonSchema(op);
  const props = (schema.properties ?? {}) as Record<string, unknown>;
  if (schema.type !== "object" || "intent" in props) return schema;
  return {
    ...schema,
    properties: { intent: { type: "string", maxLength: 200, description: "One line, for the people watching: what you are after with this call (e.g. \"check whether /api/users/{id} leaks other tenants' data\")." }, ...props },
  };
}
