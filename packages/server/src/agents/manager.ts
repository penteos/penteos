import { execFile } from "node:child_process";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { CAPABILITIES, type CapabilityId, listGaps, type Caller, type ChangeEvent, type Engagement, type Language, type OperationContext, type PluginProviderInfo, impactLeads, leadsLine, meterEgress, openQuestions, resetRepeatGuard, textForModel, Vault, type Workspace } from "@penteos/core";
import { isAutoPilot } from "@penteos/schema";
import { AnthropicSession } from "./providers/anthropic.js";
import { ClaudeCodeSession, CodexSession } from "./providers/cli.js";
import { ChatGptAuth, type ChatGptStatus } from "./chatgpt-auth.js";
import { ChatGptPlanSession } from "./providers/chatgpt.js";
import { cliPath, findCli } from "./providers/locate.js";
import { OpenAICompatibleSession } from "./providers/openai-compatible.js";
import { SubAgent } from "./subagent.js";
import { systemPrompt } from "./tools.js";
import { Verifier, type VerifierProvider } from "./verifier.js";
import { msg } from "./messages.js";
import { type AgentEvent, foldDelta, type ProviderId, type ProviderSession, type ProviderSettings, type SalaCard } from "./types.js";

/** How many times the agent may continue on its own (news only) per operator message. */
/** Long commands make notices unreadable: the run id is enough to look them up. */
const short = (text: string, max = 90) => (text.length > max ? `${text.slice(0, max)}…` : text);

/** Said to the model when the operator changes the interface language in the middle of a conversation. */
export function languageSwitchNotice(lang: Language): string {
  return lang === "es"
    ? "[Penteos - the operator switched the interface to Spanish: from now on write every message to them in Spanish (neutral, formal «usted»). The deliverable's language does not change.]"
    : "[Penteos - the operator switched the interface to English: from now on write every message to them in English. The deliverable's language does not change.]";
}

const MAX_AUTO_TURNS = 4;
// Auto (autopilot): the Maestro keeps working on its own across the round. A generous but bounded
// budget is the safety net so it never runs away; the real stop is running out of work.
const AUTO_MODE_TURNS = 40;

interface Conversation {
  events: AgentEvent[];
  /** Language of the operator who last talked to the Maestro here: what people read in this conversation. */
  lang?: Language;
  /**
   * The operator language this model session was last told to write in. Some providers keep the
   * first system prompt for the whole thread (Codex, OpenAI-compatible), so a switch mid-project
   * travels as a notice with the next message instead.
   */
  toldLang?: Language;
  provider?: ProviderId;
  session?: ProviderSession;
  running?: AbortController;
  /** Approvals the agent asked for and runs it left going, to tell it how they ended. */
  watchedApprovals: Set<string>;
  watchedRuns: Set<string>;
  notices: string[];
  autoTurns: number;
  parked?: boolean;
  /** Last time it was told about messages held in interception (one notice a minute at most). */
  stallNoticeAt?: number;
  /** Plugin failures already told to the Maestro (key → when), so one failure is told once. */
  pluginFailures?: Map<string, number>;
  saveTimer?: ReturnType<typeof setTimeout>;
}

interface StoredConversation {
  version: 1;
  provider?: ProviderId;
  session?: unknown;
  events: AgentEvent[];
  watchedApprovals: string[];
  watchedRuns: string[];
  notices: string[];
  /** The language the resumed model session was last told to write in. */
  toldLang?: Language;
}

export type AgentRole = "verifier";
export const AGENT_ROLES: AgentRole[] = ["verifier"];
export interface RoleSettings {
  provider?: ProviderId;
  model?: string;
}

interface ProviderSpec {
  id: ProviderId;
  label: string;
  /** plan: the operator's own subscription, signed in through the vendor (Sign in with ChatGPT). */
  kind: "plan" | "cli" | "api" | "local";
  description: string;
  fields: Array<keyof ProviderSettings>;
  defaults: ProviderSettings;
  env?: string;
  /** A plugin's provider: the models it offers. */
  plugin?: { models: string[]; keyless: boolean; pluginId: string };
  create(state?: unknown): ProviderSession;
}

/** The Sign in with ChatGPT session of this core (one per data folder). */
let chatgptAuth: ChatGptAuth | undefined;

const SPECS: ProviderSpec[] = [
  {
    id: "chatgpt",
    label: "ChatGPT plan",
    kind: "plan",
    description: "Your ChatGPT plan, through Sign in with ChatGPT",
    fields: ["model"],
    defaults: {},
    create: (state) => new ChatGptPlanSession(chatgptAuth!, state),
  },
  {
    id: "claude-code",
    label: "Claude Code",
    kind: "cli",
    description: "Your Claude subscription, through the installed CLI",
    fields: ["model"],
    defaults: {},
    create: (state) => new ClaudeCodeSession(state),
  },
  {
    id: "codex",
    label: "Codex",
    kind: "cli",
    description: "Your ChatGPT account, through the Codex CLI",
    fields: ["model"],
    defaults: {},
    create: (state) => new CodexSession(state),
  },
  {
    id: "claude-api",
    label: "Claude API",
    kind: "api",
    description: "Anthropic API, with an API key",
    fields: ["apiKey", "model"],
    defaults: { model: "claude-opus-5-5" },
    env: "ANTHROPIC_API_KEY",
    create: (state) => new AnthropicSession(state),
  },
  {
    id: "openai-api",
    label: "OpenAI API",
    kind: "api",
    description: "OpenAI API, with an API key",
    fields: ["apiKey", "model"],
    defaults: { model: "gpt-5" },
    env: "OPENAI_API_KEY",
    create: (state) => new OpenAICompatibleSession({ model: "gpt-5", apiKeyRequired: true }, state),
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    kind: "api",
    description: "DeepSeek API, with an API key",
    fields: ["apiKey", "model"],
    defaults: { model: "deepseek-flash", baseUrl: "https://api.deepseek.com" },
    env: "DEEPSEEK_API_KEY",
    create: (state) => new OpenAICompatibleSession({ baseUrl: "https://api.deepseek.com", model: "deepseek-flash", apiKeyRequired: true }, state),
  },
  {
    id: "local",
    label: "Local model",
    kind: "local",
    description: "Ollama, LM Studio, llama.cpp or vLLM (OpenAI-compatible API)",
    fields: ["baseUrl", "model", "apiKey"],
    defaults: { baseUrl: "http://127.0.0.1:11434/v1", model: "qwen3" },
    create: (state) => new OpenAICompatibleSession({ baseUrl: "http://127.0.0.1:11434/v1", model: "qwen3", apiKeyRequired: false }, state),
  },
];

export interface ProviderStatus {
  id: ProviderId;
  label: string;
  kind: ProviderSpec["kind"];
  description: string;
  fields: Array<keyof ProviderSettings>;
  settings: { model?: string; baseUrl?: string; hasApiKey: boolean };
  available: boolean;
  /** A message key while cached; the reader's text once returned by providers(). */
  reason?: string;
  reasonParams?: Record<string, string>;
  models?: string[];
}

function exec(command: string, args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    // Found where its installer put it, even when the app was opened from the desktop menu.
    execFile(findCli(command) ?? command, args, { timeout: 8000, env: { ...process.env, PATH: cliPath() } }, (error, stdout, stderr) =>
      resolve({ code: error ? ((error as { code?: number }).code ?? 1) : 0, out: `${stdout}${stderr}` }),
    );
  });
}

/**
 * Agent providers and conversations. One conversation per engagement; the agent acts with its
 * own identity (an agent actor), so the scope checks, approvals and audit apply exactly as for
 * external agents over MCP.
 */
/**
 * A scope rule was added: if the app's code names an API on that host (found by web_harvest_scripts
 * while it was still out of scope), the agent is told to sweep those calls now.
 */
/** After a reproduction: the impact questions still open on that finding, if any. */
function deepenReminder(e: ReturnType<Workspace["get"]>, findingId: string): string {
  const f = e.get(findingId);
  const open = f ? openQuestions(f) : [];
  return open.length ? ` It holds; now measure how bad it is: impact questions open (${open.join(", ")}). finding_impact gives the leads.` : "";
}

function apiSweepHint(e: ReturnType<Workspace["get"]>, summary: string): string {
  const bases = (e.getState<Array<{ base: string; origin: string; basePath: string; pageOrigin: string; calls: number }>>("apiBases") ?? []).filter((b) => {
    try {
      return summary.includes(new URL(b.origin).hostname);
    } catch {
      return false;
    }
  });
  return bases
    .slice(0, 1)
    .map((b) => ` The application's code calls its API on ${b.origin} (${b.calls} relative calls found). Sweep them all now without credentials: web_probe_endpoints with origin ${b.origin} and fromOrigin ${b.pageOrigin}, without basePath (Penteos measures which base path they live under).`)
    .join("");
}

export class AgentManager {
  private readonly configPath: string;
  private config: { providers: Partial<Record<ProviderId, ProviderSettings>>; selected?: ProviderId; roles?: Partial<Record<AgentRole, RoleSettings>> };
  readonly verifier: Verifier;
  /** Projects where the panic button is pressed: no agent moves until someone resumes. */
  private readonly pausedProjects = new Set<string>();
  private readonly conversations = new Map<string, Conversation>();
  private readonly listening = new Set<string>();
  private statusCache: { at: number; list: ProviderStatus[] } | undefined;
  readonly chatgpt: ChatGptAuth;

  constructor(
    private readonly workspace: Workspace,
    private readonly dataDir: string,
    private readonly makeContext: (caller: Caller, engagementId: string) => OperationContext,
    private readonly caller: Caller,
    private readonly operator: Caller,
    private readonly broadcast: (engagementId: string, event: AgentEvent) => void,
    private readonly broadcastSub: (engagementId: string, key: string, event: AgentEvent) => void = () => {},
  ) {
    this.configPath = join(dataDir, "config", "agents.json");
    this.chatgpt = chatgptAuth = new ChatGptAuth(dataDir, () => this.workspace.vault());
    try {
      this.config = JSON.parse(readFileSync(this.configPath, "utf8")) as typeof this.config;
    } catch {
      this.config = { providers: {} };
    }
    // API keys are sealed with the workspace key on disk and held open only in memory. A key saved
    // in clear by an older version is read as is and sealed right away.
    let clear = false;
    for (const settings of Object.values(this.config.providers)) {
      if (!settings?.apiKey) continue;
      if (!Vault.isSealed(settings.apiKey)) {
        clear = true;
        continue;
      }
      try {
        settings.apiKey = this.workspace.vault().open(settings.apiKey);
      } catch {
        // Sealed with a key this workspace no longer has: the operator enters it again.
        delete settings.apiKey;
      }
    }
    if (clear) this.persist();
    // While the panic button is pressed nothing new starts, verifications included.
    const unlessPaused = (id: string, role: AgentRole) => (this.pausedProjects.has(id) ? { reason: msg(this.lang(id), "role.paused") } : this.roleProvider(id, role));
    this.verifier = new Verifier(workspace, dataDir, makeContext, (id) => unlessPaused(id, "verifier"), (id, key, e) => this.broadcastSub(id, key, e), (id) => this.lang(id));
  }

  /** The Team panel: every agent of the project and its state. */
  teamStatus(engagementId: string) {
    const c = this.conversations.get(engagementId);
    const autonomy = this.workspace.get(engagementId).info.autonomy;
    return {
      autonomy,
      paused: this.pausedProjects.has(engagementId),
      maestro: { running: Boolean(c?.running), provider: c?.provider ?? null, parked: Boolean(c?.parked) },
      verifier: { active: this.verifier.activeCount(engagementId), ...(() => { const p = this.roleProvider(engagementId, "verifier"); return "reason" in p ? { reason: p.reason } : { provider: p.label }; })() },
    };
  }

  /** The panic button: every agent of the project stops where it is. Humans keep working. */
  pauseAll(engagementId: string, by: Caller): void {
    this.pausedProjects.add(engagementId);
    this.stop(engagementId);
    this.verifier.stopEngagement(engagementId, "end.pausedCap");
    const engagement = this.workspace.get(engagementId);
    engagement.audit(by.actor, "agents.pause", {}, {});
    engagement.emit({ type: "agents.paused", paused: true, by: by.actor });
    const c = this.conversations.get(engagementId);
    if (c) this.emitter(engagementId, c)({ kind: "status", text: msg(this.lang(engagementId), "status.paused", { by: by.name ?? msg(this.lang(engagementId), "role.operatorName") }) });
  }

  resumeAll(engagementId: string, by: Caller): void {
    if (!this.pausedProjects.delete(engagementId)) return;
    const engagement = this.workspace.get(engagementId);
    engagement.audit(by.actor, "agents.resume", {}, {});
    engagement.emit({ type: "agents.paused", paused: false, by: by.actor });
    const c = this.conversations.get(engagementId);
    if (c) {
      c.autoTurns = 0;
      this.emitter(engagementId, c)({ kind: "status", text: msg(this.lang(engagementId), "status.resumed") });
      setTimeout(() => void this.continueWithNews(engagementId), 500);
    }
  }

  isPaused(engagementId: string): boolean {
    return this.pausedProjects.has(engagementId);
  }

  /** A card in the Sala: it stays in the conversation, next to the Maestro's messages. */
  /** The language people read this project's conversation in. */
  lang(engagementId: string): Language {
    return this.conversations.get(engagementId)?.lang ?? this.workspace.languageOf(this.operator.actor.id);
  }

  private card(engagementId: string, card: SalaCard): void {
    const c = this.conversation(engagementId);
    this.emitter(engagementId, c)({ kind: "card", card });
  }

  /**
   * The provider of an agent that runs alongside the Maestro (the verifier): only over an API.
   * Claude Code and Codex are subscriptions for one person at a time.
   */
  roleProvider(engagementId: string, role: AgentRole): VerifierProvider {
    const policy = this.workspace.get(engagementId).info.dataPolicy;
    const L = this.lang(engagementId);
    if (policy === "no_ai") return { reason: msg(L, "provider.noAi") };
    const enabledPlugins = this.workspace.get(engagementId).info.plugins;
    const usable = (spec: ProviderSpec) => spec.kind !== "cli" && (!spec.plugin || enabledPlugins.includes(spec.plugin.pluginId)) && (policy !== "local_only" || spec.kind === "local") && (spec.kind === "plan" ? Boolean(chatgptAuth?.status().plan) : spec.kind === "local" ? Boolean(this.config.providers[spec.id]) || this.config.selected === spec.id : Boolean(this.settings(spec.id).apiKey));
    const chosen = this.config.roles?.[role]?.provider;
    // The role's own choice, then the project's, then any usable one in the order they are listed.
    const order = [chosen, this.config.selected, ...this.allSpecs().map((s) => s.id)].filter((x): x is ProviderId => Boolean(x));
    const spec = order.map((id) => this.allSpecs().find((s) => s.id === id)).find((s): s is ProviderSpec => Boolean(s) && usable(s!));
    if (!spec) return { reason: msg(L, `${policy === "local_only" ? "role.needsLocal" : "role.needsApi"}.${role}`) };
    const settings = { ...this.settings(spec.id), ...(this.config.roles?.[role]?.model ? { model: this.config.roles[role]!.model } : {}) };
    return { id: spec.id, label: spec.label, settings, create: () => spec.create() };
  }

  roles(engagementId: string): Record<AgentRole, RoleSettings & { resolved?: string; reason?: string }> {
    const out = {} as Record<AgentRole, RoleSettings & { resolved?: string; reason?: string }>;
    for (const role of AGENT_ROLES) {
      const p = this.roleProvider(engagementId, role);
      out[role] = { ...(this.config.roles?.[role] ?? {}), ...("reason" in p ? { reason: p.reason } : { resolved: `${p.label}${p.settings.model ? ` · ${p.settings.model}` : ""}` }) };
    }
    return out;
  }

  setRole(role: AgentRole, settings: RoleSettings): void {
    const spec = settings.provider ? this.allSpecs().find((s) => s.id === settings.provider) : undefined;
    if (spec?.kind === "cli") throw new Error(msg(this.workspace.languageOf(this.operator.actor.id), "role.cli", { provider: spec.label }));
    if (!AGENT_ROLES.includes(role)) throw new Error(`unknown role: ${role}`);
    this.config.roles = { ...(this.config.roles ?? {}), [role]: { ...(settings.provider ? { provider: settings.provider } : {}), ...(settings.model ? { model: settings.model } : {}) } };
    this.persist();
  }

  /** What the verifier did, for the operator to read. */
  transcript(engagementId: string, key: string): AgentEvent[] {
    if (!/^[a-z]+-[0-9A-Z]{26}$/.test(key)) return [];
    return SubAgent.transcript(this.workspace, engagementId, key);
  }

  private settings(id: ProviderId): ProviderSettings {
    const spec = this.allSpecs().find((s) => s.id === id);
    if (!spec) return {};
    const saved = this.config.providers[id] ?? {};
    // A plugin's endpoint and key come from the plugin (its approved manifest and its settings):
    // nothing saved here may point it elsewhere.
    // Model names change all the time: any saved one goes (it is only a name sent to the plugin's endpoint).
    if (spec.plugin) return { ...spec.defaults, ...(saved.model ? { model: saved.model } : {}) };
    const apiKey = saved.apiKey || (spec.env ? process.env[spec.env] : undefined);
    return { ...spec.defaults, ...saved, ...(apiKey ? { apiKey } : {}) };
  }

  private pluginProviders: () => PluginProviderInfo[] = () => [];

  /** Plugins changed: the provider list is read again. */
  invalidateProviders(): void {
    this.statusCache = undefined;
  }

  private pluginSkills: (engagement: Engagement) => Array<{ plugin: string; title: string; text: string }> = () => [];

  /** What plugins enabled in a project teach the Maestro there (the plugin runtime). */
  usePluginSkills(source: (engagement: Engagement) => Array<{ plugin: string; title: string; text: string }>): void {
    this.pluginSkills = source;
  }

  /** The system prompt plus what the project's plugins teach the Maestro. */
  private withSkills(system: string, engagement: Engagement): string {
    let skills: Array<{ plugin: string; title: string; text: string }> = [];
    try {
      skills = this.pluginSkills(engagement);
    } catch {
      /* a plugin problem never breaks the Maestro */
    }
    if (!skills.length) return system;
    const parts = skills.map((s) => `### ${s.title} (plugin ${s.plugin})\n${s.text.trim()}`);
    return `${system}\n\n## Knowledge from plugins the operator installed in this project\nThe operator chose these plugins; follow their guidance where it fits, within your rules above (scope, approvals and safety always come first).\n\n${parts.join("\n\n")}`;
  }

  /** Where the providers of running plugins come from (the plugin runtime). */
  usePluginProviders(source: () => PluginProviderInfo[]): void {
    this.pluginProviders = source;
    this.statusCache = undefined;
  }

  /** The built-in providers plus those of running plugins (remote APIs: their results are masked). */
  private allSpecs(): ProviderSpec[] {
    let extra: ProviderSpec[] = [];
    try {
      extra = this.pluginProviders().map((p) => ({
        id: p.key as ProviderId,
        label: p.label,
        kind: "api" as const,
        description: p.description ?? p.baseUrl,
        fields: ["model"] as Array<keyof ProviderSettings>,
        defaults: { model: p.models[0]!, baseUrl: p.baseUrl, ...(p.apiKey ? { apiKey: p.apiKey } : {}) },
        plugin: { models: p.models, keyless: !p.apiKey, pluginId: p.pluginId },
        create: (state?: unknown) => new OpenAICompatibleSession({ baseUrl: p.baseUrl, model: p.models[0]!, apiKeyRequired: false }, state),
      }));
    } catch {
      /* a plugin runtime problem never hides the built-in providers */
    }
    return [...SPECS, ...extra];
  }

  /** Sign in with ChatGPT: where the operator's browser goes; `done` hears the outcome. */
  async chatgptSignIn(done: (result: { ok: true } | { ok: false; error: string }) => void): Promise<{ url: string }> {
    return this.chatgpt.begin((result) => {
      this.statusCache = undefined;
      done(result);
    });
  }

  async chatgptSignOut(): Promise<{ revoked: boolean }> {
    const out = await this.chatgpt.signOut();
    this.statusCache = undefined;
    return out;
  }

  chatgptStatus(): ChatGptStatus {
    return this.chatgpt.status();
  }

  configure(id: ProviderId, settings: ProviderSettings): void {
    const current = this.config.providers[id] ?? {};
    const next: ProviderSettings = { ...current };
    for (const key of ["apiKey", "model", "baseUrl"] as const) {
      if (settings[key] === undefined) continue;
      if (settings[key] === "") delete next[key];
      else next[key] = settings[key];
    }
    this.config.providers[id] = next;
    this.persist();
  }

  /** Saves the configuration: owner-only, with every API key sealed by the workspace key. */
  private persist(): void {
    mkdirSync(join(this.dataDir, "config"), { recursive: true });
    const vault = this.workspace.vault();
    const providers = Object.fromEntries(
      Object.entries(this.config.providers).map(([id, settings]) => [id, settings?.apiKey ? { ...settings, apiKey: vault.seal(settings.apiKey) } : settings]),
    );
    writeFileSync(this.configPath, JSON.stringify({ ...this.config, providers }, null, 2), { mode: 0o600 });
    this.statusCache = undefined;
  }

  select(id: ProviderId): void {
    this.config.selected = id;
    this.configure(id, {});
  }

  /** Providers as one operator reads them (descriptions and reasons in their language). */
  async providers(engagementId: string, force = false, lang: Language = this.lang(engagementId)): Promise<{ selected?: ProviderId; providers: ProviderStatus[] }> {
    if (force || !this.statusCache || Date.now() - this.statusCache.at > 30_000) {
      this.statusCache = { at: Date.now(), list: await Promise.all(this.allSpecs().map((s) => this.detect(s))) };
    }
    const { dataPolicy: policy, plugins: enabledPlugins } = this.workspace.get(engagementId).info;
    const list = this.statusCache.list.map((cached) => {
      const { reasonParams, ...p } = cached;
      const shown = { ...p, description: p.id.startsWith("plugin:") ? p.description : msg(lang, `provider.desc.${p.id}`), ...(p.reason ? { reason: msg(lang, p.reason, reasonParams) } : {}) };
      if (policy === "no_ai") return { ...shown, available: false, reason: msg(lang, "provider.noAi") };
      if (policy === "local_only" && p.kind !== "local") return { ...shown, available: false, reason: msg(lang, "provider.localOnly") };
      // A plugin's provider sends the project's data to a third party: only where the plugin is enabled.
      const owner = this.allSpecs().find((s) => s.id === p.id)?.plugin?.pluginId;
      if (owner && !enabledPlugins.includes(owner)) return { ...shown, available: false, reason: msg(lang, "provider.pluginOff") };
      return shown;
    });
    return { ...(this.config.selected ? { selected: this.config.selected } : {}), providers: list };
  }

  private async detect(spec: ProviderSpec): Promise<ProviderStatus> {
    const s = this.settings(spec.id);
    const base: ProviderStatus = {
      id: spec.id,
      label: spec.label,
      kind: spec.kind,
      description: spec.description,
      fields: spec.fields,
      settings: { ...(s.model ? { model: s.model } : {}), ...(s.baseUrl ? { baseUrl: s.baseUrl } : {}), hasApiKey: Boolean(s.apiKey) },
      available: false,
    };
    if (spec.kind === "plan") {
      const st = this.chatgpt.status();
      if (!st.signedIn) return { ...base, reason: "provider.chatgptSignIn" };
      if (!st.plan) return { ...base, reason: "provider.chatgptPlanOff" };
      const models = await this.chatgpt.models().catch(() => []);
      return { ...base, available: true, ...(models.length ? { models: models.map((m) => m.slug) } : {}) };
    }
    if (spec.id === "claude-code") {
      const r = await exec("claude", ["auth", "status"]);
      if (r.code !== 0 && !r.out.includes("loggedIn")) return { ...base, reason: "provider.claudeMissing" };
      return /"loggedIn":\s*true/.test(r.out) ? { ...base, available: true } : { ...base, reason: "provider.claudeLogin" };
    }
    if (spec.id === "codex") {
      const r = await exec("codex", ["login", "status"]);
      if (/not found|ENOENT/i.test(r.out) && r.code !== 0) return { ...base, reason: "provider.codexMissing" };
      return r.code === 0 && /logged in/i.test(r.out) ? { ...base, available: true } : { ...base, reason: "provider.codexLogin" };
    }
    if (spec.kind === "local") {
      try {
        const res = await fetch(`${s.baseUrl}/models`, { signal: AbortSignal.timeout(1500), headers: s.apiKey ? { authorization: `Bearer ${s.apiKey}` } : {} });
        const body = (await res.json()) as { data?: Array<{ id: string }> };
        const models = (body.data ?? []).map((m) => m.id);
        if (models.length === 0) return { ...base, reason: "provider.localNoModels" };
        return { ...base, available: true, models };
      } catch {
        return { ...base, reason: "provider.localDown", reasonParams: { url: String(s.baseUrl) } };
      }
    }
    // No `models` list: the model is typed freely (the plugin's list is only its default).
    if (spec.plugin) return s.apiKey || spec.plugin.keyless ? { ...base, available: true } : { ...base, reason: "provider.noKey" };
    return s.apiKey ? { ...base, available: true } : { ...base, reason: "provider.noKey" };
  }

  history(engagementId: string): { events: AgentEvent[]; provider?: ProviderId; running: boolean; parked: boolean } {
    const c = this.conversation(engagementId);
    return { events: c?.events ?? [], ...(c?.provider ? { provider: c.provider } : {}), running: Boolean(c?.running), parked: this.parked(engagementId) };
  }

  reset(engagementId: string): void {
    this.stop(engagementId);
    this.conversations.delete(engagementId);
    rmSync(this.conversationFile(engagementId), { force: true });
  }

  private conversationFile(engagementId: string): string {
    return join(this.workspace.get(engagementId).dir, "agent", "conversation.json");
  }

  /** Conversations live with their engagement, so they survive restarts (and move with exports). */
  private load(engagementId: string): Conversation {
    const fresh: Conversation = { events: [], watchedApprovals: new Set(), watchedRuns: new Set(), notices: [], autoTurns: 0 };
    try {
      const stored = JSON.parse(readFileSync(this.conversationFile(engagementId), "utf8")) as StoredConversation;
      const spec = this.allSpecs().find((p) => p.id === stored.provider);
      return {
        ...fresh,
        events: stored.events ?? [],
        watchedApprovals: new Set(stored.watchedApprovals ?? []),
        watchedRuns: new Set(stored.watchedRuns ?? []),
        notices: stored.notices ?? [],
        ...(spec ? { provider: spec.id, session: spec.create(stored.session) } : {}),
        ...(spec && stored.toldLang ? { toldLang: stored.toldLang } : {}),
      };
    } catch {
      return fresh;
    }
  }

  private save(engagementId: string, c: Conversation, now = false): void {
    clearTimeout(c.saveTimer);
    const write = () => {
      const stored: StoredConversation = {
        version: 1,
        ...(c.provider ? { provider: c.provider } : {}),
        ...(c.session ? { session: c.session.snapshot() } : {}),
        events: c.events,
        watchedApprovals: [...c.watchedApprovals],
        watchedRuns: [...c.watchedRuns],
        notices: c.notices,
        ...(c.toldLang ? { toldLang: c.toldLang } : {}),
      };
      const file = this.conversationFile(engagementId);
      mkdirSync(dirname(file), { recursive: true });
      // Write-then-rename: a crash mid-write never leaves a truncated conversation.
      writeFileSync(`${file}.tmp`, JSON.stringify(stored), { mode: 0o600 });
      renameSync(`${file}.tmp`, file);
    };
    if (now) write();
    else
      c.saveTimer = setTimeout(() => {
        // The project may have been closed in the meantime (the app quitting, a test ending): the
        // last immediate save already has the conversation, and a late one must never crash the core.
        try {
          write();
        } catch (e) {
          process.stderr.write(`conversation not saved for ${engagementId}: ${(e as Error).message}\n`);
        }
      }, 1000);
  }

  stop(engagementId: string): void {
    const c = this.conversations.get(engagementId);
    c?.running?.abort();
    // Stopping also means "don't carry on by yourself" - past any mode's budget.
    if (c) c.autoTurns = Number.MAX_SAFE_INTEGER;
  }

  private conversation(engagementId: string): Conversation {
    let c = this.conversations.get(engagementId);
    if (!c) {
      c = this.load(engagementId);
      this.conversations.set(engagementId, c);
      this.listen(engagementId);
    }
    return c;
  }

  private emitter(engagementId: string, c: Conversation) {
    return (raw: AgentEvent) => {
      const event = this.redactEvent(engagementId, raw);
      // Providers often report the same failure twice (event + exit code): show it once.
      if (event.kind === "error") {
        const recent = c.events.slice(-3);
        if (recent.some((e) => e.kind === "error" && (e.text === event.text || event.text.includes(e.text) || e.text.includes(event.text)))) return;
      }
      // Remember what the agent is waiting for, to tell it when it happens.
      if (event.kind === "tool" && event.approvalId) c.watchedApprovals.add(event.approvalId);
      if (event.kind === "tool" && event.runId) c.watchedRuns.add(event.runId);
      if (event.kind !== "delta") c.events.push(event);
      else {
        // Fold deltas into one text event so history replays cleanly.
        foldDelta(c.events, event.text);
      }
      if (c.events.length > 1000) c.events.splice(0, c.events.length - 1000);
      this.broadcast(engagementId, event);
      this.save(engagementId, c, event.kind === "done");
    };
  }

  /** Saved credentials never show up in the conversation, not even in tool inputs. */
  private redactEvent(engagementId: string, event: AgentEvent): AgentEvent {
    let engagement;
    try {
      engagement = this.workspace.get(engagementId);
    } catch {
      return event;
    }
    if (event.kind === "tool") {
      let input = event.input;
      if (/secret[._]save/.test(event.name) && input && typeof input === "object") input = { ...(input as Record<string, unknown>), value: "••••••" };
      try {
        input = JSON.parse(engagement.redact(JSON.stringify(input)));
      } catch {
        /* keep as is */
      }
      return { ...event, input, ...(event.summary ? { summary: engagement.redact(event.summary) } : {}) };
    }
    if (event.kind === "text" || event.kind === "notice") return { ...event, text: engagement.redact(event.text) };
    return event;
  }

  /** Approvals the agent asked for and runs it left going: turn them into news for it. */
  private listen(engagementId: string): void {
    if (this.listening.has(engagementId)) return;
    this.listening.add(engagementId);
    const engagement = this.workspace.get(engagementId);
    engagement.events.on("change", (e: ChangeEvent) => {
      const c = this.conversations.get(engagementId);
      if (!c) return;
      const L = this.lang(engagementId);
      // A request that lapsed unanswered: the Maestro hears it and asks again if it still needs it.
      if (e.type === "approval.expired" && c.watchedApprovals.has(e.id)) {
        c.watchedApprovals.delete(e.id);
        this.notify(
          engagementId,
          c,
          `Your request «${short(e.summary, 160)}» expired after 8 hours without an answer from the operator. If you still need it, ask again (one request); otherwise continue with what you can do without it and say so in one line.`,
          msg(L, "notice.approvalExpired", { what: short(e.summary, 160) }),
        );
      }
      if (e.type === "approval.resolved" && c.watchedApprovals.has(e.id)) {
        c.watchedApprovals.delete(e.id);
        if (e.runId) c.watchedRuns.add(e.runId);
        const what = short(e.summary);
        const [model, human] = e.approved
          ? e.runId
            ? [`The operator accepted «${what}». Penteos is ALREADY running it (run ${e.runId}): do not ask for it or run it again; wait for the result with run_wait.`, msg(L, "notice.approved.running", { what, run: e.runId })]
            : e.result === "phase_changed"
              ? [`The operator accepted: ${what}. Start the phase by writing its plan with plan_set_phase_plan. If it is the reporting phase, do not write the report on your own: it is written when the operator asks. Sum up where things stand and propose what is worth exploring with plan_propose_paths.`, msg(L, "notice.approved.phase", { what: /^Move to phase "(.*)"$/.exec(e.summary)?.[1] ?? what })]
              : e.result === "findings_approved"
                ? [`The operator decided on the findings you put up for approval: the ones they ticked are approved and go to the report, the rest stay in review. Check with entity_query (kind finding) before saying which; do not ask again for the approved ones.`, msg(L, "notice.approved.findings")]
              : e.result === "manual_install"
                ? [`The operator accepted «${what}»; they install it themselves in their terminal.`, msg(L, "notice.approved.manual", { what })]
                : [`The operator accepted «${what}».${e.result === "scope_added" ? apiSweepHint(this.workspace.get(engagementId), e.summary) : ""}`, msg(L, "notice.approved", { what })]
          : [`The operator rejected «${what}». Do not do it; if needed, propose an alternative.`, msg(L, "notice.rejected", { what })];
        this.notify(engagementId, c, model, human, e.decidedBy.type === "human");
      }
      // A gap (left for lack of a tool) taken up again now that the tool is there.
      if (e.type === "gap.resumed" && e.requestedBy.id === this.caller.actor.id) {
        const def = CAPABILITIES[e.capability as CapabilityId];
        const gap = listGaps(engagement).find((g) => g.id === e.id);
        const targets = short((gap?.targets ?? []).join(", "), 160);
        const title = def?.title[L] ?? e.capability;
        if (e.runId) c.watchedRuns.add(e.runId);
        this.notify(
          engagementId,
          c,
          e.runId
            ? `${e.tool} is installed now, so Penteos resumed gap ${e.id} by itself: «${def?.title.en ?? e.capability}» on ${targets} is running with ${e.tool} (run ${e.runId}). Do not run it again: wait for it with run_wait and use its results (they replace what the fallback found).`
            : `${e.tool} is installed now; resuming gap ${e.id} («${def?.title.en ?? e.capability}» on ${targets}) ended as ${e.status}${e.status === "pending_approval" ? ": it waits for the operator's approval, do not ask again" : ""}.`,
          msg(L, e.runId ? "notice.gapResumed" : "notice.gapResumeWaiting", { tool: e.tool, capability: title, targets }),
        );
      }
      if (e.type === "task.answered" && (!e.askedBy || e.askedBy.id === this.caller.actor.id)) {
        this.notify(
          engagementId,
          c,
          `The operator answered your question «${short(e.question, 160)}» (task ${e.taskId}): ${e.answer}\nContinue the plan using that answer.`,
          msg(L, "notice.answered", { question: short(e.question, 160), answer: e.answer }),
          true,
        );
      }
      // The Maestro asked the operator for a plugin setting: the operator sees it where they talk to it.
      if (e.type === "plugin.setting_requested") {
        this.emitter(engagementId, c)({ kind: "notice", text: msg(L, "notice.pluginSettingRequested", { label: short(e.label, 60), name: short(e.name, 80), reason: short(e.reason, 200) }) });
      }
      // A plugin it is building got what it asked the operator for (never the value).
      if (e.type === "plugin.setting_given") {
        this.notify(
          engagementId,
          c,
          `The operator gave ${e.settings.join(", ")} for the plugin draft ${e.draftId} («${short(e.name, 80)}»). You do not see secret values: the core fills them in. Probe the real service with it (plugin_probe with draft) if useful, then test the draft live and continue.`,
          msg(L, "notice.pluginSettingGiven", { name: short(e.name, 80) }),
          true,
        );
      }
      // A plugin it built failed when the operator used it: find out why and fix it.
      if (e.type === "plugin.failed") {
        const key = `${e.pluginId}:${e.operation}:${e.error.slice(0, 120)}`;
        const seen = (c.pluginFailures ??= new Map<string, number>());
        if (Date.now() - (seen.get(key) ?? 0) > 10 * 60_000) {
          seen.set(key, Date.now());
          this.notify(
            engagementId,
            c,
            `The plugin you built «${short(e.name, 80)}» (${e.pluginId}) ${e.own ? "stopped with its own message" : "failed"} when the operator ran ${e.operation} with ${short(JSON.stringify(e.input), 300)}: ${short(e.error, 600)}\n${e.own ? "Check whether that message is TRUE for that input (a missing key or a changed API must not read as 'not found'); if it is right, nothing to do. " : ""}If it is the plugin's fault: find the cause against the real service (plugin_probe), start a new version (plugin_draft_from_installed), fix it, test it live with that same input, and propose it. Tell the operator in one line what went wrong and that you are fixing it; if you need something from them, ask.`,
            msg(L, "notice.pluginFailed", { name: short(e.name, 80) }),
            true,
          );
        }
      }
      if (e.type === "oob.interaction") {
        const what = e.purpose ? `«${short(e.purpose, 120)}»` : "an out-of-band test";
        this.notify(
          engagementId,
          c,
          `Out-of-band hit: the target made a ${e.protocol.toUpperCase()} request to your interaction host for ${what} (from ${e.remote}). That is proof the input reached a sink - the vulnerability is real. ${e.rawId ? `Save it as evidence with evidence_from_raw (rawId ${e.rawId})` : "Record it"}, then promote the finding.`,
          msg(L, "notice.oob", { protocol: e.protocol.toUpperCase(), purpose: e.purpose ? short(e.purpose, 120) : "" }),
          true,
        );
      }
      if (e.type === "client_question.answered") {
        this.notify(
          engagementId,
          c,
          `The client answered «${short(e.question, 160)}»: ${e.answer}\nUse it: if it opens a path (accounts, a window, a service to test), say in one line what you will do with it.`,
          msg(L, "notice.clientAnswered", { question: short(e.question, 160), answer: e.answer }),
          true,
        );
      }
      // The operator browsed what the Maestro asked for: what the proxy captured, and where.
      if (e.type === "browse.responded" && (!e.askedBy || e.askedBy.id === this.caller.actor.id)) {
        const where = e.hosts.length ? ` on ${e.hosts.slice(0, 6).join(", ")}` : "";
        this.notify(
          engagementId,
          c,
          e.outcome === "done"
            ? `The operator finished browsing «${short(e.title, 160)}» (task ${e.taskId}): the proxy recorded ${e.exchanges} exchange(s)${where}.${e.note ? ` Their note: ${e.note}` : ""} Read them with proxy_history (filter by host) and continue from there.`
            : `The operator declined the browsing request «${short(e.title, 160)}» (task ${e.taskId}).${e.note ? ` Their note: ${e.note}` : ""} Continue without it; record it as a limitation if it matters.`,
          e.outcome === "done"
            ? msg(L, "notice.browseDone", { title: short(e.title, 160), n: e.exchanges })
            : msg(L, "notice.browseDeclined", { title: short(e.title, 160) }),
          true,
        );
      }
      // A host that stopped accepting connections: probably a ban of this machine's IP.
      if (e.type === "host.unreachable") {
        this.notify(
          engagementId,
          c,
          `${e.host} answered until ${e.lastOkAt} and has now refused or dropped ${e.failures} connections in a row: the target's firewall has most likely blocked this machine's IP (often after a scan). Stop all traffic to ${e.host} and the hosts that share its address, tell the operator in one line, and suggest asking the client to allow the tester's IP. Continue with other hosts.`,
          msg(L, "notice.hostUnreachable", { host: e.host }),
        );
      }
      // An in-scope site that redirects out of scope: ask for exactly that host, never a wildcard.
      if (e.type === "scope.redirect_outside") {
        this.notify(
          engagementId,
          c,
          `${e.from} (in scope) redirects to ${e.to}, which is out of scope. If the work needs that site, propose exactly that host with scope_propose_rule (a domain rule for ${e.host}), not a wildcard. Otherwise keep working on what is in scope.`,
          msg(L, "notice.redirectOutside", { from: e.from, to: e.to }),
        );
      }
      // Flows held in interception hang the operator's browser: whoever drives the project decides.
      if (e.type === "intercept.stalled" && Date.now() - (c.stallNoticeAt ?? 0) > 60_000) {
        c.stallNoticeAt = Date.now();
        const byAgent = engagement.getMeta<{ by?: string }>("intercept")?.by === "agent";
        const held = `${e.waiting} message(s) have been held in the proxy interception for more than 15 s: the operator's browser is waiting.`;
        this.notify(
          engagementId,
          c,
          byAgent
            ? `${held} You turned it on: if you no longer need it, turn it off with intercept_configure (with the reason); if you expect the operator to edit something, tell them.`
            : `${held} The operator turned it on. If there is no sign they are using it, ask them in your reply whether to turn it off; after a minute with no decision you may release the queue with intercept_release_all or turn it off with intercept_configure (with the reason).`,
          msg(L, byAgent ? "notice.intercept.agent" : "notice.intercept.operator", { n: e.waiting }),
        );
      }
      if (e.type === "verification.done") {
        const v = e.verdict === "reproduced" || e.verdict === "not_reproduced" ? e.verdict : "inconclusive";
        this.card(engagementId, {
          type: "verdict",
          title: msg(L, `card.verdict.${v}`, { title: short(e.title, 60) }),
          text: short(e.summary, 400),
          at: new Date().toISOString(),
          findingId: e.findingId,
          key: `verifier-${e.findingId}`,
          who: msg(L, "role.verifierName"),
        });
        this.notify(
          engagementId,
          c,
          `The independent verifier ${v === "reproduced" ? "reproduced" : v === "not_reproduced" ? "could NOT reproduce" : "was inconclusive on"} «${short(e.title)}»: ${short(e.summary, 300)}${v === "reproduced" ? deepenReminder(engagement, e.findingId) : " Review it before defending it: fix the finding, complete the evidence or drop it if it was a false positive."}`,
          msg(L, `notice.verdict.${v}`, { title: short(e.title), summary: short(e.summary, 300) }),
        );
      }
      if (e.type === "finding.deepen") {
        const f = engagement.get(e.findingId);
        const leads = f ? leadsLine(impactLeads(engagement, f)) : "";
        this.notify(
          engagementId,
          c,
          `«${short(e.title)}» (${e.severity}, ${e.findingId}) has open impact questions: reach (how many records or organisations, measured), exposed (what each exposed secret, account or reference allows) and chain (what it combines with). Detecting is not the end: answer them before moving on (finding_impact gives the leads with the tools ready; finding_answer_impact records each answer, with evidence).${leads ? ` Leads: ${short(leads, 900)}` : ""}`,
          msg(L, "notice.deepen", { title: short(e.title) }),
        );
      }
      if (e.type === "schedule.completed" && e.headline !== "sin cambios" && e.headline !== "no changes") {
        this.notify(engagementId, c, `Scheduled scan «${e.label}» ran: ${e.headline}. Look at the detail with snapshot_diff and decide whether something needs investigating.`, msg(L, "notice.schedule", { label: e.label, headline: e.headline }));
      }
      if (e.type === "run.finished" && c.watchedRuns.has(e.id)) {
        c.watchedRuns.delete(e.id);
        const run = engagement.getRun(e.id);
        if (!run) return;
        const ingested = run.summary?.ingested as { created?: Record<string, number> } | undefined;
        const created = ingested?.created ? Object.entries(ingested.created).map(([k, n]) => `${n} ${k}`).join(", ") : "";
        this.notify(
          engagementId,
          c,
          `«${short(run.command ?? "")}» finished (run ${run.id}): ${run.status}${run.exitCode !== undefined ? `, exit code ${run.exitCode}` : ""}${created ? `; into the graph: ${created}` : ""}.`,
          msg(L, "notice.run", {
            command: short(run.command ?? ""),
            run: run.id,
            status: msg(L, `run.${run.status}`),
            code: run.exitCode !== undefined ? msg(L, "notice.run.code", { code: run.exitCode }) : "",
            ingested: created ? msg(L, "notice.run.ingested", { what: created }) : "",
          }),
        );
      }
    });
  }

  /**
   * News for the Maestro. When a human caused it (an approval, an answer) it counts as the operator
   * talking: the self-continuation budget starts again, so the Maestro never goes quiet right after
   * the operator did what it asked for.
   */
  private notify(engagementId: string, c: Conversation, model: string, human: string, fromHuman = false): void {
    if (fromHuman) {
      c.autoTurns = 0;
      c.parked = false;
    }
    // The model reads English; the operator sees the notice in their own language.
    c.notices.push(model);
    this.emitter(engagementId, c)({ kind: "notice", text: human });
    // Let the turn that is running end first; then pick up the news.
    setTimeout(() => void this.continueWithNews(engagementId), 1500);
  }

  private async continueWithNews(engagementId: string): Promise<void> {
    const c = this.conversations.get(engagementId);
    if (!c || c.running || c.notices.length === 0 || !c.provider) return;
    if (c.autoTurns >= this.autoBudget(engagementId)) {
      if (!c.parked) {
        c.parked = true;
        this.emitter(engagementId, c)({ kind: "status", text: msg(this.lang(engagementId), "status.parked") });
      }
      return;
    }
    c.autoTurns++;
    await this.send(engagementId, c.provider, "", { auto: true });
  }

  /** Self-continuation budget: generous in auto (autopilot), small in interactive. */
  private autoBudget(engagementId: string): number {
    try {
      return isAutoPilot(this.workspace.get(engagementId).info.autonomy) ? AUTO_MODE_TURNS : MAX_AUTO_TURNS;
    } catch {
      return MAX_AUTO_TURNS;
    }
  }

  /** The operator says "go on" to a Maestro that parked with unseen news. */
  resume(engagementId: string): void {
    const c = this.conversations.get(engagementId);
    if (!c) return;
    c.autoTurns = 0;
    c.parked = false;
    void this.continueWithNews(engagementId);
  }

  /** Whether the Maestro has news it has not seen because it ran out of self-continuations. */
  parked(engagementId: string): boolean {
    const c = this.conversations.get(engagementId);
    return Boolean(c?.parked && c.notices.length);
  }

  async send(engagementId: string, providerId: ProviderId, text: string, options: { auto?: boolean; by?: Caller } = {}): Promise<void> {
    const conversation = this.conversation(engagementId);
    // Whoever writes sets the language people read this conversation in.
    if (!options.auto) conversation.lang = this.workspace.languageOf((options.by ?? this.operator).actor.id);
    const emit = this.emitter(engagementId, conversation);

    if (conversation.running) {
      emit({ kind: "error", text: msg(this.lang(engagementId), "error.busy") });
      return;
    }
    if (this.pausedProjects.has(engagementId)) {
      emit({ kind: "error", text: msg(this.lang(engagementId), "error.paused") });
      return;
    }
    const { providers } = await this.providers(engagementId);
    const status = providers.find((p) => p.id === providerId);
    if (!status?.available) {
      emit({ kind: "error", text: status?.reason ?? msg(this.lang(engagementId), "error.unknownProvider") });
      return;
    }
    if (conversation.provider !== providerId || !conversation.session) {
      if (conversation.session) emit({ kind: "status", text: msg(this.lang(engagementId), "status.newConversation", { provider: status.label }) });
      conversation.provider = providerId;
      const spec = this.allSpecs().find((s) => s.id === providerId);
      if (!spec) {
        emit({ kind: "error", text: status.reason ?? msg(this.lang(engagementId), "error.unknownProvider") });
        return;
      }
      conversation.session = spec.create();
      // A new session starts with a fresh system prompt in the current language.
      conversation.toldLang = undefined;
    }

    // A message from the operator resets the self-continuation budget; pending news travel with it.
    if (!options.auto) {
      conversation.autoTurns = 0;
      resetRepeatGuard(this.caller.actor.id);
    }
    conversation.parked = false;
    const news = conversation.notices.splice(0);
    const operatorLang = conversation.lang ?? this.lang(engagementId);
    const switched = conversation.toldLang && conversation.toldLang !== operatorLang ? languageSwitchNotice(operatorLang) : "";
    conversation.toldLang = operatorLang;
    const prompt = [
      switched,
      news.length ? `[Penteos - news (not written by the operator)]\n${news.map((n) => `- ${n}`).join("\n")}${text ? "" : "\nIntegrate them: check results where relevant and continue the plan, without repeating what you already said."}` : "",
      text,
    ]
      .filter(Boolean)
      .join("\n\n");
    if (!prompt) return;

    const engagement = this.workspace.get(engagementId);
    const info = { ...engagement.info, scope: engagement.scopeRules(), counts: engagement.counts() };
    const controller = new AbortController();
    conversation.running = controller;
    emit({
      kind: "user",
      text: options.auto ? msg(this.lang(engagementId), "prompt.auto") : text,
      at: new Date().toISOString(),
      ...(options.auto ? { auto: true } : {}),
      ...(options.by?.name ? { by: options.by.name } : {}),
    });
    if (!options.auto) engagement.audit((options.by ?? this.operator).actor, "agent.prompt", { provider: providerId }, { text });

    // Copilot: the Maestro suggests and the operator executes, so every target action asks.
    const caller: Caller = info.autonomy === "copilot" ? { ...this.caller, policy: { type: "agent", autonomy: "with_approval", maxRisk: "passive" } } : this.caller;
    const system = this.withSkills(systemPrompt(info, status.kind === "cli" ? "mcp" : "tools", conversation.lang ?? this.lang(engagementId)), engagement);
    // What the model is about to read: through the leak meter.
    // The operator's words and the news may carry the client's data too: masked like any result.
    const local = status.kind === "local";
    const toModel = textForModel(engagement, prompt, { local });
    meterEgress(engagement, "system", system);
    meterEgress(engagement, "prompt", toModel);
    try {
      await conversation.session.send(toModel, {
        system,
        ops: { ...this.makeContext(caller, engagementId), modelIsLocal: local },
        caller,
        settings: this.settings(providerId),
        workDir: join(engagement.dir, "agent"),
        dataDir: this.dataDir,
        emit,
        signal: controller.signal,
        lang: this.lang(engagementId),
      });
    } catch (error) {
      if (!controller.signal.aborted) emit({ kind: "error", text: (error as Error).message });
    } finally {
      conversation.running = undefined;
      if (controller.signal.aborted) emit({ kind: "status", text: msg(this.lang(engagementId), "status.stopped") });
      emit({ kind: "done", provider: providerId, at: new Date().toISOString() });
      // News that arrived while working.
      if (!controller.signal.aborted) setTimeout(() => void this.continueWithNews(engagementId), 500);
    }
  }
}
