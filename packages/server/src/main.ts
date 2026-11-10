#!/usr/bin/env node
import { z } from "zod";
import { mcpLaunch } from "./agents/providers/cli.js";
import { createHash, randomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  defaultDataDir,
  defineOperation,
  analyzeNmapArgs,
  type Caller,
  type ChangeEvent,
  combineDecisions,
  executeOperation,
  OperationError,
  type OperationContext,
  type Role,
  ROLES,
  FindingLibrary,
  listSchedules,
  runDueSchedules,
  ToolRegistry,
  Toolbox,
  activeToolbox,
  ToolRunner,
  PenteosProxy,
  CertificateAuthority,
  Interceptor,
  DEFAULT_PROXY_SETTINGS,
  type ProxyControl,
  type ProxySettings,
  Workspace,
  AGENT_BROWSER_SOURCE,
  closeAllBrowsers,
  configureAgentBrowser,
  closeAllOob,
  reapOrphanListeners,
  resumeOob,
  meterEgress,
  interceptionHooks,
  composeProxyHooks,
  pluginProxyHooks,
  forModel,
  textForModel,
  PluginHost,
  PluginData,
  PluginRuntime,
  EgressProxy,
  PluginDrafts,
  PanelTickets,
  PluginSettings,
  declarativeActivator,
  codeActivator,
} from "@penteos/core";
import { type WebSocket, WebSocketServer } from "ws";
import { AGENT, HUMAN, MAESTRO } from "./actors.js";
import { AgentManager } from "./agents/manager.js";
import { msg as serverText } from "./agents/messages.js";
import type { ProviderId } from "./agents/types.js";
import { TerminalManager } from "./terminal.js";

/**
 * The Penteos core process. The desktop app starts it locally (solo mode); a team server runs
 * the very same process. Every client - UI, CLI, MCP agents - talks to it through the
 * operation catalog.
 */

// `penteos-server plugin …`: the plugin author's tools; nothing else of the core starts.
if (process.argv[2] === "plugin") {
  const { runPluginCli } = await import("./plugin-cli.js");
  process.exit(await runPluginCli(process.argv.slice(3)));
}
const { values: args, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "data-dir": { type: "string", default: process.env.PENTEOS_DATA_DIR ?? defaultDataDir() },
    port: { type: "string", default: process.env.PENTEOS_PORT ?? "0" },
    host: { type: "string", default: "127.0.0.1" },
    "tls-cert": { type: "string" },
    "tls-key": { type: "string" },
    /** Serve another machine without TLS anyway: only behind a VPN or an SSH tunnel. */
    "allow-plaintext": { type: "boolean", default: false },
    /** Start with every plugin off: the way out when one breaks the start. */
    "safe-mode": { type: "boolean", default: process.env.PENTEOS_SAFE_MODE === "1" },
  },
});

const dataDir = args["data-dir"]!;
const tls = args["tls-cert"] && args["tls-key"] ? { cert: readFileSync(args["tls-cert"]), key: readFileSync(args["tls-key"]) } : undefined;
/** Team mode: reachable from other machines. The integrated terminal is local-only. */
const teamMode = Boolean(tls) || !["127.0.0.1", "::1", "localhost"].includes(args.host!);
// Reachable from the network means TLS, unless the operator says the channel is already private.
if (teamMode && !tls && !args["allow-plaintext"]) {
  process.stderr.write(
    `Penteos: refusing to serve ${args.host} without TLS. Pass --tls-cert and --tls-key, or --allow-plaintext if the server is only reachable through a VPN or an SSH tunnel.
`,
  );
  process.exit(2);
}
const humanToken = process.env.PENTEOS_TOKEN ?? randomBytes(24).toString("hex");
const agentToken = process.env.PENTEOS_AGENT_TOKEN ?? randomBytes(24).toString("hex");
/** What the integrated terminal's shells get: it opens the terminal hooks and nothing else. */
const terminalToken = randomBytes(24).toString("hex");

const workspace = new Workspace(dataDir);

// How any MCP client (an AI coding agent) connects to this Penteos: the bridge's command, as JSON
// for any client and as the exact command for a few well-known ones.
defineOperation({
  name: "agent.mcp_config",
  title: "MCP connection",
  description: "How an external MCP client starts the Penteos bridge on this machine: the command, its arguments and environment, as a standard mcpServers JSON block and as commands for common clients.",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: () => {
    const l = mcpLaunch(dataDir);
    const q = (a: string) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replaceAll("'", "'\\''")}'`);
    const envFlags = (flag: string) => Object.entries(l.env).map(([k, v]) => `${flag} ${k}=${q(v)}`).join(" ");
    const cmd = [l.command, ...l.args].map(q).join(" ");
    return {
      json: { mcpServers: { penteos: { command: l.command, args: l.args, env: l.env } } },
      clients: {
        "Claude Code": `claude mcp add penteos ${envFlags("-e")} -- ${cmd}`,
        Codex: `codex mcp add penteos ${envFlags("--env")} -- ${cmd}`,
      },
    };
  },
});

/**
 * The plugin host. Declarative plugins register what they keep (entity
 * types, annotations, their databases); operations, forms and menus arrive in P2. Code plugins are
 * not runnable in this version and show as incompatible.
 */
const pluginData = new PluginData({ dataDir, globalVault: () => workspace.vault() });
const pluginSettings = new PluginSettings(dataDir, () => workspace.vault());
// Free plugins go out through here: Penteos sees every destination and warns, it does not block.
const egress = new EgressProxy();
await egress.start();
const pluginRuntime = new PluginRuntime({
  data: pluginData,
  settings: pluginSettings,
  workspace,
  currentEngagementId: () => activeId,
  // Event-triggered calls run as the plugin itself, with the policy of an automatic source.
  context: (engagementId, actor) => context({ actor, policy: { type: "agent", autonomy: "with_approval", maxRisk: "passive" } }, engagementId),
});
const plugins = new PluginHost({
  dataDir,
  safeMode: Boolean(args["safe-mode"]),
  activators: {
    declarative: declarativeActivator(pluginData, pluginRuntime),
    // Code plugins: each in an isolated process (no network, no files but its own, clean environment).
    code: codeActivator(pluginData, pluginRuntime, {
      hostDir: join(dataDir, "plugin-host"),
      onLog: (id, text) => plugins.note(id, text),
      onCrash: (id, detail) => plugins.recordCrash(id, detail),
      egressEnv: (id) => egress.env(id),
    }),
  },
});
pluginData.bind(plugins);
pluginRuntime.bind(plugins);
egress.onConnection((e) => pluginRuntime.egress(e));
const pluginDrafts = new PluginDrafts(dataDir, plugins);
const pluginPanels = new PanelTickets();

// `penteos-server operator add <name> <role>` / `operator list` / `operator disable <name>`
if (positionals[0] === "operator") {
  const [, action, name, role] = positionals;
  if (action === "add" && name && ["observer", "reviewer", "operator", "lead"].includes(role ?? "")) {
    const { operator, token } = workspace.addOperator(name, role as "observer" | "reviewer" | "operator" | "lead");
    process.stdout.write(`Operator ${operator.name} (${operator.role}) created.\nToken (shown only once): ${token}\n`);
  } else if (action === "list") {
    for (const o of workspace.operators()) process.stdout.write(`${o.name}\t${o.role}\t${o.disabled ? "disabled" : "active"}\t${o.createdAt}\n`);
  } else if (action === "disable" && name) {
    const o = workspace.operators().find((x) => x.name === name);
    if (!o) process.exitCode = 1;
    else workspace.setOperatorDisabled(o.id, true);
  } else {
    process.stdout.write("usage: operator add <name> <observer|reviewer|operator|lead> | operator list | operator disable <name>\n");
    process.exitCode = 1;
  }
  workspace.close();
  process.exit();
}


// Projects whose folder is reachable. A missing one (moved, deleted, on a disk that is not
// mounted) stays listed so the operator can locate or forget it, but nothing opens it on its own.
const reachable = () => workspace.list().filter((e) => !e.missing);
// A first-run lab engagement, scoped to targets that are always legal to scan.
if (reachable().length === 0) {
  const lab = workspace.create({ clientName: "Lab", name: "Local lab", mode: "web", maxRisk: "intrusive" }, HUMAN.actor);
  lab.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, reason: "this machine" }, HUMAN.actor);
  lab.addScopeRule({ effect: "include", target: { type: "domain", value: "localhost" }, reason: "this machine" }, HUMAN.actor);
  lab.addScopeRule(
    { effect: "include", target: { type: "domain", value: "scanme.nmap.org" }, maxRisk: "active", reason: "authorized by the nmap project for testing" },
    HUMAN.actor,
  );
}
// Open where the local operator left off.
const lastOpened = workspace.lastOpened(HUMAN.actor.id);
let activeId = reachable().find((e) => e.id === lastOpened)?.id ?? reachable()[0]!.id;

/** Built-in manifests plus the ones approved at runtime (dataDir/tools/*.json). */
// Penteos's own tool box: verified tools installed without root.
const toolbox = new Toolbox(join(dataDir, "toolbox"));
activeToolbox.box = toolbox;
const tools = new ToolRegistry(join(dataDir, "tools"), toolbox);
/** The organization's finding templates (one JSON per template; can be a git repository). */
const library = new FindingLibrary(join(dataDir, "library", "findings"));

// The intercepting proxy: local cores only - on a team server, each
// operator's browser would need its own credentials and network path (not yet).
interface ProxyConfig {
  token: string;
  upstream?: string;
}
const proxyConfigFile = join(dataDir, "config", "proxy.json");
const proxyConfig: ProxyConfig = (() => {
  try {
    return JSON.parse(readFileSync(proxyConfigFile, "utf8")) as ProxyConfig;
  } catch {
    const fresh = { token: randomBytes(18).toString("hex") };
    mkdirSync(join(dataDir, "config"), { recursive: true });
    writeFileSync(proxyConfigFile, JSON.stringify(fresh, null, 2), { mode: 0o600 });
    return fresh;
  }
})();
let proxy: PenteosProxy | undefined;
const interceptor = new Interceptor();
// Whoever is looking at that project sees the queue change.
interceptor.events.on("changed", (engagementId: string) => {
  try {
    workspace.get(engagementId).emit({ type: "intercept.changed" });
  } catch {
    /* the project is gone */
  }
});
interceptor.events.on("stalled", (engagementId: string, waiting: number) => {
  try {
    if (waiting > 0) workspace.get(engagementId).emit({ type: "intercept.stalled", waiting });
  } catch {
    /* the project is gone */
  }
});
let proxyCa: CertificateAuthority | undefined;
if (!teamMode) {
  try {
    proxyCa = await CertificateAuthority.load(join(dataDir, "config"));
    proxy = new PenteosProxy(workspace, proxyCa, {
      token: proxyConfig.token,
      actor: HUMAN.actor,
      upstream: () => proxyConfig.upstream,
      settings: (e) => ({ ...DEFAULT_PROXY_SETTINGS, ...(e.getMeta<Partial<ProxySettings>>("proxy") ?? {}) }),
    });
    // Plugins' proxy hooks first, then the operator's interception sees what they let through.
    proxy.hooks = composeProxyHooks(pluginProxyHooks(pluginRuntime), interceptionHooks(interceptor, AGENT_BROWSER_SOURCE));
    await proxy.start(Number(process.env.PENTEOS_PROXY_PORT ?? 8899));
    // The agents' browser goes through this proxy with the project's credentials.
    configureAgentBrowser({ port: proxy.port, token: proxyConfig.token });
  } catch (e) {
    process.stderr.write(`proxy: ${(e as Error).message}\n`);
    proxy = undefined;
  }
}
const proxyControl: ProxyControl | undefined =
  proxy && proxyCa
    ? {
        status: () => ({ running: true, host: "127.0.0.1", port: proxy!.port, ...(proxy!.requestedPort && proxy!.requestedPort !== proxy!.port ? { requestedPort: proxy!.requestedPort } : {}), token: proxyConfig.token, caFingerprint: proxyCa!.fingerprint, ...(proxyConfig.upstream ? { upstream: proxyConfig.upstream } : {}) }),
        ca: () => ({ pem: proxyCa!.certPem, derBase64: proxyCa!.derBase64, fingerprint: proxyCa!.fingerprint }),
        setUpstream: (url) => {
          if (url) proxyConfig.upstream = url;
          else delete proxyConfig.upstream;
          writeFileSync(proxyConfigFile, JSON.stringify(proxyConfig, null, 2), { mode: 0o600 });
        },
        interceptor,
        letThrough: (engagementId, host, minutes) => proxy!.letThrough(engagementId, host, minutes),
      }
    : undefined;
const runners = new Map<string, ToolRunner>();
function runner(id = activeId): ToolRunner {
  let r = runners.get(id);
  if (!r) {
    r = new ToolRunner(workspace.get(id), tools);
    // A plugin the Maestro built, approved by the operator: installed and enabled in this project.
    r.pluginInstall = (proposal, by, options) => pluginDrafts.install(proposal, workspace.get(id), by, options);
    runners.set(id, r);
  }
  return r;
}

function context(caller: Caller, engagementId?: string): OperationContext {
  const current = () => engagementId ?? activeId;
  return {
    workspace,
    caller,
    defaultEngagementId: current(),
    engagement: (id) => workspace.get(id ?? current()),
    runner: (id) => runner(id ?? current()),
    library,
    ...(proxyControl ? { proxy: proxyControl } : {}),
    verifier: { request: (...args) => agents.verifier.request(...args) },
    plugins,
    pluginData,
    pluginRuntime,
    pluginSettings,
    pluginDrafts,
    pluginPanels,
    agents: {
      teamStatus: (id) => agents.teamStatus(id),
      pauseAll: (id, by) => agents.pauseAll(id, by),
      resumeAll: (id, by) => agents.resumeAll(id, by),
    },
    presence: () => online(),
    onOperatorsChanged: () => dropDisabled(),
  };
}

/** Who is connected (de-duplicated: one operator may have several windows). */
const sessions = new Map<WebSocket, Caller>();
function online(): Array<{ id: string; name: string; role: Role; engagementId?: string }> {
  const seen = new Map<string, { id: string; name: string; role: Role; engagementId?: string }>();
  for (const [ws, c] of sessions) {
    const engagementId = viewing.get(ws);
    seen.set(c.actor.id, { id: c.actor.id, name: c.name ?? "Local operator", role: c.role ?? "lead", ...(engagementId ? { engagementId } : {}) });
  }
  return [...seen.values()];
}
function broadcastPresence() {
  broadcast({ t: "presence", operators: online(), teamMode });
}
function dropDisabled() {
  const active = new Set(workspace.operators().filter((o) => !o.disabled).map((o) => o.id));
  for (const [ws, c] of sessions) if (c !== HUMAN && !active.has(c.actor.id)) ws.close(4001, "operator disabled");
}
const atLeast = (c: Caller, role: Role) => ROLES.indexOf(c.role ?? "lead") >= ROLES.indexOf(role);

function errorBody(error: unknown) {
  if (error instanceof OperationError) return { code: error.code, message: error.message, details: error.details };
  return { code: "INTERNAL", message: (error as Error).message ?? String(error) };
}

function tokenMatches(given: string | undefined, expected: string): boolean {
  if (!given) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Who is calling: the Authorization header, or for a WebSocket the "penteos.token.<token>" protocol
 * (browsers can't set headers there). A token in the URL is accepted only on this machine: in team
 * mode URLs end up in proxy and server logs.
 */
function callerFor(req: IncomingMessage, url: URL): Caller | undefined {
  const fromProtocol = String(req.headers["sec-websocket-protocol"] ?? "")
    .split(",")
    .map((p) => p.trim())
    .find((p) => p.startsWith("penteos.token."))
    ?.slice("penteos.token.".length);
  const fromUrl = teamMode ? undefined : (url.searchParams.get("token") ?? undefined);
  const token = req.headers.authorization?.replace(/^Bearer /, "") ?? fromProtocol ?? fromUrl;
  if (tokenMatches(token, humanToken)) return HUMAN;
  if (tokenMatches(token, agentToken)) return AGENT;
  const operator = token ? workspace.operatorByToken(token) : undefined;
  if (operator) return { actor: { type: "human", id: operator.id }, policy: { type: "human" }, role: operator.role, name: operator.name };
  return undefined;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? (JSON.parse(text) as unknown) : {};
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const STATUS: Record<string, number> = { VALIDATION_ERROR: 400, PERMISSION_DENIED: 403, NOT_FOUND: 404, UNKNOWN_OPERATION: 404, RATE_LIMITED: 429, UPSTREAM_ERROR: 502, INTERNAL: 500 };

const handler = async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/v0/health") return send(res, 200, { ok: true });
  // A plugin panel: its ticket is the credential (an isolated frame cannot send the token).
  const panelMatch = /^\/v0\/plugin-panel\/([A-Za-z0-9_-]{20,64})$/.exec(url.pathname);
  if (panelMatch && req.method === "GET") {
    const page = pluginPanels.serve(panelMatch[1]!);
    res.writeHead(page.status, page.headers);
    res.end(page.body);
    return;
  }

  // The terminal's own token works on the terminal hooks only, as the local operator.
  const bearer = req.headers.authorization?.replace(/^Bearer /, "");
  const terminalHook = req.method === "POST" && (url.pathname === "/v0/terminal/pre" || url.pathname === "/v0/terminal/post");
  const caller = terminalHook && tokenMatches(bearer, terminalToken) ? HUMAN : callerFor(req, url);
  if (!caller) return send(res, 401, { code: "UNAUTHORIZED", message: "missing or invalid token" });

  try {
    const opMatch = /^\/v0\/ops\/([a-z_.]+)$/.exec(url.pathname);
    if (req.method === "POST" && opMatch) {
      // Agents over MCP (Claude Code, Codex) read exactly this answer: through the leak meter.
      const agentCall = caller.actor.type === "agent";
      try {
        const result = await executeOperation(opMatch[1]!, await readJson(req), context(caller));
        if (!agentCall) return send(res, 200, { ok: true, result });
        // What the model reads: masked and fitted by structure; the MCP bridge passes the text as is.
        const e = workspace.get(activeId);
        const text = forModel(e, result);
        meterEgress(e, "tool", text);
        return send(res, 200, { ok: true, result: text, forModel: true });
      } catch (error) {
        if (agentCall && error instanceof OperationError) {
          const e = workspace.get(activeId);
          const masked = new OperationError(error.code, textForModel(e, error.message), error.details);
          meterEgress(e, "tool", masked.message);
          throw masked;
        }
        throw error;
      }
    }

    // Integrated terminal hooks (only for the human operator's own shell).
    if (req.method === "POST" && url.pathname === "/v0/terminal/pre" && caller === HUMAN) {
      const { tool, argv } = (await readJson(req)) as { tool: string; argv: string[] };
      const engagement = workspace.get(activeId);
      const analysis = analyzeNmapArgs(argv);
      const decision = analysis.unchecked
        ? ({ decision: "deny", code: "UNCHECKED_TARGETS", reason: analysis.unchecked } as const)
        : combineDecisions(analysis.targets.map((t) => engagement.checkScope(t, analysis.risk, HUMAN.policy)));
      const allowed = decision.decision !== "deny";
      const run = engagement.startRun({
        actor: HUMAN.actor,
        origin: "terminal",
        tool,
        command: [tool, ...argv].join(" "),
        targets: analysis.targets,
        risk: analysis.risk,
        policy: allowed
          ? { result: "allowed", ...("ruleId" in decision && decision.ruleId ? { ruleId: decision.ruleId } : {}) }
          : { result: "denied", reason: decision.reason },
        runner: "terminal",
        status: allowed ? "running" : "denied",
      });
      return send(res, 200, allowed
        ? { decision: "allow", runId: run.id, targets: analysis.targets }
        : { decision: "deny", reason: decision.reason, runId: run.id });
    }
    if (req.method === "POST" && url.pathname === "/v0/terminal/post" && caller === HUMAN) {
      const { runId, exitCode, xmlPath } = (await readJson(req)) as { runId: string; exitCode: number; xmlPath: string };
      const engagement = workspace.get(activeId);
      let summary;
      try {
        summary = runner().ingestNmapXml(runId, xmlPath);
      } catch (error) {
        summary = undefined;
        engagement.finishRun(runId, { status: "failed", exitCode, summary: { ingestError: (error as Error).message } });
        return send(res, 200, { error: (error as Error).message });
      }
      engagement.finishRun(runId, { status: exitCode === 0 ? "finished" : "failed", exitCode, ...(summary ? { summary: { ingested: summary } } : {}) });
      return send(res, 200, { summary });
    }

    return send(res, 404, { code: "NOT_FOUND", message: url.pathname });
  } catch (error) {
    const body = errorBody(error);
    return send(res, STATUS[body.code] ?? 422, { ok: false, error: body });
  }
};
const server = tls ? createHttpsServer(tls, handler) : createServer(handler);

// ---------------------------------------------------------------------------------------------
// WebSocket: operations, live events and terminals for the desktop UI
// ---------------------------------------------------------------------------------------------

const terminalEnv = {
  url: "", // set once listening
  token: terminalToken,
  workDir: join(dataDir, "terminal-work"),
  hookDir: join(dataDir, "terminal"),
};
const terminals = new TerminalManager(terminalEnv);

// The client offers "penteos" plus its token as protocols; the answer names only "penteos".
const wss = new WebSocketServer({ noServer: true, handleProtocols: (offered) => (offered.has("penteos") ? "penteos" : false) });
const clients = new Set<WebSocket>();

function broadcast(message: unknown) {
  const text = JSON.stringify(message);
  for (const ws of clients) if (ws.readyState === ws.OPEN) ws.send(text);
}

/**
 * Each connection works on its own engagement: one operator switching engagements must not
 * switch everyone else's. (The global activeId only serves local-machine clients: the terminal
 * hooks and MCP agents.)
 */
const viewing = new Map<WebSocket, string>();
function broadcastTo(engagementId: string, message: unknown) {
  const text = JSON.stringify(message);
  for (const ws of clients) if (ws.readyState === ws.OPEN && viewing.get(ws) === engagementId) ws.send(text);
}

const subscribed = new Set<string>();
function subscribe(id: string) {
  if (subscribed.has(id)) return;
  subscribed.add(id);
  // Changes reach the connections working on that engagement.
  workspace.get(id).events.on("change", (event: ChangeEvent) => broadcastTo(id, { t: "event", engagementId: id, event }));
}
const agents = new AgentManager(
  workspace,
  dataDir,
  context,
  MAESTRO,
  HUMAN,
  (engagementId, event) => broadcastTo(engagementId, { t: "agent.event", engagementId, event }),
  (engagementId, key, event) => broadcastTo(engagementId, { t: "subagent.event", engagementId, key, event }),
);
subscribe(activeId);

function activate(ws: WebSocket, caller: Caller, id: string) {
  workspace.get(id); // throws if unknown
  viewing.set(ws, id);
  if (caller === HUMAN) activeId = id;
  workspace.rememberOpened(caller.actor.id, id);
  subscribe(id);
  ws.send(JSON.stringify({ t: "event", engagementId: id, event: { type: "engagement.switched" } }));
  broadcastPresence();
}

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  const caller = callerFor(req, url);
  if (url.pathname !== "/v0/ws" || !caller || caller.actor.type !== "human") {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    clients.add(ws);
    sessions.set(ws, caller);
    viewing.set(ws, caller === HUMAN ? activeId : (workspace.lastOpened(caller.actor.id) ?? activeId));
    const mine = () => viewing.get(ws) ?? activeId;
    broadcastPresence();
    ws.send(JSON.stringify({ t: "hello", you: { id: caller.actor.id, name: caller.name ?? "Local operator", role: caller.role ?? "lead" }, teamMode }));
    const own = new Set<string>();
    ws.on("close", () => {
      clients.delete(ws);
      sessions.delete(ws);
      viewing.delete(ws);
      broadcastPresence();
      for (const id of own) terminals.close(id);
    });
    // Agent errors for this operator only (permission problems are nobody else's business).
    const tellAgentError = (text: string) => ws.send(JSON.stringify({ t: "agent.event", engagementId: mine(), event: { kind: "error", text } }));
    ws.on("message", async (data) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(String(data)) as Record<string, unknown>;
      } catch {
        return;
      }
      switch (msg.t) {
        case "call": {
          try {
            const result = await executeOperation(String(msg.op), msg.input, context(caller, mine()));
            if (msg.op === "engagement.create" && result && typeof result === "object" && "id" in result) {
              activate(ws, caller, String((result as { id: string }).id));
            }
            ws.send(JSON.stringify({ t: "result", id: msg.id, ok: true, result }));
          } catch (error) {
            ws.send(JSON.stringify({ t: "result", id: msg.id, ok: false, error: errorBody(error) }));
          }
          break;
        }
        case "activate":
          try {
            activate(ws, caller, String(msg.engagementId));
          } catch (error) {
            // A project whose folder was moved or deleted: tell the operator instead of nothing.
            const detail = error instanceof Error ? error.message : "";
            if (detail.startsWith("PROJECT_FOLDER_MISSING")) ws.send(JSON.stringify({ t: "event", event: { type: "activate.failed", dir: detail.slice(detail.indexOf(":") + 2) } }));
          }
          break;
        case "term.open": {
          // A shell on the server is not something to hand to remote operators.
          if (teamMode || caller !== HUMAN) {
            ws.send(JSON.stringify({ t: "term.denied", ref: msg.ref, reason: serverText(workspace.languageOf(caller.actor.id), "terminal.denied") }));
            break;
          }
          const termId = terminals.open(
            Number(msg.cols ?? 80),
            Number(msg.rows ?? 24),
            (out) => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ t: "term.data", termId, data: out })),
            (code) => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ t: "term.exit", termId, code })),
          );
          own.add(termId);
          ws.send(JSON.stringify({ t: "term.opened", ref: msg.ref, termId }));
          break;
        }
        case "agent.providers":
          ws.send(JSON.stringify({ t: "agent.providers", ref: msg.ref, ...(await agents.providers(mine(), Boolean(msg.refresh), workspace.languageOf(caller.actor.id))) }));
          break;
        case "agent.configure":
          // Provider settings may hold API keys: lead only.
          if (!atLeast(caller, "lead")) {
            tellAgentError(serverText(workspace.languageOf(caller.actor.id), "error.roleProviders"));
            break;
          }
          agents.configure(msg.provider as ProviderId, (msg.settings ?? {}) as Record<string, string>);
          ws.send(JSON.stringify({ t: "agent.providers", ref: msg.ref, ...(await agents.providers(mine(), true, workspace.languageOf(caller.actor.id))) }));
          break;
        case "agent.select":
          // The provider is shared by everyone on this core: lead only, like its settings.
          if (!atLeast(caller, "lead")) {
            tellAgentError(serverText(workspace.languageOf(caller.actor.id), "error.roleProviders"));
            break;
          }
          agents.select(msg.provider as ProviderId);
          break;
        case "chatgpt.signin": {
          // Sign in with ChatGPT: the browser goes to OpenAI's page; the outcome reaches every client.
          if (!atLeast(caller, "lead")) {
            tellAgentError(serverText(workspace.languageOf(caller.actor.id), "error.roleProviders"));
            break;
          }
          try {
            const { url } = await agents.chatgptSignIn((result) => broadcast({ t: "chatgpt.done", ...result }));
            ws.send(JSON.stringify({ t: "chatgpt.signin", ref: msg.ref, url }));
          } catch (e) {
            ws.send(JSON.stringify({ t: "chatgpt.signin", ref: msg.ref, error: (e as Error).message }));
          }
          break;
        }
        case "chatgpt.signout":
          if (!atLeast(caller, "lead")) break;
          ws.send(JSON.stringify({ t: "chatgpt.signout", ref: msg.ref, ...(await agents.chatgptSignOut()) }));
          break;
        case "chatgpt.status":
          ws.send(JSON.stringify({ t: "chatgpt.status", ref: msg.ref, ...agents.chatgptStatus() }));
          break;
        case "chatgpt.welcomed":
          agents.chatgpt.acknowledgeWelcome();
          break;
        case "agent.roles":
          ws.send(JSON.stringify({ t: "agent.roles", ref: msg.ref, roles: agents.roles(mine()) }));
          break;
        case "agent.set_role":
          if (!atLeast(caller, "lead")) {
            tellAgentError(serverText(workspace.languageOf(caller.actor.id), "error.roleAgents"));
            break;
          }
          try {
            agents.setRole(msg.role as "verifier", (msg.settings ?? {}) as { provider?: ProviderId; model?: string });
            ws.send(JSON.stringify({ t: "agent.roles", ref: msg.ref, roles: agents.roles(mine()) }));
          } catch (e) {
            ws.send(JSON.stringify({ t: "agent.roles", ref: msg.ref, roles: agents.roles(mine()), error: (e as Error).message }));
          }
          break;
        case "subagent.transcript":
          ws.send(JSON.stringify({ t: "subagent.transcript", ref: msg.ref, key: msg.key, events: agents.transcript(mine(), String(msg.key ?? "")) }));
          break;
        case "verification.cancel":
          if (atLeast(caller, "operator")) agents.verifier.cancel(String(msg.findingId ?? ""));
          break;
        case "ui.error":
          // An error in the interface goes to the core's log (logs/core.log), to attach to a bug report.
          process.stderr.write(`[ui] ${String(msg.where ?? "").slice(0, 80)}: ${String(msg.message ?? "").slice(0, 500)}\n${String(msg.stack ?? "").slice(0, 2000)}\n`);
          break;
        case "agent.history":
          ws.send(JSON.stringify({ t: "agent.history", ref: msg.ref, ...agents.history(mine()) }));
          break;
        case "agent.send":
          // The Maestro acts with its own permissions: instructing it must not let an observer
          // or reviewer do what their role forbids.
          if (!atLeast(caller, "operator")) {
            tellAgentError(serverText(workspace.languageOf(caller.actor.id), "error.roleInstruct"));
            break;
          }
          void agents.send(mine(), msg.provider as ProviderId, String(msg.text ?? ""), { by: caller });
          break;
        case "agent.resume":
          if (atLeast(caller, "operator")) agents.resume(mine());
          break;
        case "agent.stop":
          if (atLeast(caller, "operator")) agents.stop(mine());
          break;
        case "agent.reset":
          if (!atLeast(caller, "operator")) break;
          agents.reset(mine());
          broadcastTo(mine(), { t: "agent.reset", engagementId: mine() });
          break;
        // A connection drives only the terminals it opened.
        case "term.input":
          if (own.has(String(msg.termId))) terminals.write(String(msg.termId), String(msg.data));
          break;
        case "term.resize":
          if (own.has(String(msg.termId))) terminals.resize(String(msg.termId), Number(msg.cols), Number(msg.rows));
          break;
        case "term.close":
          if (own.has(String(msg.termId))) terminals.close(String(msg.termId));
          break;
      }
    });
  });
});

agents.usePluginProviders(() => pluginRuntime.providers());
agents.usePluginSkills((engagement) => pluginRuntime.skillsFor(engagement));
library.usePluginTemplates(() => pluginRuntime.templates());
plugins.onChange(() => {
  agents.invalidateProviders();
  broadcast({ t: "event", event: { type: "plugins.changed" } });
});

// Plugins load before the port opens, with progress for the splash. load() never throws: a broken
// plugin can delay the start by its budget at most, never stop it.
void plugins
  .load((p) => process.stdout.write(`PENTEOS_PLUGINS ${JSON.stringify(p)}\n`))
  .then(() => server.listen(Number(args.port), args.host, onListening));

function onListening() {
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  terminalEnv.url = `http://127.0.0.1:${port}`;
  if (teamMode) {
    process.stderr.write(`Penteos: team server at ${tls ? "https" : "http"}://${args.host}:${port}${tls ? "" : " (no TLS: use it only behind a VPN or an SSH tunnel)"}\n`);
    if (tls) {
      // What operators paste in the app to trust exactly this certificate (self-signed servers).
      const fingerprint = `sha256/${createHash("sha256").update(new X509Certificate(tls.cert).raw).digest("base64")}`;
      process.stderr.write(`Penteos: certificate fingerprint: ${fingerprint}\n`);
    }
  }
  // Lets local agents (MCP bridge) find the core. Owner-only: it holds the agent token.
  writeFileSync(join(dataDir, "core.json"), JSON.stringify({ port, agentToken, pid: process.pid }), { mode: 0o600 });
  // Machine-readable line for the desktop app, which spawns this process.
  // In team mode stdout ends up in service logs: never print the owner's token there.
  process.stdout.write(`PENTEOS_READY ${JSON.stringify(teamMode ? { port, teamMode, dataDir } : { port, token: humanToken, agentToken, dataDir })}\n`);
  // The start got this far: it counts as good, so the safe-mode countdown starts over.
  plugins.bootCompleted();
  // Listeners a previous core left running when it died (before they were tied to it): stop them
  // before re-opening the ones that should be on.
  const reaped = reapOrphanListeners(reachable().map((e) => workspace.dirOf(e.id)));
  if (reaped.length) process.stderr.write(`stopped ${reaped.length} interaction listener(s) left by a previous run\n`);
  // Re-open the OOB listeners of engagements that had it on (their domain is kept across restarts).
  void resumeOob(reachable().filter((e) => !["closed", "archived"].includes(e.status)).map((e) => workspace.get(e.id)));
}

// Scheduled scans (recurrent mode): checked every minute; one at a time per engagement.
const scheduling = new Set<string>();
const scheduler = setInterval(() => {
  for (const summary of reachable()) {
    if (["closed", "archived"].includes(summary.status) || scheduling.has(summary.id)) continue;
    const engagement = workspace.get(summary.id);
    if (!listSchedules(engagement).some((s) => s.enabled && s.nextAt <= new Date().toISOString())) continue;
    scheduling.add(summary.id);
    subscribe(summary.id);
    runDueSchedules(engagement, runner(summary.id))
      .catch((e: Error) => process.stderr.write(`schedule ${summary.id}: ${e.message}\n`))
      .finally(() => scheduling.delete(summary.id));
  }
}, 60_000);

function shutdown() {
  clearInterval(scheduler);
  interceptor.releaseAll();
  agents.verifier.stopAll();
  closeAllBrowsers();
  closeAllOob();
  void proxy?.close();
  terminals.closeAll();
  for (const r of runners.values()) {
    // Tools run in their own process groups: stop them outright, the core is going away.
    r.cancelAll("SIGTERM");
    r.closeAllWs();
  }
  server.close();
  workspace.close();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
