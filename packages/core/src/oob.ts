import { activeToolbox } from "./tools/toolbox.js";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { ulid } from "@penteos/schema";
import type { Engagement } from "./engagement.js";

/**
 * Out-of-band interactions. Some weaknesses never show in the
 * response: the target makes a request of its own somewhere else. Penteos gives each test a
 * unique host under the engagement's interaction domain; when the target contacts it (DNS, HTTP,
 * SMTP…), that is proof, recorded with time, source and the raw request, and the agent that asked
 * for it hears about it. The listener is ProjectDiscovery's interactsh: a public server for labs,
 * or the team's own for real engagements (nothing the target sends then reaches a third party).
 */

/** Public interactsh servers: handy for labs, but whatever the target sends them goes to a third party. */
export const PUBLIC_OOB_SERVERS = ["oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me"];
export const isPublicServer = (server: string): boolean => PUBLIC_OOB_SERVERS.includes(server.toLowerCase());

export interface OobTag {
  tag: string;
  /** What the test is: "SSRF in the import-from-URL field of POST /api/import". */
  purpose: string;
  target?: string;
  by: Actor;
  at: string;
}

export interface OobInteraction {
  id: string;
  /** The test it belongs to, when the contacted host carried one of our tags. */
  tag?: string;
  purpose?: string;
  protocol: string;
  /** The full host (or host path) that was contacted. */
  fullId: string;
  qtype?: string;
  remote: string;
  at: string;
  /** Raw artifact with the request as the server received it. */
  rawId?: string;
}

export interface OobState {
  enabled: boolean;
  server: string;
  /** Name of the secret holding the server token, for a private server that needs one. */
  tokenSecret?: string;
  /** The interaction domain the listener was given (kept across restarts by its session file). */
  base?: string;
  tags: OobTag[];
  interactions: OobInteraction[];
}

export function oobState(e: Engagement): OobState {
  return e.getState<OobState>("oob") ?? { enabled: false, server: PUBLIC_OOB_SERVERS[0]!, tags: [], interactions: [] };
}

function save(e: Engagement, s: OobState): void {
  e.setState("oob", { ...s, interactions: s.interactions.slice(-500), tags: s.tags.slice(-500) });
}

/** The interactsh client to use: PENTEOS_INTERACTSH, Penteos's tool box, the Go install path, or the one on PATH. */
export function findInteractsh(): string | undefined {
  const env = process.env.PENTEOS_INTERACTSH;
  if (env && existsSync(env)) return env;
  const own = activeToolbox.box?.binaryPath("interactsh-client");
  if (own) return own;
  const go = join(homedir(), "go", "bin", "interactsh-client");
  if (existsSync(go)) return go;
  const r = spawnSync("which", ["interactsh-client"], { encoding: "utf8" });
  return r.status === 0 && r.stdout.trim() ? r.stdout.trim() : undefined;
}

const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

/** One running interactsh-client per engagement: its process, its domain, and what it hears. */
class Listener {
  private child?: ChildProcess;
  private ready?: Promise<string>;
  private base?: string;

  constructor(private readonly engagement: Engagement) {}

  get domain(): string | undefined {
    return this.base;
  }

  /** Starts the client if it is not up; resolves with the interaction domain. */
  start(): Promise<string> {
    if (this.ready) return this.ready;
    const bin = findInteractsh();
    if (!bin) return Promise.reject(new Error("interactsh-client is not installed (set PENTEOS_INTERACTSH, or Penteos can install it without root from its verified catalog: tool_propose_install with tool interactsh-client)"));
    const s = oobState(this.engagement);
    const stateDir = join(this.engagement.dir, "oob");
    mkdirSync(stateDir, { recursive: true });
    const args = ["-server", s.server, "-json", "-n", "1", "-sf", join(stateDir, "session.yaml")];
    if (s.tokenSecret) {
      const resolved = this.engagement.resolveSecrets([`{{secret:${s.tokenSecret}}}`]);
      if (resolved.missing.length) return Promise.reject(new Error(`unknown secret "${s.tokenSecret}" for the interaction server token`));
      args.push("-token", resolved.argv[0]!);
    }
    const server = s.server.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const domainRe = new RegExp(`\\b([a-z0-9]{20,}\\.${server})\\b`, "i");

    this.ready = new Promise<string>((resolve, reject) => {
      const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
      this.child = child;
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) reject(new Error(`the interaction server did not answer (${s.server})`));
      }, 30_000);
      let err = "";
      child.stderr?.on("data", (d) => {
        err += stripAnsi(String(d));
        const m = !this.base ? domainRe.exec(err) : null;
        if (m) {
          this.base = m[1]!.toLowerCase();
          settled = true;
          clearTimeout(timer);
          const now = oobState(this.engagement);
          save(this.engagement, { ...now, base: this.base });
          resolve(this.base);
        }
      });
      let buf = "";
      child.stdout?.on("data", (d) => {
        buf += String(d);
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (line) this.ingest(line);
        }
      });
      child.once("error", (e) => {
        if (!settled) {
          clearTimeout(timer);
          reject(e);
        }
      });
      child.once("exit", () => {
        this.ready = undefined;
        this.child = undefined;
      });
    });
    return this.ready;
  }

  /** One JSON interaction line from interactsh: filter resolver noise, match the tag, keep the proof. */
  private ingest(line: string): void {
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line);
    } catch {
      return;
    }
    const full = String(o["full-id"] ?? "").toLowerCase();
    const base = String(o["unique-id"] ?? "").toLowerCase();
    // The bare interaction domain is queried constantly by resolvers (NS, DNSKEY, A…): not a target
    // contact. Our payloads always carry a tag label, so a real callback has one.
    if (!full || full === base) return;
    const labels = (full.endsWith(`.${base}`) ? full.slice(0, -(base.length + 1)) : full).split(".");
    const tagLabel = labels[labels.length - 1];
    const state = oobState(this.engagement);
    const match = state.tags.find((t) => t.tag === tagLabel);
    const raw = o["raw-request"];
    const rawId = typeof raw === "string" && raw ? this.engagement.putRaw(raw, { type: "stdout", mime: "text/plain" }) : undefined;
    const interaction: OobInteraction = {
      id: ulid(),
      ...(match ? { tag: match.tag, purpose: match.purpose } : {}),
      protocol: String(o.protocol ?? "dns"),
      fullId: String(o["full-id"] ?? ""),
      ...(o["q-type"] ? { qtype: String(o["q-type"]) } : {}),
      remote: String(o["remote-address"] ?? ""),
      at: String(o.timestamp ?? new Date().toISOString()),
      ...(rawId ? { rawId } : {}),
    };
    save(this.engagement, { ...state, interactions: [...state.interactions, interaction] });
    this.engagement.emit({ type: "oob.interaction", id: interaction.id, protocol: interaction.protocol, fullId: interaction.fullId, remote: interaction.remote, ...(match ? { tag: match.tag, purpose: match.purpose } : {}), ...(rawId ? { rawId } : {}), ...(match ? { requestedBy: match.by } : {}) });
  }

  stop(): void {
    const child = this.child;
    this.child = undefined;
    this.ready = undefined;
    if (!child?.pid) return;
    try {
      if (child.exitCode === null) process.kill(-child.pid, "SIGTERM");
    } catch {
      child.kill("SIGTERM");
    }
  }
}

const listeners = new Map<string, Listener>();

function listenerFor(e: Engagement): Listener {
  let l = listeners.get(e.info.id);
  if (!l) {
    l = new Listener(e);
    listeners.set(e.info.id, l);
  }
  return l;
}

/** Turns OOB on with a server, starts the listener and returns the interaction domain. */
export async function oobEnable(e: Engagement, opts: { server?: string; tokenSecret?: string } = {}): Promise<{ base: string; server: string; public: boolean }> {
  const prev = oobState(e);
  const server = (opts.server ?? prev.server ?? PUBLIC_OOB_SERVERS[0]!).toLowerCase();
  save(e, { ...prev, enabled: true, server, ...(opts.tokenSecret ? { tokenSecret: opts.tokenSecret } : {}) });
  // A changed server means a new listener.
  if (prev.server !== server || prev.tokenSecret !== opts.tokenSecret) {
    listeners.get(e.info.id)?.stop();
    listeners.delete(e.info.id);
  }
  const base = await listenerFor(e).start();
  return { base, server, public: isPublicServer(server) };
}

/** Registers a test and returns the host to embed in its payload. Auto-enables with defaults if off. */
export async function oobNew(e: Engagement, opts: { purpose: string; target?: string; by: Actor }): Promise<{ address: string; tag: string; base: string; server: string; public: boolean }> {
  let s = oobState(e);
  let pub = isPublicServer(s.server);
  if (!s.enabled || !listeners.get(e.info.id)?.domain) {
    const r = await oobEnable(e, { server: s.server, ...(s.tokenSecret ? { tokenSecret: s.tokenSecret } : {}) });
    pub = r.public;
    s = oobState(e);
  }
  const base = s.base ?? listenerFor(e).domain!;
  const tag = `o${randomBytes(5).toString("hex")}`;
  const entry: OobTag = { tag, purpose: opts.purpose, ...(opts.target ? { target: opts.target } : {}), by: opts.by, at: new Date().toISOString() };
  save(e, { ...s, tags: [...s.tags, entry] });
  return { address: `${tag}.${base}`, tag, base, server: s.server, public: pub };
}

export function oobDisable(e: Engagement): void {
  listeners.get(e.info.id)?.stop();
  listeners.delete(e.info.id);
  save(e, { ...oobState(e), enabled: false });
}

export function closeOob(engagementId: string): void {
  listeners.get(engagementId)?.stop();
  listeners.delete(engagementId);
}

export function closeAllOob(): void {
  for (const l of listeners.values()) l.stop();
  listeners.clear();
}

/** Re-opens the listeners of engagements that had OOB on, after a restart (keeps their domain). */
export async function resumeOob(engagements: Engagement[]): Promise<void> {
  for (const e of engagements) {
    if (oobState(e).enabled) await listenerFor(e).start().catch(() => undefined);
  }
}
