import type { FuzzResult } from "./fuzz.js";
import { Vault } from "./vault.js";
import { chmodSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  type Actor,
  apexOf,
  autonomyOf,
  type EdgeType,
  ENTITY_ATTRIBUTES,
  type EngagementAttributes,
  normalizeMode,
  roundModeOf,
  type EntityKind,
  type AnyEntityKind,
  type PluginKind,
  type IngestBatch,
  isPluginKind,
  jsonBytes,
  MAX_ANNOTATION_BYTES,
  ownerOfKind,
  isEdgeAllowed,
  isKeyedKind,
  type KeyFields,
  naturalKeyFor,
  normalizeFqdn,
  normalizeIp,
  normalizeOrigin,
  pathTemplate,
  type RiskLevel,
  type ScopeRuleAttributes,
  ulid,
} from "@penteos/schema";
import Database from "./store/sqlite.js";
import { EventEmitter } from "node:events";
import { mergeSightings, type FieldConflict, type SightingInput } from "./merge.js";
import { evaluateScope, type ActorPolicy, type ScopeDecision, type ScopeRule } from "./scope/evaluate.js";
import { canonicalJson, sha256Hex } from "./store/hash.js";
import { ENGAGEMENT_SCHEMA } from "./store/sql.js";
import { dormantReason, type PluginTypeRegistry, pluginTypes } from "./plugins/types.js";

export interface EngagementInfo extends EngagementAttributes {
  id: string;
  clientName: string;
}

export interface ProxyEntry {
  seq: number;
  id: string;
  at: string;
  /** Who sent it: the project browser, an external proxy (Burp, Caido…), the fuzzer… */
  source: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status?: number;
  mime?: string;
  reqSize: number;
  resSize: number;
  /** Time on the network (Penteos → server → Penteos), without the time held in interception. */
  durationMs?: number;
  /** Time the request or response waited in the interception queue for the operator. */
  heldMs?: number;
  inScope: boolean;
  blocked: boolean;
  reason?: string;
  rawId?: string;
  /** Bytes of the request inside the raw exchange (the response follows after a blank line). */
  requestLength?: number;
  /** "2" for HTTP/2 between the client and Penteos. */
  httpVersion?: string;
  error?: string;
  static: boolean;
  /** Changed by the operator (interception) or by a replace rule before it left. */
  edited: boolean;
  note?: string;
  highlight?: string;
}

export interface WsMessage {
  seq: number;
  entryId: string;
  at: string;
  /** out: client → server; in: server → client. */
  direction: "out" | "in";
  opcode: number;
  /** Text, or base64 when binary. */
  data: string;
  binary: boolean;
  size: number;
  edited: boolean;
}

export interface ProxyQuery {
  limit?: number;
  /** Only entries after this sequence number (for live updates). */
  afterSeq?: number;
  beforeSeq?: number;
  text?: string;
  host?: string;
  methods?: string[];
  status?: "2xx" | "3xx" | "4xx" | "5xx" | "error";
  inScopeOnly?: boolean;
  includeBlocked?: boolean;
  includeStatic?: boolean;
}

export interface SecretInfo {
  name: string;
  kind: string;
  note?: string;
  createdBy: Actor;
  createdAt: string;
  ref: string;
}

export interface Entity {
  id: string;
  /** An official kind, or a plugin's own (`acme.shodan:banner`), which may be dormant. */
  kind: AnyEntityKind;
  naturalKey: string;
  attributes: Record<string, unknown>;
  conflicts: FieldConflict[];
  tags: string[];
  outOfScope: boolean;
  createdAt: string;
  createdBy: Actor;
  updatedAt: string;
  revision: number;
  /** Plugin annotations, by plugin id (only on a single-entity read). */
  ext?: Record<string, Record<string, unknown>>;
}

/** Thrown when writing to an entity type whose plugin is not running. */
export class DormantTypeError extends Error {
  readonly code = "PLUGIN_UNAVAILABLE";
  constructor(readonly kind: string) {
    super(dormantReason(kind));
    this.name = "DormantTypeError";
  }
}

export interface EdgeRow {
  id: string;
  type: EdgeType;
  from: { kind: AnyEntityKind; id: string };
  to: { kind: AnyEntityKind; id: string };
  firstSeen: string;
  lastSeen: string;
}

export interface Run {
  id: string;
  actor: Actor;
  origin: "terminal" | "runner" | "agent_tool" | "import" | "api";
  tool?: string;
  command?: string;
  targets: string[];
  risk: RiskLevel;
  policy: { result: "allowed" | "approved" | "denied" | "unchecked"; ruleId?: string; reason?: string };
  runner: string;
  status: "running" | "finished" | "failed" | "denied" | "cancelled";
  startedAt: string;
  endedAt?: string;
  exitCode?: number;
  rawIds: string[];
  summary?: Record<string, unknown>;
  /** MITRE ATT&CK techniques this execution corresponds to (shown in the operator log). */
  attack?: string[];
}

export interface AuditEvent {
  seq: number;
  at: string;
  actor: Actor;
  action: string;
  subject?: unknown;
  payloadHash: string;
  prevHash: string;
  hash: string;
}

export type ChangeEvent =
  | { type: "entity.created" | "entity.updated"; kind: AnyEntityKind; id: string }
  | { type: "edge.created"; edgeType: EdgeType; id: string }
  | { type: "run.started" | "run.finished"; id: string }
  | { type: "run.output"; id: string; chunk: string; offset: number }
  | { type: "tool.installed"; tool: string; version: string }
  /** A gap (something a missing tool kept from being done) opened, changed or closed. */
  | { type: "gap.changed"; id: string }
  /** A gap was taken up again because its tool is now there: the run doing it. */
  | { type: "gap.resumed"; id: string; capability: string; tool: string; runId?: string; status: string; requestedBy: Actor }
  | { type: "approval.changed" }
  /** A request waited past its expiry with no decision. */
  | { type: "approval.expired"; id: string; summary: string; requestedBy: Actor }
  | { type: "approval.resolved"; id: string; approved: boolean; summary: string; requestedBy: Actor; decidedBy: Actor; runId?: string; result?: string }
  /** The operator answered a question an agent left on the board (the agent hears it). */
  | { type: "task.answered"; taskId: string; title: string; question: string; answer: string; by: Actor; askedBy?: Actor }
  /** The list of questions for the client changed; one of them got the client's answer. */
  | { type: "client_questions.changed" }
  /** Something a test left on the target was recorded or resolved. */
  | { type: "traces.changed" }
  /** The operator noted something about how the run went. */
  | { type: "metrics.changed" }
  /** The target contacted our out-of-band server: an interaction came in (likely a blind vuln). */
  | { type: "oob.interaction"; id: string; protocol: string; fullId: string; remote: string; tag?: string; purpose?: string; rawId?: string; requestedBy?: Actor }
  | { type: "client_question.answered"; id: string; question: string; answer: string; by: Actor }
  | { type: "audit.appended"; seq: number; action: string }
  | { type: "engagement.updated" }
  | { type: "scope.changed" }
  | { type: "schedule.completed"; id: string; label: string; headline: string }
  | { type: "proxy.entry"; id: string; seq: number }
  /** A host that answered before stopped accepting connections: likely this machine's IP was blocked. */
  | { type: "host.unreachable"; host: string; failures: number; lastOkAt: string }
  /** The operator finished (or declined) browsing what an agent asked for. */
  | { type: "browse.responded"; taskId: string; title: string; outcome: "done" | "declined"; exchanges: number; hosts: string[]; note?: string; by: Actor; askedBy?: Actor }
  | { type: "intercept.changed" }
  /** A finding got an independent verdict (the Maestro hears about it). */
  /** An in-scope site redirects to a host outside the scope. */
  | { type: "scope.redirect_outside"; from: string; to: string; host: string }
  | { type: "verification.done"; findingId: string; title: string; verdict: string; summary: string }
  /** A serious finding has open impact questions (reach, what the exposed data allows, chains). */
  | { type: "finding.deepen"; findingId: string; title: string; severity: string; open: string[] }
  /** Messages have been held in interception for a while with nobody deciding. */
  | { type: "intercept.stalled"; waiting: number }
  /** An agent changed how the proxy treats the operator's traffic (shown to the operator). */
  /** An agent changed the proxy. `text` is English (for agents and logs); the interface builds its own from the rest. */
  | { type: "proxy.agent_changed"; text: string; change?: "intercept" | "release" | "rules"; on?: string[]; count?: number; reason?: string }
  | { type: "fuzz.progress"; runId: string; done: number; total: number; anomalies: number }
  | { type: "ws.message"; entryId: string; seq: number }
  /** The panic button: every agent of the project paused or resumed. */
  | { type: "agents.paused"; paused: boolean; by: Actor }
  /** A plugin told the operator something (rate-limited by the plugin runtime). */
  | { type: "plugin.notify"; pluginId: string; pluginName: string; title: string; body?: string; level: "info" | "warn" }
  /** A free plugin did something worth knowing (reached a host outside the scope, sent the client's data): Penteos tells, it does not stop it. */
  | { type: "plugin.alert"; pluginId: string; pluginName: string; kind: "destination" | "client_data"; text: string }
  /** The Maestro needs a setting (a key, an account) from the operator to finish a plugin. */
  | { type: "plugin.setting_requested"; draftId: string; name: string; setting: string; label: string; secret: boolean; reason: string }
  /** The operator gave what the Maestro asked for (the Maestro hears it; never the value). */
  | { type: "plugin.setting_given"; draftId: string; name: string; settings: string[] }
  /** A plugin the Maestro built failed when a person used it (the Maestro hears it, to fix it). */
  | { type: "plugin.failed"; pluginId: string; name: string; operation: string; error: string; input: Record<string, unknown>; own?: boolean };

export class IngestError extends Error {
  constructor(
    message: string,
    readonly itemIndex?: number,
  ) {
    super(itemIndex === undefined ? message : `item ${itemIndex}: ${message}`);
    this.name = "IngestError";
  }
}

export interface IngestSummary {
  created: Partial<Record<EntityKind, number>>;
  updated: Partial<Record<EntityKind, number>>;
  edges: number;
  conflicts: number;
}

const GENESIS = "0".repeat(64);

/** Fields derived from the natural key: fixed at creation, never merged from sightings. */
function structuralFields(kind: EntityKind, key: KeyFields, context: string): Record<string, unknown> {
  switch (kind) {
    case "host":
      return { ip: normalizeIp(String(key.ip)), networkContext: String(key.networkContext ?? context) };
    case "domain": {
      const fqdn = normalizeFqdn(String(key.fqdn));
      return { fqdn, apex: apexOf(fqdn) };
    }
    case "service":
      return { transport: String(key.transport).toLowerCase(), port: Number(key.port) };
    case "webapp":
      return { origin: normalizeOrigin(String(key.origin)) };
    case "endpoint":
      return {
        pathTemplate: pathTemplate(String(key.path)),
        ...(key.operation === undefined ? {} : { operation: String(key.operation) }),
      };
    case "principal":
      return { realm: String(key.realm), name: String(key.name) };
    default:
      return {};
  }
}

const STRUCTURAL: Partial<Record<EntityKind, string[]>> = {
  host: ["ip", "networkContext"],
  domain: ["fqdn", "apex"],
  service: ["hostId", "transport", "port"],
  webapp: ["origin"],
  endpoint: ["webappId", "pathTemplate", "operation"],
  principal: ["realm", "name"],
};

/** Kinds that may be created implicitly when another item references them. */
const AUTO_CREATE: ReadonlySet<EntityKind> = new Set(["host", "domain", "webapp"]);

/**
 * One engagement: its SQLite database, raw artifact store and audit chain. All mutations go
 * through this class so provenance and audit can never be skipped.
 */
export class Engagement {
  readonly events = new EventEmitter();
  private readonly db: Database.Database;

  private constructor(
    readonly dir: string,
    db: Database.Database,
    /** The plugin types this project validates against (a sandbox brings its own). */
    readonly types: PluginTypeRegistry,
  ) {
    this.db = db;
  }

  static open(dir: string, types: PluginTypeRegistry = pluginTypes): Engagement {
    mkdirSync(join(dir, "raw"), { recursive: true, mode: 0o700 });
    // The client's evidence lives here: readable by the operator only, also for folders made before.
    for (const d of [dir, join(dir, "raw")]) {
      try {
        chmodSync(d, 0o700);
      } catch {
        /* not ours to change (a mounted or shared folder): leave it */
      }
    }
    const db = new Database(join(dir, "engagement.db"));
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.exec(ENGAGEMENT_SCHEMA);
    db.exec(`create table if not exists proxy_history (
      seq integer primary key autoincrement,
      id text not null unique,
      at text not null,
      source text not null,
      method text not null,
      url text not null,
      host text not null,
      path text not null,
      status integer,
      mime text,
      req_size integer not null default 0,
      res_size integer not null default 0,
      duration_ms integer,
      in_scope integer not null,
      blocked integer not null default 0,
      reason text,
      raw_id text,
      request_length integer,
      http_version text,
      held_ms integer,
      error text,
      static integer not null default 0,
      edited integer not null default 0,
      note text,
      highlight text
    )`);
    db.exec("create index if not exists proxy_history_host on proxy_history (host)");
    db.exec(`create table if not exists ws_messages (
      seq integer primary key autoincrement,
      entry_id text not null,
      at text not null,
      direction text not null,
      opcode integer not null,
      data text not null,
      binary integer not null,
      size integer not null,
      edited integer not null default 0
    )`);
    db.exec("create index if not exists ws_messages_entry on ws_messages (entry_id, seq)");
    db.exec(`create table if not exists fuzz_results (
      run_id text not null,
      idx integer not null,
      payloads text not null,
      position integer,
      status integer,
      length integer not null,
      words integer not null,
      lines integer not null,
      time_ms integer not null,
      error text,
      matches text not null,
      extracted text,
      anomalies text not null,
      raw_id text,
      primary key (run_id, idx)
    )`);
    db.exec(`create table if not exists secrets (
      name text primary key,
      kind text not null,
      value text not null,
      note text,
      created_by text not null,
      created_at text not null
    )`);
    // Plugin annotations on entities: a space of their own, never an official field.
    db.exec(`create table if not exists entity_ext (
      entity_id text not null,
      plugin_id text not null,
      data text not null,
      updated_at text not null,
      updated_by text not null,
      primary key (entity_id, plugin_id)
    )`);
    db.exec("create index if not exists entity_ext_plugin on entity_ext (plugin_id)");
    return new Engagement(dir, db, types);
  }

  private readonly closeHooks = new Set<() => void>();

  /** Runs before the database closes (plugin databases of this project close with it). */
  onClose(hook: () => void): () => void {
    this.closeHooks.add(hook);
    return () => this.closeHooks.delete(hook);
  }

  close(): void {
    for (const hook of [...this.closeHooks]) {
      try {
        hook();
      } catch {
        /* a hook must not keep the project open */
      }
    }
    this.closeHooks.clear();
    this.db.close();
  }

  /** Whether values can be sealed with the project's key (sensitive plugin columns require it). */
  get hasVault(): boolean {
    return this.vault !== undefined;
  }

  /** A consistent copy of this engagement's database into `file`, safe while it is open (for export). */
  async backupTo(file: string): Promise<void> {
    await this.db.backup(file);
  }

  emit(event: ChangeEvent): void {
    this.events.emit("change", event);
  }

  // -------------------------------------------------------------------------------------------
  // Engagement metadata
  // -------------------------------------------------------------------------------------------

  get info(): EngagementInfo {
    const row = this.db.prepare("select value from meta where key = 'engagement'").get() as { value: string } | undefined;
    if (!row) throw new Error(`engagement metadata missing in ${this.dir}`);
    const raw = JSON.parse(row.value) as Record<string, unknown> & EngagementInfo;
    return {
      ...raw,
      mode: normalizeMode(String(raw.mode)),
      roundMode: roundModeOf(raw),
      autonomy: autonomyOf(raw),
      plugins: Array.isArray(raw.plugins) ? (raw.plugins as unknown[]).filter((p): p is string => typeof p === "string") : [],
    };
  }

  // -------------------------------------------------------------------------------------------
  // Proxy history
  // -------------------------------------------------------------------------------------------

  addProxyEntry(e: Omit<ProxyEntry, "seq">): ProxyEntry {
    const r = this.db
      .prepare(
        `insert into proxy_history (id, at, source, method, url, host, path, status, mime, req_size, res_size, duration_ms, in_scope, blocked, reason, raw_id, request_length, http_version, held_ms, error, static, edited, note, highlight)
         values (@id, @at, @source, @method, @url, @host, @path, @status, @mime, @reqSize, @resSize, @durationMs, @inScope, @blocked, @reason, @rawId, @requestLength, @httpVersion, @heldMs, @error, @static, @edited, @note, @highlight)`,
      )
      .run({
        ...e,
        status: e.status ?? null,
        mime: e.mime ?? null,
        durationMs: e.durationMs ?? null,
        inScope: e.inScope ? 1 : 0,
        blocked: e.blocked ? 1 : 0,
        reason: e.reason ?? null,
        rawId: e.rawId ?? null,
        requestLength: e.requestLength ?? null,
        httpVersion: e.httpVersion ?? null,
        heldMs: e.heldMs ?? null,
        error: e.error ?? null,
        static: e.static ? 1 : 0,
        edited: e.edited ? 1 : 0,
        note: e.note ?? null,
        highlight: e.highlight ?? null,
      });
    const entry = { ...e, seq: Number(r.lastInsertRowid) };
    this.emit({ type: "proxy.entry", id: e.id, seq: entry.seq });
    if (!e.blocked) this.noteReachability(e.host, e.status !== undefined && e.status !== null, e.error);
    return entry;
  }

  /** Per host: when it last answered, and how many connection failures came after. */
  private readonly reach = new Map<string, { lastOkAt?: string; failures: number; reported: boolean }>();

  /**
   * Firewalls on the target (CSF, fail2ban, a WAF) often ban the tester's IP after a scan: the
   * host simply stops accepting connections. After two connection failures in a row on a host that
   * answered before, say so once, so the agents stop hammering it and the operator can ask the
   * client to allow the IP.
   */
  noteReachability(host: string, ok: boolean, error?: string): void {
    const h = host.toLowerCase();
    const cur = this.reach.get(h) ?? { failures: 0, reported: false };
    if (ok) {
      this.reach.set(h, { lastOkAt: new Date().toISOString(), failures: 0, reported: false });
      return;
    }
    if (!error || !/no TCP connection|did not answer within|ETIMEDOUT|ECONNREFUSED|ECONNRESET|socket hang up/i.test(error)) return;
    cur.failures++;
    this.reach.set(h, cur);
    if (cur.lastOkAt && cur.failures >= 2 && !cur.reported) {
      cur.reported = true;
      this.emit({ type: "host.unreachable", host: h, failures: cur.failures, lastOkAt: cur.lastOkAt });
    }
  }

  /** Hosts that answered before and stopped accepting connections (likely a ban on the tester's IP). */
  unreachableHosts(): string[] {
    return [...this.reach.entries()].filter(([, v]) => v.reported).map(([h]) => h);
  }

  private rowToProxy(r: Record<string, unknown>): ProxyEntry {
    const opt = <T>(v: unknown) => (v === null || v === undefined ? undefined : (v as T));
    const out: ProxyEntry = {
      seq: r.seq as number,
      id: r.id as string,
      at: r.at as string,
      source: r.source as string,
      method: r.method as string,
      url: r.url as string,
      host: r.host as string,
      path: r.path as string,
      reqSize: r.req_size as number,
      resSize: r.res_size as number,
      inScope: r.in_scope === 1,
      blocked: r.blocked === 1,
      static: r.static === 1,
      edited: r.edited === 1,
    };
    const extra: Partial<ProxyEntry> = {
      status: opt<number>(r.status),
      mime: opt<string>(r.mime),
      durationMs: opt<number>(r.duration_ms),
      reason: opt<string>(r.reason),
      rawId: opt<string>(r.raw_id),
      requestLength: opt<number>(r.request_length),
      httpVersion: opt<string>(r.http_version),
      heldMs: opt<number>(r.held_ms),
      error: opt<string>(r.error),
      note: opt<string>(r.note),
      highlight: opt<string>(r.highlight),
    };
    for (const [k, v] of Object.entries(extra)) if (v !== undefined) (out as unknown as Record<string, unknown>)[k] = v;
    return out;
  }

  queryProxy(q: ProxyQuery = {}): ProxyEntry[] {
    const where: string[] = [];
    const params: Record<string, unknown> = {};
    if (q.afterSeq !== undefined) (where.push("seq > @afterSeq"), (params.afterSeq = q.afterSeq));
    if (q.beforeSeq !== undefined) (where.push("seq < @beforeSeq"), (params.beforeSeq = q.beforeSeq));
    if (q.host) (where.push("host = @host"), (params.host = q.host));
    if (q.text) (where.push("(url like @text or note like @text)"), (params.text = `%${q.text}%`));
    if (q.methods?.length) {
      where.push(`method in (${q.methods.map((_, i) => `@m${i}`).join(",")})`);
      q.methods.forEach((m, i) => (params[`m${i}`] = m));
    }
    if (q.status === "error") where.push("(error is not null)");
    else if (q.status) (where.push("status >= @smin and status < @smax"), (params.smin = Number(q.status[0]) * 100), (params.smax = Number(q.status[0]) * 100 + 100));
    if (q.inScopeOnly) where.push("in_scope = 1");
    if (!q.includeBlocked) where.push("blocked = 0");
    if (!q.includeStatic) where.push("static = 0");
    const sql = `select * from proxy_history ${where.length ? `where ${where.join(" and ")}` : ""} order by seq desc limit ${Math.min(Math.max(q.limit ?? 500, 1), 5000)}`;
    return (this.db.prepare(sql).all(params) as Array<Record<string, unknown>>).map((r) => this.rowToProxy(r));
  }

  getProxyEntry(id: string): ProxyEntry | undefined {
    const r = this.db.prepare("select * from proxy_history where id = ?").get(id) as Record<string, unknown> | undefined;
    return r ? this.rowToProxy(r) : undefined;
  }

  annotateProxyEntry(id: string, patch: { note?: string; highlight?: string | null }): ProxyEntry | undefined {
    if (patch.note !== undefined) this.db.prepare("update proxy_history set note = ? where id = ?").run(patch.note || null, id);
    if (patch.highlight !== undefined) this.db.prepare("update proxy_history set highlight = ? where id = ?").run(patch.highlight, id);
    return this.getProxyEntry(id);
  }

  proxyHosts(): Array<{ host: string; count: number; inScope: boolean }> {
    return (this.db.prepare("select host, count(*) as count, max(in_scope) as in_scope from proxy_history where blocked = 0 group by host order by count desc").all() as Array<{ host: string; count: number; in_scope: number }>).map(
      (r) => ({ host: r.host, count: r.count, inScope: r.in_scope === 1 }),
    );
  }

  // -------------------------------------------------------------------------------------------
  // WebSocket messages (of a proxy entry: the handshake)
  // -------------------------------------------------------------------------------------------

  addWsMessage(m: { entryId: string; direction: "out" | "in"; opcode: number; payload: Buffer; edited?: boolean }): WsMessage {
    const MAX = 1024 * 1024;
    const binary = m.opcode === 2 || !Buffer.from(m.payload.toString("utf8"), "utf8").equals(m.payload);
    const kept = m.payload.subarray(0, MAX);
    const data = binary ? kept.toString("base64") : kept.toString("utf8");
    const at = new Date().toISOString();
    const r = this.db
      .prepare("insert into ws_messages (entry_id, at, direction, opcode, data, binary, size, edited) values (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(m.entryId, at, m.direction, m.opcode, data, binary ? 1 : 0, m.payload.length, m.edited ? 1 : 0);
    const seq = Number(r.lastInsertRowid);
    this.emit({ type: "ws.message", entryId: m.entryId, seq });
    return { seq, entryId: m.entryId, at, direction: m.direction, opcode: m.opcode, data, binary, size: m.payload.length, edited: Boolean(m.edited) };
  }

  queryWs(entryId: string, q: { afterSeq?: number; limit?: number } = {}): WsMessage[] {
    return (
      this.db
        .prepare("select * from ws_messages where entry_id = ? and seq > ? order by seq limit ?")
        .all(entryId, q.afterSeq ?? 0, Math.min(q.limit ?? 1000, 10_000)) as Array<Record<string, unknown>>
    ).map((r) => ({
      seq: r.seq as number,
      entryId: r.entry_id as string,
      at: r.at as string,
      direction: r.direction as "out" | "in",
      opcode: r.opcode as number,
      data: r.data as string,
      binary: r.binary === 1,
      size: r.size as number,
      edited: r.edited === 1,
    }));
  }

  // -------------------------------------------------------------------------------------------
  // Fuzzer results
  // -------------------------------------------------------------------------------------------

  addFuzzResults(runId: string, results: FuzzResult[]): void {
    const ins = this.db.prepare(
      `insert or replace into fuzz_results (run_id, idx, payloads, position, status, length, words, lines, time_ms, error, matches, extracted, anomalies, raw_id)
       values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    this.db.transaction(() => {
      for (const r of results)
        ins.run(runId, r.index, JSON.stringify(r.payloads), r.position ?? null, r.status ?? null, r.length, r.words, r.lines, r.timeMs, r.error ?? null, JSON.stringify(r.matches), r.extracted ?? null, JSON.stringify(r.anomalies), r.rawId ?? null);
    })();
  }

  /**
   * Fuzzing results with their anomalies. Besides what is wrong on its own (errors, grep matches,
   * slowness), a response is flagged when it is uncommon in this attack: what most payloads get
   * back (same status and word count) is "normal", the rest stands out. With few results, the
   * reference is the baseline (the original request).
   */
  queryFuzz(runId: string, q: { onlyAnomalies?: boolean; limit?: number; offset?: number; sort?: "index" | "status" | "length" | "time" } = {}): { total: number; anomalies: number; rows: FuzzResult[] } {
    const groups = this.db
      .prepare("select status, words, count(*) as n, avg(length) as len from fuzz_results where run_id = ? and error is null and idx > 0 group by status, words order by n desc")
      .all(runId) as Array<{ status: number | null; words: number; n: number; len: number }>;
    const sent = groups.reduce((a, g) => a + g.n, 0);
    const top = groups[0];
    const fragmented = groups.length > Math.max(3, sent * 0.5);
    const base = this.db.prepare("select status, length, words from fuzz_results where run_id = ? and idx = 0").get(runId) as { status: number | null; length: number; words: number } | undefined;
    const byMajority = Boolean(top && sent >= 5 && !fragmented);
    const ref = byMajority ? { status: top!.status, length: Math.round(top!.len), words: top!.words } : base;
    const commonEnough = (status: number | null, words: number) => {
      if (!byMajority) return true;
      const g = groups.find((x) => x.status === status && x.words === words);
      return Boolean(g && (g === top || g.n > Math.max(1, sent * 0.1)));
    };
    const relative = (r: { status?: number; length: number; words: number; index: number }): string[] => {
      if (!ref || r.index === 0) return [];
      if (byMajority && commonEnough(r.status ?? null, r.words)) return [];
      const out: string[] = [];
      if ((r.status ?? null) !== ref.status) out.push(`status ${ref.status ?? "-"}→${r.status ?? "-"}`);
      const delta = Math.abs(r.length - ref.length);
      if (delta > Math.max(50, ref.length * 0.05)) out.push(`size ${r.length > ref.length ? "+" : "−"}${delta}`);
      if (byMajority && !out.length) out.push("uncommon");
      return out;
    };
    const order = q.sort === "status" ? "status desc, idx" : q.sort === "length" ? "length desc, idx" : q.sort === "time" ? "time_ms desc, idx" : "idx";
    const toRow = (r: Record<string, unknown>): FuzzResult => {
      const row: FuzzResult = {
        index: r.idx as number,
        payloads: JSON.parse(r.payloads as string) as string[],
        ...(r.position !== null ? { position: r.position as number } : {}),
        ...(r.status !== null ? { status: r.status as number } : {}),
        length: r.length as number,
        words: r.words as number,
        lines: r.lines as number,
        timeMs: r.time_ms as number,
        ...(r.error ? { error: r.error as string } : {}),
        matches: JSON.parse(r.matches as string) as string[],
        ...(r.extracted ? { extracted: r.extracted as string } : {}),
        anomalies: JSON.parse(r.anomalies as string) as string[],
        ...(r.raw_id ? { rawId: r.raw_id as string } : {}),
      };
      return { ...row, anomalies: [...row.anomalies, ...(row.error ? [] : relative(row))] };
    };
    const limit = Math.min(q.limit ?? 500, 5000);
    const offset = q.offset ?? 0;
    const total = (this.db.prepare("select count(*) as n from fuzz_results where run_id = ?").get(runId) as { n: number }).n;
    // Anomalies depend on the whole attack: computed over every row (light columns only).
    const all = (this.db.prepare(`select * from fuzz_results where run_id = ? order by ${order}`).all(runId) as Array<Record<string, unknown>>).map(toRow);
    const flagged = all.filter((r) => r.anomalies.length > 0);
    const list = q.onlyAnomalies ? flagged : all;
    return { total: list.length, anomalies: flagged.length, rows: list.slice(offset, offset + limit) };
  }

  // -------------------------------------------------------------------------------------------
  // Secrets: credentials, tokens and session cookies, used by reference ({{secret:name}}) so
  // their values never appear in commands, logs, conversations or findings.
  // -------------------------------------------------------------------------------------------

  private vault?: Vault;

  /** Secrets are encrypted with the engagement's key; any saved before the key was set are sealed now. */
  useVault(vault: Vault): void {
    this.vault = vault;
    const rows = this.db.prepare("select name, value from secrets").all() as Array<{ name: string; value: string }>;
    const update = this.db.prepare("update secrets set value = ? where name = ?");
    for (const r of rows) if (!Vault.isSealed(r.value)) update.run(vault.seal(r.value), r.name);
  }

  /** Encrypts a value with the engagement's key (the pseudonym vault keeps real values this way). */
  seal(value: string): string {
    return this.sealed(value);
  }

  unseal(value: string): string {
    return this.unsealed(value);
  }

  private sealed(value: string): string {
    return this.vault ? this.vault.seal(value) : value;
  }

  private unsealed(value: string): string {
    if (!Vault.isSealed(value)) return value;
    if (!this.vault) throw new Error("secrets are encrypted and the vault key is not available");
    return this.vault.open(value);
  }

  saveSecret(input: { name: string; kind: string; value: string; note?: string }, actor: Actor): SecretInfo {
    const name = input.name.trim().toLowerCase().replace(/[^a-z0-9_.-]+/g, "_");
    if (!name) throw new Error("secret name is empty");
    this.db
      .prepare(
        "insert into secrets (name, kind, value, note, created_by, created_at) values (?, ?, ?, ?, ?, ?) on conflict (name) do update set kind = excluded.kind, value = excluded.value, note = excluded.note",
      )
      .run(name, input.kind, this.sealed(input.value), input.note ?? null, JSON.stringify(actor), new Date().toISOString());
    // The audit records that it exists, never its value.
    this.audit(actor, "secret.save", { secret: name }, { name, kind: input.kind });
    this.emit({ type: "engagement.updated" });
    return this.secrets().find((x) => x.name === name)!;
  }

  secrets(): SecretInfo[] {
    return (this.db.prepare("select name, kind, note, created_by, created_at from secrets order by name").all() as Array<Record<string, string>>).map((r) => ({
      name: r.name!,
      kind: r.kind!,
      ...(r.note ? { note: r.note } : {}),
      createdBy: JSON.parse(r.created_by!) as Actor,
      createdAt: r.created_at!,
      ref: `{{secret:${r.name}}}`,
    }));
  }

  secretValue(name: string): string | undefined {
    const row = this.db.prepare("select value from secrets where name = ?").get(name) as { value: string } | undefined;
    return row ? this.unsealed(row.value) : undefined;
  }

  deleteSecret(name: string, actor: Actor): void {
    this.db.prepare("delete from secrets where name = ?").run(name);
    this.audit(actor, "secret.delete", { secret: name }, { name });
    this.emit({ type: "engagement.updated" });
  }

  /** {{secret:name}} → value, for the process only. Unknown names are reported. */
  resolveSecrets(argv: string[]): { argv: string[]; missing: string[] } {
    const missing: string[] = [];
    const out = argv.map((a) =>
      a.replace(/\{\{secret:([a-z0-9_.-]+)\}\}/gi, (whole, name: string) => {
        const v = this.secretValue(name.toLowerCase());
        if (v === undefined) {
          missing.push(name);
          return whole;
        }
        return v;
      }),
    );
    return { argv: out, missing };
  }

  /** Replaces every known secret value in a text by its reference. */
  redact(text: string): string {
    const rows = (this.db.prepare("select name, value from secrets").all() as Array<{ name: string; value: string }>).map((r) => ({ name: r.name, value: this.unsealed(r.value) }));
    let out = text;
    // Longest first, so a value that contains another is replaced whole.
    for (const r of rows.sort((a, b) => b.value.length - a.value.length)) {
      if (r.value.length < 4) continue;
      out = out.split(r.value).join(`{{secret:${r.name}}}`);
    }
    return out;
  }

  /** Small documents that belong to the engagement but are not graph entities (report draft…). */
  getMeta<T>(key: string): T | undefined {
    const row = this.db.prepare("select value from meta where key = ?").get(`doc:${key}`) as { value: string } | undefined;
    return row ? (JSON.parse(row.value) as T) : undefined;
  }

  /**
   * Internal working state that must survive a restart but is not a decision of its own (the
   * actions behind it are audited one by one): no audit entry, no change event.
   */
  getState<T>(key: string): T | undefined {
    const row = this.db.prepare("select value from meta where key = ?").get(`state:${key}`) as { value: string } | undefined;
    return row ? (JSON.parse(row.value) as T) : undefined;
  }

  setState(key: string, value: unknown): void {
    this.db.prepare("insert into meta (key, value) values (?, ?) on conflict (key) do update set value = excluded.value").run(`state:${key}`, JSON.stringify(value));
  }

  setMeta(key: string, value: unknown, actor: Actor): void {
    this.db
      .prepare("insert into meta (key, value) values (?, ?) on conflict (key) do update set value = excluded.value")
      .run(`doc:${key}`, JSON.stringify(value));
    this.audit(actor, `meta.${key}`, { key }, value);
    this.emit({ type: "engagement.updated" });
  }

  setInfo(info: EngagementInfo, actor: Actor, action = "engagement.update"): void {
    this.db
      .prepare("insert into meta (key, value) values ('engagement', ?) on conflict (key) do update set value = excluded.value")
      .run(JSON.stringify(info));
    this.audit(actor, action, { id: info.id }, info);
    this.emit({ type: "engagement.updated" });
  }

  // -------------------------------------------------------------------------------------------
  // Audit chain
  // -------------------------------------------------------------------------------------------

  audit(actor: Actor, action: string, subject: unknown, payload: unknown): AuditEvent {
    const last = this.db.prepare("select seq, hash from audit_events order by seq desc limit 1").get() as
      | { seq: number; hash: string }
      | undefined;
    const seq = (last?.seq ?? 0) + 1;
    const at = new Date().toISOString();
    const payloadHash = sha256Hex(canonicalJson(payload ?? null));
    const prevHash = last?.hash ?? GENESIS;
    const hash = sha256Hex(canonicalJson({ seq, at, actor, action, subject: subject ?? null, payloadHash, prevHash }));
    this.db
      .prepare(
        "insert into audit_events (seq, at, actor, action, subject, payload_hash, prev_hash, hash) values (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(seq, at, JSON.stringify(actor), action, subject === undefined ? null : JSON.stringify(subject), payloadHash, prevHash, hash);
    this.emit({ type: "audit.appended", seq, action });
    return { seq, at, actor, action, subject, payloadHash, prevHash, hash };
  }

  auditEvents(options: { limit?: number; beforeSeq?: number } = {}): AuditEvent[] {
    const rows = this.db
      .prepare("select * from audit_events where seq < ? order by seq desc limit ?")
      .all(options.beforeSeq ?? Number.MAX_SAFE_INTEGER, options.limit ?? 100) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      seq: r.seq as number,
      at: r.at as string,
      actor: JSON.parse(r.actor as string) as Actor,
      action: r.action as string,
      subject: r.subject === null ? undefined : (JSON.parse(r.subject as string) as unknown),
      payloadHash: r.payload_hash as string,
      prevHash: r.prev_hash as string,
      hash: r.hash as string,
    }));
  }

  /** Recomputes the whole chain. Returns the first broken sequence number, if any. */
  verifyAudit(): { ok: true; events: number } | { ok: false; brokenAt: number } {
    const rows = this.db.prepare("select * from audit_events order by seq asc").all() as Array<Record<string, unknown>>;
    let prev = GENESIS;
    for (const r of rows) {
      const subject = r.subject === null ? null : (JSON.parse(r.subject as string) as unknown);
      const expected = sha256Hex(
        canonicalJson({
          seq: r.seq,
          at: r.at,
          actor: JSON.parse(r.actor as string) as unknown,
          action: r.action,
          subject,
          payloadHash: r.payload_hash,
          prevHash: prev,
        }),
      );
      if (r.prev_hash !== prev || r.hash !== expected) return { ok: false, brokenAt: r.seq as number };
      prev = r.hash as string;
    }
    return { ok: true, events: rows.length };
  }

  // -------------------------------------------------------------------------------------------
  // Raw artifacts
  // -------------------------------------------------------------------------------------------

  putRaw(content: string | Uint8Array, meta: { type: string; mime: string; runId?: string; originalName?: string }): string {
    const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : content;
    const hex = sha256Hex(bytes);
    const dir = join(this.dir, "raw", hex.slice(0, 2), hex.slice(2, 4));
    const path = join(dir, hex);
    if (!existsSync(path)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(path, bytes, { mode: 0o600 });
    }
    this.db
      .prepare(
        "insert or ignore into raw_artifacts (sha256, type, mime, size, run_id, original_name, stored_at) values (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(hex, meta.type, meta.mime, bytes.length, meta.runId ?? null, meta.originalName ?? null, new Date().toISOString());
    return `sha256:${hex}`;
  }

  /** Whether a raw artifact with this reference was stored in this engagement. */
  hasRaw(ref: string): boolean {
    const hex = ref.replace(/^sha256:/, "");
    if (!/^[0-9a-f]{64}$/.test(hex)) return false;
    return Boolean(this.db.prepare("select 1 from raw_artifacts where sha256 = ?").get(hex));
  }

  /** A raw artifact's media type, as it was stored ("message/http", "image/png"…). */
  rawMime(ref: string): string | undefined {
    const hex = ref.replace(/^sha256:/, "");
    if (!/^[0-9a-f]{64}$/.test(hex)) return undefined;
    return (this.db.prepare("select mime from raw_artifacts where sha256 = ?").get(hex) as { mime?: string } | undefined)?.mime;
  }

  readRaw(ref: string): Buffer {
    const hex = ref.replace(/^sha256:/, "");
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`invalid raw reference: ${ref}`);
    return readFileSync(join(this.dir, "raw", hex.slice(0, 2), hex.slice(2, 4), hex));
  }

  // -------------------------------------------------------------------------------------------
  // Scope
  // -------------------------------------------------------------------------------------------

  scopeRules(): ScopeRule[] {
    return this.query({ kind: "scope_rule", limit: 10_000 }).map((e) => ({ id: e.id, ...(e.attributes as ScopeRuleAttributes) }));
  }

  addScopeRule(rule: ScopeRuleAttributes, actor: Actor): string {
    const parsed = ENTITY_ATTRIBUTES.scope_rule.parse(rule);
    const id = ulid();
    this.insertEntity(id, "scope_rule", id, parsed as Record<string, unknown>, actor);
    this.audit(actor, "scope.add_rule", { kind: "scope_rule", id }, parsed);
    this.refreshOutOfScope();
    this.emit({ type: "scope.changed" });
    return id;
  }

  /** Removes a task from the board (soft delete: it stays in the audit and the database). */
  deleteTask(id: string, actor: Actor): void {
    const result = this.db
      .prepare("update entities set deleted_at = ? where id = ? and kind = 'task' and deleted_at is null")
      .run(new Date().toISOString(), id);
    if (result.changes === 0) throw new Error(`task not found: ${id}`);
    this.audit(actor, "task.delete", { kind: "task", id }, { id });
    this.emit({ type: "entity.updated", kind: "task", id });
  }

  removeScopeRule(id: string, actor: Actor): void {
    const result = this.db
      .prepare("update entities set deleted_at = ? where id = ? and kind = 'scope_rule' and deleted_at is null")
      .run(new Date().toISOString(), id);
    if (result.changes === 0) throw new Error(`scope rule not found: ${id}`);
    this.audit(actor, "scope.remove_rule", { kind: "scope_rule", id }, { id });
    this.refreshOutOfScope();
    this.emit({ type: "scope.changed" });
  }

  checkScope(target: string, risk: RiskLevel, actor: ActorPolicy, networkContext?: string): ScopeDecision {
    return evaluateScope(this.info, this.scopeRules(), {
      target,
      risk,
      actor,
      ...(networkContext ? { networkContext } : {}),
    });
  }

  /** The address that represents an entity for scope purposes, if it has one. */
  /** The address a plugin entity declares for scope (its type's target field), if any. */
  private pluginTarget(kind: AnyEntityKind, attrs: Record<string, unknown>): string | null {
    if (!isPluginKind(kind)) return null;
    const field = this.types.type(kind)?.spec.target;
    const value = field ? attrs[field] : undefined;
    return typeof value === "string" && value ? value : null;
  }

  private scopeTargetOf(kind: AnyEntityKind, attrs: Record<string, unknown>): { target: string; context?: string } | undefined {
    if (isPluginKind(kind)) {
      const target = this.pluginTarget(kind, attrs);
      return target ? { target } : undefined;
    }
    if (kind === "host") return { target: String(attrs.ip), context: String(attrs.networkContext) };
    if (kind === "domain") return { target: String(attrs.fqdn) };
    if (kind === "webapp") return { target: String(attrs.origin) };
    if (kind === "service") {
      const host = this.get(String(attrs.hostId));
      if (!host) return undefined;
      const ip = String(host.attributes.ip);
      return { target: `${ip.includes(":") ? `[${ip}]` : ip}:${attrs.port}`, context: String(host.attributes.networkContext) };
    }
    return undefined;
  }

  private isOutOfScope(kind: AnyEntityKind, attrs: Record<string, unknown>): boolean {
    return this.targetOutOfScope(this.scopeTargetOf(kind, attrs));
  }

  /** Whether an address (host, IP, URL) is inside this project's scope (no risk or window rules). */
  inScope(target: string): boolean {
    return !this.targetOutOfScope({ target });
  }

  private targetOutOfScope(t: { target: string; context?: string } | undefined): boolean {
    if (!t) return false;
    const rules = this.scopeRules();
    const decision = evaluateScope({ maxRisk: "exploitation" }, rules, {
      target: t.target,
      risk: "passive",
      actor: { type: "human" },
      ...(t.context ? { networkContext: t.context } : {}),
    });
    return decision.decision === "deny" && decision.code === "OUT_OF_SCOPE";
  }

  private refreshOutOfScope(): void {
    const rows = this.db
      .prepare("select id, kind, attributes, out_of_scope, scope_target from entities where (kind in ('host','domain','webapp','service') or scope_target is not null) and deleted_at is null")
      .all() as Array<{ id: string; kind: AnyEntityKind; attributes: string; out_of_scope: number; scope_target: string | null }>;
    const update = this.db.prepare("update entities set out_of_scope = ? where id = ?");
    for (const r of rows) {
      // A plugin entity uses the address stored with it: this works with its plugin off, too.
      const out = (isPluginKind(r.kind) ? this.targetOutOfScope(r.scope_target ? { target: r.scope_target } : undefined) : this.isOutOfScope(r.kind, JSON.parse(r.attributes) as Record<string, unknown>)) ? 1 : 0;
      if (out !== r.out_of_scope) {
        update.run(out, r.id);
        this.emit({ type: "entity.updated", kind: r.kind, id: r.id });
      }
    }
  }

  // -------------------------------------------------------------------------------------------
  // Entities
  // -------------------------------------------------------------------------------------------

  private rowToEntity(r: Record<string, unknown>): Entity {
    return {
      id: r.id as string,
      kind: r.kind as AnyEntityKind,
      naturalKey: r.natural_key as string,
      attributes: JSON.parse(r.attributes as string) as Record<string, unknown>,
      conflicts: JSON.parse(r.conflicts as string) as FieldConflict[],
      tags: JSON.parse(r.tags as string) as string[],
      outOfScope: r.out_of_scope === 1,
      createdAt: r.created_at as string,
      createdBy: JSON.parse(r.created_by as string) as Actor,
      updatedAt: r.updated_at as string,
      revision: r.revision as number,
    };
  }

  get(id: string): Entity | undefined {
    const row = this.db.prepare("select * from entities where id = ? and deleted_at is null").get(id) as
      | Record<string, unknown>
      | undefined;
    if (!row) return undefined;
    const entity = this.rowToEntity(row);
    const ext = this.annotationsOf(id);
    return Object.keys(ext).length > 0 ? { ...entity, ext } : entity;
  }

  findByKey(kind: AnyEntityKind, naturalKey: string): Entity | undefined {
    const row = this.db
      .prepare("select * from entities where kind = ? and natural_key = ? and deleted_at is null")
      .get(kind, naturalKey) as Record<string, unknown> | undefined;
    return row ? this.rowToEntity(row) : undefined;
  }

  query(options: { kind?: AnyEntityKind; text?: string; limit?: number; offset?: number }): Entity[] {
    const where = ["deleted_at is null"];
    const params: unknown[] = [];
    if (options.kind) {
      where.push("kind = ?");
      params.push(options.kind);
    }
    if (options.text) {
      where.push("(natural_key like ? or attributes like ?)");
      params.push(`%${options.text}%`, `%${options.text}%`);
    }
    params.push(options.limit ?? 500, options.offset ?? 0);
    const rows = this.db
      .prepare(`select * from entities where ${where.join(" and ")} order by updated_at desc limit ? offset ?`)
      .all(...params) as Array<Record<string, unknown>>;
    return rows.map((r) => this.rowToEntity(r));
  }

  counts(): Partial<Record<AnyEntityKind, number>> {
    const rows = this.db
      .prepare("select kind, count(*) as n from entities where deleted_at is null group by kind")
      .all() as Array<{ kind: AnyEntityKind; n: number }>;
    return Object.fromEntries(rows.map((r) => [r.kind, r.n]));
  }

  edgesOf(id: string): EdgeRow[] {
    const rows = this.db
      .prepare("select * from edges where (from_id = ? or to_id = ?) and deleted_at is null")
      .all(id, id) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: r.id as string,
      type: r.type as EdgeType,
      from: { kind: r.from_kind as AnyEntityKind, id: r.from_id as string },
      to: { kind: r.to_kind as AnyEntityKind, id: r.to_id as string },
      firstSeen: r.first_seen as string,
      lastSeen: r.last_seen as string,
    }));
  }

  sightingsOf(id: string): Array<SightingInput & { id: string; rawId?: string; runId?: string }> {
    const rows = this.db
      .prepare("select * from sightings where subject_id = ? order by observed_at asc")
      .all(id) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: r.id as string,
      attributes: JSON.parse(r.attributes as string) as Record<string, unknown>,
      source: JSON.parse(r.source as string) as Actor,
      confidence: r.confidence as number,
      observedAt: r.observed_at as string,
      ...(r.raw_id ? { rawId: r.raw_id as string } : {}),
      ...(r.run_id ? { runId: r.run_id as string } : {}),
    }));
  }

  private insertEntity(id: string, kind: AnyEntityKind, naturalKey: string, attributes: Record<string, unknown>, actor: Actor): void {
    const now = new Date().toISOString();
    const out = this.isOutOfScope(kind, attributes) ? 1 : 0;
    this.db
      .prepare(
        "insert into entities (id, kind, natural_key, attributes, created_at, created_by, updated_at, revision, out_of_scope, scope_target) values (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
      )
      .run(id, kind, naturalKey, JSON.stringify(attributes), now, JSON.stringify(actor), now, out, this.pluginTarget(kind, attributes));
  }

  /** Adds or removes free tags ("owned", "pci", "legacy"…). */
  tag(id: string, add: string[], remove: string[], actor: Actor): Entity {
    const entity = this.get(id);
    if (!entity) throw new Error(`entity not found: ${id}`);
    const tags = [...new Set([...entity.tags.filter((t) => !remove.includes(t)), ...add])];
    this.db.prepare("update entities set tags = ?, updated_at = ? where id = ?").run(JSON.stringify(tags), new Date().toISOString(), id);
    this.audit(actor, "entity.tag", { kind: entity.kind, id }, { add, remove });
    this.emit({ type: "entity.updated", kind: entity.kind, id });
    return this.get(id)!;
  }

  /** Creates an entity that has no natural key (findings, notes, evidence, tasks…). */
  createEntity(kind: AnyEntityKind, attributes: Record<string, unknown>, actor: Actor): Entity {
    if (isPluginKind(kind)) return this.putPluginEntity(kind, attributes, actor).entity;
    const parsed = ENTITY_ATTRIBUTES[kind].parse(attributes) as Record<string, unknown>;
    const id = ulid();
    this.insertEntity(id, kind, id, parsed, actor);
    this.audit(actor, `${kind}.create`, { kind, id }, parsed);
    this.emit({ type: "entity.created", kind, id });
    return this.get(id)!;
  }

  /** Human or agent edit: the given fields become authoritative over automatic sources. */
  editEntity(id: string, fields: Record<string, unknown>, actor: Actor): Entity {
    const row = this.db.prepare("select * from entities where id = ? and deleted_at is null").get(id) as
      | Record<string, unknown>
      | undefined;
    if (!row) throw new Error(`entity not found: ${id}`);
    const entity = this.rowToEntity(row);
    const human = { ...(JSON.parse(row.human_fields as string) as Record<string, unknown>), ...fields };
    // One transaction: an edit that does not validate must leave nothing behind (it used to stay in
    // human_fields and make every later edit of the entity fail).
    this.db.transaction(() => {
      this.db.prepare("update entities set human_fields = ? where id = ?").run(JSON.stringify(human), id);
      this.recompute(entity.kind, id);
    })();
    this.audit(actor, `${entity.kind}.edit`, { kind: entity.kind, id }, fields);
    this.emit({ type: "entity.updated", kind: entity.kind, id });
    return this.get(id)!;
  }

  // -------------------------------------------------------------------------------------------
  // Plugin data in the graph
  // -------------------------------------------------------------------------------------------

  /**
   * Adds or updates an entity of a plugin's own type. A type with a key updates the entity with the
   * same key (the operator's edits still win); one without a key always adds. Dormant type: refused.
   */
  putPluginEntity(kind: PluginKind, attributes: Record<string, unknown>, actor: Actor): { entity: Entity; created: boolean } {
    const type = this.types.type(kind);
    if (!type) throw new DormantTypeError(kind);
    const parsed = type.schema.safeParse(attributes);
    if (!parsed.success) throw new IngestError(`invalid ${kind}: ${parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
    const attrs = parsed.data as Record<string, unknown>;
    const fieldType = new Map(type.spec.fields.map((f) => [f.name, f.type]));
    const naturalKey = type.spec.key
      ? type.spec.key
          .map((f) => {
            const v = String(attrs[f]).trim();
            return fieldType.get(f) === "host" || fieldType.get(f) === "url" ? v.toLowerCase() : v;
          })
          .join("|")
      : undefined;
    const existing = naturalKey ? this.db.prepare("select id, attributes, human_fields from entities where kind = ? and natural_key = ? and deleted_at is null").get(kind, naturalKey) as
      | { id: string; attributes: string; human_fields: string }
      | undefined : undefined;
    if (!existing) {
      const id = ulid();
      this.insertEntity(id, kind, naturalKey ?? id, attrs, actor);
      this.audit(actor, `${kind}.create`, { kind, id }, attrs);
      this.emit({ type: "entity.created", kind, id });
      return { entity: this.get(id)!, created: true };
    }
    const human = JSON.parse(existing.human_fields) as Record<string, unknown>;
    const next = type.schema.safeParse({ ...(JSON.parse(existing.attributes) as Record<string, unknown>), ...attrs, ...human });
    if (!next.success) throw new IngestError(`invalid ${kind}: ${next.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
    const nextAttrs = next.data as Record<string, unknown>;
    const out = this.isOutOfScope(kind, nextAttrs) ? 1 : 0;
    this.db
      .prepare("update entities set attributes = ?, out_of_scope = ?, scope_target = ?, updated_at = ?, revision = revision + 1 where id = ?")
      .run(JSON.stringify(nextAttrs), out, this.pluginTarget(kind, nextAttrs), new Date().toISOString(), existing.id);
    this.audit(actor, `${kind}.update`, { kind, id: existing.id }, attrs);
    this.emit({ type: "entity.updated", kind, id: existing.id });
    return { entity: this.get(existing.id)!, created: false };
  }

  /**
   * Sets a plugin's annotation on an official entity: merged into what it had (a null removes a
   * field), validated by the plugin's declared fields. Official attributes, revision and
   * conflicts are never touched.
   */
  annotate(entityId: string, pluginId: string, patch: Record<string, unknown>, actor: Actor): Record<string, unknown> {
    const row = this.db.prepare("select kind from entities where id = ? and deleted_at is null").get(entityId) as { kind: string } | undefined;
    if (!row) throw new Error(`entity not found: ${entityId}`);
    if (isPluginKind(row.kind)) throw new IngestError(`${row.kind} is a plugin type: it carries its own fields, annotations are for official entities`);
    const reg = this.types.annotation(pluginId, row.kind);
    if (!reg) {
      if (!this.types.pluginName(pluginId)) throw new DormantTypeError(`${pluginId}:annotation`);
      throw new IngestError(`${pluginId} does not declare annotations on ${row.kind} entities`);
    }
    const current = this.annotationOf(entityId, pluginId) ?? {};
    const merged: Record<string, unknown> = { ...current };
    for (const [k, v] of Object.entries(patch)) {
      if (v === null) delete merged[k];
      else merged[k] = v;
    }
    const parsed = reg.schema.safeParse(merged);
    if (!parsed.success) throw new IngestError(`invalid annotation from ${pluginId}: ${parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
    const data = parsed.data as Record<string, unknown>;
    if (jsonBytes(data) > MAX_ANNOTATION_BYTES) throw new IngestError(`an annotation is at most ${MAX_ANNOTATION_BYTES} bytes`);
    if (Object.keys(data).length === 0) {
      this.db.prepare("delete from entity_ext where entity_id = ? and plugin_id = ?").run(entityId, pluginId);
    } else {
      this.db
        .prepare(
          "insert into entity_ext (entity_id, plugin_id, data, updated_at, updated_by) values (?, ?, ?, ?, ?) on conflict(entity_id, plugin_id) do update set data = excluded.data, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        )
        .run(entityId, pluginId, JSON.stringify(data), new Date().toISOString(), JSON.stringify(actor));
    }
    this.audit(actor, "plugin.annotate", { kind: row.kind, id: entityId }, { plugin: pluginId, patch });
    this.emit({ type: "entity.updated", kind: row.kind as EntityKind, id: entityId });
    return data;
  }

  annotationOf(entityId: string, pluginId: string): Record<string, unknown> | undefined {
    const row = this.db.prepare("select data from entity_ext where entity_id = ? and plugin_id = ?").get(entityId, pluginId) as { data: string } | undefined;
    return row ? (JSON.parse(row.data) as Record<string, unknown>) : undefined;
  }

  /** Every plugin's annotation on an entity, including dormant plugins' (they are still data). */
  annotationsOf(entityId: string): Record<string, Record<string, unknown>> {
    const rows = this.db.prepare("select plugin_id, data from entity_ext where entity_id = ? order by plugin_id").all(entityId) as Array<{ plugin_id: string; data: string }>;
    return Object.fromEntries(rows.map((r) => [r.plugin_id, JSON.parse(r.data) as Record<string, unknown>]));
  }

  /** What a plugin left in this project's graph (for the Plugins section and before purging). */
  pluginFootprint(pluginId: string): { entities: Partial<Record<string, number>>; annotations: number } {
    const rows = this.db
      .prepare("select kind, count(*) as n from entities where kind like ? escape '\\' and deleted_at is null group by kind")
      .all(`${pluginId.replace(/[\\%_]/g, "\\$&")}:%`) as Array<{ kind: string; n: number }>;
    const annotations = (this.db.prepare("select count(*) as n from entity_ext where plugin_id = ?").get(pluginId) as { n: number }).n;
    return { entities: Object.fromEntries(rows.map((r) => [r.kind, r.n])), annotations };
  }

  /** Removes everything a plugin left in this project's graph: its entities, their edges, its annotations. */
  purgePluginData(pluginId: string, actor: Actor): { entities: number; annotations: number } {
    const like = `${pluginId.replace(/[\\%_]/g, "\\$&")}:%`;
    const now = new Date().toISOString();
    const result = this.db.transaction(() => {
      const ids = (this.db.prepare("select id from entities where kind like ? escape '\\' and deleted_at is null").all(like) as Array<{ id: string }>).map((r) => r.id);
      const markEntity = this.db.prepare("update entities set deleted_at = ? where id = ?");
      const markEdges = this.db.prepare("update edges set deleted_at = ? where (from_id = ? or to_id = ?) and deleted_at is null");
      for (const id of ids) {
        markEntity.run(now, id);
        markEdges.run(now, id, id);
      }
      const annotations = this.db.prepare("delete from entity_ext where plugin_id = ?").run(pluginId).changes;
      return { entities: ids.length, annotations };
    })();
    this.audit(actor, "plugin.purge_graph", { plugin: pluginId }, result);
    return result;
  }

  /**
   * Relates two entities (`related_to`), at least one of them a plugin's: how a plugin type joins
   * the official graph (a banner related to its host). Idempotent.
   */
  relate(fromId: string, toId: string, actor: Actor): EdgeRow {
    const from = this.get(fromId);
    const to = this.get(toId);
    if (!from || !to) throw new Error(`entity not found: ${!from ? fromId : toId}`);
    if (fromId === toId) throw new IngestError("an entity cannot be related to itself");
    if (!isPluginKind(from.kind) && !isPluginKind(to.kind)) throw new IngestError("relate links a plugin entity to another entity; official entities are related by ingest");
    for (const k of [from.kind, to.kind]) if (isPluginKind(k) && !this.types.type(k)) throw new DormantTypeError(k);
    const existing = this.db
      .prepare("select id from edges where type = 'related_to' and from_id = ? and to_id = ? and deleted_at is null")
      .get(fromId, toId) as { id: string } | undefined;
    const now = new Date().toISOString();
    if (existing) {
      this.db.prepare("update edges set last_seen = ? where id = ?").run(now, existing.id);
      return this.edgesOf(fromId).find((e) => e.id === existing.id)!;
    }
    const id = ulid();
    this.db
      .prepare("insert into edges (id, type, from_kind, from_id, to_kind, to_id, attributes, first_seen, last_seen) values (?, 'related_to', ?, ?, ?, ?, '{}', ?, ?)")
      .run(id, from.kind, fromId, to.kind, toId, now, now);
    this.audit(actor, "entity.relate", { from: fromId, to: toId }, { owner: ownerOfKind(from.kind) ?? ownerOfKind(to.kind) });
    this.emit({ type: "edge.created", edgeType: "related_to", id });
    return this.edgesOf(fromId).find((e) => e.id === id)!;
  }

  private recompute(kind: AnyEntityKind, id: string): { conflicts: number } {
    const row = this.db.prepare("select attributes, human_fields from entities where id = ?").get(id) as {
      attributes: string;
      human_fields: string;
    };
    const previous = JSON.parse(row.attributes) as Record<string, unknown>;
    const sightings = this.sightingsOf(id);
    const human = JSON.parse(row.human_fields) as Record<string, unknown>;

    if (sightings.length === 0 && Object.keys(human).length === 0) return { conflicts: 0 };

    if (isPluginKind(kind)) {
      // Plugin entities have no sightings: what the plugin put, with the operator's edits on top.
      const type = this.types.type(kind);
      if (!type) throw new DormantTypeError(kind);
      const parsedPlugin = type.schema.safeParse({ ...previous, ...human });
      if (!parsedPlugin.success) {
        throw new IngestError(`invalid ${kind} attributes: ${parsedPlugin.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
      }
      const attrs = parsedPlugin.data as Record<string, unknown>;
      this.db
        .prepare("update entities set attributes = ?, out_of_scope = ?, scope_target = ?, updated_at = ?, revision = revision + 1 where id = ?")
        .run(JSON.stringify(attrs), this.isOutOfScope(kind, attrs) ? 1 : 0, this.pluginTarget(kind, attrs), new Date().toISOString(), id);
      return { conflicts: 0 };
    }
    const merged = mergeSightings(kind, sightings, human);
    const structural = Object.fromEntries((STRUCTURAL[kind] ?? []).filter((f) => f in previous).map((f) => [f, previous[f]]));
    const candidate = sightings.length > 0 ? { ...merged.attributes, ...structural } : { ...previous, ...human };
    const parsed = ENTITY_ATTRIBUTES[kind].safeParse(candidate);
    if (!parsed.success) {
      throw new IngestError(`invalid ${kind} attributes: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
    }
    this.db
      .prepare("update entities set attributes = ?, conflicts = ?, updated_at = ?, revision = revision + 1 where id = ?")
      .run(JSON.stringify(parsed.data), JSON.stringify(merged.conflicts), new Date().toISOString(), id);
    return { conflicts: merged.conflicts.length };
  }

  // -------------------------------------------------------------------------------------------
  // Ingest
  // -------------------------------------------------------------------------------------------

  /**
   * Applies an ingest batch atomically. Every assertion becomes a
   * sighting, entity state is recomputed from sightings, and a single audit event covers the batch.
   */
  ingest(batch: IngestBatch, actor: Actor): IngestSummary {
    const context = batch.networkContext ?? "default";
    const source: Actor = { type: "parser", id: batch.source.parser };
    const summary: IngestSummary = { created: {}, updated: {}, edges: 0, conflicts: 0 };
    const events: ChangeEvent[] = [];
    const touched = new Map<string, EntityKind>();
    const created = new Set<string>();

    const resolve = (kind: EntityKind, key: KeyFields, allowCreate: boolean): string => {
      if (!isKeyedKind(kind)) throw new IngestError(`entities of kind "${kind}" cannot be referenced by key`);
      const naturalKey = naturalKeyFor(kind, key, context);
      const existing = this.findByKey(kind, naturalKey);
      if (existing) return existing.id;
      if (!allowCreate) throw new IngestError(`${kind} ${naturalKey} does not exist; upsert it before referencing it`);

      const attributes = structuralFields(kind, key, context);
      if (kind === "service") attributes.hostId = resolve("host", key, true);
      if (kind === "endpoint") attributes.webappId = resolve("webapp", { origin: key.origin! }, true);
      const id = ulid();
      if (kind === "host") attributes.status = "unknown";
      this.insertEntity(id, kind, naturalKey, attributes, source);
      created.add(id);
      touched.set(id, kind);
      summary.created[kind] = (summary.created[kind] ?? 0) + 1;
      events.push({ type: "entity.created", kind, id });
      return id;
    };

    const addSighting = (subjectType: "entity" | "edge", subjectId: string, attributes: Record<string, unknown>, confidence: number) => {
      this.db
        .prepare(
          "insert into sightings (id, subject_type, subject_id, attributes, source, raw_id, run_id, confidence, observed_at, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          ulid(),
          subjectType,
          subjectId,
          JSON.stringify(attributes),
          JSON.stringify(source),
          batch.rawIds[0]?.replace(/^sha256:/, "") ?? null,
          batch.runId ?? null,
          confidence,
          batch.observedAt,
          new Date().toISOString(),
        );
    };

    const apply = this.db.transaction(() => {
      batch.items.forEach((item, index) => {
        try {
          switch (item.op) {
            case "upsert": {
              const id = resolve(item.kind, item.key, true);
              addSighting("entity", id, item.attributes ?? {}, item.confidence ?? 1);
              touched.set(id, item.kind);
              break;
            }
            case "relate": {
              const fromId = resolve(item.from.kind, item.from.key, AUTO_CREATE.has(item.from.kind));
              const toId = resolve(item.to.kind, item.to.key, AUTO_CREATE.has(item.to.kind));
              if (!isEdgeAllowed(item.type, item.from.kind, item.to.kind)) {
                throw new IngestError(`relation ${item.type} is not allowed from ${item.from.kind} to ${item.to.kind}`);
              }
              const existing = this.db
                .prepare("select id from edges where type = ? and from_id = ? and to_id = ?")
                .get(item.type, fromId, toId) as { id: string } | undefined;
              const edgeId = existing?.id ?? ulid();
              if (existing) {
                this.db.prepare("update edges set last_seen = max(last_seen, ?), deleted_at = null where id = ?").run(batch.observedAt, edgeId);
              } else {
                this.db
                  .prepare(
                    "insert into edges (id, type, from_kind, from_id, to_kind, to_id, attributes, first_seen, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  )
                  .run(edgeId, item.type, item.from.kind, fromId, item.to.kind, toId, item.attributes ? JSON.stringify(item.attributes) : null, batch.observedAt, batch.observedAt);
                summary.edges++;
                events.push({ type: "edge.created", edgeType: item.type, id: edgeId });
              }
              addSighting("edge", edgeId, item.attributes ?? {}, item.confidence ?? 1);
              break;
            }
            case "observe": {
              const affects = item.affects.map((ref) => ({ kind: ref.kind, id: resolve(ref.kind, ref.key, AUTO_CREATE.has(ref.kind)) }));
              const naturalKey = `${item.sourceRule}|${affects.map((a) => a.id).sort().join(",")}|${item.location ?? ""}`;
              let obs = this.findByKey("observation", naturalKey);
              if (!obs) {
                const id = ulid();
                this.insertEntity(id, "observation", naturalKey, { title: item.title, sourceRule: item.sourceRule, affects }, source);
                created.add(id);
                summary.created.observation = (summary.created.observation ?? 0) + 1;
                events.push({ type: "entity.created", kind: "observation", id });
                obs = this.get(id)!;
              }
              addSighting("entity", obs.id, {
                title: item.title,
                sourceRule: item.sourceRule,
                affects,
                ...(item.location ? { location: item.location } : {}),
                ...(item.severityHint ? { severityHint: item.severityHint } : {}),
                ...(item.detail ? { detail: item.detail } : {}),
                ...(item.rawId ? { rawId: item.rawId } : {}),
              }, 1);
              touched.set(obs.id, "observation");
              break;
            }
            default:
              throw new IngestError(`op "${item.op}" is not supported yet`);
          }
        } catch (error) {
          if (error instanceof IngestError && error.itemIndex !== undefined) throw error;
          throw new IngestError((error as Error).message, index);
        }
      });

      for (const [id, kind] of touched) {
        summary.conflicts += this.recompute(kind, id).conflicts;
        if (!created.has(id)) {
          summary.updated[kind] = (summary.updated[kind] ?? 0) + 1;
          events.push({ type: "entity.updated", kind, id });
        }
      }

      this.audit(actor, "ingest.batch", { parser: batch.source.parser, runId: batch.runId ?? null }, { batch: sha256Hex(canonicalJson(batch)), summary });
    });

    apply();
    for (const e of events) this.emit(e);
    this.redirectsOutside(batch);
    return summary;
  }

  /** Hosts already reported as redirect destinations outside the scope (once each). */
  private readonly redirectHosts = new Set<string>();

  /**
   * An in-scope site that redirects somewhere out of scope (the apex to www, a login on another
   * host) blocks the work without saying why. Each such destination is reported once, so the
   * Maestro can ask for exactly that host instead of a whole wildcard.
   */
  private redirectsOutside(batch: IngestBatch): void {
    for (const item of batch.items) {
      if (item.op !== "observe" || !/:redirect$/.test(String(item.sourceRule ?? ""))) continue;
      const location = /^Redirects to (\S+)/.exec(String(item.title))?.[1];
      const origin = (item.affects ?? []).map((a) => (a.key as { origin?: string } | undefined)?.origin).find(Boolean);
      if (!location || !origin) continue;
      let to: URL;
      let from: URL;
      try {
        from = new URL(origin);
        to = new URL(location, origin);
      } catch {
        continue;
      }
      if (to.hostname === from.hostname || this.redirectHosts.has(to.hostname)) continue;
      const decision = this.checkScope(to.origin, "passive", { type: "human" });
      if (decision.decision !== "deny" || decision.code !== "OUT_OF_SCOPE") continue;
      this.redirectHosts.add(to.hostname);
      this.emit({ type: "scope.redirect_outside", from: from.origin, to: to.origin, host: to.hostname });
    }
  }

  // -------------------------------------------------------------------------------------------
  // Runs
  // -------------------------------------------------------------------------------------------

  private rowToRun(r: Record<string, unknown>): Run {
    return {
      id: r.id as string,
      actor: JSON.parse(r.actor as string) as Actor,
      origin: r.origin as Run["origin"],
      ...(r.tool ? { tool: r.tool as string } : {}),
      ...(r.command ? { command: r.command as string } : {}),
      targets: JSON.parse(r.targets as string) as string[],
      risk: r.risk as RiskLevel,
      policy: JSON.parse(r.policy as string) as Run["policy"],
      runner: r.runner as string,
      status: r.status as Run["status"],
      startedAt: r.started_at as string,
      ...(r.ended_at ? { endedAt: r.ended_at as string } : {}),
      ...(r.exit_code !== null && r.exit_code !== undefined ? { exitCode: r.exit_code as number } : {}),
      rawIds: JSON.parse(r.raw_ids as string) as string[],
      ...(r.summary ? { summary: JSON.parse(r.summary as string) as Record<string, unknown> } : {}),
      ...(r.attack ? { attack: JSON.parse(r.attack as string) as string[] } : {}),
    };
  }

  startRun(run: Omit<Run, "id" | "startedAt" | "rawIds" | "status"> & { status?: Run["status"] }): Run {
    const id = ulid();
    const startedAt = new Date().toISOString();
    const status = run.status ?? "running";
    this.db
      .prepare(
        "insert into runs (id, actor, origin, tool, command, targets, risk, policy, runner, status, started_at, attack) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(id, JSON.stringify(run.actor), run.origin, run.tool ?? null, run.command ?? null, JSON.stringify(run.targets), run.risk, JSON.stringify(run.policy), run.runner, status, startedAt, run.attack?.length ? JSON.stringify(run.attack) : null);
    this.audit(run.actor, status === "denied" ? "run.denied" : "run.start", { run: id }, { ...run, id });
    this.emit({ type: "run.started", id });
    return this.getRun(id)!;
  }

  finishRun(id: string, result: { status: Run["status"]; exitCode?: number; rawIds?: string[]; summary?: Record<string, unknown> }): Run {
    const run = this.getRun(id);
    if (!run) throw new Error(`run not found: ${id}`);
    // A cancelled run stays cancelled: a result that arrives late (a request in flight) does not overwrite it.
    if (run.status === "cancelled") return run;
    this.db
      .prepare("update runs set status = ?, exit_code = ?, raw_ids = ?, summary = ?, ended_at = ? where id = ?")
      .run(result.status, result.exitCode ?? null, JSON.stringify([...run.rawIds, ...(result.rawIds ?? [])]), result.summary ? JSON.stringify(result.summary) : null, new Date().toISOString(), id);
    this.audit(run.actor, "run.finish", { run: id }, result);
    this.emit({ type: "run.finished", id });
    return this.getRun(id)!;
  }

  getRun(id: string): Run | undefined {
    const row = this.db.prepare("select * from runs where id = ?").get(id) as Record<string, unknown> | undefined;
    return row ? this.rowToRun(row) : undefined;
  }

  runs(limit = 100): Run[] {
    const rows = this.db.prepare("select * from runs order by started_at desc limit ?").all(limit) as Array<Record<string, unknown>>;
    return rows.map((r) => this.rowToRun(r));
  }
}
