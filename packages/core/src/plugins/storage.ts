import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import Database from "../store/sqlite.js";
import { type ColumnSpec, type Migration, type MigrationStep, IMPLICIT_COLUMNS, replayMigrations, type StorageShape } from "@penteos/schema";

/**
 * A plugin's own database. The plugin never opens the
 * file nor writes SQL: it declares migrations, and calls insert/query/update/delete here. Every
 * statement is built by the core from validated names, with values always bound as parameters.
 *
 * Guarantees:
 *  - Migrations run in one transaction after a backup; a failure leaves the data exactly as it was.
 *  - An applied migration that changed in the manifest, or a database newer than the plugin, is
 *    refused (the data is never touched to "fit").
 *  - The quota is enforced by SQLite itself (max_page_count), not by counting.
 *  - Sensitive columns are sealed with the project's key at rest and cannot be searched.
 *  - The database describes itself (`_penteos_meta`), so it can be shown, exported or stripped
 *    without the plugin installed.
 */

export type StorageErrorCode =
  | "QUOTA_EXCEEDED"
  | "INVALID_ROW"
  | "INVALID_QUERY"
  | "UNKNOWN_TABLE"
  | "UNKNOWN_COLUMN"
  | "NOT_FOUND"
  | "MIGRATION_FAILED"
  | "MIGRATION_CHANGED"
  | "STORAGE_NEWER"
  | "STORAGE_CORRUPT"
  | "NO_KEY"
  | "CLOSED";

export class PluginStorageError extends Error {
  constructor(
    readonly code: StorageErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PluginStorageError";
  }
}

/** Seals sensitive values with a key the plugin never sees (the project's vault). */
export interface Sealer {
  seal(plain: string): string;
  open(sealed: string): string;
}

export type Scalar = string | number | boolean | null;
export type Row = Record<string, unknown> & { id: number; created_at: string; updated_at: string };
export type WhereValue = Scalar | { op: "eq" | "ne" | "lt" | "lte" | "gt" | "gte" | "like"; value: Scalar } | { op: "in"; value: Scalar[] } | { op: "null"; value: boolean };
export type Where = Record<string, WhereValue>;

export interface QueryOptions {
  where?: Where;
  orderBy?: { column: string; dir?: "asc" | "desc" };
  limit?: number;
  offset?: number;
}

export interface StorageStats {
  file: string;
  version: number;
  bytes: number;
  quotaBytes: number;
  tables: Array<{ name: string; rows: number }>;
}

export interface PluginStoreOptions {
  file: string;
  pluginId: string;
  migrations: readonly Migration[];
  quotaMb: number;
  sealer?: Sealer;
  /** Backups taken before a migration that are kept (older ones are removed). */
  keepBackups?: number;
}

export const STORAGE_LIMITS = {
  /** One row, all its values encoded. */
  rowBytes: 1024 * 1024,
  /** One json value. */
  jsonBytes: 256 * 1024,
  queryLimit: 1000,
  inValues: 500,
} as const;

const SQL_TYPE: Record<ColumnSpec["type"], string> = { text: "TEXT", integer: "INTEGER", real: "REAL", boolean: "INTEGER", date: "TEXT", json: "TEXT" };
const IMPLICIT: Record<(typeof IMPLICIT_COLUMNS)[number], ColumnSpec> = {
  id: { name: "id", type: "integer", required: true, sensitive: false },
  created_at: { name: "created_at", type: "date", required: true, sensitive: false },
  updated_at: { name: "updated_at", type: "date", required: true, sensitive: false },
};

/** Identifiers are validated by the manifest schema; quoting is the second lock. */
const q = (name: string) => `"${name.replace(/"/g, '""')}"`;

function literal(v: string | number | boolean): string {
  if (typeof v === "boolean") return v ? "1" : "0";
  if (typeof v === "number") return String(v);
  return `'${v.replace(/'/g, "''")}'`;
}

function columnSql(c: ColumnSpec, forAdd: boolean): string {
  let sql = `${q(c.name)} ${SQL_TYPE[c.type]}`;
  if (c.required) sql += " NOT NULL";
  if (c.default !== undefined) sql += ` DEFAULT ${literal(c.default)}`;
  else if (forAdd && c.required) throw new Error(`required column ${c.name} added without a default`); // replay forbids it
  return sql;
}

function stepSql(step: MigrationStep): string {
  switch (step.op) {
    case "create_table":
      return `create table ${q(step.table)} (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ${step.columns.map((c) => columnSql(c, false)).join(", ")}) STRICT`;
    case "add_column":
      return `alter table ${q(step.table)} add column ${columnSql(step.column, true)}`;
    case "rename_column":
      return `alter table ${q(step.table)} rename column ${q(step.from)} to ${q(step.to)}`;
    case "drop_column":
      return `alter table ${q(step.table)} drop column ${q(step.column)}`;
    case "create_index":
      return `create ${step.unique ? "unique " : ""}index ${q(step.name)} on ${q(step.table)} (${step.columns.map(q).join(", ")})`;
    case "drop_index":
      return `drop index ${q(step.name)}`;
    case "drop_table":
      return `drop table ${q(step.table)}`;
  }
}

/** The fingerprint of an applied migration: if the manifest's copy changes, history was rewritten. */
export function migrationHash(m: Migration): string {
  return createHash("sha256").update(JSON.stringify(m)).digest("hex");
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

function isFull(e: unknown): boolean {
  return typeof e === "object" && e !== null && (e as { code?: string }).code === "SQLITE_FULL";
}

export class PluginStore {
  readonly file: string;
  readonly pluginId: string;
  private db: Database.Database | undefined;
  private shape: StorageShape;
  private readonly sealer: Sealer | undefined;
  private readonly quotaBytes: number;
  private readonly statements = new Map<string, Database.Statement>();

  private constructor(options: PluginStoreOptions, db: Database.Database, shape: StorageShape) {
    this.file = options.file;
    this.pluginId = options.pluginId;
    this.db = db;
    this.shape = shape;
    this.sealer = options.sealer;
    this.quotaBytes = options.quotaMb * 1024 * 1024;
  }

  /** Opens (creating if needed) and migrates. Throws a PluginStorageError and leaves the file as it was on any problem. */
  static open(options: PluginStoreOptions): PluginStore {
    mkdirSync(dirname(options.file), { recursive: true });
    const existed = existsSync(options.file);
    let db: Database.Database;
    try {
      db = new Database(options.file);
    } catch (e) {
      throw new PluginStorageError("STORAGE_CORRUPT", `cannot open ${basename(options.file)}: ${message(e)}`);
    }
    try {
      const shape = PluginStore.prepare(db, options, existed);
      const store = new PluginStore(options, db, shape);
      store.applyQuota();
      return store;
    } catch (e) {
      db.close();
      if (e instanceof PluginStorageError) throw e;
      throw new PluginStorageError("STORAGE_CORRUPT", `${basename(options.file)}: ${message(e)}`);
    }
  }

  private static prepare(db: Database.Database, options: PluginStoreOptions, existed: boolean): StorageShape {
    try {
      db.pragma("journal_mode = WAL");
      // A plugin database is data, never code: no triggers or views run with elevated trust.
      db.pragma("trusted_schema = OFF");
      if (existed) {
        const check = db.pragma("quick_check", { simple: true });
        if (check !== "ok") throw new PluginStorageError("STORAGE_CORRUPT", `integrity check failed: ${String(check)}`);
      }
      db.exec(`create table if not exists _penteos_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
        create table if not exists _penteos_migrations (version INTEGER PRIMARY KEY, hash TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT;`);
    } catch (e) {
      if (e instanceof PluginStorageError) throw e;
      throw new PluginStorageError("STORAGE_CORRUPT", `not a readable database: ${message(e)}`);
    }
    const owner = (db.prepare("select value from _penteos_meta where key = 'plugin_id'").get() as { value: string } | undefined)?.value;
    if (owner && owner !== options.pluginId) throw new PluginStorageError("STORAGE_CORRUPT", `this database belongs to ${owner}, not ${options.pluginId}`);

    const applied = db.prepare("select version, hash from _penteos_migrations order by version").all() as Array<{ version: number; hash: string }>;
    const declared = options.migrations;
    for (const a of applied) {
      const m = declared[a.version - 1];
      if (!m) {
        throw new PluginStorageError("STORAGE_NEWER", `the data is at version ${applied.length} but this plugin version only knows ${declared.length}: update the plugin (nothing was changed)`);
      }
      if (migrationHash(m) !== a.hash) {
        throw new PluginStorageError("MIGRATION_CHANGED", `migration ${a.version} changed after it was applied; applied migrations cannot be edited, add a new one (nothing was changed)`);
      }
    }
    const shape = replayMigrations(declared);
    const pending = declared.slice(applied.length);
    if (pending.length > 0) {
      if (applied.length > 0) PluginStore.backup(db, options, applied.length);
      const now = new Date().toISOString();
      const record = db.prepare("insert into _penteos_migrations (version, hash, applied_at) values (?, ?, ?)");
      let current: { version: number; step: number; op: string } | undefined;
      try {
        db.transaction(() => {
          for (const m of pending) {
            m.steps.forEach((step, i) => {
              current = { version: m.version, step: i + 1, op: step.op };
              db.exec(stepSql(step));
            });
            record.run(m.version, migrationHash(m), now);
          }
          current = undefined;
          PluginStore.verify(db, shape);
          db.prepare("insert into _penteos_meta (key, value) values ('plugin_id', ?) on conflict(key) do update set value = excluded.value").run(options.pluginId);
          db.prepare("insert into _penteos_meta (key, value) values ('shape', ?) on conflict(key) do update set value = excluded.value").run(JSON.stringify(shape));
        })();
      } catch (e) {
        const where = current ? `migration ${current.version}, step ${current.step} (${current.op})` : "verifying the result";
        throw new PluginStorageError("MIGRATION_FAILED", `${where}: ${isFull(e) ? "the database is over its quota" : message(e)} - rolled back, the data is as it was`);
      }
    } else {
      PluginStore.verify(db, shape);
    }
    return shape;
  }

  /** The database must hold exactly what the migrations say; anything else means someone touched it. */
  private static verify(db: Database.Database, shape: StorageShape): void {
    for (const [table, t] of Object.entries(shape.tables)) {
      const cols = (db.prepare(`pragma table_info(${q(table)})`).all() as Array<{ name: string }>).map((c) => c.name).sort();
      const want = [...IMPLICIT_COLUMNS, ...t.columns.map((c) => c.name)].sort();
      if (cols.join(",") !== want.join(",")) {
        throw new PluginStorageError("STORAGE_CORRUPT", `table ${table} has columns [${cols.join(", ")}] but its migrations say [${want.join(", ")}]`);
      }
    }
  }

  private static backup(db: Database.Database, options: PluginStoreOptions, version: number): void {
    const dir = dirname(options.file);
    const base = basename(options.file);
    const target = join(dir, `${base}.v${version}-${Date.now()}.bak`);
    db.prepare("vacuum into ?").run(target);
    const keep = options.keepBackups ?? 2;
    const backups = readdirSync(dir)
      .filter((f) => f.startsWith(`${base}.v`) && f.endsWith(".bak"))
      .sort((a, b) => Number(/-(\d+)\.bak$/.exec(a)?.[1]) - Number(/-(\d+)\.bak$/.exec(b)?.[1]));
    for (const old of backups.slice(0, Math.max(0, backups.length - keep))) rmSync(join(dir, old), { force: true });
  }

  private applyQuota(): void {
    const pageSize = this.conn.pragma("page_size", { simple: true }) as number;
    this.conn.pragma(`max_page_count = ${Math.max(1, Math.floor(this.quotaBytes / pageSize))}`);
  }

  // -------------------------------------------------------------------------------------------
  // The API a plugin gets
  // -------------------------------------------------------------------------------------------

  get version(): number {
    return this.shape.version;
  }

  /** Tables and columns, as the migrations left them. */
  get tables(): StorageShape["tables"] {
    return this.shape.tables;
  }

  insert(table: string, row: Record<string, unknown>): Row {
    const cols = this.columnsOf(table);
    const now = new Date().toISOString();
    const values = this.encodeRow(table, cols, row, true);
    const names = ["created_at", "updated_at", ...Object.keys(values)];
    const id = this.write(() =>
      this.stmt(`insert into ${q(table)} (${names.map(q).join(", ")}) values (${names.map(() => "?").join(", ")})`).run(now, now, ...Object.values(values)).lastInsertRowid,
    );
    return this.get(table, Number(id))!;
  }

  /** All or nothing. */
  insertMany(table: string, rows: Array<Record<string, unknown>>): number {
    if (rows.length > 10_000) throw new PluginStorageError("INVALID_ROW", "at most 10000 rows per call");
    this.write(() =>
      this.conn.transaction(() => {
        for (const r of rows) this.insertRaw(table, r);
      })(),
    );
    return rows.length;
  }

  get(table: string, id: number): Row | undefined {
    const cols = this.columnsOf(table);
    const row = this.stmt(`select * from ${q(table)} where id = ?`).get(id) as Record<string, unknown> | undefined;
    return row ? this.decodeRow(cols, row) : undefined;
  }

  query(table: string, options: QueryOptions = {}): Row[] {
    const cols = this.columnsOf(table);
    const { sql, params } = this.whereSql(table, cols, options.where);
    const limit = options.limit ?? 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > STORAGE_LIMITS.queryLimit) throw new PluginStorageError("INVALID_QUERY", `limit goes from 1 to ${STORAGE_LIMITS.queryLimit}`);
    const offset = options.offset ?? 0;
    if (!Number.isInteger(offset) || offset < 0) throw new PluginStorageError("INVALID_QUERY", "offset must be 0 or more");
    let order = "id asc";
    if (options.orderBy) {
      const c = this.filterable(table, cols, options.orderBy.column);
      order = `${q(c.name)} ${options.orderBy.dir === "desc" ? "desc" : "asc"}, id asc`;
    }
    const rows = this.stmt(`select * from ${q(table)}${sql} order by ${order} limit ? offset ?`).all(...params, limit, offset) as Array<Record<string, unknown>>;
    return rows.map((r) => this.decodeRow(cols, r));
  }

  count(table: string, where?: Where): number {
    const cols = this.columnsOf(table);
    const { sql, params } = this.whereSql(table, cols, where);
    return (this.stmt(`select count(*) as n from ${q(table)}${sql}`).get(...params) as { n: number }).n;
  }

  update(table: string, id: number, set: Record<string, unknown>): Row {
    const n = this.updateWhere(table, { id }, set);
    if (n === 0) throw new PluginStorageError("NOT_FOUND", `${table} has no row ${id}`);
    return this.get(table, id)!;
  }

  /** Needs a filter: updating every row takes an explicit one. */
  updateWhere(table: string, where: Where, set: Record<string, unknown>): number {
    const cols = this.columnsOf(table);
    if (Object.keys(where).length === 0) throw new PluginStorageError("INVALID_QUERY", "an update needs a where");
    const values = this.encodeRow(table, cols, set, false);
    if (Object.keys(values).length === 0) throw new PluginStorageError("INVALID_ROW", "nothing to update");
    const w = this.whereSql(table, cols, where);
    const assignments = ["updated_at = ?", ...Object.keys(values).map((k) => `${q(k)} = ?`)].join(", ");
    return this.write(() => this.stmt(`update ${q(table)} set ${assignments}${w.sql}`).run(new Date().toISOString(), ...Object.values(values), ...w.params).changes);
  }

  delete(table: string, id: number): boolean {
    return this.deleteWhere(table, { id }) > 0;
  }

  /** Needs a filter, like updateWhere. */
  deleteWhere(table: string, where: Where): number {
    const cols = this.columnsOf(table);
    if (Object.keys(where).length === 0) throw new PluginStorageError("INVALID_QUERY", "a delete needs a where");
    const w = this.whereSql(table, cols, where);
    return this.write(() => this.stmt(`delete from ${q(table)}${w.sql}`).run(...w.params).changes);
  }

  stats(): StorageStats {
    const pageCount = this.conn.pragma("page_count", { simple: true }) as number;
    const pageSize = this.conn.pragma("page_size", { simple: true }) as number;
    return {
      file: this.file,
      version: this.shape.version,
      bytes: pageCount * pageSize,
      quotaBytes: this.quotaBytes,
      tables: Object.keys(this.shape.tables)
        .sort()
        .map((name) => ({ name, rows: (this.stmt(`select count(*) as n from ${q(name)}`).get() as { n: number }).n })),
    };
  }

  close(): void {
    this.statements.clear();
    this.db?.close();
    this.db = undefined;
  }

  // -------------------------------------------------------------------------------------------
  // Inside
  // -------------------------------------------------------------------------------------------

  private get conn(): Database.Database {
    if (!this.db) throw new PluginStorageError("CLOSED", `the database of ${this.pluginId} is closed`);
    return this.db;
  }

  private stmt(sql: string): Database.Statement {
    let s = this.statements.get(sql);
    if (!s) {
      s = this.conn.prepare(sql);
      if (this.statements.size > 200) this.statements.clear();
      this.statements.set(sql, s);
    }
    return s;
  }

  private write<T>(work: () => T): T {
    try {
      return work();
    } catch (e) {
      if (isFull(e)) throw new PluginStorageError("QUOTA_EXCEEDED", `${this.pluginId} reached its storage quota (${Math.round(this.quotaBytes / 1048576)} MB); nothing was written`);
      if (e instanceof PluginStorageError) throw e;
      const code = (e as { code?: string }).code ?? "";
      if (code.startsWith("SQLITE_CONSTRAINT")) throw new PluginStorageError("INVALID_ROW", message(e));
      throw e;
    }
  }

  private insertRaw(table: string, row: Record<string, unknown>): void {
    const cols = this.columnsOf(table);
    const now = new Date().toISOString();
    const values = this.encodeRow(table, cols, row, true);
    const names = ["created_at", "updated_at", ...Object.keys(values)];
    this.stmt(`insert into ${q(table)} (${names.map(q).join(", ")}) values (${names.map(() => "?").join(", ")})`).run(now, now, ...Object.values(values));
  }

  private columnsOf(table: string): Map<string, ColumnSpec> {
    const t = Object.hasOwn(this.shape.tables, table) ? this.shape.tables[table] : undefined;
    if (!t) throw new PluginStorageError("UNKNOWN_TABLE", `${this.pluginId} has no table "${table}"`);
    return new Map([...Object.values(IMPLICIT), ...t.columns].map((c) => [c.name, c]));
  }

  private column(table: string, cols: Map<string, ColumnSpec>, name: string): ColumnSpec {
    const c = cols.get(name);
    if (!c) throw new PluginStorageError("UNKNOWN_COLUMN", `${table} has no column "${name}"`);
    return c;
  }

  private filterable(table: string, cols: Map<string, ColumnSpec>, name: string): ColumnSpec {
    const c = this.column(table, cols, name);
    if (c.sensitive) throw new PluginStorageError("INVALID_QUERY", `${table}.${name} is sensitive: it is encrypted and cannot be searched or sorted`);
    if (c.type === "json") throw new PluginStorageError("INVALID_QUERY", `${table}.${name} is json and cannot be searched or sorted`);
    return c;
  }

  private encodeRow(table: string, cols: Map<string, ColumnSpec>, row: Record<string, unknown>, full: boolean): Record<string, Scalar> {
    if (typeof row !== "object" || row === null || Array.isArray(row)) throw new PluginStorageError("INVALID_ROW", "a row is an object");
    const out: Record<string, Scalar> = {};
    let bytes = 0;
    for (const [name, value] of Object.entries(row)) {
      if ((IMPLICIT_COLUMNS as readonly string[]).includes(name)) throw new PluginStorageError("INVALID_ROW", `${name} is set by Penteos`);
      const c = this.column(table, cols, name);
      if (value === undefined) continue;
      const encoded = this.encode(table, c, value);
      bytes += typeof encoded === "string" ? encoded.length : 8;
      out[name] = encoded;
    }
    if (bytes > STORAGE_LIMITS.rowBytes) throw new PluginStorageError("INVALID_ROW", `a row is at most ${STORAGE_LIMITS.rowBytes} bytes`);
    if (full) {
      for (const c of cols.values()) {
        if ((IMPLICIT_COLUMNS as readonly string[]).includes(c.name)) continue;
        if (c.required && c.default === undefined && out[c.name] === undefined) throw new PluginStorageError("INVALID_ROW", `${table}.${c.name} is required`);
      }
    }
    return out;
  }

  private encode(table: string, c: ColumnSpec, value: unknown): Scalar {
    const bad = (want: string) => new PluginStorageError("INVALID_ROW", `${table}.${c.name} expects ${want}`);
    if (value === null) {
      if (c.required) throw new PluginStorageError("INVALID_ROW", `${table}.${c.name} is required`);
      return null;
    }
    let plain: Scalar;
    switch (c.type) {
      case "text":
        if (typeof value !== "string") throw bad("text");
        plain = value;
        break;
      case "date":
        if (typeof value !== "string" || Number.isNaN(Date.parse(value))) throw bad("an ISO date");
        plain = new Date(value).toISOString();
        break;
      case "integer":
        if (typeof value !== "number" || !Number.isSafeInteger(value)) throw bad("an integer");
        plain = value;
        break;
      case "real":
        if (typeof value !== "number" || !Number.isFinite(value)) throw bad("a number");
        plain = value;
        break;
      case "boolean":
        if (typeof value !== "boolean") throw bad("true or false");
        plain = value ? 1 : 0;
        break;
      case "json": {
        const s = JSON.stringify(value);
        if (s === undefined) throw bad("a JSON value");
        if (s.length > STORAGE_LIMITS.jsonBytes) throw bad(`JSON of at most ${STORAGE_LIMITS.jsonBytes} bytes`);
        plain = s;
        break;
      }
    }
    if (!c.sensitive) return plain;
    if (!this.sealer) throw new PluginStorageError("NO_KEY", `${table}.${c.name} is sensitive and this project has no key to encrypt it`);
    return this.sealer.seal(String(plain));
  }

  private decodeRow(cols: Map<string, ColumnSpec>, row: Record<string, unknown>): Row {
    const out: Record<string, unknown> = {};
    for (const [name, raw] of Object.entries(row)) {
      const c = cols.get(name);
      out[name] = c ? this.decode(c, raw) : raw;
    }
    return out as Row;
  }

  private decode(c: ColumnSpec, raw: unknown): unknown {
    if (raw === null || raw === undefined) return null;
    let value = raw;
    if (c.sensitive) {
      // Stripped on export ('') or sealed with a key this project does not have: unreadable, not fatal.
      if (raw === "" || !this.sealer) return null;
      try {
        value = this.sealer.open(String(raw));
      } catch {
        return null;
      }
    }
    if (c.type === "boolean") return value === 1 || value === "1";
    if (c.type === "json") {
      try {
        return JSON.parse(String(value));
      } catch {
        return null;
      }
    }
    if (c.sensitive && (c.type === "integer" || c.type === "real")) return Number(value);
    return value;
  }

  private whereSql(table: string, cols: Map<string, ColumnSpec>, where: Where | undefined): { sql: string; params: Scalar[] } {
    if (!where || Object.keys(where).length === 0) return { sql: "", params: [] };
    if (typeof where !== "object" || Array.isArray(where)) throw new PluginStorageError("INVALID_QUERY", "where is an object of column: value");
    const parts: string[] = [];
    const params: Scalar[] = [];
    for (const [name, cond] of Object.entries(where)) {
      const isOp = typeof cond === "object" && cond !== null;
      const op = isOp ? (cond as { op: string }).op : "eq";
      const value = isOp ? (cond as { value: unknown }).value : cond;
      const c = op === "null" ? this.column(table, cols, name) : this.filterable(table, cols, name);
      if (op === "null") {
        if (c.required) throw new PluginStorageError("INVALID_QUERY", `${table}.${name} is required and is never null`);
        parts.push(`${q(name)} is ${value ? "" : "not "}null`);
        continue;
      }
      const enc = (v: unknown): Scalar => {
        if (v === null) throw new PluginStorageError("INVALID_QUERY", `use { op: "null" } to look for missing ${name}`);
        return this.encode(table, { ...c, sensitive: false, required: false }, v);
      };
      const sqlOp = { eq: "=", ne: "!=", lt: "<", lte: "<=", gt: ">", gte: ">=", like: "like" }[op as "eq"];
      if (op === "in") {
        if (!Array.isArray(value) || value.length === 0 || value.length > STORAGE_LIMITS.inValues) {
          throw new PluginStorageError("INVALID_QUERY", `in takes from 1 to ${STORAGE_LIMITS.inValues} values`);
        }
        parts.push(`${q(name)} in (${value.map(() => "?").join(", ")})`);
        params.push(...value.map(enc));
      } else if (sqlOp) {
        if (op === "like" && c.type !== "text") throw new PluginStorageError("INVALID_QUERY", `like works on text columns`);
        parts.push(op === "like" ? `${q(name)} like ? escape '\\'` : `${q(name)} ${sqlOp} ?`);
        params.push(enc(value));
      } else {
        throw new PluginStorageError("INVALID_QUERY", `unknown operator "${op}"`);
      }
    }
    return { sql: ` where ${parts.join(" and ")}`, params };
  }
}

/** Reads what a plugin database says about itself (for the generic view and export), without the plugin. */
export function describeStorage(file: string): { pluginId?: string; shape?: StorageShape } {
  if (!existsSync(file)) return {};
  const db = new Database(file, { readonly: true, fileMustExist: true });
  try {
    const get = (key: string) => (db.prepare("select value from _penteos_meta where key = ?").get(key) as { value: string } | undefined)?.value;
    const shape = get("shape");
    const pluginId = get("plugin_id");
    return { ...(pluginId ? { pluginId } : {}), ...(shape ? { shape: JSON.parse(shape) as StorageShape } : {}) };
  } catch {
    return {};
  } finally {
    db.close();
  }
}

/**
 * A consistent copy of a plugin database for export (safe while it is open), with every sensitive
 * value emptied: the project key does not travel, so they would not decrypt elsewhere anyway.
 */
export async function exportStorageCopy(file: string, dest: string): Promise<{ stripped: number }> {
  const src = new Database(file, { readonly: true, fileMustExist: true });
  try {
    await src.backup(dest);
  } finally {
    src.close();
  }
  const copy = new Database(dest);
  let stripped = 0;
  try {
    const shapeRow = copy.prepare("select value from _penteos_meta where key = 'shape'").get() as { value: string } | undefined;
    const shape = shapeRow ? (JSON.parse(shapeRow.value) as StorageShape) : undefined;
    for (const [table, t] of Object.entries(shape?.tables ?? {})) {
      for (const c of t.columns) {
        if (!c.sensitive) continue;
        stripped += copy.prepare(`update ${q(table)} set ${q(c.name)} = '' where ${q(c.name)} is not null and ${q(c.name)} != ''`).run().changes;
      }
    }
    copy.pragma("journal_mode = DELETE");
  } finally {
    copy.close();
  }
  return { stripped };
}
