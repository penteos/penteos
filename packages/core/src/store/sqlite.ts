import { existsSync } from "node:fs";
import { backup as sqliteBackup, DatabaseSync, type StatementSync } from "node:sqlite";

/**
 * Penteos's SQLite, on the one built into Node (and so into Electron): no native module to compile,
 * so the database never depends on the distribution's glibc nor on Electron's version.
 * The surface is the part of better-sqlite3 Penteos used -
 * prepare/run/get/all/iterate, exec, pragma, transaction (nested through savepoints), backup -
 * with its behavior: plain row objects, BLOBs as Buffer, `undefined` bound as NULL, and errors
 * carrying SQLite's own code ("SQLITE_FULL", "SQLITE_CONSTRAINT"…).
 */

type Params = unknown[];

/** SQLite's primary result codes, by number (extended codes keep their primary in the low byte). */
const CODES: Record<number, string> = {
  1: "SQLITE_ERROR",
  2: "SQLITE_INTERNAL",
  3: "SQLITE_PERM",
  4: "SQLITE_ABORT",
  5: "SQLITE_BUSY",
  6: "SQLITE_LOCKED",
  7: "SQLITE_NOMEM",
  8: "SQLITE_READONLY",
  9: "SQLITE_INTERRUPT",
  10: "SQLITE_IOERR",
  11: "SQLITE_CORRUPT",
  12: "SQLITE_NOTFOUND",
  13: "SQLITE_FULL",
  14: "SQLITE_CANTOPEN",
  15: "SQLITE_PROTOCOL",
  16: "SQLITE_EMPTY",
  17: "SQLITE_SCHEMA",
  18: "SQLITE_TOOBIG",
  19: "SQLITE_CONSTRAINT",
  20: "SQLITE_MISMATCH",
  21: "SQLITE_MISUSE",
  22: "SQLITE_NOLFS",
  23: "SQLITE_AUTH",
  24: "SQLITE_FORMAT",
  25: "SQLITE_RANGE",
  26: "SQLITE_NOTADB",
};

/** An error with SQLite's own code, as callers check it (`e.code === "SQLITE_FULL"`). */
export class SqliteError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = "SqliteError";
  }
}

function translate(e: unknown): unknown {
  const err = e as { errcode?: number; errstr?: string; message?: string; code?: string };
  if (err && typeof err.errcode === "number") return new SqliteError(err.message ?? err.errstr ?? "SQLite error", CODES[err.errcode & 0xff] ?? `SQLITE_${err.errcode}`);
  return e;
}

function guard<T>(work: () => T): T {
  try {
    return work();
  } catch (e) {
    throw translate(e);
  }
}

/** A row as callers expect it: a plain object, BLOBs as Buffer. */
function row<T>(r: unknown): T {
  if (!r || typeof r !== "object") return r as T;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r as Record<string, unknown>)) out[k] = v instanceof Uint8Array && !(v instanceof Buffer) ? Buffer.from(v.buffer, v.byteOffset, v.byteLength) : v;
  return out as T;
}

/** Parameters as SQLite takes them: `undefined` is NULL, booleans are 0/1 (as better-sqlite3 refused them, callers never relied on more). */
function bind(params: Params): Params {
  return params.map((p) => {
    if (p === undefined) return null;
    if (p && typeof p === "object" && !(p instanceof Uint8Array) && !Array.isArray(p)) {
      return Object.fromEntries(Object.entries(p as Record<string, unknown>).map(([k, v]) => [k, v === undefined ? null : v]));
    }
    return p;
  });
}

export class Statement {
  constructor(private readonly stmt: StatementSync) {}

  run(...params: Params): { changes: number; lastInsertRowid: number | bigint } {
    return guard(() => {
      const r = this.stmt.run(...(bind(params) as []));
      return { changes: Number(r.changes), lastInsertRowid: r.lastInsertRowid };
    });
  }

  get<T = unknown>(...params: Params): T | undefined {
    return guard(() => {
      const r = this.stmt.get(...(bind(params) as []));
      return r === undefined ? undefined : row<T>(r);
    });
  }

  all<T = unknown>(...params: Params): T[] {
    return guard(() => this.stmt.all(...(bind(params) as [])).map((r) => row<T>(r)));
  }

  *iterate<T = unknown>(...params: Params): IterableIterator<T> {
    const it = guard(() => this.stmt.iterate(...(bind(params) as [])));
    for (;;) {
      const next = guard(() => it.next());
      if (next.done) return;
      yield row<T>(next.value);
    }
  }
}

export interface DatabaseOptions {
  readonly?: boolean;
  /** Refuse to create the file: it must be there already. */
  fileMustExist?: boolean;
  /** How long to wait for a lock held by another connection (ms). */
  timeout?: number;
}

class SqliteDatabase {
  readonly name: string;
  private readonly db: DatabaseSync;
  private depth = 0;

  constructor(file: string, options: DatabaseOptions = {}) {
    this.name = file;
    if (options.fileMustExist && file !== ":memory:" && !existsSync(file)) throw new SqliteError(`unable to open database file: ${file}`, "SQLITE_CANTOPEN");
    this.db = guard(() => new DatabaseSync(file, { readOnly: Boolean(options.readonly), timeout: options.timeout ?? 5000 }));
  }

  get open(): boolean {
    return this.db.isOpen;
  }

  get inTransaction(): boolean {
    return this.depth > 0 || this.db.isTransaction;
  }

  prepare(sql: string): Statement {
    return new Statement(guard(() => this.db.prepare(sql)));
  }

  exec(sql: string): this {
    guard(() => this.db.exec(sql));
    return this;
  }

  /** `pragma("journal_mode = WAL")` → its rows; with `{ simple: true }`, the first value of the first row. */
  pragma(source: string, options: { simple?: boolean } = {}): unknown {
    const rows = guard(() => this.db.prepare(`PRAGMA ${source}`).all()).map((r) => row<Record<string, unknown>>(r));
    if (options.simple) {
      const first = rows[0];
      return first ? Object.values(first)[0] : undefined;
    }
    return rows;
  }

  /**
   * A function that runs `fn` in a transaction: committed when it returns, rolled back when it
   * throws. Called inside another transaction it becomes a savepoint of it.
   */
  transaction<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
    return (...args: A): R => {
      const outer = this.depth === 0 && !this.db.isTransaction;
      const savepoint = `penteos_sp_${this.depth}`;
      this.exec(outer ? "BEGIN" : `SAVEPOINT ${savepoint}`);
      this.depth++;
      try {
        const result = fn(...args);
        this.depth--;
        this.exec(outer ? "COMMIT" : `RELEASE ${savepoint}`);
        return result;
      } catch (e) {
        this.depth--;
        try {
          if (outer) this.exec("ROLLBACK");
          else this.exec(`ROLLBACK TO ${savepoint}; RELEASE ${savepoint}`);
        } catch {
          /* SQLite may have rolled back already (a constraint, a full disk) */
        }
        throw e;
      }
    };
  }

  /** A consistent copy of the open database into another file (safe while it is in use). */
  async backup(destination: string): Promise<void> {
    try {
      await sqliteBackup(this.db, destination);
    } catch (e) {
      throw translate(e);
    }
  }

  close(): void {
    if (this.db.isOpen) this.db.close();
  }
}

/** better-sqlite3's shape: `new Database(file, options)`, and the types `Database.Database` / `Database.Statement`. */
type SqliteStatement = Statement;
type SqliteDb = SqliteDatabase;
const Database = SqliteDatabase as typeof SqliteDatabase;
// eslint-disable-next-line @typescript-eslint/no-namespace, @typescript-eslint/no-redeclare
namespace Database {
  export type Database = SqliteDb;
  export type Statement = SqliteStatement;
}
export default Database;
