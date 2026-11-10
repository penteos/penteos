import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "../src/store/sqlite.js";

/**
 * Penteos's SQLite on Node's own: the behavior the rest of the
 * code relied on from better-sqlite3, kept exactly.
 */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-sqlite-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("the database", () => {
  it("rows are plain objects, BLOBs are Buffers, undefined is NULL, named and positional parameters work", () => {
    const db = new Database(join(dir, "a.db"));
    db.exec("create table t (id integer primary key, name text, data blob, n integer)");
    const r = db.prepare("insert into t (name, data, n) values (@name, @data, @n)").run({ name: "x", data: Buffer.from("hola"), n: undefined });
    expect(r).toEqual({ changes: 1, lastInsertRowid: 1 });
    db.prepare("insert into t (name, data) values (?, ?)").run("y", null);
    const row = db.prepare("select * from t where id = ?").get<{ name: string; data: Buffer; n: null }>(1)!;
    expect(Object.getPrototypeOf(row)).toBe(Object.prototype);
    expect(Buffer.isBuffer(row.data) && row.data.toString()).toBe("hola");
    expect(row.n).toBeNull();
    expect(db.prepare("select name from t order by id").all()).toEqual([{ name: "x" }, { name: "y" }]);
    expect([...db.prepare("select id from t order by id").iterate()]).toEqual([{ id: 1 }, { id: 2 }]);
    expect(db.prepare("select * from t where id = 99").get()).toBeUndefined();
    db.close();
    expect(db.open).toBe(false);
  });

  it("transactions commit, roll back on a throw, and nest as savepoints", () => {
    const db = new Database(":memory:");
    db.exec("create table t (x integer)");
    const add = db.transaction((x: number) => db.prepare("insert into t values (?)").run(x));
    add(1);
    expect(() =>
      db.transaction(() => {
        add(2);
        throw new Error("boom");
      })(),
    ).toThrow("boom");
    db.transaction(() => {
      add(3);
      try {
        db.transaction(() => {
          add(4);
          throw new Error("inner");
        })();
      } catch {
        /* only the inner part goes */
      }
    })();
    expect(db.prepare("select x from t order by x").all()).toEqual([{ x: 1 }, { x: 3 }]);
    expect(db.inTransaction).toBe(false);
  });

  it("pragmas, SQLite's error codes, read-only and must-exist files, and a consistent backup", async () => {
    const file = join(dir, "b.db");
    const db = new Database(file);
    expect(db.pragma("journal_mode = WAL")).toEqual([{ journal_mode: "wal" }]);
    expect(typeof db.pragma("page_size", { simple: true })).toBe("number");
    db.exec("create table t (x text unique)");
    db.prepare("insert into t values ('a')").run();
    try {
      db.prepare("insert into t values ('a')").run();
      expect.unreachable();
    } catch (e) {
      expect((e as { code: string }).code).toBe("SQLITE_CONSTRAINT");
    }
    db.pragma(`max_page_count = ${db.pragma("page_count", { simple: true }) as number}`);
    try {
      db.transaction(() => {
        for (let i = 0; i < 5000; i++) db.prepare("insert into t values (?)").run(`row-${i}-${"x".repeat(200)}`);
      })();
      expect.unreachable();
    } catch (e) {
      expect((e as { code: string }).code).toBe("SQLITE_FULL");
    }
    await db.backup(join(dir, "copy.db"));
    db.close();
    const copy = new Database(join(dir, "copy.db"), { readonly: true });
    expect(copy.prepare("select count(*) as n from t").get()).toEqual({ n: 1 });
    expect(() => copy.prepare("insert into t values ('b')").run()).toThrow();
    copy.close();
    expect(() => new Database(join(dir, "missing.db"), { fileMustExist: true })).toThrow(/unable to open/);
    expect(existsSync(join(dir, "missing.db"))).toBe(false);
  });
});
