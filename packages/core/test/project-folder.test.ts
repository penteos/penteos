import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { Workspace } from "../src/index.js";

/** Projects live in legible, self-describing folders that can be opened from anywhere. */

const human: Actor = { type: "human", id: "01JA000000000000000000HUMN" };
let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "penteos-folder-test-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

it("creates a project in a legible folder with a project.json", () => {
  const ws = new Workspace(join(root, "a"));
  const eng = ws.create({ clientName: "ACME", name: "Web audit", mode: "web" }, human);
  const dir = ws.dirOf(eng.info.id);
  expect(basename(dir)).toBe("ACME - Web audit");
  const meta = JSON.parse(readFileSync(join(dir, "project.json"), "utf8"));
  expect(meta).toMatchObject({ format: "penteos-project/1", id: eng.info.id, clientName: "ACME", name: "Web audit", mode: "web" });
  ws.close();
});

it("honours a chosen projects root and avoids folder collisions", () => {
  const ws = new Workspace(join(root, "a"));
  const chosen = join(root, "MisProyectos");
  ws.setPrefs({ projectsRoot: chosen });
  const a = ws.dirOf(ws.create({ clientName: "ACME", name: "Web", mode: "web" }, human).info.id);
  const b = ws.dirOf(ws.create({ clientName: "ACME", name: "Web", mode: "web" }, human).info.id);
  expect(a).toBe(join(chosen, "ACME - Web"));
  expect(b).toBe(join(chosen, "ACME - Web (2)")); // no collision
  ws.close();
});

it("opens a project folder from another workspace and registers it in the index", () => {
  const wsA = new Workspace(join(root, "a"));
  const eng = wsA.create({ clientName: "ACME", name: "Pentest", mode: "web" }, human);
  const dir = wsA.dirOf(eng.info.id);
  const id = eng.info.id;
  wsA.close();

  const wsB = new Workspace(join(root, "b"));
  expect(() => wsB.openFolder(join(root, "nope"), human)).toThrow(); // not a project
  const summary = wsB.openFolder(dir, human);
  expect(summary.id).toBe(id);
  expect(summary.clientName).toBe("ACME");
  expect(wsB.list().map((e) => e.id)).toContain(id);
  expect(wsB.dirOf(id)).toBe(dir); // the index points at the real folder, wherever it is
  expect(existsSync(dir)).toBe(true);
  wsB.close();
});

it("fails clearly when a project's folder is gone, instead of recreating it empty", () => {
  const ws = new Workspace(join(root, "a"));
  const id = ws.create({ clientName: "ACME", name: "Gone", mode: "web" }, human).info.id;
  const dir = ws.dirOf(id);
  ws.close();
  rmSync(dir, { recursive: true, force: true });

  const ws2 = new Workspace(join(root, "a"));
  expect(() => ws2.get(id)).toThrow(/PROJECT_FOLDER_MISSING/);
  expect(existsSync(dir)).toBe(false); // not recreated behind the operator's back
  ws2.close();
});

it("keeps secrets when the project folder is moved (per-project key travels with it)", () => {
  const ws = new Workspace(join(root, "a"));
  const eng = ws.create({ clientName: "ACME", name: "Keys", mode: "web" }, human);
  eng.saveSecret({ name: "tok", kind: "token", value: "abc123" }, human);
  const id = eng.info.id;
  const dir = ws.dirOf(id);
  expect(existsSync(join(dir, ".key"))).toBe(true);
  ws.close();

  const moved = join(root, "moved");
  cpSync(dir, moved, { recursive: true });
  rmSync(dir, { recursive: true, force: true });

  const ws2 = new Workspace(join(root, "a"));
  const summary = ws2.openFolder(moved, human); // index points at the new location
  expect(ws2.get(summary.id).secretValue("tok")).toBe("abc123"); // decrypted with the key that moved along
  ws2.close();
});

it("marks a project whose folder is gone as missing, and can forget it", () => {
  const ws = new Workspace(join(root, "a"));
  const id = ws.create({ clientName: "ACME", name: "ToForget", mode: "web" }, human).info.id;
  rmSync(ws.dirOf(id), { recursive: true, force: true });
  expect(ws.list().find((e) => e.id === id)?.missing).toBe(true);
  ws.forget(id);
  expect(ws.list().find((e) => e.id === id)).toBeUndefined();
  ws.close();
});

it("relocates a project folder to a new parent, keeping its data and secrets", () => {
  const ws = new Workspace(join(root, "a"));
  const eng = ws.create({ clientName: "ACME", name: "Relocate", mode: "web" }, human);
  eng.saveSecret({ name: "tok", kind: "token", value: "zzz" }, human);
  const id = eng.info.id;
  const from = ws.dirOf(id);
  const dest = join(root, "elsewhere");
  const to = ws.relocate(id, dest);
  expect(to.startsWith(dest)).toBe(true);
  expect(existsSync(from)).toBe(false); // moved, not copied
  expect(ws.dirOf(id)).toBe(to);
  expect(JSON.parse(readFileSync(join(to, "project.json"), "utf8")).id).toBe(id);
  expect(ws.get(id).secretValue("tok")).toBe("zzz");
  ws.close();
});

it("treats an opened copy of a project as its own new project (no id fight)", () => {
  const ws = new Workspace(join(root, "a"));
  const orig = ws.create({ clientName: "ACME", name: "Copiado", mode: "web" }, human);
  const origId = orig.info.id;
  const origDir = ws.dirOf(origId);
  const copyDir = join(root, "copia");
  cpSync(origDir, copyDir, { recursive: true });

  const summary = ws.openFolder(copyDir, human); // original still exists → the copy is a new project
  expect(summary.id).not.toBe(origId);
  expect(ws.dirOf(origId)).toBe(origDir); // original untouched
  expect(ws.dirOf(summary.id)).toBe(copyDir);
  expect(JSON.parse(readFileSync(join(copyDir, "project.json"), "utf8")).id).toBe(summary.id); // copy re-stamped
  ws.close();
});

it("lists a project the index cannot place as missing instead of failing to start", () => {
  // A workspace.db from before projects had folders: its index rows have no dir.
  const dataDir = join(root, "a");
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(join(dataDir, "workspace.db"));
  db.exec(`create table clients (id text primary key, name text not null, created_at text not null);
    create table engagements (id text primary key, client_id text not null, name text not null, mode text not null,
      status text not null, created_at text not null, dir text);
    insert into clients values ('c1', 'ACME', '2026-01-01T00:00:00.000Z');
    insert into engagements values ('e1', 'c1', 'Web', 'web', 'active', '2026-01-01T00:00:00.000Z', null);`);
  db.close();
  const ws = new Workspace(dataDir);
  expect(ws.list()).toEqual([expect.objectContaining({ id: "e1", name: "Web", missing: true })]);
  expect(() => ws.dirOf("e1")).toThrow(/folder unknown/);
  ws.close();
});
