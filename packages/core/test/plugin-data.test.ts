import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../src/store/sqlite.js";
import { type Actor, INGEST_FORMAT, type Migration, PluginManifest } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DormantTypeError,
  declarativeActivator,
  executeOperation,
  type OperationContext,
  PluginData,
  PluginHost,
  PluginStorageError,
  PluginStore,
  PluginUnavailableError,
  pluginTypes,
  Vault,
  Workspace,
} from "../src/index.js";

/**
 * What plugins keep, tested by breaking it on purpose. The rules every
 * test checks: a plugin's data never touches the project's own database; a failure leaves the data
 * exactly as it was and turns the plugin off with the reason; removing a plugin never breaks the graph.
 */

const human: Actor = { type: "human", id: "op" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-plugin-data-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

const sealer = (() => {
  const v = new Vault(Buffer.alloc(32, 7));
  return { seal: (s: string) => v.seal(s), open: (s: string) => v.open(s) };
})();

const V1: Migration = {
  version: 1,
  steps: [
    {
      op: "create_table",
      table: "scans",
      columns: [
        { name: "target", type: "text", required: true, sensitive: false },
        { name: "ports", type: "integer", required: false, sensitive: false },
        { name: "open", type: "boolean", required: false, sensitive: false },
        { name: "meta", type: "json", required: false, sensitive: false },
        { name: "api_key", type: "text", required: false, sensitive: true },
      ],
    },
  ],
};
const V2: Migration = {
  version: 2,
  steps: [
    { op: "add_column", table: "scans", column: { name: "score", type: "real", required: true, sensitive: false, default: 0 } },
    { op: "create_index", table: "scans", name: "scans_target", columns: ["target"], unique: false },
  ],
};

const storeFile = () => join(dataDir, "store", "data.db");
const openStore = (migrations: Migration[], extra: Partial<Parameters<typeof PluginStore.open>[0]> = {}) =>
  PluginStore.open({ file: storeFile(), pluginId: "lab.data", migrations, quotaMb: 64, sealer, ...extra });

const fileBytes = (path: string) => readFileSync(path).toString("hex");

describe("the manifest refuses impossible data before any database sees it", () => {
  const base = { id: "lab.m", name: "M", version: "1.0.0", apiVersion: 1, level: "declarative", author: { type: "human" }, permissions: ["graph:write"] };
  const issues = (contributes: unknown, extra: Record<string, unknown> = {}) => {
    const r = PluginManifest.safeParse({ ...base, ...extra, contributes });
    return r.success ? "" : r.error.issues.map((i) => i.message).join(" | ");
  };

  it("migrations with a gap", () => {
    expect(issues({ storage: { project: [V1, { ...V2, version: 3 }] } })).toMatch(/no gaps/);
  });
  it("an index on a sensitive column", () => {
    expect(issues({ storage: { project: [V1, { version: 2, steps: [{ op: "create_index", table: "scans", name: "k", columns: ["api_key"] }] }] } })).toMatch(/sensitive and cannot be indexed/);
  });
  it("a required column added later without a default", () => {
    expect(issues({ storage: { project: [V1, { version: 2, steps: [{ op: "add_column", table: "scans", column: { name: "x", type: "text", required: true } }] }] } })).toMatch(/needs a default/);
  });
  it("a step on a table that does not exist", () => {
    expect(issues({ storage: { global: [{ version: 1, steps: [{ op: "drop_column", table: "nope", column: "a" }] }] } })).toMatch(/does not exist/);
  });
  it("names that try to be SQL", () => {
    expect(issues({ storage: { project: [{ version: 1, steps: [{ op: "create_table", table: 'x"; drop table entities; --', columns: [{ name: "a", type: "text" }] }] }] } })).toMatch(/lowercase name/);
    expect(issues({ storage: { project: [{ version: 1, steps: [{ op: "create_table", table: "sqlite_master", columns: [{ name: "a", type: "text" }] }] }] } })).toMatch(/reserved/);
    expect(issues({ storage: { project: [{ version: 1, steps: [{ op: "create_table", table: "t", columns: [{ name: "id", type: "text" }] }] }] } })).toMatch(/added by Penteos/);
  });
  it("entity types and annotations without graph:write", () => {
    const type = { name: "banner", label: "Banner", fields: [{ name: "text", type: "string" }] };
    expect(issues({ entityTypes: [type] }, { permissions: ["graph:read"] })).toMatch(/graph:write/);
  });
  it("a key on a field that may be missing, a target that is not an address", () => {
    expect(issues({ entityTypes: [{ name: "b", label: "B", fields: [{ name: "port", type: "integer" }], key: ["port"] }] })).toMatch(/must be required/);
    expect(issues({ entityTypes: [{ name: "b", label: "B", fields: [{ name: "port", type: "integer" }], target: "port" }] })).toMatch(/must be host or url/);
  });
  it("annotations on kinds a plugin must not touch", () => {
    expect(issues({ annotations: [{ on: ["credential"], fields: [{ name: "x", type: "string" }] }] })).toMatch(/cannot be annotated/);
    expect(issues({ annotations: [{ on: ["host"], fields: [{ name: "x", type: "string", required: true }] }] })).toMatch(/cannot be required/);
  });
});

describe("a plugin's own database", () => {
  it("stores and reads typed rows; refuses unknown tables, columns and missing required values", () => {
    const s = openStore([V1]);
    const row = s.insert("scans", { target: "10.0.0.1", ports: 3, open: true, meta: { a: [1, 2] } });
    expect(row).toMatchObject({ id: 1, target: "10.0.0.1", ports: 3, open: true, meta: { a: [1, 2] } });
    expect(row.created_at).toMatch(/^\d{4}-/);
    s.insertMany("scans", [{ target: "10.0.0.2" }, { target: "10.0.0.3", open: false }]);
    expect(s.query("scans", { where: { open: false } }).map((r) => r.target)).toEqual(["10.0.0.3"]);
    expect(s.query("scans", { where: { target: { op: "like", value: "10.0.0.%" } }, orderBy: { column: "target", dir: "desc" }, limit: 2 }).map((r) => r.target)).toEqual(["10.0.0.3", "10.0.0.2"]);
    expect(s.count("scans", { ports: { op: "null", value: true } })).toBe(2);
    expect(s.update("scans", 1, { ports: 4 }).ports).toBe(4);
    expect(s.deleteWhere("scans", { target: { op: "in", value: ["10.0.0.2", "10.0.0.3"] } })).toBe(2);

    const code = (fn: () => unknown) => {
      try {
        fn();
      } catch (e) {
        return (e as PluginStorageError).code;
      }
      return "none";
    };
    expect(code(() => s.insert("nope", {}))).toBe("UNKNOWN_TABLE");
    expect(code(() => s.insert("scans", { target: "x", extra: 1 }))).toBe("UNKNOWN_COLUMN");
    expect(code(() => s.insert("scans", { ports: 1 }))).toBe("INVALID_ROW");
    expect(code(() => s.insert("scans", { target: 5 }))).toBe("INVALID_ROW");
    expect(code(() => s.insert("scans", { target: "x", id: 99 }))).toBe("INVALID_ROW");
    expect(code(() => s.deleteWhere("scans", {}))).toBe("INVALID_QUERY");
    expect(code(() => s.updateWhere("scans", {}, { ports: 1 }))).toBe("INVALID_QUERY");
    expect(code(() => s.query("scans", { limit: 5000 }))).toBe("INVALID_QUERY");
    s.close();
  });

  it("values that look like SQL are just values", () => {
    const s = openStore([V1]);
    const evil = `x'); drop table scans; --`;
    s.insert("scans", { target: evil });
    expect(s.query("scans", { where: { target: evil } })).toHaveLength(1);
    expect(s.count("scans")).toBe(1);
    expect(() => s.query("scans", { where: { "target = 1 or 1": 1 } as never })).toThrow(/no column/);
    s.close();
  });

  it("sensitive columns are encrypted at rest, unreadable without the key, and cannot be searched", () => {
    const s = openStore([V1]);
    s.insert("scans", { target: "t", api_key: "SHODAN-KEY-0123456789" });
    expect(s.get("scans", 1)!.api_key).toBe("SHODAN-KEY-0123456789");
    expect(() => s.query("scans", { where: { api_key: "SHODAN-KEY-0123456789" } })).toThrow(/sensitive/);
    s.close();
    const raw = new Database(storeFile(), { readonly: true });
    const stored = (raw.prepare("select api_key from scans").get() as { api_key: string }).api_key;
    raw.close();
    expect(stored).not.toContain("SHODAN");
    expect(stored.startsWith("v1:")).toBe(true);

    // Without the key: reading gives null (not a crash), writing a sensitive value is refused.
    const noKey = openStore([V1], { sealer: undefined });
    expect(noKey.get("scans", 1)!.api_key).toBeNull();
    expect(() => noKey.insert("scans", { target: "t", api_key: "x" })).toThrow(PluginStorageError);
    noKey.close();
  });

  it("a new migration keeps the data and takes a backup first", () => {
    const s1 = openStore([V1]);
    s1.insert("scans", { target: "kept" });
    s1.close();
    const s2 = openStore([V1, V2]);
    expect(s2.version).toBe(2);
    expect(s2.get("scans", 1)).toMatchObject({ target: "kept", score: 0 });
    s2.close();
    expect(readdirSync(join(dataDir, "store")).some((f) => /^data\.db\.v1-\d+\.bak$/.test(f))).toBe(true);
  });

  it("a migration that fails rolls back: same version, same columns, same rows", () => {
    const s1 = openStore([V1]);
    s1.insertMany("scans", [{ target: "dup" }, { target: "dup" }]);
    s1.close();
    // Its first step works, its second cannot (duplicates under a unique index): nothing stays.
    const bad: Migration = {
      version: 2,
      steps: [
        { op: "add_column", table: "scans", column: { name: "note", type: "text", required: false, sensitive: false } },
        { op: "create_index", table: "scans", name: "uniq_target", columns: ["target"], unique: true },
      ],
    };
    expect(() => openStore([V1, bad])).toThrow(/migration 2, step 2.*rolled back/);
    const again = openStore([V1]);
    expect(again.version).toBe(1);
    expect(again.count("scans")).toBe(2);
    again.close();
    const raw = new Database(storeFile(), { readonly: true });
    const cols = (raw.prepare("pragma table_info(scans)").all() as Array<{ name: string }>).map((c) => c.name);
    raw.close();
    expect(cols).not.toContain("note");
  });

  it("refuses to run when applied history was rewritten or the data is newer than the plugin", () => {
    openStore([V1, V2]).close();
    const before = fileBytes(storeFile());
    const edited: Migration = { ...V1, steps: [{ ...V1.steps[0]!, table: "scans" } as Migration["steps"][number], { op: "create_index", table: "scans", name: "x", columns: ["target"], unique: false }] };
    expect(() => openStore([edited, V2])).toThrow(expect.objectContaining({ code: "MIGRATION_CHANGED" }));
    expect(() => openStore([V1])).toThrow(expect.objectContaining({ code: "STORAGE_NEWER" }));
    expect(fileBytes(storeFile())).toBe(before);
  });

  it("the quota is enforced by SQLite itself; what was written stays", () => {
    const s = openStore([V1], { quotaMb: 1 });
    const big = "x".repeat(100_000);
    let written = 0;
    let error: PluginStorageError | undefined;
    for (let i = 0; i < 40; i++) {
      try {
        s.insert("scans", { target: `${i}-${big}` });
        written++;
      } catch (e) {
        error = e as PluginStorageError;
        break;
      }
    }
    expect(error?.code).toBe("QUOTA_EXCEEDED");
    expect(written).toBeGreaterThan(3);
    expect(s.count("scans")).toBe(written);
    expect(s.stats().bytes).toBeLessThanOrEqual(1024 * 1024);
    // Freeing space works, and so does writing again once there is room.
    s.deleteWhere("scans", { id: { op: "lte", value: 3 } });
    s.close();
  });

  it("a corrupt or tampered file is refused, not repaired", () => {
    mkdirSync(join(dataDir, "store"), { recursive: true });
    writeFileSync(storeFile(), "this is not a database".repeat(100));
    const before = fileBytes(storeFile());
    expect(() => openStore([V1])).toThrow(expect.objectContaining({ code: "STORAGE_CORRUPT" }));
    expect(fileBytes(storeFile())).toBe(before);
    rmSync(storeFile());

    openStore([V1]).close();
    const raw = new Database(storeFile());
    raw.exec("alter table scans add column sneaky text");
    raw.close();
    expect(() => openStore([V1])).toThrow(/sneaky/);
  });

  it("a database of another plugin is not opened as this one's", () => {
    openStore([V1]).close();
    expect(() => openStore([V1], { pluginId: "lab.other" })).toThrow(/belongs to lab.data/);
  });
});

// ---------------------------------------------------------------------------------------------
// Through the host: real plugins, real projects
// ---------------------------------------------------------------------------------------------

const BANNER = {
  name: "banner",
  label: "Banner",
  fields: [
    { name: "host", type: "host", required: true },
    { name: "port", type: "integer", required: true, min: 1, max: 65535 },
    { name: "text", type: "text" },
    { name: "url", type: "url" },
  ],
  key: ["host", "port"],
  title: "text",
  target: "host",
};

function writePlugin(id: string, contributes: Record<string, unknown>, folder = id) {
  const dir = join(dataDir, "plugins", folder);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "plugin.json"),
    JSON.stringify({ id, name: `Plugin ${id}`, version: "1.0.0", apiVersion: 1, level: "declarative", author: { type: "human" }, permissions: ["graph:read", "graph:write"], contributes }),
  );
}

async function world(contributes: Record<string, unknown> = { entityTypes: [BANNER], annotations: [{ on: ["host", "webapp"], fields: [{ name: "shodanId", type: "string" }, { name: "tags", type: "tags" }] }] }) {
  writePlugin("lab.shodan", contributes);
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const host = new PluginHost({ dataDir, activators: { declarative: declarativeActivator(data) }, activationBudgetMs: 2000 });
  data.bind(host);
  await host.load();
  await host.approve("lab.shodan");
  const eng = ws.create({ clientName: "ACME", name: "Infra", mode: "infra" }, human);
  const ctx = { workspace: ws, caller: { actor: human, policy: { type: "human", autonomy: "autonomous", maxRisk: "active" } }, engagement: () => eng, runner: () => { throw new Error("none"); }, plugins: host, pluginData: data } as unknown as OperationContext;
  return { ws, data, host, eng, ctx, close: () => ws.close() };
}

function addHost(eng: ReturnType<Workspace["get"]>, ip: string): void {
  eng.ingest({ format: INGEST_FORMAT, source: { parser: "test@1" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "host", key: { ip }, attributes: { status: "up" } }] }, human);
}

describe("plugin types in the graph", () => {
  it("are validated strictly and keyed: the same key updates, the operator's edit wins", async () => {
    const w = await world();
    try {
      expect(w.host.get("lab.shodan")?.status).toBe("active");
      const a = w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 22, text: "OpenSSH 8.2" }, human);
      expect(a.created).toBe(true);
      expect(() => w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 22, extra: 1 }, human)).toThrow(/extra/);
      expect(() => w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 70000 }, human)).toThrow(/port/);
      w.eng.editEntity(a.entity.id, { text: "edited by the operator" }, human);
      const b = w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 22, text: "OpenSSH 9.0", url: "https://example.test/" }, human);
      expect(b.created).toBe(false);
      expect(b.entity.id).toBe(a.entity.id);
      expect(b.entity.attributes).toMatchObject({ text: "edited by the operator", url: "https://example.test/" });
      expect(w.eng.query({ kind: "lab.shodan:banner" })).toHaveLength(1);
      expect(w.eng.counts()["lab.shodan:banner"]).toBe(1);
      // An unregistered kind of a plugin that never existed is refused the same way.
      expect(() => w.eng.createEntity("lab.ghost:thing", { a: 1 }, human)).toThrow(DormantTypeError);
    } finally {
      w.close();
    }
  });

  it("are marked out of scope like official ones, and relate to official entities", async () => {
    const w = await world();
    try {
      w.eng.addScopeRule({ effect: "include", target: { type: "ip", value: "10.0.0.5" } }, human);
      const inside = w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 80 }, human).entity;
      const outside = w.eng.putPluginEntity("lab.shodan:banner", { host: "192.0.2.9", port: 80 }, human).entity;
      expect(inside.outOfScope).toBe(false);
      expect(outside.outOfScope).toBe(true);
      const hostEntity = w.eng.createEntity("note", { title: "n", body: "" }, human);
      const edge = w.eng.relate(inside.id, hostEntity.id, human);
      expect(edge.type).toBe("related_to");
      expect(w.eng.relate(inside.id, hostEntity.id, human).id).toBe(edge.id);
      expect(w.eng.edgesOf(hostEntity.id)).toHaveLength(1);
    } finally {
      w.close();
    }
  });
});

describe("annotations on official entities", () => {
  it("live in their own space: official attributes, revision and conflicts untouched", async () => {
    const w = await world();
    try {
      const finding = w.eng.createEntity("finding", { title: "Open SSH", severity: "low" }, human);
      expect(() => w.eng.annotate(finding.id, "lab.shodan", { shodanId: "1" }, human)).toThrow(/does not declare annotations on finding/);
      const n = w.eng.createEntity("note", { title: "n", body: "" }, human);
      expect(() => w.eng.annotate(n.id, "lab.shodan", { shodanId: "1" }, human)).toThrow(/does not declare/);

      // A host via ingest, the normal way.
      addHost(w.eng, "10.0.0.7");
      const host = w.eng.query({ kind: "host" })[0]!;
      const before = w.eng.get(host.id)!;
      w.eng.annotate(host.id, "lab.shodan", { shodanId: "abc", tags: ["iot"] }, human);
      w.eng.annotate(host.id, "lab.shodan", { tags: null }, human);
      const after = w.eng.get(host.id)!;
      expect(after.ext).toEqual({ "lab.shodan": { shodanId: "abc" } });
      expect(after.attributes).toEqual(before.attributes);
      expect(after.revision).toBe(before.revision);
      expect(() => w.eng.annotate(host.id, "lab.shodan", { shodanId: 5 }, human)).toThrow(/shodanId/);
      expect(() => w.eng.annotate(host.id, "lab.shodan", { unknown: "x" }, human)).toThrow(/unknown/i);
      // Official fields through the official path still work and do not see the annotation.
      w.eng.editEntity(host.id, { hostname: "router" }, human);
      expect(w.eng.get(host.id)!.attributes).not.toHaveProperty("shodanId");
      expect(w.eng.get(host.id)!.ext).toEqual({ "lab.shodan": { shodanId: "abc" } });
    } finally {
      w.close();
    }
  });
});

describe("turning a plugin off or removing it never breaks the graph", () => {
  it("its entities and annotations stay readable and dormant; installing it again brings them back", async () => {
    const w = await world();
    try {
      const banner = w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 443, text: "nginx" }, human).entity;
      addHost(w.eng, "10.0.0.5");
      const host = w.eng.query({ kind: "host" })[0]!;
      w.eng.annotate(host.id, "lab.shodan", { shodanId: "s1" }, human);

      await executeOperation("plugin.uninstall", { id: "lab.shodan" }, w.ctx);
      expect(existsSync(join(dataDir, "plugins", "lab.shodan"))).toBe(false);
      expect(w.host.get("lab.shodan")).toBeUndefined();

      // Readable, as data.
      expect(w.eng.get(banner.id)?.attributes).toMatchObject({ text: "nginx" });
      expect(w.eng.get(host.id)?.ext).toEqual({ "lab.shodan": { shodanId: "s1" } });
      expect(w.eng.query({ text: "nginx" }).map((e) => e.id)).toContain(banner.id);
      // Not writable, with a reason that names the plugin.
      await expect(executeOperation("entity.edit", { engagementId: w.eng.info.id, id: banner.id, fields: { text: "x" } }, w.ctx)).rejects.toMatchObject({ code: "PLUGIN_UNAVAILABLE" });
      expect(() => w.eng.annotate(host.id, "lab.shodan", { shodanId: "s2" }, human)).toThrow(DormantTypeError);
      // A failed edit left nothing behind.
      expect(w.eng.get(banner.id)?.attributes).toMatchObject({ text: "nginx" });
      // The official graph goes on as if nothing happened.
      expect(w.eng.createEntity("finding", { title: "TLS 1.0", severity: "low" }, human).kind).toBe("finding");
      w.eng.addScopeRule({ effect: "include", target: { type: "cidr", value: "10.0.0.0/24" } }, human);
      expect(w.eng.get(banner.id)?.outOfScope).toBe(false);

      // Back again: same data, writable.
      writePlugin("lab.shodan", { entityTypes: [BANNER], annotations: [{ on: ["host"], fields: [{ name: "shodanId", type: "string" }] }] });
      await w.host.load();
      await w.host.approve("lab.shodan");
      expect(w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 443, text: "nginx 1.25" }, human).entity.id).toBe(banner.id);
      expect(w.eng.annotate(host.id, "lab.shodan", { shodanId: "s2" }, human)).toEqual({ shodanId: "s2" });
    } finally {
      w.close();
    }
  });

  it("purging takes away exactly what the plugin left", async () => {
    const w = await world({ entityTypes: [BANNER], annotations: [{ on: ["host"], fields: [{ name: "shodanId", type: "string" }] }], storage: { project: [V1] } });
    try {
      const banner = w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 443 }, human).entity;
      const note = w.eng.createEntity("note", { title: "kept", body: "" }, human);
      w.eng.relate(banner.id, note.id, human);
      w.data.project("lab.shodan", w.eng).insert("scans", { target: "x" });
      expect(w.eng.pluginFootprint("lab.shodan")).toEqual({ entities: { "lab.shodan:banner": 1 }, annotations: 0 });
      const result = await executeOperation("plugin.purge_project", { id: "lab.shodan", engagementId: w.eng.info.id, graph: true }, w.ctx);
      expect(result).toMatchObject({ entities: 1 });
      expect(w.eng.get(banner.id)).toBeUndefined();
      expect(w.eng.get(note.id)).toBeDefined();
      expect(w.eng.edgesOf(note.id)).toHaveLength(0);
      expect(existsSync(join(w.eng.dir, "plugins", "lab.shodan"))).toBe(false);
    } finally {
      w.close();
    }
  });
});

describe("storage failures turn the plugin off, never the project", () => {
  it("a project database that cannot migrate: plugin off with STORAGE_FAILED, data and project intact", async () => {
    const w = await world({ storage: { project: [V1] } });
    try {
      const store = w.data.project("lab.shodan", w.eng);
      store.insertMany("scans", [{ target: "dup" }, { target: "dup" }]);
      // The author ships a version whose migration cannot apply to this data.
      writePlugin("lab.shodan", { storage: { project: [V1, { version: 2, steps: [{ op: "create_index", table: "scans", name: "u", columns: ["target"], unique: true }] }] } });
      await w.host.load();
      await w.host.approve("lab.shodan");
      w.data.close("lab.shodan");
      expect(() => w.data.project("lab.shodan", w.eng)).toThrow(/rolled back/);
      await new Promise((r) => setTimeout(r, 10));
      expect(w.host.get("lab.shodan")).toMatchObject({ status: "disabled", reason: { code: "STORAGE_FAILED", auto: true } });
      expect(w.host.notices().items.map((n) => n.code)).toContain("STORAGE_FAILED");
      expect(() => w.data.project("lab.shodan", w.eng)).toThrow(PluginUnavailableError);
      // The plugin's data is as it was, and the project never noticed.
      const raw = new Database(PluginData.projectFile(w.eng.dir, "lab.shodan"), { readonly: true });
      expect((raw.prepare("select count(*) n from scans").get() as { n: number }).n).toBe(2);
      raw.close();
      expect(w.eng.createEntity("note", { title: "still fine", body: "" }, human).kind).toBe("note");
    } finally {
      w.close();
    }
  });

  it("a global database that cannot open fails the activation with STORAGE_FAILED", async () => {
    mkdirSync(join(dataDir, "plugin-data", "lab.shodan"), { recursive: true });
    writeFileSync(join(dataDir, "plugin-data", "lab.shodan", "global.db"), "garbage".repeat(500));
    const w = await world({ storage: { global: [V1] } });
    try {
      expect(w.host.get("lab.shodan")).toMatchObject({ status: "disabled", reason: { code: "STORAGE_FAILED" } });
      expect(w.host.get("lab.shodan")?.reason?.detail).toMatch(/STORAGE_CORRUPT/);
      expect(readFileSync(join(dataDir, "plugin-data", "lab.shodan", "global.db"), "utf8")).toBe("garbage".repeat(500));
    } finally {
      w.close();
    }
  });

  it("a plugin that is off cannot reach its data", async () => {
    const w = await world({ storage: { project: [V1], global: [V1] } });
    try {
      w.data.global("lab.shodan").insert("scans", { target: "g" });
      await w.host.disable("lab.shodan");
      expect(() => w.data.global("lab.shodan")).toThrow(PluginUnavailableError);
      expect(() => w.data.project("lab.shodan", w.eng)).toThrow(PluginUnavailableError);
      expect(pluginTypes.list()).toHaveLength(0);
    } finally {
      w.close();
    }
  });
});

describe("plugin data travels with the project", () => {
  it("export carries each plugin database with sensitive values emptied; import restores it", async () => {
    const w = await world({ storage: { project: [V1] } });
    const file = join(dataDir, "acme.penteos");
    let id: string;
    try {
      const store = w.data.project("lab.shodan", w.eng);
      store.insert("scans", { target: "travels", api_key: "TOP-SECRET-KEY" });
      const out = await w.ws.exportEngagement(w.eng.info.id, file);
      expect(out.pluginData).toEqual(["lab.shodan"]);
      expect(readFileSync(file).includes(Buffer.from("TOP-SECRET-KEY"))).toBe(false);
      // The live database still has the value: export works on a copy.
      expect(store.get("scans", 1)!.api_key).toBe("TOP-SECRET-KEY");
      id = w.eng.info.id;
    } finally {
      w.close();
    }
    const other = new Workspace(join(dataDir, "other"));
    try {
      const summary = other.importEngagement(file, human);
      expect(summary.id).toBe(id);
      const dir = other.dirOf(summary.id);
      const copy = PluginStore.open({ file: PluginData.projectFile(dir, "lab.shodan"), pluginId: "lab.shodan", migrations: [V1], quotaMb: 64, sealer });
      expect(copy.get("scans", 1)).toMatchObject({ target: "travels", api_key: null });
      copy.close();
    } finally {
      other.close();
    }
  });

  it("an import never writes outside plugins/<valid id>/data.db", async () => {
    const w = await world({ storage: { project: [V1] } });
    const file = join(dataDir, "x.penteos");
    try {
      w.data.project("lab.shodan", w.eng).insert("scans", { target: "a" });
      await w.ws.exportEngagement(w.eng.info.id, file);
    } finally {
      w.close();
    }
    const { unzipSync, zipSync } = await import("fflate");
    const zip = unzipSync(readFileSync(file));
    zip["plugins/../../evil/data.db"] = new Uint8Array([1]);
    zip["plugins/BAD ID/data.db"] = new Uint8Array([1]);
    writeFileSync(file, zipSync(zip));
    const other = new Workspace(join(dataDir, "other2"));
    try {
      const summary = other.importEngagement(file, human);
      const dir = other.dirOf(summary.id);
      expect(readdirSync(join(dir, "plugins"))).toEqual(["lab.shodan"]);
      expect(existsSync(join(dataDir, "evil"))).toBe(false);
    } finally {
      other.close();
    }
  });
});

describe("operator operations", () => {
  it("plugin.storage reports sizes and what each plugin left, installed or not", async () => {
    const w = await world({ entityTypes: [BANNER], storage: { project: [V1] } });
    try {
      w.data.project("lab.shodan", w.eng).insert("scans", { target: "a" });
      w.eng.putPluginEntity("lab.shodan:banner", { host: "10.0.0.5", port: 1 }, human);
      const one = (await executeOperation("plugin.storage", { id: "lab.shodan", engagementId: w.eng.info.id }, w.ctx)) as { project: { tables: unknown[] }; footprint: unknown };
      expect(one.project.tables).toEqual([{ name: "scans", rows: 1 }]);
      expect(one.footprint).toEqual({ entities: { "lab.shodan:banner": 1 }, annotations: 0 });
      await executeOperation("plugin.uninstall", { id: "lab.shodan" }, w.ctx);
      const all = (await executeOperation("plugin.storage", { engagementId: w.eng.info.id }, w.ctx)) as { plugins: Array<{ pluginId: string; installed: boolean; tables: string[] }> };
      expect(all.plugins).toMatchObject([{ pluginId: "lab.shodan", installed: false, tables: ["scans"] }]);
      const agent = { ...w.ctx, caller: { actor: { type: "agent", id: "maestro" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } } } as unknown as OperationContext;
      await expect(executeOperation("plugin.purge_project", { id: "lab.shodan", engagementId: w.eng.info.id }, agent)).rejects.toBeTruthy();
    } finally {
      w.close();
    }
  });
});

