import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, PluginManifest } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  changedOutputs,
  codeActivator,
  declarativeActivator,
  deleteOutput,
  executeOperation,
  listOutputs,
  type OperationContext,
  OutputError,
  outputDir,
  outputPath,
  PluginData,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginTypes,
  readOutput,
  Workspace,
  writeOutput,
} from "../src/index.js";

/**
 * Files plugins make for the operator: in the project's
 * folder, offered to download or open after the run, listed per plugin, exported with the project.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-outputs-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

describe("the output folder", () => {
  it("takes names inside it only, writes atomically and never follows a planted link", () => {
    const dir = join(dataDir, "out");
    for (const bad of ["../x", "/etc/passwd", "a/../../x", ".hidden", "a/.git/x", "C:/x", "a\u0000b", ""]) {
      expect(() => writeOutput(dir, bad, Buffer.from("x")), bad).toThrow(OutputError);
    }
    const f = writeOutput(dir, "informes/Acme Q3.docx", Buffer.from("PK..."));
    expect(f).toMatchObject({ name: "informes/Acme Q3.docx", size: 5, type: expect.stringContaining("wordprocessingml") });
    expect(readFileSync(join(dir, "informes", "Acme Q3.docx"), "utf8")).toBe("PK...");

    // A link to a file outside: reading it is refused, writing over it replaces the link, not the target.
    const secret = join(dataDir, "secret.txt");
    writeFileSync(secret, "do not read");
    symlinkSync(secret, join(dir, "link.txt"));
    expect(() => readOutput(dir, "link.txt")).toThrow(/outside/);
    expect(listOutputs(dir).files.map((x) => x.name)).toEqual(["informes/Acme Q3.docx"]);
    writeOutput(dir, "link.txt", Buffer.from("mine"));
    expect(readFileSync(secret, "utf8")).toBe("do not read");
    // A linked folder is not a way out either.
    symlinkSync(dataDir, join(dir, "up"));
    expect(() => writeOutput(dir, "up/escaped.txt", Buffer.from("x"))).toThrow(OutputError);
    expect(existsSync(join(dataDir, "escaped.txt"))).toBe(false);

    deleteOutput(dir, "informes/Acme Q3.docx");
    expect(existsSync(join(dir, "informes"))).toBe(false);
    expect(() => outputPath(dir, "informes/Acme Q3.docx")).toThrow(/no file/);
  });

  it("tells new and rewritten files from the ones that were already there", () => {
    const a = { name: "a.csv", size: 1, modifiedAt: "2026-01-01T00:00:00.000Z", type: "text/csv" };
    const b = { name: "b.csv", size: 1, modifiedAt: "2026-01-01T00:00:00.000Z", type: "text/csv" };
    expect(changedOutputs([a, b], [{ ...a, size: 2 }, b, { ...b, name: "c.csv" }]).map((f) => f.name)).toEqual(["a.csv", "c.csv"]);
  });
});

const NODE_CODE = String.raw`
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
export async function activate(p) {
  p.operation("through_core", async (input, penteos) => {
    const bytes = new Uint8Array([0x50, 0x4b, 3, 4, 255]);
    const a = await penteos.files.write("bin/data.bin", bytes);
    const b = await penteos.files.write("summary.json", { client: input.client, hosts: 3 });
    return { a, b, dir: penteos.files.dir ?? null };
  });
  p.operation("by_itself", async (input, penteos) => {
    mkdirSync(join(penteos.files.dir, "charts"), { recursive: true });
    writeFileSync(join(penteos.files.dir, "charts", "risk.svg"), "<svg/>");
    return "drawn";
  });
}
`;

const PY_CODE = `
import os

def activate(plugin):
    @plugin.operation("report")
    def report(input, penteos):
        penteos.files.write("notes.md", "# " + input["client"])
        with open(os.path.join(penteos.files.dir, "raw.csv"), "w") as f:
            f.write("host,port\\n10.0.0.1,443\\n")
        return {"ok": True}
`;

function manifest(id: string, extra: Record<string, unknown>): Record<string, unknown> {
  return { id, name: id, version: "1.0.0", apiVersion: 1, author: { type: "human", name: "Lab" }, ...extra };
}

const DECLARATIVE = manifest("lab.csv", {
  level: "declarative",
  permissions: ["files:write"],
  contributes: {
    operations: [
      {
        name: "export_csv",
        title: "Export",
        action: { en: "Export CSV", es: "Exportar CSV" },
        description: "Exports hosts",
        input: [{ name: "client", type: "string", required: true }],
        steps: [{ do: "file", id: "csv", name: "exports/{{input.client | lower}}.csv", content: "host,port\n10.0.0.1,443\n" }],
        result: "{{steps.csv}}",
        view: { type: "card", fields: [{ field: "name", label: "File" }, { field: "size", label: "Bytes" }] },
      },
    ],
  },
});

const OP = (name: string) => ({ name, title: name, description: name, handler: name, input: [{ name: "client", type: "string" }], timeoutMs: 8000 });

async function world(m: Record<string, unknown>, files: Record<string, string> = {}, trust: "free" | "isolated" = "isolated") {
  const dir = join(dataDir, "plugins", String(m.id));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), JSON.stringify(m));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  const ws = new Workspace(join(dataDir, "ws"));
  const data = new PluginData({ dataDir, globalVault: () => ws.vault() });
  const settings = new PluginSettings(dataDir, () => ws.vault());
  const runtime = new PluginRuntime({ data, settings, workspace: ws });
  const host = new PluginHost({
    dataDir,
    activationBudgetMs: 15_000,
    activators: { declarative: declarativeActivator(data, runtime), code: codeActivator(data, runtime, { hostDir: join(dataDir, "plugin-host"), limits: { sampleMs: 300 } }) },
  });
  runtime.bind(host);
  data.bind(host);
  await host.load();
  await host.approve(String(m.id), { reviewedCode: true, trust });
  expect(host.get(String(m.id))?.status, String(host.get(String(m.id))?.reason)).toBe("active");
  const eng = ws.create({ clientName: "Lab", name: "Files", mode: "web", plugins: [String(m.id)] }, human);
  const ctx = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => { throw new Error("no runner"); }, plugins: host, pluginData: data, pluginRuntime: runtime, pluginSettings: settings } as unknown as OperationContext;
  const op = (name: string, input: Record<string, unknown> = {}) => executeOperation(name, input, ctx);
  const run = (name: string, input: Record<string, unknown> = {}) => op("plugin.run", { name: `plugin.${String(m.id)}.${name}`, input }) as Promise<{ result: unknown; plugin?: string; files?: Array<{ name: string; size: number }> }>;
  return { ws, eng, op, run, close: () => { runtime.detachCode(String(m.id))?.stop(); ws.close(); } };
}

describe("a plugin's files", () => {
  it("needs files:write to save one", () => {
    const m = structuredClone(DECLARATIVE) as { permissions: string[] };
    m.permissions = [];
    const r = PluginManifest.safeParse(m);
    expect(r.success).toBe(false);
    expect(JSON.stringify(r.error?.issues)).toMatch(/files:write/);
  });

  it("a declarative plugin saves one; the run brings it, the project lists it, and it can be read and deleted", async () => {
    const w = await world(DECLARATIVE);
    try {
      const r = await w.run("export_csv", { client: "ACME" });
      expect(r.result).toMatchObject({ name: "exports/acme.csv", type: "text/csv" });
      expect(r.plugin).toBe("lab.csv");
      expect(r.files?.map((f) => f.name)).toEqual(["exports/acme.csv"]);
      const listed = (await w.op("plugin.outputs", {})) as { plugins: Array<{ id: string; files: Array<{ name: string }> }> };
      expect(listed.plugins.map((p) => [p.id, p.files.map((f) => f.name)])).toEqual([["lab.csv", ["exports/acme.csv"]]]);
      const read = (await w.op("plugin.output_read", { id: "lab.csv", name: "exports/acme.csv" })) as { base64: string };
      expect(Buffer.from(read.base64, "base64").toString()).toBe("host,port\n10.0.0.1,443\n");
      const where = (await w.op("plugin.output_path", { id: "lab.csv", name: "exports/acme.csv" })) as { path: string };
      expect(where.path).toBe(join(outputDir(w.eng.dir, "lab.csv"), "exports", "acme.csv"));
      await expect(w.op("plugin.output_read", { id: "lab.csv", name: "../data.db" })).rejects.toThrow();
      // Running it again with the same content still reports the file (it was written again).
      await new Promise((r) => setTimeout(r, 15));
      expect((await w.run("export_csv", { client: "ACME" })).files?.length).toBe(1);
      expect(w.eng.auditEvents({ limit: 50 }).some((a) => a.action === "plugin.file_written")).toBe(true);
      await w.op("plugin.output_delete", { id: "lab.csv", name: "exports/acme.csv" });
      expect(((await w.op("plugin.outputs", { id: "lab.csv" })) as { plugins: Array<{ total: number }> }).plugins[0]!.total).toBe(0);
    } finally {
      w.close();
    }
  });

  it("an isolated code plugin saves bytes and JSON through the core and gets no folder of its own", async () => {
    const m = manifest("lab.nodefiles", { level: "code", main: "main.mjs", permissions: ["files:write"], contributes: { operations: [OP("through_core")] } });
    const w = await world(m, { "main.mjs": NODE_CODE });
    try {
      const r = await w.run("through_core", { client: "ACME" });
      expect(r.result).toMatchObject({ a: { name: "bin/data.bin", size: 5 }, b: { name: "summary.json" }, dir: null });
      const dir = outputDir(w.eng.dir, "lab.nodefiles");
      expect([...readFileSync(join(dir, "bin", "data.bin"))]).toEqual([0x50, 0x4b, 3, 4, 255]);
      expect(JSON.parse(readFileSync(join(dir, "summary.json"), "utf8"))).toEqual({ client: "ACME", hosts: 3 });
      expect(r.files?.map((f) => f.name).sort()).toEqual(["bin/data.bin", "summary.json"]);
    } finally {
      w.close();
    }
  });

  it("a free code plugin writes in its folder by itself, and the run still finds what it made", async () => {
    const m = manifest("lab.freefiles", { level: "code", main: "main.mjs", permissions: [], contributes: { operations: [OP("by_itself")] } });
    const w = await world(m, { "main.mjs": NODE_CODE }, "free");
    try {
      const r = await w.run("by_itself");
      expect(r.result).toBe("drawn");
      expect(r.files?.map((f) => f.name)).toEqual(["charts/risk.svg"]);
      expect(r.files?.[0]).toMatchObject({ type: "image/svg+xml" });
    } finally {
      w.close();
    }
  });

  it.skipIf(spawnSync("python3", ["--version"]).status !== 0)("a Python plugin does both", async () => {
    const m = manifest("lab.pyfiles", { level: "code", main: "main.py", runtime: "python", permissions: ["files:write"], contributes: { operations: [OP("report")] } });
    const w = await world(m, { "main.py": PY_CODE }, "free");
    try {
      const r = await w.run("report", { client: "ACME" });
      expect(r.files?.map((f) => f.name).sort()).toEqual(["notes.md", "raw.csv"]);
      expect(readFileSync(join(outputDir(w.eng.dir, "lab.pyfiles"), "notes.md"), "utf8")).toBe("# ACME");
    } finally {
      w.close();
    }
  });

  it("travel with the project's export, without what a link points to", async () => {
    const w = await world(DECLARATIVE);
    try {
      await w.run("export_csv", { client: "ACME" });
      const dir = outputDir(w.eng.dir, "lab.csv");
      writeFileSync(join(dataDir, "outside.txt"), "not part of the project");
      symlinkSync(join(dataDir, "outside.txt"), join(dir, "sneaky.txt"));
      const file = join(dataDir, "acme.penteos");
      await w.ws.exportEngagement(w.eng.info.id, file);
      const imported = w.ws.importEngagement(file, human);
      const copy = outputDir(w.ws.dirOf(imported.id), "lab.csv");
      expect(readFileSync(join(copy, "exports", "acme.csv"), "utf8")).toBe("host,port\n10.0.0.1,443\n");
      expect(existsSync(join(copy, "sneaky.txt"))).toBe(false);
    } finally {
      w.close();
    }
  });
});
