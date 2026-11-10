import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, PluginManifest, ulid } from "@penteos/schema";
import { unzipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  codeActivator,
  declarativeActivator,
  type Engagement,
  executeOperation,
  type OperationContext,
  outputDir,
  PluginData,
  PluginHost,
  PluginRuntime,
  PluginSettings,
  pluginTypes,
  Workspace,
} from "../src/index.js";

/**
 * The report engine as a capability: a plugin asks for the
 * official deliverable with its own choices, and plugins add sections to the official one.
 */

const human: Actor = { type: "human", id: "01J00000000000000000000000" };
const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "penteos-report-"));
});
afterEach(() => {
  pluginTypes.clear();
  rmSync(dataDir, { recursive: true, force: true });
});

function manifest(id: string, extra: Record<string, unknown>): Record<string, unknown> {
  return { id, name: id, version: "1.0.0", apiVersion: 1, author: { type: "human", name: "Lab" }, ...extra };
}

const WORD = manifest("lab.word", {
  level: "declarative",
  permissions: ["graph:read", "files:write"],
  contributes: {
    operations: [
      {
        name: "word",
        title: "Word report",
        action: { en: "Generate report", es: "Generar informe" },
        icon: "file-text",
        description: "The deliverable signed by whoever runs it",
        input: [
          { name: "author", type: "string", required: true },
          { name: "notes", type: "text" },
        ],
        steps: [
          {
            do: "report",
            id: "doc",
            name: "informes/{{input.author | lower | replace:' ':'-'}}.docx",
            title: "Informe de seguridad - {{engagement.clientName}}",
            author: "{{input.author}}",
            company: "Auditores SA",
            color: "#0f766e",
            logo: "assets/logo.png",
            skip: ["surface", "annex"],
            extra: [{ title: "Notas del auditor", markdown: "{{input.notes | default:'Sin notas.'}}", after: "executive_summary" }],
          },
        ],
        result: "{{steps.doc}}",
        view: { type: "card", fields: [{ field: "name", label: "File" }] },
      },
      {
        name: "brief",
        title: "Brief",
        description: "Only the findings, as markdown",
        input: [],
        steps: [{ do: "report", id: "md", format: "markdown", sections: ["findings", "detailed"], minSeverity: "high", includeDrafts: true }],
        result: "{{steps.md}}",
        view: { type: "json" },
      },
      {
        name: "bad_color",
        title: "Bad",
        description: "Bad color",
        input: [],
        steps: [{ do: "report", color: "teal" }],
        view: { type: "json" },
      },
    ],
  },
});

const SECTIONS = manifest("lab.sections", {
  level: "declarative",
  permissions: ["graph:read"],
  contributes: {
    operations: [
      { name: "hosts_table", title: "Hosts", description: "A table of hosts", input: [], steps: [{ do: "graph_query", id: "h", kind: "host" }], result: "| Host |\n|---|\n{{steps.h | pluck:'attributes.ip' | join:'\n'}}", view: { type: "markdown" } },
      { name: "empty", title: "Empty", description: "Nothing to say", input: [], steps: [{ do: "set", vars: { x: 1 } }], result: "", view: { type: "markdown" } },
      { name: "broken", title: "Broken", description: "Fails", input: [], steps: [{ do: "fail", message: "the API is down" }], view: { type: "markdown" } },
    ],
    reportSections: [
      { id: "hosts", title: { en: "Hosts seen", es: "Hosts relevados" }, operation: "hosts_table", after: "findings" },
      { id: "nothing", title: "Nothing", operation: "empty" },
      { id: "broken", title: "Broken one", operation: "broken" },
      { id: "infra_only", title: "Only infrastructure", operation: "hosts_table", modes: ["infra"] },
    ],
  },
});

async function world(manifests: Array<{ m: Record<string, unknown>; files?: Record<string, string | Buffer> }>, trust: "free" | "isolated" = "isolated") {
  for (const { m, files } of manifests) {
    const dir = join(dataDir, "plugins", String(m.id));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "plugin.json"), JSON.stringify(m));
    for (const [name, content] of Object.entries(files ?? {})) {
      mkdirSync(join(dir, name, ".."), { recursive: true });
      writeFileSync(join(dir, name), content);
    }
  }
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
  for (const { m } of manifests) {
    await host.approve(String(m.id), { reviewedCode: true, trust });
    expect(host.get(String(m.id))?.status, String(host.get(String(m.id))?.reason)).toBe("active");
  }
  const eng = ws.create({ language: "es", clientName: "Acme", name: "Q3", mode: "web", plugins: manifests.map(({ m }) => String(m.id)) }, human);
  seed(eng);
  const ctx = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => { throw new Error("no runner"); }, plugins: host, pluginData: data, pluginRuntime: runtime, pluginSettings: settings } as unknown as OperationContext;
  const op = (name: string, input: Record<string, unknown> = {}) => executeOperation(name, input, ctx);
  return { ws, eng, op, close: () => { for (const { m } of manifests) runtime.detachCode(String(m.id))?.stop(); ws.close(); } };
}

function seed(eng: Engagement): void {
  const h = eng.createEntity("host", { ip: "10.0.0.7", networkContext: "default" }, human);
  eng.createEntity("finding", { title: "SQL injection in login", severity: "critical", status: "approved", description: "The login form builds its query by hand.", remediation: "Use parameters.", instances: [{ id: ulid(), entity: { id: h.id, kind: "host" }, status: "open" }] }, human);
  eng.createEntity("finding", { title: "Verbose banner", severity: "low", status: "approved" }, human);
  eng.createEntity("finding", { title: "Weak TLS (draft)", severity: "high", status: "draft" }, human);
}

const docText = (bytes: Buffer) => new TextDecoder().decode(unzipSync(new Uint8Array(bytes))["word/document.xml"]!);

describe("the report step", () => {
  it("needs graph:read and files:write", () => {
    const m = structuredClone(WORD) as { permissions: string[] };
    m.permissions = ["files:write"];
    expect(JSON.stringify(PluginManifest.safeParse(m).error?.issues)).toMatch(/graph:read/);
  });

  it("makes the official .docx with the plugin's title, author, company, color, logo, sections and its own text", async () => {
    const w = await world([{ m: WORD, files: { "assets/logo.png": Buffer.from(PNG, "base64") } }]);
    try {
      const r = (await w.op("plugin.run", { name: "plugin.lab.word.word", input: { author: "Juan Pérez", notes: "Se probó **solo** la app web." } })) as { result: { name: string; type: string }; files: Array<{ name: string }> };
      expect(r.result).toMatchObject({ name: "informes/juan-pérez.docx", type: expect.stringContaining("wordprocessingml") });
      expect(r.files.map((f) => f.name)).toEqual(["informes/juan-pérez.docx"]);
      const bytes = readFileSync(join(outputDir(w.eng.dir, "lab.word"), "informes", "juan-pérez.docx"));
      const zip = unzipSync(new Uint8Array(bytes));
      const xml = docText(bytes);
      expect(xml).toContain("Informe de seguridad - Acme");
      expect(xml).toContain("Juan Pérez");
      expect(xml).toContain("Auditores SA");
      expect(xml.toLowerCase()).toContain("0f766e");
      expect(xml).toContain("Notas del auditor");
      expect(xml).toContain("SQL injection in login");
      // The draft finding is not in a final deliverable; skipped sections are not there.
      expect(xml).not.toContain("Weak TLS");
      expect(xml).not.toContain("Trazabilidad");
      expect(Object.keys(zip).some((k) => k.startsWith("word/media/"))).toBe(true);
      // The order: summary, the plugin's notes, then the findings.
      expect(xml.indexOf("Notas del auditor")).toBeGreaterThan(xml.indexOf("Resumen ejecutivo"));
      expect(xml.indexOf("Notas del auditor")).toBeLessThan(xml.indexOf("Resumen de hallazgos"));
    } finally {
      w.close();
    }
  });

  it("gives back the markdown (with the vault's markers) and refuses a bad option clearly", async () => {
    const w = await world([{ m: WORD, files: { "assets/logo.png": Buffer.from(PNG, "base64") } }]);
    try {
      const r = (await w.op("plugin.run", { name: "plugin.lab.word.brief" })) as { result: { name: string; markdown: string } };
      expect(r.result.name).toMatch(/\.md$/);
      expect(r.result.markdown).toMatch(/## 1\. Resumen de hallazgos/);
      expect(r.result.markdown).toContain("Weak TLS (draft)");
      expect(r.result.markdown).not.toContain("Verbose banner");
      expect(r.result.markdown).not.toContain("Alcance");
      await expect(w.op("plugin.run", { name: "plugin.lab.word.bad_color" })).rejects.toThrow(/#1f6feb/);
    } finally {
      w.close();
    }
  });

  it("is there for code too: Node and Python", async () => {
    const node = manifest("lab.noderep", { level: "code", main: "main.mjs", permissions: ["graph:read", "files:write"], contributes: { operations: [{ name: "go", title: "Go", description: "go", handler: "go", input: [] }] } });
    const code = `export async function activate(p) { p.operation("go", async (input, penteos) => penteos.report({ title: "Desde código", author: "Ana", sections: ["findings"], name: "code.docx" })); }`;
    const runs: Array<Record<string, unknown>> = [{ m: node, files: { "main.mjs": code } }];
    const hasPython = spawnSync("python3", ["--version"]).status === 0;
    if (hasPython) {
      const py = manifest("lab.pyrep", { level: "code", main: "main.py", runtime: "python", permissions: ["graph:read", "files:write"], contributes: { operations: [{ name: "go", title: "Go", description: "go", handler: "go", input: [] }] } });
      runs.push({ m: py, files: { "main.py": `def activate(plugin):\n    @plugin.operation("go")\n    def go(input, penteos):\n        return penteos.report(format="markdown", include_drafts=True, min_severity="high")\n` } });
    }
    const w = await world(runs as never, "free");
    try {
      const r = (await w.op("plugin.run", { name: "plugin.lab.noderep.go" })) as { result: { name: string } };
      expect(r.result.name).toBe("code.docx");
      expect(docText(readFileSync(join(outputDir(w.eng.dir, "lab.noderep"), "code.docx")))).toContain("Desde código");
      if (hasPython) {
        const p = (await w.op("plugin.run", { name: "plugin.lab.pyrep.go" })) as { result: { markdown: string } };
        expect(p.result.markdown).toContain("Weak TLS (draft)");
        expect(p.result.markdown).not.toContain("Verbose banner");
      }
    } finally {
      w.close();
    }
  });
});

describe("plugin sections in the official deliverable", () => {
  it("go where they say, leave out what has nothing to say or fails (and say so), and respect the project's mode", async () => {
    const w = await world([{ m: SECTIONS }]);
    try {
      const r = (await w.op("report.render", { format: "markdown" })) as { markdown: string; pluginProblems?: Array<{ plugin: string; section: string; error: string }> };
      expect(r.markdown).toMatch(/## \d+\. Resumen de hallazgos[\s\S]*## \d+\. Hosts relevados\n\n\| Host \|\n\|---\|\n10\.0\.0\.7[\s\S]*## \d+\. Hallazgos detallados/);
      expect(r.markdown).not.toContain("Nothing");
      expect(r.markdown).not.toContain("Only infrastructure");
      expect(r.pluginProblems).toEqual([{ plugin: "lab.sections", section: "Broken one", error: expect.stringMatching(/the API is down/) }]);
      const d = (await w.op("report.render", { format: "docx" })) as { docxBase64: string };
      expect(docText(Buffer.from(d.docxBase64, "base64"))).toContain("Hosts relevados");
      // Removed from the project: its sections go too.
      w.eng.setInfo({ ...w.eng.info, plugins: [] }, human);
      expect(((await w.op("report.render", { format: "markdown" })) as { markdown: string }).markdown).not.toContain("Hosts relevados");
    } finally {
      w.close();
    }
  });

  it("need an operation with no required input", () => {
    const m = structuredClone(SECTIONS) as { contributes: { operations: Array<{ input: unknown[] }> } };
    m.contributes.operations[0]!.input = [{ name: "x", type: "string", required: true }];
    expect(JSON.stringify(PluginManifest.safeParse(m).error?.issues)).toMatch(/cannot have required fields/);
  });
});
