import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { packPlugin, testDraft } from "@penteos/core";
import { manifestHosts, PLUGIN_API_VERSION, PluginManifest } from "@penteos/schema";

/**
 * `penteos-server plugin <command>`: the tools for whoever builds plugins.
 *
 *   new <author.name> [--code] [--dir <parent>]   a working plugin to start from
 *   validate [dir]                                 the manifest, with each problem's exact path
 *   test [dir] --op <name> [--input <json|@file>] [--responses <@file>] [--fixtures <@file>] [--settings <json|@file>]
 *                                                  runs one operation in the sandbox (fake internet, lab project)
 *   pack [dir] [--out <file>]                      the .penteos-plugin file to install from the interface
 */

const out = (text: string) => process.stdout.write(`${text}\n`);
const err = (text: string) => process.stderr.write(`${text}\n`);

function readJsonArg(value: string | undefined): unknown {
  if (value === undefined) return undefined;
  const text = value.startsWith("@") ? readFileSync(value.slice(1), "utf8") : value;
  return JSON.parse(text);
}

function loadManifest(dir: string): { raw: unknown; parsed: ReturnType<typeof PluginManifest.safeParse> } {
  const file = join(dir, "plugin.json");
  if (!existsSync(file)) throw new Error(`no plugin.json in ${dir}`);
  const raw = JSON.parse(readFileSync(file, "utf8")) as unknown;
  return { raw, parsed: PluginManifest.safeParse(raw) };
}

function scaffold(id: string, kind: "declarative" | "code" | "python", parent: string): string {
  const code = kind !== "declarative";
  if (!/^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$/.test(id)) throw new Error("the id is author.name, lowercase (e.g. acme.status-page)");
  const dir = resolve(parent, id);
  if (existsSync(dir)) throw new Error(`${dir} already exists`);
  mkdirSync(dir, { recursive: true });
  const name = id.split(".").slice(1).join(" ");
  const manifest = code
    ? {
        id,
        name,
        version: "0.1.0",
        apiVersion: PLUGIN_API_VERSION,
        level: "code",
        main: kind === "python" ? "main.py" : "main.mjs",
        ...(kind === "python" ? { runtime: "python" } : {}),
        author: { type: "human", name: id.split(".")[0] },
        description: { es: "Describa qué hace.", en: "Say what it does." },
        permissions: ["graph:read", "ui:panel"],
        contributes: {
          operations: [{ name: "hello", title: { es: "Saludar", en: "Say hello" }, description: "Returns a greeting and how many hosts the project has.", handler: "hello", input: [{ name: "name", type: "string", required: true }] }],
          panels: [{ id: "main", title: { es: "Panel", en: "Panel" }, file: "panel.html" }],
        },
      }
    : {
        id,
        name,
        version: "0.1.0",
        apiVersion: PLUGIN_API_VERSION,
        level: "declarative",
        author: { type: "human", name: id.split(".")[0] },
        description: { es: "Describa qué hace.", en: "Say what it does." },
        permissions: ["net:status.example.com"],
        contributes: {
          operations: [
            {
              name: "status",
              title: { es: "Ver estado", en: "Check status" },
              description: "Reads a service's public status page.",
              steps: [{ do: "http", id: "r", url: "https://status.example.com/api/v2/status.json" }],
              result: { status: "{{steps.r.body.status.description}}" },
              view: { type: "message", text: "{{result.status}}" },
            },
          ],
        },
      };
  writeFileSync(join(dir, "plugin.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  if (kind === "python") {
    writeFileSync(
      join(dir, "main.py"),
      `# Runs free (a normal program, watched by Penteos): any Python library you install works.\n# What the core keeps (graph, storage, secrets) goes through \`penteos\`.\n\ndef activate(plugin):\n    @plugin.operation("hello")\n    def hello(input, penteos):\n        hosts = penteos.graph.query("host", limit=500)\n        return {"greeting": "Hello, " + input["name"], "hosts": len(hosts)}\n`,
    );
  }
  if (code) {
    if (kind === "code") writeFileSync(
      join(dir, "main.mjs"),
      `// Talk to the target and the project through \`penteos\`: then it works the same isolated or free.\nexport async function activate(plugin) {\n  plugin.operation("hello", async (input, penteos) => {\n    const hosts = await penteos.graph.query("host", { limit: 500 });\n    return { greeting: \`Hello, \${input.name}\`, hosts: hosts.length };\n  });\n}\n`,
    );
    writeFileSync(
      join(dir, "panel.html"),
      `<!doctype html>\n<html><head><meta charset="utf-8"><style>body{font:13px system-ui;color:#ddd;background:#16131c;margin:12px}</style></head>\n<body><div id="out">…</div>\n<script>\n  // No network here: the only way out is penteos.call(operation, input).\n  penteos.call("hello", { name: "panel" }).then((r) => { document.getElementById("out").textContent = r.greeting + " · " + r.hosts + " hosts"; });\n</script></body></html>\n`,
    );
  }
  writeFileSync(
    join(dir, "README.md"),
    `# ${name}\n\n- Validate: \`penteos-server plugin validate ${id}\`\n- Test: \`penteos-server plugin test ${id} --op ${code ? "hello --input '{\"name\":\"me\"}'" : "status --responses @responses.json"}\`\n- Pack: \`penteos-server plugin pack ${id}\`, then Plugins → Install from file.\n`,
  );
  if (!code) writeFileSync(join(dir, "responses.json"), `${JSON.stringify([{ url: "https://status.example.com/", body: { status: { description: "All Systems Operational" } } }], null, 2)}\n`);
  return dir;
}

export async function runPluginCli(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      code: { type: "boolean", default: false },
      python: { type: "boolean", default: false },
      dir: { type: "string" },
      op: { type: "string" },
      input: { type: "string" },
      responses: { type: "string" },
      fixtures: { type: "string" },
      settings: { type: "string" },
      out: { type: "string" },
    },
  });
  const [command, target] = positionals;
  try {
    switch (command) {
      case "new": {
        if (!target) throw new Error("usage: plugin new <author.name> [--code | --python] [--dir <parent>]");
        const dir = scaffold(target, values.python ? "python" : values.code ? "code" : "declarative", values.dir ?? process.cwd());
        out(`Plugin created in ${dir}`);
        return 0;
      }
      case "validate": {
        const dir = resolve(target ?? ".");
        const { parsed } = loadManifest(dir);
        if (!parsed.success) {
          err(`plugin.json has ${parsed.error.issues.length} problem(s):`);
          for (const i of parsed.error.issues) err(`  ${i.path.join(".") || "(manifest)"}: ${i.message}`);
          return 1;
        }
        const m = parsed.data;
        out(`${m.id} ${m.version} (${m.level}) is valid.`);
        out(`  permissions: ${m.permissions.join(", ") || "none"}`);
        const hosts = manifestHosts(m.contributes, m.permissions);
        out(`  sends data to: ${hosts.join(", ") || "nobody"}`);
        out(`  operations: ${(m.contributes.operations ?? []).map((o) => o.name).join(", ") || "none"}`);
        return 0;
      }
      case "test": {
        const dir = resolve(target ?? ".");
        if (!values.op) throw new Error("usage: plugin test [dir] --op <name> [--input …] [--responses @file] [--fixtures @file] [--settings …]");
        const { raw } = loadManifest(dir);
        const report = await testDraft(
          raw,
          {
            operation: values.op,
            input: (readJsonArg(values.input) ?? {}) as Record<string, unknown>,
            ...(values.settings ? { settings: readJsonArg(values.settings) as Record<string, unknown> } : {}),
            responses: (readJsonArg(values.responses) ?? []) as never,
            ...(values.fixtures ? { fixtures: readJsonArg(values.fixtures) as never } : {}),
          },
          { sourceDir: dir },
        );
        for (const s of report.steps) out(`  ${s.ok ? "✓" : "✗"} ${s.path} ${s.do}${s.id ? ` ${s.id}` : ""}${s.skipped ? " (skipped)" : ""}${s.error ? ` - ${s.error}` : ""}`);
        for (const r of report.requests) out(`  → ${r.method} ${r.url}${r.matched ? "" : "  (no recorded response: not sent)"}`);
        for (const n of report.notices) out(`  · ${n}`);
        if (report.issues) for (const i of report.issues) err(`  ${i}`);
        if (report.ok) {
          out(`OK in ${report.durationMs} ms. Result:`);
          out(JSON.stringify(report.result, null, 2));
          if (report.wrote.entities.length || report.wrote.annotations.length || report.wrote.findings.length) out(`Would write: ${JSON.stringify(report.wrote)}`);
          return 0;
        }
        err(`Failed: ${report.error}`);
        return 1;
      }
      case "pack": {
        const dir = resolve(target ?? ".");
        const packed = packPlugin(dir);
        const file = resolve(values.out ?? join(dir, "..", packed.name));
        writeFileSync(file, packed.bytes);
        out(`${file}\n  ${packed.files} files, ${packed.bytes.length} bytes, sha256 ${packed.sha256}`);
        return 0;
      }
      default:
        err("usage: penteos-server plugin new|validate|test|pack …");
        return 2;
    }
  } catch (e) {
    err(e instanceof Error ? e.message : String(e));
    return 1;
  }
}
