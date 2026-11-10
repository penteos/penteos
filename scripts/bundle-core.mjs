// Bundles the core (server + MCP bridge) into two self-contained files, for the desktop
// package and the team server image. Native modules stay external: they are installed next to
// the bundle, built for the runtime that will load them (Node or Electron).
//
//   node scripts/bundle-core.mjs <outdir>
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { thirdPartyLicenses } from "./licenses.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(process.argv[2] ?? join(root, "build", "core"));
mkdirSync(out, { recursive: true });

// The database is Node's own SQLite (node:sqlite): the terminal is the only native module left.
const NATIVE = ["node-pty"];
await build({
  entryPoints: { core: join(root, "packages/server/src/main.ts"), mcp: join(root, "packages/server/src/mcp.ts") },
  outdir: out,
  outExtension: { ".js": ".mjs" },
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  conditions: ["penteos-source"],
  external: [...NATIVE, "bufferutil", "utf-8-validate"],
  // Some bundled dependencies are CommonJS and call require().
  banner: { js: "import { createRequire as __penteosRequire } from 'node:module'; const require = __penteosRequire(import.meta.url);" },
  logLevel: "warning",
});

// The plugins that ship with Penteos travel next to the bundle (the core looks for ./catalog).
rmSync(join(out, "catalog"), { recursive: true, force: true });
cpSync(join(root, "packages/core/catalog"), join(out, "catalog"), { recursive: true });

// The native modules, at the versions the workspace uses.
const resolvers = ["packages/core", "packages/server"].map((p) => createRequire(join(root, p, "package.json")));
const version = (name) => {
  for (const r of resolvers) {
    try {
      return r(`${name}/package.json`).version;
    } catch {
      /* not a dependency of this package */
    }
  }
  throw new Error(`${name} is not installed in the workspace`);
};
writeFileSync(
  join(out, "package.json"),
  JSON.stringify({ name: "penteos-core", private: true, type: "module", dependencies: Object.fromEntries(NATIVE.map((n) => [n, version(n)])) }, null, 2),
);
// The license and notice texts of everything folded into the bundle travel with it.
const licenses = thirdPartyLicenses();
writeFileSync(join(out, "THIRD_PARTY_LICENSES.txt"), licenses.text);
console.log(`core bundled in ${out} (${licenses.count} third-party packages listed in THIRD_PARTY_LICENSES.txt)`);
