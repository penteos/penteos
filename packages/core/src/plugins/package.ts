import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { PluginManifest } from "@penteos/schema";
import { unzipSync, zipSync } from "fflate";

/**
 * A plugin as one file, `<id>-<version>.penteos-plugin` (a zip with plugin.json at its root), to
 * hand around and install from the interface. Installing one never
 * trusts it: names that leave the folder, links, too many files, too many bytes once unpacked (a
 * zip bomb is refused before it is expanded) and an invalid manifest are refused; what passes lands
 * in the plugins folder waiting for approval like any other.
 */

export const PACKAGE_LIMITS = { files: 20_000, bytes: 300 * 1024 * 1024 } as const;
export const PACKAGE_EXTENSION = ".penteos-plugin";

const SAFE_NAME = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_@+=,.\/ ~-]+$/;

/** Packs a plugin folder (validated first). Links and dot-folders such as .git are left out. */
export function packPlugin(dir: string): { bytes: Uint8Array; manifest: PluginManifest; files: number; sha256: string; name: string } {
  const raw = JSON.parse(readFileSync(join(dir, "plugin.json"), "utf8")) as unknown;
  const parsed = PluginManifest.safeParse(raw);
  if (!parsed.success) throw new Error(`plugin.json does not validate: ${parsed.error.issues.map((i) => `${i.path.join(".") || "(manifest)"}: ${i.message}`).join("; ")}`);
  const files: Record<string, Uint8Array> = {};
  let total = 0;
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      // Its dependencies travel with it (node_modules included); version control and caches do not.
      if (e.name === ".git" || e.name === "__pycache__" || e.name.endsWith(PACKAGE_EXTENSION)) continue;
      const full = join(d, e.name);
      // npm puts links in node_modules/.bin: those are skipped; any other link is refused.
      if (lstatSync(full).isSymbolicLink()) {
        if (relative(dir, full).split(/[\\/]/).includes(".bin")) continue;
        throw new Error(`${relative(dir, full)} is a link: plugins carry their files, not links`);
      }
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) {
        const content = readFileSync(full);
        total += content.length;
        files[relative(dir, full).split("\\").join("/")] = new Uint8Array(content);
      }
      if (Object.keys(files).length > PACKAGE_LIMITS.files) throw new Error(`more than ${PACKAGE_LIMITS.files} files`);
      if (total > PACKAGE_LIMITS.bytes) throw new Error(`more than ${PACKAGE_LIMITS.bytes / 1048576} MB`);
    }
  };
  walk(dir);
  if (parsed.data.main && !files[parsed.data.main]) throw new Error(`main ${parsed.data.main} is not in the folder`);
  for (const p of parsed.data.contributes.panels ?? []) if (!files[p.file]) throw new Error(`panel ${p.id}: ${p.file} is not in the folder`);
  const bytes = zipSync(files, { level: 9, mtime: new Date("2026-01-01T00:00:00Z") });
  return { bytes, manifest: parsed.data, files: Object.keys(files).length, sha256: createHash("sha256").update(bytes).digest("hex"), name: `${parsed.data.id}-${parsed.data.version}${PACKAGE_EXTENSION}` };
}

/**
 * Unpacks a plugin file into the plugins folder as `<id>/`, replacing an earlier copy of the same
 * plugin (which then needs approval again: its files changed). Returns its manifest.
 */
export function installPackage(bytes: Uint8Array, pluginsDir: string, limits: { files: number; bytes: number } = PACKAGE_LIMITS): PluginManifest {
  let declared = 0;
  let count = 0;
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(bytes, {
      // Decided from the zip's own directory, before anything is expanded.
      filter: (f) => {
        count++;
        declared += f.originalSize;
        if (count > limits.files) throw new Error(`more than ${limits.files} files`);
        if (declared > limits.bytes) throw new Error(`more than ${limits.bytes} bytes once unpacked`);
        if (!SAFE_NAME.test(f.name) || f.name.includes("\\")) throw new Error(`unsafe file name in the package: ${f.name.slice(0, 120)}`);
        return !f.name.endsWith("/");
      },
    });
  } catch (e) {
    throw new Error(`not a valid plugin package: ${e instanceof Error ? e.message : String(e)}`);
  }
  const total = Object.values(entries).reduce((n, b) => n + b.length, 0);
  if (total > limits.bytes) throw new Error(`more than ${limits.bytes} bytes once unpacked`);
  const manifestBytes = entries["plugin.json"];
  if (!manifestBytes) throw new Error("the package has no plugin.json at its root");
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(manifestBytes));
  } catch {
    throw new Error("its plugin.json is not valid JSON");
  }
  const parsed = PluginManifest.safeParse(raw);
  if (!parsed.success) throw new Error(`its plugin.json does not validate: ${parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(manifest)"}: ${i.message}`).join("; ")}`);
  const id = parsed.data.id;
  const staging = join(pluginsDir, `.installing-${id}-${Date.now()}`);
  try {
    for (const [name, content] of Object.entries(entries)) {
      const out = join(staging, name);
      if (!out.startsWith(staging)) throw new Error(`unsafe file name in the package: ${name}`);
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, content);
    }
    const target = join(pluginsDir, id);
    rmSync(target, { recursive: true, force: true });
    renameSync(staging, target);
  } finally {
    if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
  }
  return parsed.data;
}
