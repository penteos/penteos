import { cpSync, existsSync, lstatSync, readdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { manifestHosts, PluginManifest } from "@penteos/schema";
import type { PluginHost, PluginInfo } from "./host.js";

/**
 * The plugins that ship with Penteos: ready to install with one
 * approval. They are ordinary declarative plugins - same contract, same checks, same host - kept in
 * `packages/core/catalog/<id>/`. Installing copies one into the plugins folder; it then goes
 * through the host like any other (hashed, approved, activated, breaker).
 */

/** From the sources or the compiled package (`../../catalog`), or next to the desktop bundle (`./catalog`). */
export const BUNDLED_CATALOG_DIR = ["../../catalog", "./catalog"].map((p) => fileURLToPath(new URL(p, import.meta.url))).find((d) => existsSync(d)) ?? fileURLToPath(new URL("../../catalog", import.meta.url));

export interface CatalogEntry {
  id: string;
  name: string;
  version: string;
  description?: PluginManifest["description"];
  author: PluginManifest["author"];
  permissions: string[];
  /** Hosts it sends data to. */
  sendsTo: string[];
  /** What it adds, for the operator to judge before installing. */
  offers: { operations: number; menus: number; providers: number; entityTypes: number; events: number };
  installed?: { version?: string; status: PluginInfo["status"] };
  /** The installed version is older than this one. */
  update: boolean;
}

function newer(a: string, b: string): boolean {
  const p = (v: string) => v.split(/[.-]/).slice(0, 3).map(Number);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
}

export class PluginCatalog {
  constructor(
    private readonly host: PluginHost,
    private readonly dir: string = BUNDLED_CATALOG_DIR,
  ) {}

  private manifests(): Array<{ folder: string; manifest: PluginManifest }> {
    if (!existsSync(this.dir)) return [];
    const out: Array<{ folder: string; manifest: PluginManifest }> = [];
    for (const folder of readdirSync(this.dir).sort()) {
      const file = join(this.dir, folder, "plugin.json");
      if (!existsSync(file)) continue;
      try {
        const parsed = PluginManifest.safeParse(JSON.parse(readFileSync(file, "utf8")));
        // A broken bundled plugin is a Penteos bug (the contract suite catches it); never offered.
        if (parsed.success && parsed.data.id === folder) out.push({ folder, manifest: parsed.data });
      } catch {
        /* skipped */
      }
    }
    return out;
  }

  list(): CatalogEntry[] {
    return this.manifests().map(({ manifest: m }) => {
      const info = this.host.get(m.id);
      const c = m.contributes;
      return {
        id: m.id,
        name: m.name,
        version: m.version,
        ...(m.description ? { description: m.description } : {}),
        author: m.author,
        permissions: m.permissions,
        sendsTo: manifestHosts(c, m.permissions),
        offers: { operations: (c.operations ?? []).length, menus: (c.menus ?? []).length, providers: (c.providers ?? []).length, entityTypes: (c.entityTypes ?? []).length, events: (c.events ?? []).length },
        ...(info ? { installed: { ...(info.version ? { version: info.version } : {}), status: info.status } } : {}),
        update: Boolean(info?.version && newer(m.version, info.version)),
      };
    });
  }

  /**
   * Installs (or updates) a bundled plugin and, if asked, approves it as installed - the operator
   * approved it seeing its permissions. An update replaces the package; the data stays.
   */
  async install(id: string, options: { approve: boolean }): Promise<PluginInfo | undefined> {
    const entry = this.manifests().find((x) => x.manifest.id === id);
    if (!entry) throw new Error(`${id} is not in the catalog`);
    const target = join(this.host.pluginsDir, id);
    // Another folder already holding this id (copied by hand) is replaced too: one package per id.
    const existing = this.host.get(id)?.folder;
    const staging = join(this.host.pluginsDir, `.installing-${id}-${Date.now()}`);
    cpSync(join(this.dir, entry.folder), staging, { recursive: true, filter: (src) => !lstatSync(src).isSymbolicLink() });
    if (existing && existing !== id) rmSync(join(this.host.pluginsDir, existing), { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
    renameSync(staging, target);
    await this.host.rescan();
    // What ships with Penteos was reviewed where it was written: its code needs no second review here.
    if (options.approve) await this.host.approve(id, { reviewedCode: true });
    return this.host.get(id);
  }
}
