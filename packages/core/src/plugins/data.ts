import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { PluginId } from "@penteos/schema";
import type { Engagement } from "../engagement.js";
import type { Vault } from "../vault.js";
import { type PluginHost, PluginUnavailableError } from "./host.js";
import { describeStorage, PluginStorageError, PluginStore, type Sealer, type StorageStats } from "./storage.js";
import { type PluginTypeRegistry, pluginTypes } from "./types.js";

/**
 * Where each plugin's data lives, and the one door to it:
 *  - per project: `<project>/plugins/<id>/data.db` - moves, backs up and exports with the project;
 *  - global: `<dataDir>/plugin-data/<id>/global.db` - never inside the plugin's package folder,
 *    which is hashed.
 * A database that cannot open or migrate turns its plugin off (reason STORAGE_FAILED) and is left
 * exactly as it was; the project's own database never notices.
 */

export interface PluginDataOptions {
  dataDir: string;
  /** The key for sensitive columns of global databases (the workspace key). */
  globalVault?: () => Vault | undefined;
  types?: PluginTypeRegistry;
}

/** Errors that mean the database itself is unusable (as opposed to a bad call). */
const FATAL = new Set(["MIGRATION_FAILED", "MIGRATION_CHANGED", "STORAGE_NEWER", "STORAGE_CORRUPT"]);

export class PluginData {
  private host: PluginHost | undefined;
  private readonly stores = new Map<string, PluginStore>();
  private readonly hooked = new WeakSet<Engagement>();
  readonly types: PluginTypeRegistry;

  constructor(private readonly options: PluginDataOptions) {
    this.types = options.types ?? pluginTypes;
  }

  /** The host is created with this object's activator, so it is bound afterwards. */
  bind(host: PluginHost): void {
    this.host = host;
  }

  static projectFile(projectDir: string, pluginId: string): string {
    return join(projectDir, "plugins", PluginId.parse(pluginId), "data.db");
  }

  globalFile(pluginId: string): string {
    return join(this.options.dataDir, "plugin-data", PluginId.parse(pluginId), "global.db");
  }

  /** The project database of a running plugin, migrated. */
  project(pluginId: string, engagement: Engagement): PluginStore {
    this.requireActive(pluginId);
    const file = PluginData.projectFile(engagement.dir, pluginId);
    const cached = this.stores.get(file);
    if (cached) return cached;
    const manifest = this.host!.manifest(pluginId)!;
    const storage = manifest.contributes.storage;
    const sealer: Sealer | undefined = engagement.hasVault ? { seal: (v) => engagement.seal(v), open: (v) => engagement.unseal(v) } : undefined;
    const store = this.openOrSuspend(pluginId, () =>
      PluginStore.open({ file, pluginId, migrations: storage?.project ?? [], quotaMb: storage?.quotaMb ?? 64, ...(sealer ? { sealer } : {}) }),
    );
    this.stores.set(file, store);
    if (!this.hooked.has(engagement)) {
      this.hooked.add(engagement);
      engagement.onClose(() => this.closeUnder(engagement.dir));
    }
    return store;
  }

  /** The global database of a running plugin, migrated. */
  global(pluginId: string): PluginStore {
    this.requireActive(pluginId);
    return this.openGlobal(pluginId);
  }

  /**
   * Opens (and migrates) a plugin's global database during activation: a failure fails the
   * activation with STORAGE_FAILED, before anything of the plugin runs.
   */
  openGlobal(pluginId: string): PluginStore {
    const file = this.globalFile(pluginId);
    const cached = this.stores.get(file);
    if (cached) return cached;
    const manifest = this.host?.manifest(pluginId);
    const storage = manifest?.contributes.storage;
    const vault = this.options.globalVault?.();
    const store = PluginStore.open({
      file,
      pluginId,
      migrations: storage?.global ?? [],
      quotaMb: storage?.quotaMb ?? 64,
      ...(vault ? { sealer: { seal: (v: string) => vault.seal(v), open: (v: string) => vault.open(v) } } : {}),
    });
    this.stores.set(file, store);
    return store;
  }

  /** Sizes and row counts, for the Plugins section. Works with the plugin off (reads what is on disk). */
  stats(pluginId: string, engagement?: Engagement): { global?: StorageStats; project?: StorageStats; footprint?: ReturnType<Engagement["pluginFootprint"]> } {
    const out: { global?: StorageStats; project?: StorageStats; footprint?: ReturnType<Engagement["pluginFootprint"]> } = {};
    const g = this.stores.get(this.globalFile(pluginId));
    if (g) out.global = g.stats();
    if (engagement) {
      const p = this.stores.get(PluginData.projectFile(engagement.dir, pluginId));
      if (p) out.project = p.stats();
      out.footprint = engagement.pluginFootprint(pluginId);
    }
    return out;
  }

  /** What a project holds of each plugin, installed or not (dormant data shows up here). */
  projectPlugins(projectDir: string): Array<{ pluginId: string; file: string; installed: boolean; tables: string[] }> {
    const root = join(projectDir, "plugins");
    if (!existsSync(root)) return [];
    return readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory() && PluginId.safeParse(e.name).success && existsSync(join(root, e.name, "data.db")))
      .map((e) => {
        const file = join(root, e.name, "data.db");
        const described = describeStorage(file);
        return { pluginId: e.name, file, installed: Boolean(this.host?.get(e.name)), tables: Object.keys(described.shape?.tables ?? {}) };
      });
  }

  /** Closes every database of a plugin (it was turned off or uninstalled). */
  close(pluginId: string): void {
    for (const [file, store] of this.stores) {
      if (store.pluginId !== pluginId) continue;
      store.close();
      this.stores.delete(file);
    }
  }

  /** Deletes a plugin's global database (and its backups). Explicit and separate from uninstalling. */
  purgeGlobal(pluginId: string): void {
    this.closeFile(this.globalFile(pluginId));
    rmSync(join(this.options.dataDir, "plugin-data", PluginId.parse(pluginId)), { recursive: true, force: true });
  }

  /** Deletes a plugin's project database (and its backups) from one project. */
  purgeProject(pluginId: string, engagement: Engagement): void {
    this.closeFile(PluginData.projectFile(engagement.dir, pluginId));
    rmSync(join(engagement.dir, "plugins", PluginId.parse(pluginId)), { recursive: true, force: true });
  }

  closeAll(): void {
    for (const store of this.stores.values()) store.close();
    this.stores.clear();
  }

  private closeFile(file: string): void {
    this.stores.get(file)?.close();
    this.stores.delete(file);
  }

  private closeUnder(dir: string): void {
    for (const [file, store] of this.stores) {
      if (!file.startsWith(join(dir, "plugins"))) continue;
      store.close();
      this.stores.delete(file);
    }
  }

  private requireActive(pluginId: string): void {
    const info = this.host?.get(pluginId);
    if (!info || info.status !== "active") throw new PluginUnavailableError(pluginId, info?.status ?? "unknown");
  }

  private openOrSuspend(pluginId: string, open: () => PluginStore): PluginStore {
    try {
      return open();
    } catch (e) {
      if (e instanceof PluginStorageError && FATAL.has(e.code)) void this.host?.suspend(pluginId, "STORAGE_FAILED", `${e.code}: ${e.message}`);
      throw e;
    }
  }
}

/** Marks an activation failure as a storage one, so the operator reads the right reason. */
export function storageActivationError(e: unknown): Error {
  const err = e instanceof Error ? e : new Error(String(e));
  if (e instanceof PluginStorageError) Object.assign(err, { reasonCode: "STORAGE_FAILED", message: `${e.code}: ${e.message}` });
  return err;
}
