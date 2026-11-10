import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { Branding } from "./report.js";
import { dirname, join, relative } from "node:path";
import { homedir, tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { unzipSync, zipSync } from "fflate";
import { type Actor, type EngagementAttributes, ENTITY_ATTRIBUTES, PluginId, ulid } from "@penteos/schema";
import { exportStorageCopy } from "./plugins/storage.js";
import { listOutputs, outputDir, writeOutput } from "./plugins/outputs.js";
import { type PluginTypeRegistry, pluginTypes as globalPluginTypes } from "./plugins/types.js";
import type { Role } from "./ops/registry.js";
import { sha256Hex } from "./store/hash.js";
import Database from "./store/sqlite.js";
import { Engagement, type EngagementInfo } from "./engagement.js";
import { WORKSPACE_SCHEMA } from "./store/sql.js";
import { Vault } from "./vault.js";

export interface WorkspacePrefs {
  /** The first-run assistant was completed (or skipped). */
  onboarded: boolean;
  /** Solo on this machine, or with a team server. Asked once, not per engagement. */
  workStyle?: "solo" | "team";
  /** actor id → engagement id */
  lastOpened: Record<string, string>;
  /** actor id → interface language (each operator reads the app and talks to the Maestro in theirs). */
  languages?: Record<string, "es" | "en">;
  /** Where new projects are created (solo mode): a folder the operator can see, e.g. ~/Penteos. */
  projectsRoot?: string;
  /** Default autonomy for new projects (chosen at onboarding); default "maestro". */
  autonomy?: "copilot" | "maestro" | "maestro_auto";
}

export interface EngagementSummary {
  id: string;
  clientId: string;
  clientName: string;
  name: string;
  mode: string;
  status: string;
  createdAt: string;
  /** The project's folder is gone from disk (moved or deleted); it can be located again or removed. */
  missing?: boolean;
}

export interface Operator {
  id: string;
  name: string;
  role: Role;
  createdAt: string;
  disabled: boolean;
}

export interface CreateEngagementInput {
  clientName: string;
  name: string;
  mode: EngagementAttributes["mode"];
  roundMode?: EngagementAttributes["roundMode"];
  maxRisk?: EngagementAttributes["maxRisk"];
  dataPolicy?: EngagementAttributes["dataPolicy"];
  autonomy?: EngagementAttributes["autonomy"];
  language?: EngagementAttributes["language"];
  /** Plugins to enable in this project (chosen in the onboarding). */
  plugins?: string[];
  startsAt?: string;
  endsAt?: string;
  /** Parent folder for this project's folder; defaults to the workspace's projectsRoot(). */
  dir?: string;
}

/**
 * A self-contained data directory:
 *
 *   <dataDir>/workspace.db                  index of clients and engagements
 *   <dataDir>/engagements/<id>/engagement.db
 *   <dataDir>/engagements/<id>/raw/…
 *
 * The same structure backs solo mode and the team server.
 */
export class Workspace {
  private readonly db: Database.Database;
  private readonly open = new Map<string, Engagement>();

  /** The plugin types its projects validate against: the process-wide registry, or a sandbox's own. */
  readonly pluginTypes: PluginTypeRegistry;

  constructor(
    readonly dataDir: string,
    options: { pluginTypes?: PluginTypeRegistry } = {},
  ) {
    this.pluginTypes = options.pluginTypes ?? globalPluginTypes;
    mkdirSync(join(dataDir, "engagements"), { recursive: true, mode: 0o700 });
    // The index and the default projects folder hold client names: the operator's eyes only.
    for (const d of [dataDir, join(dataDir, "engagements")]) {
      try {
        chmodSync(d, 0o700);
      } catch {
        /* a folder we can't change: leave it */
      }
    }
    this.db = new Database(join(dataDir, "workspace.db"));
    this.db.pragma("journal_mode = WAL");
    this.db.exec(WORKSPACE_SCHEMA);
  }

  /** The folder a project lives in (the index remembers where the operator put it). */
  dirOf(id: string): string {
    const row = this.db.prepare("select dir from engagements where id = ?").get(id) as { dir: string | null } | undefined;
    if (!row) throw new Error(`engagement not found: ${id}`);
    if (!row.dir) throw new Error(`engagement folder unknown: ${id}`);
    return row.dir;
  }

  /** Where new projects go by default: the operator's chosen root, else inside the data dir (tests, headless). */
  projectsRoot(): string {
    return this.prefs().projectsRoot ?? join(this.dataDir, "engagements");
  }

  /** A fresh, legible folder under `parent` for "<Client - Project>", avoiding collisions. */
  private freeFolder(parent: string, base: string): string {
    mkdirSync(parent, { recursive: true });
    const safe = base.replace(/[^\p{L}\p{N} ._-]+/gu, "-").replace(/\s+/g, " ").trim() || "Proyecto";
    let name = safe;
    for (let n = 2; existsSync(join(parent, name)); n++) name = `${safe} (${n})`;
    return join(parent, name);
  }

  private writeProjectJson(dir: string, meta: { id: string; clientName: string; name: string; mode: string; status: string; createdAt: string }): void {
    writeFileSync(join(dir, "project.json"), JSON.stringify({ format: "penteos-project/1", ...meta }, null, 2));
  }

  close(): void {
    for (const e of this.open.values()) e.close();
    this.open.clear();
    this.db.close();
  }

  list(): EngagementSummary[] {
    const rows = this.db
      .prepare(
        `select e.id, e.client_id, c.name as client_name, e.name, e.mode, e.status, e.created_at, e.dir
         from engagements e join clients c on c.id = e.client_id order by e.created_at desc`,
      )
      .all() as Array<Record<string, string | null>>;
    return rows.map((r) => {
      // A row the index cannot place (a damaged or foreign workspace.db) is listed as missing, so
      // one bad entry never stops the core from starting; the operator can locate or forget it.
      const dir = r.dir;
      const missing = !dir || !existsSync(join(dir, "engagement.db"));
      return {
        id: r.id!,
        clientId: r.client_id!,
        clientName: r.client_name!,
        name: r.name!,
        mode: r.mode!,
        status: r.status!,
        createdAt: r.created_at!,
        ...(missing ? { missing: true } : {}),
      };
    });
  }

  /** Removes a project from the index without touching its folder on disk ("forget", not delete). */
  forget(id: string): void {
    this.open.get(id)?.close();
    this.open.delete(id);
    this.db.prepare("delete from engagements where id = ?").run(id);
  }

  /**
   * Moves a project's whole folder to a new parent (e.g. somewhere more visible than where it was),
   * with a legible name, and points the index at the new place. The folder stays self-contained.
   */
  relocate(id: string, newParent: string): string {
    const from = this.dirOf(id);
    if (!existsSync(join(from, "engagement.db"))) throw new Error(`PROJECT_FOLDER_MISSING: ${from}`);
    const eng = this.get(id); // opens (and migrates secrets to a project key) before moving
    const info = eng.info;
    this.open.get(id)?.close();
    this.open.delete(id);
    const to = this.freeFolder(newParent, `${info.clientName} - ${info.name}`);
    rmSync(to, { recursive: true, force: true }); // freeFolder only reserved the name
    try {
      renameSync(from, to);
    } catch {
      cpSync(from, to, { recursive: true }); // across filesystems rename fails: copy then remove
      rmSync(from, { recursive: true, force: true });
    }
    this.db.prepare("update engagements set dir = ? where id = ?").run(to, id);
    this.writeProjectJson(to, { id, clientName: info.clientName, name: info.name, mode: info.mode, status: info.status, createdAt: this.createdAtOf(id) });
    return to;
  }

  private createdAtOf(id: string): string {
    const row = this.db.prepare("select created_at from engagements where id = ?").get(id) as { created_at: string } | undefined;
    return row?.created_at ?? new Date().toISOString();
  }

  private clientId(name: string): string {
    const existing = this.db.prepare("select id from clients where name = ?").get(name) as { id: string } | undefined;
    if (existing) return existing.id;
    const id = ulid();
    this.db.prepare("insert into clients (id, name, created_at) values (?, ?, ?)").run(id, name, new Date().toISOString());
    return id;
  }

  create(input: CreateEngagementInput, actor: Actor): Engagement {
    const id = ulid();
    const clientId = this.clientId(input.clientName);
    const attributes = ENTITY_ATTRIBUTES.engagement.parse({
      clientId,
      name: input.name,
      mode: input.mode,
      status: "active",
      dataPolicy: input.dataPolicy ?? "any_provider",
      maxRisk: input.maxRisk ?? "intrusive",
      ...(input.roundMode ? { roundMode: input.roundMode } : {}),
      ...(input.autonomy ?? this.prefs().autonomy ? { autonomy: input.autonomy ?? this.prefs().autonomy } : {}),
      ...(input.language ? { language: input.language } : {}),
      ...(input.plugins?.length ? { plugins: [...new Set(input.plugins)] } : {}),
      ...(input.startsAt ? { startsAt: input.startsAt } : {}),
      ...(input.endsAt ? { endsAt: input.endsAt } : {}),
    });
    const dir = this.freeFolder(input.dir ?? this.projectsRoot(), `${input.clientName} - ${input.name}`);
    const createdAt = new Date().toISOString();
    const engagement = Engagement.open(dir, this.pluginTypes);
    engagement.useVault(this.projectVault(dir));
    engagement.setInfo({ id, clientName: input.clientName, ...attributes }, actor, "engagement.create");
    this.db
      .prepare("insert into engagements (id, client_id, name, mode, status, created_at, dir) values (?, ?, ?, ?, ?, ?, ?)")
      .run(id, clientId, input.name, input.mode, attributes.status, createdAt, dir);
    this.writeProjectJson(dir, { id, clientName: input.clientName, name: input.name, mode: input.mode, status: attributes.status, createdAt });
    this.track(id, engagement);
    return engagement;
  }

  get(id: string): Engagement {
    const cached = this.open.get(id);
    if (cached) return cached;
    const known = this.db.prepare("select id from engagements where id = ?").get(id);
    if (!known) throw new Error(`engagement not found: ${id}`);
    const dir = this.dirOf(id);
    // Never silently recreate a project whose folder was moved or deleted: Engagement.open would make
    // an empty one. Fail clearly so the UI can tell the operator (and offer to locate or remove it).
    if (!existsSync(join(dir, "engagement.db"))) throw new Error(`PROJECT_FOLDER_MISSING: ${dir}`);
    const engagement = this.openWithVault(dir);
    this.track(id, engagement);
    return engagement;
  }

  private readonly openListeners = new Set<(engagement: Engagement) => void>();

  /** Keeps an opened project and tells the listeners (once per opening). */
  private track(id: string, engagement: Engagement): void {
    this.open.set(id, engagement);
    for (const listener of this.openListeners) {
      try {
        listener(engagement);
      } catch {
        /* a listener (a plugin runtime) never stops a project from opening */
      }
    }
  }

  /** Called once per project when it is opened (and for the ones already open). */
  onOpen(listener: (engagement: Engagement) => void): () => void {
    this.openListeners.add(listener);
    for (const e of this.open.values()) listener(e);
    return () => this.openListeners.delete(listener);
  }

  /**
   * A project as one portable `.penteos` file (a zip): its whole database and raw evidence, plus a
   * small manifest. Secret values are stripped (the vault key belongs to the workspace, not the
   * project, so they would not decrypt elsewhere; on import the operator re-enters them). Everything
   * else travels: captured traffic, session cookies and the client's data. Treat the file like the
   * engagement itself. The copies made on the way live in a private temporary folder that is always
   * removed, and the file is written readable by the operator only.
   */
  async exportEngagement(id: string, destPath: string): Promise<{ path: string; secretsStripped: number; pluginData: string[] }> {
    const row = this.db
      .prepare("select e.name, e.mode, e.status, e.created_at, c.name as client_name from engagements e join clients c on c.id = e.client_id where e.id = ?")
      .get(id) as { name: string; mode: string; status: string; created_at: string; client_name: string } | undefined;
    if (!row) throw new Error(`engagement not found: ${id}`);
    const srcDir = this.dirOf(id);
    // A consistent copy of the live database, then wipe the secret values in that copy.
    const work = mkdtempSync(join(tmpdir(), "penteos-export-"));
    try {
      const tmp = join(work, "engagement.db");
      await this.get(id).backupTo(tmp);
      const copy = new Database(tmp);
      let secretsStripped = 0;
      try {
        secretsStripped = copy.prepare("update secrets set value = ''").run().changes;
    } finally {
      copy.close();
    }
    const files: Record<string, Uint8Array> = {
      "manifest.json": new TextEncoder().encode(
        JSON.stringify({ format: "penteos/1", id, clientName: row.client_name, name: row.name, mode: row.mode, status: row.status, createdAt: row.created_at, exportedAt: new Date().toISOString(), secretsStripped: true }, null, 2),
      ),
      "engagement.db": readFileSync(tmp),
    };
    const rawDir = join(srcDir, "raw");
    if (existsSync(rawDir)) for (const file of walkFiles(rawDir)) files[`raw/${relative(rawDir, file).split("\\").join("/")}`] = readFileSync(file);
    // Plugin databases travel with the project (installed plugins or not), sensitive values emptied.
    const pluginData: string[] = [];
    const pluginsDir = join(srcDir, "plugins");
    if (existsSync(pluginsDir)) {
      for (const entry of readdirSync(pluginsDir, { withFileTypes: true })) {
        const file = join(pluginsDir, entry.name, "data.db");
        if (!entry.isDirectory() || !PluginId.safeParse(entry.name).success || !existsSync(file)) continue;
        const copyPath = join(work, `plugin-${entry.name}.db`);
        await exportStorageCopy(file, copyPath);
        files[`plugins/${entry.name}/data.db`] = readFileSync(copyPath);
        pluginData.push(entry.name);
      }
      // The files plugins made (reports, exports…) are part of the project too. Links are never followed.
      for (const entry of readdirSync(pluginsDir, { withFileTypes: true })) {
        if (!entry.isDirectory() || !PluginId.safeParse(entry.name).success) continue;
        const out = outputDir(srcDir, entry.name);
        for (const f of listOutputs(out, Number.MAX_SAFE_INTEGER).files) files[`plugins/${entry.name}/files/${f.name}`] = readFileSync(join(out, ...f.name.split("/")));
      }
    }
    writeFileSync(destPath, zipSync(files), { mode: 0o600 });
    return { path: destPath, secretsStripped, pluginData };
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }

  /** Brings a `.penteos` file in as a new project (a fresh id if the original clashes). Returns its summary. */
  importEngagement(srcPath: string, actor: Actor): EngagementSummary {
    const zip = unzipSync(readFileSync(srcPath));
    const manifestBytes = zip["manifest.json"];
    if (!manifestBytes || !zip["engagement.db"]) throw new Error("not a .penteos file: missing manifest or database");
    const manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as { format: string; id: string; clientName: string; name: string; mode: string; status?: string };
    if (manifest.format !== "penteos/1") throw new Error(`unrecognised .penteos format: ${manifest.format}`);
    const id = this.db.prepare("select 1 from engagements where id = ?").get(manifest.id) ? ulid() : manifest.id;
    const dir = this.freeFolder(this.projectsRoot(), `${manifest.clientName} - ${manifest.name}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "engagement.db"), Buffer.from(zip["engagement.db"]));
    for (const [p, bytes] of Object.entries(zip)) {
      // A plugin database: only plugins/<valid id>/data.db, nothing else from that folder.
      // A plugin's file: written only through the same checks as when the plugin made it.
      const made = /^plugins\/([^/]+)\/files\/(.+)$/.exec(p);
      if (made && PluginId.safeParse(made[1]).success && !p.endsWith("/")) {
        try {
          writeOutput(outputDir(dir, made[1]!), made[2]!, bytes);
        } catch {
          /* a name that would not pass is left out */
        }
        continue;
      }
      const plugin = /^plugins\/([^/]+)\/data\.db$/.exec(p);
      if (plugin && PluginId.safeParse(plugin[1]).success) {
        mkdirSync(join(dir, "plugins", plugin[1]!), { recursive: true });
        writeFileSync(join(dir, "plugins", plugin[1]!, "data.db"), Buffer.from(bytes));
        continue;
      }
      if (!p.startsWith("raw/") || p.endsWith("/")) continue;
      const out = join(dir, p);
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, Buffer.from(bytes));
    }
    const createdAt = new Date().toISOString();
    const clientId = this.clientId(manifest.clientName);
    this.db
      .prepare("insert into engagements (id, client_id, name, mode, status, created_at, dir) values (?, ?, ?, ?, ?, ?, ?)")
      .run(id, clientId, manifest.name, manifest.mode, manifest.status ?? "active", createdAt, dir);
    // The database carries its own id in meta; realign it with the folder when the id changed.
    const engagement = Engagement.open(dir, this.pluginTypes);
    engagement.useVault(this.projectVault(dir));
    if (engagement.info.id !== id) engagement.setInfo({ ...engagement.info, id }, actor, "engagement.import");
    this.writeProjectJson(dir, { id, clientName: manifest.clientName, name: manifest.name, mode: manifest.mode, status: manifest.status ?? "active", createdAt });
    this.track(id, engagement);
    return { id, clientId, clientName: manifest.clientName, name: manifest.name, mode: manifest.mode, status: manifest.status ?? "active", createdAt };
  }

  /**
   * Opens a project folder the operator points at ("Open project…"). Reads its project.json,
   * registers it in the index if it is not there yet (reconstructible index), and returns its summary.
   */
  openFolder(dir: string, actor: Actor): EngagementSummary {
    const metaPath = join(dir, "project.json");
    if (!existsSync(metaPath) || !existsSync(join(dir, "engagement.db"))) throw new Error("that folder is not a Penteos project");
    const meta = JSON.parse(readFileSync(metaPath, "utf8")) as { id: string; clientName: string; name: string; mode: string; status?: string; createdAt?: string };
    const existing = this.db.prepare("select id, dir from engagements where id = ?").get(meta.id) as { id: string; dir: string | null } | undefined;
    const createdAt = meta.createdAt ?? new Date().toISOString();
    const clientId = this.clientId(meta.clientName);
    // A copy: the id is known and its original folder still exists elsewhere. Bring the copy in as its
    // own project (new id) so the two don't fight over one id - and stamp the copy with the new id.
    if (existing && existing.dir && existing.dir !== dir && existsSync(join(existing.dir, "engagement.db"))) {
      const newId = ulid();
      this.db
        .prepare("insert into engagements (id, client_id, name, mode, status, created_at, dir) values (?, ?, ?, ?, ?, ?, ?)")
        .run(newId, clientId, meta.name, meta.mode, meta.status ?? "active", createdAt, dir);
      const engagement = Engagement.open(dir, this.pluginTypes);
      engagement.useVault(this.projectVault(dir));
      engagement.setInfo({ ...engagement.info, id: newId }, actor, "engagement.import");
      this.writeProjectJson(dir, { id: newId, clientName: meta.clientName, name: meta.name, mode: meta.mode, status: meta.status ?? "active", createdAt });
      this.track(newId, engagement);
      return { id: newId, clientId, clientName: meta.clientName, name: meta.name, mode: meta.mode, status: meta.status ?? "active", createdAt };
    }
    if (!existing) {
      this.db
        .prepare("insert into engagements (id, client_id, name, mode, status, created_at, dir) values (?, ?, ?, ?, ?, ?, ?)")
        .run(meta.id, clientId, meta.name, meta.mode, meta.status ?? "active", createdAt, dir);
    } else if (existing.dir !== dir) {
      this.db.prepare("update engagements set dir = ? where id = ?").run(dir, meta.id); // the folder moved
    }
    return { id: meta.id, clientId, clientName: meta.clientName, name: meta.name, mode: meta.mode, status: meta.status ?? "active", createdAt };
  }

  private vaultInstance?: Vault;
  /** The workspace key (config/vault.key, 0600): plugin settings and other secrets not tied to one project. */
  vault(): Vault {
    this.vaultInstance ??= Vault.forFile(join(this.dataDir, "config", "vault.key"));
    return this.vaultInstance;
  }

  /** A project's own key, inside its folder (.key, 0600), so moving the folder keeps its secrets. */
  projectVault(dir: string): Vault {
    return Vault.forFile(join(dir, ".key"));
  }

  /** Opens a project at `dir` with its own key. */
  private openWithVault(dir: string): Engagement {
    const engagement = Engagement.open(dir, this.pluginTypes);
    engagement.useVault(this.projectVault(dir));
    return engagement;
  }

  // -------------------------------------------------------------------------------------------
  // Team operators (team server mode)
  // -------------------------------------------------------------------------------------------

  /** Creates an operator. The token is returned once and only its hash is stored. */
  addOperator(name: string, role: Role): { operator: Operator; token: string } {
    const token = `pnt_${randomBytes(24).toString("base64url")}`;
    const operator: Operator = { id: ulid(), name, role, createdAt: new Date().toISOString(), disabled: false };
    this.db
      .prepare("insert into operators (id, name, role, token_hash, created_at) values (?, ?, ?, ?, ?)")
      .run(operator.id, name, role, sha256Hex(token), operator.createdAt);
    return { operator, token };
  }

  operators(): Operator[] {
    const rows = this.db.prepare("select * from operators order by created_at").all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({ id: r.id as string, name: r.name as string, role: r.role as Role, createdAt: r.created_at as string, disabled: r.disabled === 1 }));
  }

  /** The active operator a token belongs to, if any. */
  operatorByToken(token: string): Operator | undefined {
    const r = this.db.prepare("select * from operators where token_hash = ? and disabled = 0").get(sha256Hex(token)) as Record<string, unknown> | undefined;
    return r ? { id: r.id as string, name: r.name as string, role: r.role as Role, createdAt: r.created_at as string, disabled: false } : undefined;
  }

  setOperatorDisabled(id: string, disabled: boolean): void {
    const result = this.db.prepare("update operators set disabled = ? where id = ?").run(disabled ? 1 : 0, id);
    if (result.changes === 0) throw new Error(`operator not found: ${id}`);
  }

  branding(): Branding {
    try {
      return Branding.parse(JSON.parse(readFileSync(join(this.dataDir, "config", "branding.json"), "utf8")));
    } catch {
      return Branding.parse({});
    }
  }

  setBranding(input: unknown): Branding {
    const branding = Branding.parse(input);
    mkdirSync(join(this.dataDir, "config"), { recursive: true });
    writeFileSync(join(this.dataDir, "config", "branding.json"), JSON.stringify(branding, null, 2), { mode: 0o600 });
    return branding;
  }

  /** Workspace preferences: how the team works and where each operator left off. */
  prefs(): WorkspacePrefs {
    let stored: Partial<WorkspacePrefs> = {};
    try {
      stored = JSON.parse(readFileSync(join(this.dataDir, "config", "prefs.json"), "utf8")) as Partial<WorkspacePrefs>;
    } catch {
      /* first run */
    }
    return { lastOpened: {}, ...stored, onboarded: stored.onboarded ?? false };
  }

  setPrefs(patch: Partial<WorkspacePrefs>): WorkspacePrefs {
    const next = { ...this.prefs(), ...patch };
    mkdirSync(join(this.dataDir, "config"), { recursive: true });
    writeFileSync(join(this.dataDir, "config", "prefs.json"), JSON.stringify(next, null, 2), { mode: 0o600 });
    return next;
  }

  /** The interface language of an operator ("en" when never chosen). */
  languageOf(actorId: string): "es" | "en" {
    return this.prefs().languages?.[actorId] ?? "en";
  }

  setLanguage(actorId: string, language: "es" | "en"): void {
    const prefs = this.prefs();
    this.setPrefs({ languages: { ...(prefs.languages ?? {}), [actorId]: language } });
  }

  /** The engagement this operator had open last, if it still exists. */
  lastOpened(actorId: string): string | undefined {
    const id = this.prefs().lastOpened[actorId];
    return id && this.list().some((e) => e.id === id) ? id : undefined;
  }

  rememberOpened(actorId: string, engagementId: string): void {
    const prefs = this.prefs();
    if (prefs.lastOpened[actorId] === engagementId) return;
    this.setPrefs({ lastOpened: { ...prefs.lastOpened, [actorId]: engagementId } });
  }

  /** Keeps the index in sync when an engagement's status or name changes. */
  syncIndex(info: EngagementInfo): void {
    this.db.prepare("update engagements set name = ?, status = ?, mode = ? where id = ?").run(info.name, info.status, info.mode, info.id);
  }
}

/** Every file under `dir`, recursively (absolute paths). */
function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}
