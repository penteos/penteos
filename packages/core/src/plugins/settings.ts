import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { type FieldSpec, fieldsSchema, PluginId, SecretValue } from "@penteos/schema";
import { Vault } from "../vault.js";

/**
 * A plugin's settings: the form is generated from what it declares. Secret
 * fields (API keys) are sealed with the workspace key, never returned to anyone - the interface
 * only learns whether one is set - and reach the plugin only as a tainted value an HTTP request
 * can use. Kept in `<dataDir>/plugin-data/<id>/settings.json`, outside the hashed package.
 */

interface Stored {
  version: 1;
  values: Record<string, unknown>;
}

export interface SettingsView {
  /** Non-secret values. */
  values: Record<string, unknown>;
  /** Secret fields that have a value. */
  secretsSet: string[];
}

export class PluginSettings {
  constructor(
    private readonly dataDir: string,
    private readonly vault: () => Vault | undefined,
  ) {}

  private file(pluginId: string): string {
    return join(this.dataDir, "plugin-data", PluginId.parse(pluginId), "settings.json");
  }

  private read(pluginId: string): Stored {
    const file = this.file(pluginId);
    if (!existsSync(file)) return { version: 1, values: {} };
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as Stored;
      return parsed && typeof parsed.values === "object" ? parsed : { version: 1, values: {} };
    } catch {
      return { version: 1, values: {} };
    }
  }

  /** What the settings form shows: plain values, and which secrets are set (never their value). */
  view(pluginId: string, fields: readonly FieldSpec[]): SettingsView {
    const stored = this.read(pluginId).values;
    const values: Record<string, unknown> = {};
    const secretsSet: string[] = [];
    for (const f of fields) {
      if (!(f.name in stored)) continue;
      if (f.secret) secretsSet.push(f.name);
      else values[f.name] = stored[f.name];
    }
    return { values, secretsSet };
  }

  /**
   * Updates some settings. A secret given as "" is cleared; a secret left out keeps its value.
   * Validated against the declared fields.
   */
  update(pluginId: string, fields: readonly FieldSpec[], patch: Record<string, unknown>): SettingsView {
    const byName = new Map(fields.map((f) => [f.name, f]));
    for (const k of Object.keys(patch)) if (!byName.has(k)) throw new Error(`${pluginId} has no setting "${k}"`);
    const stored = { ...this.read(pluginId).values };
    const plainNext: Record<string, unknown> = {};
    for (const f of fields) if (!f.secret && f.name in stored) plainNext[f.name] = stored[f.name];
    for (const [k, v] of Object.entries(patch)) {
      const f = byName.get(k)!;
      if (f.secret) {
        if (v === "" || v === null) delete stored[k];
        else {
          if (typeof v !== "string") throw new Error(`setting ${k} expects text`);
          const vault = this.vault();
          if (!vault) throw new Error("no key to encrypt secret settings");
          stored[k] = vault.seal(v);
        }
      } else if (v === null || v === "") {
        delete plainNext[k];
        delete stored[k];
      } else plainNext[k] = v;
    }
    // Plain values validated together (secrets are validated as strings above).
    const plainFields = fields.filter((f) => !f.secret).map((f) => ({ ...f, required: false }));
    const parsed = fieldsSchema(plainFields).safeParse(plainNext);
    if (!parsed.success) throw new Error(`invalid settings: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
    for (const f of fields) if (!f.secret) delete stored[f.name];
    Object.assign(stored, parsed.data);
    const file = this.file(pluginId);
    mkdirSync(dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, JSON.stringify({ version: 1, values: stored }, null, 2), { mode: 0o600 });
    renameSync(tmp, file);
    return this.view(pluginId, fields);
  }

  /** The settings as a template scope: secrets as tainted values, defaults filled in. */
  scope(pluginId: string, fields: readonly FieldSpec[]): Record<string, unknown> {
    const stored = this.read(pluginId).values;
    const out: Record<string, unknown> = {};
    for (const f of fields) {
      const v = stored[f.name];
      if (f.secret) {
        if (typeof v === "string") {
          try {
            const vault = this.vault();
            out[f.name] = new SecretValue(vault && Vault.isSealed(v) ? vault.open(v) : v);
          } catch {
            /* sealed with another key (a copied data folder): treated as not set */
          }
        }
      } else if (v !== undefined) out[f.name] = v;
      else if (f.default !== undefined) out[f.name] = f.default;
    }
    return out;
  }

  /** Every secret value of a plugin (to redact it from anything that leaves the core). */
  secretValues(pluginId: string, fields: readonly FieldSpec[]): string[] {
    return Object.values(this.scope(pluginId, fields))
      .filter((v): v is SecretValue => v instanceof SecretValue)
      .map((v) => v.value)
      .filter((v) => v.length >= 4);
  }
}
