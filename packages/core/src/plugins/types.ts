import type { z } from "zod";
import {
  type AnnotationSpec,
  type EntityKind,
  type EntityTypeSpec,
  fieldsSchema,
  ownerOfKind,
  type PluginKind,
  type PluginManifest,
  pluginKind,
} from "@penteos/schema";

/**
 * The entity types and annotations of the running plugins. The official
 * kinds are fixed in @penteos/schema; these come and go with their plugins. A kind whose plugin is
 * not running is *dormant*: its entities stay in the graph, readable, and cannot be written until
 * the plugin is back. Nothing in the official graph depends on a plugin being installed.
 */

export interface RegisteredType {
  kind: PluginKind;
  pluginId: string;
  spec: EntityTypeSpec;
  schema: z.ZodObject<Record<string, z.ZodType>>;
}

export interface RegisteredAnnotation {
  pluginId: string;
  spec: AnnotationSpec;
  schema: z.ZodObject<Record<string, z.ZodType>>;
}

/** Why a write to this kind cannot happen: the owner is not running. */
export function dormantReason(kind: string): string {
  const owner = ownerOfKind(kind) ?? kind;
  return `"${kind}" belongs to the plugin ${owner}, which is not active: its entities can be read but not written until it is enabled again`;
}

export class PluginTypeRegistry {
  private readonly types = new Map<string, RegisteredType>();
  /** pluginId → official kind → annotation. */
  private readonly annotations = new Map<string, Map<string, RegisteredAnnotation>>();
  private readonly names = new Map<string, string>();

  /** Registers everything a plugin declares, replacing what it had (an update). Validates first: all or nothing. */
  register(pluginId: string, manifest: PluginManifest): void {
    const types = (manifest.contributes.entityTypes ?? []).map((spec) => ({
      kind: pluginKind(pluginId, spec.name),
      pluginId,
      spec,
      schema: fieldsSchema(spec.fields),
    }));
    const annotations = new Map<string, RegisteredAnnotation>();
    for (const spec of manifest.contributes.annotations ?? []) {
      const reg = { pluginId, spec, schema: fieldsSchema(spec.fields).partial() };
      for (const kind of spec.on) annotations.set(kind, reg);
    }
    this.unregister(pluginId);
    for (const t of types) this.types.set(t.kind, t);
    if (annotations.size > 0) this.annotations.set(pluginId, annotations);
    this.names.set(pluginId, manifest.name);
  }

  unregister(pluginId: string): void {
    for (const [kind, t] of this.types) if (t.pluginId === pluginId) this.types.delete(kind);
    this.annotations.delete(pluginId);
    this.names.delete(pluginId);
  }

  type(kind: string): RegisteredType | undefined {
    return this.types.get(kind);
  }

  annotation(pluginId: string, kind: EntityKind | string): RegisteredAnnotation | undefined {
    return this.annotations.get(pluginId)?.get(kind);
  }

  /** The running plugin types, for the Maestro and the generic views. */
  list(): RegisteredType[] {
    return [...this.types.values()].sort((a, b) => a.kind.localeCompare(b.kind));
  }

  dormantReason(kind: string): string {
    return dormantReason(kind);
  }

  pluginName(pluginId: string): string | undefined {
    return this.names.get(pluginId);
  }

  clear(): void {
    this.types.clear();
    this.annotations.clear();
    this.names.clear();
  }
}

/** One per process, like the plugin host: every open project validates against it. */
export const pluginTypes = new PluginTypeRegistry();
