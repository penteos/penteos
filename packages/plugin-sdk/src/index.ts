/**
 * @penteos/plugin-sdk - the one contract a Penteos plugin depends on. The
 * core can change inside without breaking plugins as long as this stays compatible; it supports the
 * current apiVersion and the previous one.
 */
import { PluginManifest } from "@penteos/schema";

export {
  PLUGIN_API_VERSION,
  SUPPORTED_PLUGIN_API_VERSIONS,
  PluginManifest,
  PluginPermission,
  PLUGIN_REASONS,
  engineSatisfies,
  FieldSpec,
  FIELD_TYPES,
  fieldsSchema,
  EntityTypeSpec,
  AnnotationSpec,
  StorageSpec,
  Migration,
  MigrationStep,
  ColumnSpec,
  replayMigrations,
  PluginOperation,
  PluginMenu,
  PluginEvent,
  PluginProvider,
  PluginPanel,
  PluginView,
  PluginStepSchema,
  PLUGIN_EVENTS,
  HTTP_LIMITS,
  checkContributions,
  manifestHosts,
  netAllows,
  httpsHostOf,
  pluginOperationName,
  pluginToolName,
  pluginKind,
  textOf,
  renderValue,
  templateRefs,
  FILTERS,
  SecretValue,
  TemplateError,
} from "@penteos/schema";
export type { PluginText, PluginStep, PluginReasonCode, StorageShape } from "@penteos/schema";
export type { Activate, EntityView, HttpRequest, HttpResponse, OutputFile, PanelBridge, PenteosApi, PluginRegistrar, ReportOptions, ReportSection, StoreScope, Where } from "./api.js";

/** Types a manifest written in TypeScript (no runtime change). */
export function definePlugin<const T extends PluginManifest | Record<string, unknown>>(manifest: T): T {
  return manifest;
}

/** A manifest's problems, each with its exact path ("contributes.operations.0.steps.1.url: …"). */
export function validateManifest(raw: unknown): { ok: true; manifest: PluginManifest } | { ok: false; issues: string[] } {
  const r = PluginManifest.safeParse(raw);
  return r.success ? { ok: true, manifest: r.data } : { ok: false, issues: r.error.issues.map((i) => `${i.path.join(".") || "(manifest)"}: ${i.message}`) };
}
