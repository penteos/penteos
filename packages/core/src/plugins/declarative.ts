import type { PluginActivator } from "./host.js";
import { type PluginData, storageActivationError } from "./data.js";
import type { PluginRuntime } from "./runtime.js";

/**
 * Activates a declarative plugin (data only, run by the core): its global database is migrated
 * first (a migration that fails stops the plugin before any of it runs), then its entity types and
 * annotations are registered, then its operations join the catalog - as forms for people and
 * tools for the Maestro. Deactivating undoes all of it; the data stays.
 */
export function declarativeActivator(data: PluginData, runtime?: PluginRuntime): PluginActivator {
  return {
    activate(plugin) {
      if ((plugin.manifest.contributes.storage?.global ?? []).length > 0) {
        try {
          data.openGlobal(plugin.id);
        } catch (e) {
          throw storageActivationError(e);
        }
      }
      data.types.register(plugin.id, plugin.manifest);
      try {
        runtime?.register(plugin);
      } catch (e) {
        data.types.unregister(plugin.id);
        throw e;
      }
    },
    deactivate(id) {
      runtime?.unregister(id);
      data.types.unregister(id);
      data.close(id);
    },
  };
}
