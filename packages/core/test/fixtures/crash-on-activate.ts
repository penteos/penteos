import { PluginHost } from "../../src/plugins/host.js";

/**
 * A start that dies in the middle of activating a plugin (like a native crash or an out-of-memory
 * kill): the process exits while the crash marker is on disk. Used by test/plugins.test.ts.
 */
const dataDir = process.argv[2]!;
const host = new PluginHost({
  dataDir,
  activators: {
    declarative: {
      activate: () => {
        process.exit(70);
      },
    },
  },
});
void host.load();
