import { defineConfig } from "vitest/config";

// Resolve workspace packages to their TypeScript sources ("penteos-source" export condition),
// so tests never depend on a previous build.
export default defineConfig({
  test: {
    passWithNoTests: true,
  },
  resolve: {
    conditions: ["penteos-source"],
  },
  ssr: {
    resolve: {
      conditions: ["penteos-source"],
    },
  },
});
