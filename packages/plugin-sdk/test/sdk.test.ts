import { describe, expect, it } from "vitest";
import { definePlugin, PLUGIN_API_VERSION, validateManifest } from "../src/index.js";

describe("the SDK", () => {
  it("validates a manifest with exact paths", () => {
    const good = definePlugin({ id: "acme.x", name: "X", version: "1.0.0", apiVersion: PLUGIN_API_VERSION, level: "declarative", author: { type: "human" }, permissions: [] });
    expect(validateManifest(good).ok).toBe(true);
    const bad = validateManifest({ ...good, contributes: { operations: [{ name: "a", title: "A", description: "a", steps: [{ do: "http", url: "https://evil.test/" }] }] } });
    expect(bad.ok ? "" : bad.issues.join("\n")).toMatch(/contributes.operations.0.steps.0.url: evil.test is not in the plugin's net/);
  });
});
