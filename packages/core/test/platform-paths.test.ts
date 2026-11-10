import { expect, it } from "vitest";
import { defaultDataDir } from "../src/index.js";

/** Each system keeps the data where its users look for it; XDG_DATA_HOME wins wherever it is set. */
it("keeps the data in each system's own place", () => {
  expect(defaultDataDir("linux", {}, "/home/ana")).toBe("/home/ana/.local/share/penteos");
  expect(defaultDataDir("darwin", {}, "/Users/ana")).toBe("/Users/ana/Library/Application Support/Penteos");
  expect(defaultDataDir("darwin", { XDG_DATA_HOME: "/Users/ana/.data" }, "/Users/ana")).toBe("/Users/ana/.data/penteos");
  expect(defaultDataDir("linux", { XDG_DATA_HOME: "/data" }, "/home/ana")).toBe("/data/penteos");
});
