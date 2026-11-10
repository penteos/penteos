// Loads the desktop app's main-process files with a stand-in for Electron, so a mistake that only
// shows when the app starts (a variable used before it exists, a missing require) fails here
// instead of on someone's desktop. Nothing is opened: the stand-in answers every call with itself.
import Module from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "apps", "desktop", "electron");
const any = () =>
  new Proxy(function () {}, {
    get: (_t, k) => (k === "isPackaged" ? false : k === "then" ? (fn) => any() : k === Symbol.toPrimitive ? () => "" : any()),
    apply: () => any(),
    construct: () => any(),
  });
const load = Module._load;
Module._load = function (request, ...rest) {
  return request === "electron" ? any() : load.call(this, request, ...rest);
};

const require = Module.createRequire(import.meta.url);
let failed = false;
for (const file of ["browser/window.cjs", "main.cjs"]) {
  try {
    require(join(root, file));
    console.log(`ok  ${file}`);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${file}\n${error.stack}`);
  }
}
process.exit(failed ? 1 : 0);
