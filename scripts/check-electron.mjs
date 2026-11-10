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
for (const file of ["browser/window.cjs", "shell-path.cjs", "updater.cjs", "main.cjs"]) {
  try {
    require(join(root, file));
    console.log(`ok  ${file}`);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${file}\n${error.stack}`);
  }
}
// The operator's PATH (shell-path.cjs): read between markers whatever the profile prints, the
// shell's own order first, known tool folders only when they exist, never a relative entry.
{
  const sp = require(join(root, "shell-path.cjs"));
  const exists = (d) => ["/opt/homebrew/bin", "/Users/ana/go/bin", "/usr/bin", "/bin"].includes(d);
  const cases = [
    [sp.parseShellOutput("Last login: today\n__PENTEOS_PATH__/opt/homebrew/bin:/usr/bin__PENTEOS_PATH__\n"), "/opt/homebrew/bin:/usr/bin"],
    [sp.parseShellOutput("no markers"), ""],
    [sp.mergePath("/opt/homebrew/bin:/usr/bin", "/usr/bin:/bin", exists, "/Users/ana"), "/opt/homebrew/bin:/usr/bin:/bin:/Users/ana/go/bin"],
    [sp.mergePath("", "/usr/bin:relative/dir:/bin", () => false, "/Users/ana"), "/usr/bin:/bin"],
  ];
  let ok = true;
  for (const [got, want] of cases) {
    if (got !== want) {
      ok = false;
      failed = true;
      console.error(`FAIL shell-path: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
  }
  if (ok) console.log("ok  shell-path rules");
}
process.exit(failed ? 1 : 0);
