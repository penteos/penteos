// macOS: the app is signed ad hoc ("-": no certificate, no Apple account). On Apple Silicon every
// executable must carry at least that signature or macOS refuses to run it; electron-builder's own
// signing is off (identity null) because without a certificate what it does changes between
// versions. Every nested binary is signed first (helpers, frameworks, node-pty), then the app, and
// the result is verified: a package with a broken signature never leaves the build.
const { execFileSync } = require("node:child_process");
const path = require("node:path");

exports.default = async function afterSign(context) {
  if (context.electronPlatformName !== "darwin") return;
  const app = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
  const sign = (target) => execFileSync("codesign", ["--force", "--sign", "-", "--timestamp=none", target], { stdio: "inherit" });
  // Inside out: what is nested has to be signed before what contains it.
  const nested = execFileSync("find", [app, "(", "-name", "*.node", "-o", "-name", "spawn-helper", "-o", "-name", "*.dylib", "-o", "-name", "*.framework", "-o", "-name", "*.app", ")", "-not", "-path", app], { encoding: "utf8" })
    .split("\n")
    .filter(Boolean)
    .sort((a, b) => b.split("/").length - a.split("/").length);
  for (const file of nested) sign(file);
  sign(app);
  execFileSync("codesign", ["--verify", "--deep", "--strict", "--verbose=2", app], { stdio: "inherit" });
};
