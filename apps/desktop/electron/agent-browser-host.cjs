// The Maestro's browser on Penteos's own Chromium (Electron's): no Chrome to install. The same app
// binary started with --penteos-agent-browser=<profile> runs this instead of the interface: a window
// nobody sees, its DevTools port open for the core (which drives it over CDP exactly as it drove a
// headless Chrome), every request through Penteos's proxy, every certificate accepted (they are all
// the proxy's, in a throwaway profile). It ends when the core closes its stdin.
const { app, BrowserWindow, session } = require("electron");

const arg = (name) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
};

exports.run = function run() {
  const profile = arg("penteos-agent-browser");
  const proxyPort = arg("penteos-proxy-port");
  if (!profile) {
    process.exit(2);
    return;
  }
  // Its own profile: nothing of the operator's app (cookies, storage, the project browser) is shared.
  app.setPath("userData", profile);
  app.setName("penteos-agent-browser");
  app.commandLine.appendSwitch("remote-debugging-port", "0");
  app.commandLine.appendSwitch("remote-allow-origins", "http://127.0.0.1");
  app.commandLine.appendSwitch("ignore-certificate-errors");
  if (proxyPort) {
    app.commandLine.appendSwitch("proxy-server", `http://127.0.0.1:${proxyPort}`);
    // Labs often live on localhost: through the proxy too.
    app.commandLine.appendSwitch("proxy-bypass-list", "<-loopback>");
  }
  // Nothing but the target: no background requests of its own.
  app.commandLine.appendSwitch("disable-background-networking");
  app.commandLine.appendSwitch("disable-component-update");
  app.commandLine.appendSwitch("disable-domain-reliability");
  app.commandLine.appendSwitch("no-pings");
  // A browser like any other to the target: Chrome's user agent, without Electron's or the app's name.
  app.userAgentFallback = app.userAgentFallback.replace(/\s(?:Electron|penteos[\w-]*)\/\S+/gi, "");

  // When the core goes, so does this browser.
  process.stdin.on("end", () => app.exit(0));
  process.stdin.on("error", () => app.exit(0));
  process.stdin.resume();

  app.on("window-all-closed", () => {
    /* the core opens and closes pages; the browser stays until the core ends it */
  });
  // Proxy credentials: the core answers them over CDP; this is the same answer if it is asked here.
  const user = process.env.PENTEOS_AGENT_PROXY_USER;
  const pass = process.env.PENTEOS_AGENT_PROXY_PASS;
  app.on("login", (event, _wc, _details, authInfo, callback) => {
    if (authInfo.isProxy && user && pass) {
      event.preventDefault();
      callback(user, pass);
    }
  });

  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, cb) => cb(false));
    // A first page, so the core always finds one to attach to.
    const win = new BrowserWindow({ show: false, width: 1366, height: 900, webPreferences: { offscreen: true, sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false } });
    // Offscreen: it paints without a screen, so screenshots work; a steady frame rate is enough.
    win.webContents.setFrameRate(15);
    win.webContents.setWindowOpenHandler(() => ({ action: "allow", overrideBrowserWindowOptions: { show: false } }));
    void win.loadURL("about:blank");
  });
};
