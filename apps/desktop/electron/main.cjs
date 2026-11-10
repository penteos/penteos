// Penteos desktop: starts the local core process and opens the workbench window.
// As root - common on pentesting machines (Kali, a live USB) - Chromium's sandbox will not start, so
// neither would the app nor the Maestro's browser. The operator chose to turn it off in that case so
// Penteos opens anyway; said in the log. Run as a normal user to keep the sandbox. This runs before
// the agent-browser branch below, so it covers that process too (both start through this file).
if (typeof process.getuid === "function" && process.getuid() === 0) {
  require("electron").app.commandLine.appendSwitch("no-sandbox");
  process.stderr.write("penteos: running as root, so Chromium's sandbox is off (start Penteos as a normal user to keep it)\n");
}
// The same binary is also the agents' browser (Penteos's own Chromium): started with this flag it runs
// that and nothing else - no interface, no core, no handlers.
// Penteos's own identity on the desktop, whoever started it. Launched from a terminal of another
// Electron or GTK app (VS Code's, for one), the environment says "I am that app"
// (CHROME_DESKTOP=com.microsoft.VSCode.desktop, GIO_LAUNCHED_DESKTOP_FILE…): Chromium hands that to
// the desktop and GNOME, torn between it and the window class, shows a generic icon.
if (process.platform === "linux") {
  process.env.CHROME_DESKTOP = "penteos.desktop";
  for (const k of ["GIO_LAUNCHED_DESKTOP_FILE", "GIO_LAUNCHED_DESKTOP_FILE_PID", "BAMF_DESKTOP_FILE_HINT", "DESKTOP_STARTUP_ID", "XDG_ACTIVATION_TOKEN"]) delete process.env[k];
}
if (process.argv.some((a) => a.startsWith("--penteos-agent-browser="))) {
  require("./agent-browser-host.cjs").run();
  return;
}
const { app, BrowserWindow, dialog, ipcMain, screen, session, shell } = require("electron");
// Screenshot mode, to review the interface from a script: only when running from the repository,
// never in an installed app (it can run JavaScript given in a variable).
const SHOT = !app.isPackaged ? process.env.PENTEOS_SCREENSHOT : undefined;
const SHOT_DELAY = SHOT && process.env.PENTEOS_SCREENSHOT_DELAY;
const SHOT_JS = SHOT && process.env.PENTEOS_SCREENSHOT_JS;
const SHOT_JS_DELAY = SHOT && process.env.PENTEOS_SCREENSHOT_JS_DELAY;
const { spawn } = require("node:child_process");
const { writeFileSync, mkdirSync, readFileSync, existsSync, renameSync, rmSync, statSync } = require("node:fs");
const { homedir } = require("node:os");
const path = require("node:path");
const { setNoteActionHandler, setBlockActionHandler } = require("./browser/window.cjs");
const updater = require("./updater.cjs");
const { adoptShellPath } = require("./shell-path.cjs");
/** The operator's full PATH (Homebrew, ~/go/bin…), looked up while the splash shows; the core waits for it. */
let pathReady = Promise.resolve();

/** A link the desktop may open: the web or e-mail, nothing that reaches local files or programs. */
function isWebLink(url) {
  try {
    return ["http:", "https:", "mailto:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

/** Same rule as the core's defaultDataDir (packages/core/src/paths.ts). */
function defaultDataDir() {
  if (process.env.XDG_DATA_HOME) return path.join(process.env.XDG_DATA_HOME, "penteos");
  if (process.platform === "darwin") return path.join(homedir(), "Library", "Application Support", "Penteos");
  return path.join(homedir(), ".local", "share", "penteos");
}

const repoRoot = path.resolve(__dirname, "..", "..", "..");
const dataDir = process.env.PENTEOS_DATA_DIR || defaultDataDir();
const nodeBin = process.env.PENTEOS_NODE || process.env.npm_node_execpath || "node";

let core;

// Where this window works: the local core (solo) or a team server.
const connectionFile = () => path.join(app.getPath("userData"), "connection.json");
function readConnection() {
  try {
    const c = JSON.parse(readFileSync(connectionFile(), "utf8"));
    if (c.mode === "remote" && /^https?:\/\//.test(c.url) && c.token) return c;
  } catch {
    /* default */
  }
  return { mode: "local" };
}
ipcMain.handle("connection:get", () => {
  const c = readConnection();
  return c.mode === "remote" ? { mode: "remote", url: c.url } : c;
});
ipcMain.handle("connection:set", (_e, c) => {
  const next =
    c && c.mode === "remote"
      ? { mode: "remote", url: String(c.url).replace(/\/+$/, ""), token: String(c.token), ...(c.fingerprint ? { fingerprint: String(c.fingerprint).trim() } : {}) }
      : { mode: "local" };
  mkdirSync(app.getPath("userData"), { recursive: true });
  writeFileSync(connectionFile(), JSON.stringify(next), { mode: 0o600 });
  app.relaunch();
  app.exit(0);
});

// Where a project lives on disk, and opening that folder in the OS file manager - so the operator
// always knows where their work is and can back it up or move it. Only in local mode; in team mode
// the folder is on the server.
ipcMain.handle("project:dir", () => {
  const c = readConnection();
  return { dataDir, home: homedir(), remote: c.mode === "remote" };
});
// File dialogs for exporting/importing a .penteos. The core does the actual zip/unzip (it owns the
// index); here we only ask the operator where to save or what to open.
ipcMain.handle("project:export-dialog", async (_e, suggestedName) => {
  const { canceled, filePath } = await dialog.showSaveDialog({
    defaultPath: suggestedName || "project.penteos",
    filters: [{ name: "Penteos project", extensions: ["penteos"] }],
  });
  return canceled || !filePath ? null : filePath;
});
// Tool kits for networks without internet.
ipcMain.handle("tools:export-dialog", async (_e, suggestedName) => {
  const { canceled, filePath } = await dialog.showSaveDialog({ defaultPath: suggestedName || "tools.penteos-tools", filters: [{ name: "Penteos tools", extensions: ["penteos-tools"] }] });
  return canceled || !filePath ? null : filePath;
});
ipcMain.handle("tools:import-dialog", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({ properties: ["openFile"], filters: [{ name: "Penteos tools", extensions: ["penteos-tools"] }] });
  return canceled || !filePaths.length ? null : filePaths[0];
});
ipcMain.handle("project:import-dialog", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ["openFile"],
    filters: [{ name: "Penteos project", extensions: ["penteos"] }],
  });
  return canceled || !filePaths.length ? null : filePaths[0];
});
ipcMain.handle("project:open-dialog", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  return canceled || !filePaths.length ? null : filePaths[0];
});
ipcMain.handle("project:choose-root", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({ properties: ["openDirectory", "createDirectory"] });
  return canceled || !filePaths.length ? null : filePaths[0];
});

// Files plugins made: open one with the program the system
// uses for it, or show it in its folder. Only documents, data and images open this way: never
// something the system would run. Local mode only (in team mode the files are on the server).
const OPENABLE = new Set([".docx", ".xlsx", ".pptx", ".odt", ".ods", ".pdf", ".csv", ".tsv", ".txt", ".log", ".md", ".html", ".htm", ".json", ".xml", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".zip", ".gz", ".pcap"]);
function localFile(p) {
  if (readConnection().mode === "remote") return null;
  const file = String(p || "");
  if (!path.isAbsolute(file)) return null;
  const st = statSync(file, { throwIfNoEntry: false });
  return st ? { file, dir: st.isDirectory() } : null;
}
ipcMain.handle("file:open", async (_e, p) => {
  const f = localFile(p);
  if (!f || f.dir || !OPENABLE.has(path.extname(f.file).toLowerCase())) return { ok: false };
  const error = await shell.openPath(f.file);
  return error ? { ok: false, error } : { ok: true };
});
ipcMain.handle("file:reveal", async (_e, p) => {
  const f = localFile(p);
  if (!f) return { ok: false };
  if (f.dir) {
    const error = await shell.openPath(f.file);
    return error ? { ok: false, error } : { ok: true };
  }
  shell.showItemInFolder(f.file);
  return { ok: true };
});

// The deliverable as a PDF: the core's print-ready document, laid out by Paged.js (pages, contents
// with page numbers, running header, page X of Y) and printed by Chromium with bookmarks.
ipcMain.handle("report:pdf", async (_e, opts) => {
  const html = String((opts && opts.html) || "");
  const fileName = String((opts && opts.fileName) || "report").replace(/[\\/:*?"<>|]+/g, "-");
  if (!html.startsWith("<!doctype html>")) return { ok: false, error: "not a report document" };
  const { canceled, filePath } = await dialog.showSaveDialog({ defaultPath: `${fileName}.pdf`, filters: [{ name: "PDF", extensions: ["pdf"] }] });
  if (canceled || !filePath) return { ok: false, canceled: true };
  const { mkdtempSync, rmSync, copyFileSync } = require("node:fs");
  const dir = mkdtempSync(path.join(require("node:os").tmpdir(), "penteos-pdf-"));
  let win;
  try {
    // Packaged: shipped in electron/vendor; in development, from node_modules.
    const vendored = path.join(__dirname, "vendor", "paged.polyfill.js");
    const dev = () => path.join(path.dirname(path.dirname(require.resolve("pagedjs"))), "dist", "paged.polyfill.js");
    copyFileSync(existsSync(vendored) ? vendored : dev(), path.join(dir, "paged.js"));
    const hook = '<script>document.documentElement.classList.add("paged");window.PagedConfig={auto:true,after:function(){window.__pagedDone=true}};</script><script src="paged.js"></script>';
    writeFileSync(path.join(dir, "report.html"), html.replace("</head>", `${hook}</head>`));
    win = new BrowserWindow({ show: false, width: 1240, height: 1754, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false } });
    win.webContents.on("will-navigate", (e) => e.preventDefault());
    win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    await win.loadFile(path.join(dir, "report.html"));
    const started = Date.now();
    while (!(await win.webContents.executeJavaScript("Boolean(window.__pagedDone)").catch(() => false))) {
      if (Date.now() - started > 120000) throw new Error("the document took too long to lay out");
      await new Promise((r) => setTimeout(r, 250));
    }
    const pdf = await win.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true, generateDocumentOutline: true, margins: { marginType: "none" } });
    writeFileSync(filePath, pdf);
    return { ok: true, path: filePath, size: pdf.length };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  } finally {
    if (win && !win.isDestroyed()) win.destroy();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Safe mode: every plugin off for this start. `--safe-mode` or PENTEOS_SAFE_MODE=1. */
const safeMode = process.argv.includes("--safe-mode") || process.env.PENTEOS_SAFE_MODE === "1";

/**
 * How the core starts the agents' browser: this very app in its agent-browser mode (installed: the
 * binary loads its own app; from the repository: Electron with the app's folder).
 */
function agentBrowser() {
  return JSON.stringify({ command: process.execPath, args: app.isPackaged ? [] : [app.getAppPath()] });
}

function startCore(onPlugins) {
  return new Promise((resolve, reject) => {
    mkdirSync(dataDir, { recursive: true });
    const extra = safeMode ? ["--safe-mode"] : [];
    // Installed app: the bundled core in resources/core, run by Electron's own Node.
    // From the repository: the sources, with the project's Node and tsx.
    core = app.isPackaged
      ? spawn(process.execPath, [path.join(process.resourcesPath, "core", "core.mjs"), "--data-dir", dataDir, ...extra], {
          cwd: path.join(process.resourcesPath, "core"),
          env: { ...process.env, ELECTRON_RUN_AS_NODE: "1", PENTEOS_AGENT_BROWSER: agentBrowser(), PENTEOS_PASSWORD_PROMPTS: "1" },
          stdio: ["ignore", "pipe", "pipe"],
        })
      : spawn(nodeBin, ["--conditions=penteos-source", "--import", "tsx", "src/main.ts", "--data-dir", dataDir, ...extra], {
          cwd: path.join(repoRoot, "packages", "server"),
          env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined, PENTEOS_AGENT_BROWSER: agentBrowser(), PENTEOS_PASSWORD_PROMPTS: "1" },
          stdio: ["ignore", "pipe", "pipe"],
        });
    // Line protocol on stdout: PENTEOS_PLUGINS <progress> while plugins load, then PENTEOS_READY.
    let buffer = "";
    let ready = false;
    core.stdout.on("data", (chunk) => {
      buffer += chunk.toString();
      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        if (line.startsWith("PENTEOS_PLUGINS ")) {
          try {
            onPlugins?.(JSON.parse(line.slice("PENTEOS_PLUGINS ".length)));
          } catch {
            /* a bad progress line never matters */
          }
        } else if (!ready && line.startsWith("PENTEOS_READY ")) {
          ready = true;
          resolve(JSON.parse(line.slice("PENTEOS_READY ".length)));
        }
      }
    });
    // What the core says goes to its log (whoever opened Penteos from the menu has no console) and is
    // kept to explain a failure at start.
    const log = coreLog();
    core.stderr.on("data", (chunk) => {
      process.stderr.write(chunk);
      log.write(chunk);
      recentErrors.push(...chunk.toString().split("\n").filter((l) => l.trim()));
      recentErrors.splice(0, Math.max(0, recentErrors.length - 40));
    });
    core.on("error", (e) => reject(e));
    core.on("exit", (code) => reject(new Error(`core exited with code ${code}`)));
  });
}

/** The core's last lines on stderr (to say why it did not start). */
const recentErrors = [];

/** The core's log: <data>/logs/core.log, the previous run's kept as core.log.1. */
function coreLog() {
  const dir = path.join(dataDir, "logs");
  const file = path.join(dir, "core.log");
  try {
    mkdirSync(dir, { recursive: true });
    if (existsSync(file)) renameSync(file, `${file}.1`);
  } catch {
    /* no log is better than no start */
  }
  let size = 0;
  return {
    file,
    write(chunk) {
      // Capped: a core that loops on an error must not fill the disk.
      if (size > 5 * 1024 * 1024) return;
      size += chunk.length;
      try {
        require("node:fs").appendFileSync(file, chunk);
      } catch {
        /* a full or read-only disk: the console still has it */
      }
    },
  };
}

/**
 * The operator's language for the few things said before the interface exists: the one they chose
 * in the workbench (saved here by "language:set"), English until they choose.
 */
const languageFile = () => path.join(app.getPath("userData"), "language.json");
const spanish = () => {
  try {
    return JSON.parse(readFileSync(languageFile(), "utf8")).language === "es";
  } catch {
    return false;
  }
};
ipcMain.handle("language:set", (_e, language) => {
  if (language !== "es" && language !== "en") return;
  mkdirSync(app.getPath("userData"), { recursive: true });
  writeFileSync(languageFile(), JSON.stringify({ language }));
});

// Updates: the workbench asks for the state, the operator decides when to install.
let mainWindow;
ipcMain.handle("update:state", () => ({ ...updater.state(), automatic: updater.automatic() }));
ipcMain.handle("update:check", () => updater.check({ manual: true }));
ipcMain.handle("update:apply", () => updater.apply());
ipcMain.handle("update:automatic", (_e, on) => {
  updater.setAutomatic(on);
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("update:state", { ...updater.state(), automatic: updater.automatic() });
  return updater.automatic();
});

/** Penteos could not start: say why, where the log is, and offer the way out. */
async function startFailed(error) {
  const es = spanish();
  const reason = recentErrors.filter((l) => /error|cannot|failed|no se|EACCES|ENOSPC|EADDR|glibc|GLIBC/i.test(l)).slice(-3).join("\n") || String(error && error.message ? error.message : error);
  const logFile = path.join(dataDir, "logs", "core.log");
  const { response } = await dialog.showMessageBox({
    type: "error",
    title: "Penteos",
    message: es ? "Penteos no pudo iniciar" : "Penteos could not start",
    detail: `${reason.slice(0, 900)}\n\n${es ? "Registro completo" : "Full log"}: ${logFile}${safeMode ? "" : `\n\n${es ? "Si el problema empezó con un plugin, el modo seguro inicia sin ninguno." : "If it started with a plugin, safe mode starts without any."}`}`,
    buttons: es ? ["Reintentar", "Iniciar en modo seguro", "Salir"] : ["Retry", "Start in safe mode", "Quit"],
    defaultId: 0,
    cancelId: 2,
    noLink: true,
  });
  if (response === 0) restartApp(safeMode);
  else if (response === 1) restartApp(true);
  else app.exit(1);
}

/** Little room left on the disk the data lives on: said once at start, before it causes odd failures. */
function warnLowDisk() {
  try {
    const st = require("node:fs").statfsSync(existsSync(dataDir) ? dataDir : homedir());
    const freeMb = (st.bavail * st.bsize) / 1024 / 1024;
    if (freeMb > 500) return;
    const es = spanish();
    void dialog.showMessageBox({
      type: "warning",
      title: "Penteos",
      message: es ? "Queda poco espacio en el disco" : "The disk is almost full",
      detail: es
        ? `Quedan ${Math.round(freeMb)} MB libres donde Penteos guarda sus proyectos (${dataDir}). Con el disco lleno pueden fallar las capturas del proxy, los informes y la base de datos.`
        : `${Math.round(freeMb)} MB left where Penteos keeps its projects (${dataDir}). With a full disk, proxy captures, reports and the database can fail.`,
      buttons: ["OK"],
      noLink: true,
    });
  } catch {
    /* not every system reports it */
  }
}

/** Restarts the whole app, in safe mode or out of it. */
function restartApp(safe) {
  const args = process.argv.slice(1).filter((a) => a !== "--safe-mode");
  app.relaunch({ args: safe ? [...args, "--safe-mode"] : args });
  app.exit(0);
}
ipcMain.handle("app:restart", (_e, opts) => restartApp(Boolean(opts && opts.safeMode)));
ipcMain.handle("app:safe-mode", () => safeMode);

/**
 * The splash: a small frameless window with the brand while the core starts and the workbench
 * connects. It stays at least SPLASH_MIN_MS, so it does not just flash by.
 */
const SPLASH_MIN_MS = 8500;
function openSplash() {
  const splash = new BrowserWindow({
    width: 380,
    height: 560,
    frame: false,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    center: true,
    show: false,
    backgroundColor: "#07060c",
    title: "Penteos",
    ...(existsSync(path.join(__dirname, "..", "build-resources", "icon.png")) ? { icon: path.join(__dirname, "..", "build-resources", "icon.png") } : {}),
    webPreferences: { contextIsolation: true, sandbox: true },
  });
  const shownAt = Date.now();
  splash.once("ready-to-show", () => splash.show());
  splash.loadFile(path.join(__dirname, "splash", "splash.html")).catch(() => {});
  return {
    /** Real plugin progress from the core, shown under the start-up steps. */
    plugins(p) {
      if (splash.isDestroyed()) return;
      splash.webContents.executeJavaScript(`window.penteosPlugins && window.penteosPlugins(${JSON.stringify(p)})`).catch(() => {});
    },
    /** A newer release, said on the splash; installing happens from the workbench. */
    update(s) {
      if (splash.isDestroyed() || s.status !== "available") return;
      splash.webContents.executeJavaScript(`window.penteosUpdate && window.penteosUpdate(${JSON.stringify({ latest: s.latest })})`).catch(() => {});
    },
    /** Closes the splash once it has been visible long enough, then runs `next`. */
    close(next) {
      setTimeout(() => {
        if (!splash.isDestroyed()) splash.close();
        next();
      }, Math.max(0, SPLASH_MIN_MS - (Date.now() - shownAt)));
    },
  };
}

async function createWindow() {
  const splash = SHOT ? undefined : openSplash();
  if (!SHOT) {
    updater.start((s) => {
      splash?.update(s);
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("update:state", { ...s, automatic: updater.automatic() });
    });
  }
  const connection = readConnection();
  await pathReady;
  const info = connection.mode === "remote" ? undefined : await startCore((p) => splash?.plugins(p));
  // Always opens maximized. The size here is only what "restore" goes back to: it leaves a margin
  // because on GNOME/X11 Electron reports the whole screen as work area, top bar and dock included.
  const area = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
  const width = Math.min(1560, area.width - 80);
  const height = Math.min(940, area.height - 140);
  const win = (mainWindow = new BrowserWindow({
    width,
    height,
    x: area.x + Math.round((area.width - width) / 2),
    y: area.y + Math.round((area.height - height) / 2),
    minWidth: Math.min(960, area.width),
    minHeight: Math.min(600, area.height),
    // The splash's own background, so the window opens without a flash of another colour.
    backgroundColor: "#07060c",
    ...(existsSync(path.join(__dirname, "..", "build-resources", "icon.png")) ? { icon: path.join(__dirname, "..", "build-resources", "icon.png") } : {}),
    title: "Penteos",
    autoHideMenuBar: true,
    // Shown already maximized below, so it never flashes at its restored size.
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, "preload.cjs"),
      backgroundThrottling: !SHOT,
    },
  }));
  // Shown first, then maximized: X11 window managers ignore maximizing a hidden window, and may
  // drop a request made at the same moment the window appears, so it is repeated until it holds.
  // The workbench appears when it is connected to the core (it says so with "app:ready"), or after
  // 15 s so a core that never answers shows its error instead of an endless splash.
  if (!SHOT) {
    let shown = false;
    const reveal = () => {
      if (shown || win.isDestroyed()) return;
      shown = true;
      const show = () => {
        if (win.isDestroyed()) return;
        win.show();
        win.maximize();
        for (const ms of [150, 400, 1000]) setTimeout(() => !win.isDestroyed() && !win.isMaximized() && win.maximize(), ms);
      };
      if (splash) splash.close(show);
      else show();
    };
    ipcMain.once("app:ready", reveal);
    setTimeout(reveal, 15000);
  }
  // "Done" on the Maestro's note in the project browser reaches the workbench, which tells the core.
  setNoteActionHandler((p) => !win.isDestroyed() && win.webContents.send("browser:note-action", p));
  // A way out of a blocked page (add to scope, let through, lift the pause): the workbench does it.
  setBlockActionHandler((p) => {
    if (win.isDestroyed()) return;
    if (p.action === "open_scope") win.focus();
    win.webContents.send("browser:block-action", p);
  });
  // Links leave the app only to the web or mail: agent text can carry links from the target, and a
  // file:// or custom scheme handed to the desktop would open local files or other programs.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isWebLink(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  // The workbench never navigates away from itself: a navigation is a link, opened outside or dropped.
  win.webContents.on("will-navigate", (e, url) => {
    e.preventDefault();
    if (isWebLink(url)) shell.openExternal(url);
  });

  const query = info
    ? { port: String(info.port), token: info.token }
    : { url: connection.url, token: connection.token, remote: "1" };
  // The Vite dev server, only when running from source: a packaged app never loads a page from elsewhere.
  const devUrl = !app.isPackaged ? process.env.VITE_DEV_URL : undefined;
  if (devUrl) {
    await win.loadURL(`${devUrl}?${new URLSearchParams(query)}`);
  } else {
    await win.loadFile(path.join(__dirname, "..", "dist", "index.html"), { query });
  }

  if (SHOT) {
    win.webContents.on("console-message", (e) => {
      if (e.level === "error" || e.level === "warning") console.error(`[renderer ${e.level}] ${e.message} @ ${e.sourceId}:${e.lineNumber}`);
    });
    win.webContents.on("render-process-gone", (_e, d) => console.error(`[renderer gone] ${d.reason}`));
    const delay = Number(SHOT_DELAY || 4000);
    if (SHOT_JS) {
      setTimeout(() => win.webContents.executeJavaScript(SHOT_JS).catch(() => {}), Number(SHOT_JS_DELAY || delay / 2));
    }
    setTimeout(async () => {
      const image = await win.webContents.capturePage();
      writeFileSync(SHOT, image.toPNG());
      app.quit();
    }, delay);
  }
}

// Self-signed team servers: trust exactly the pinned certificate for that host, nothing else.
// (A session-level verifier also covers WebSocket connections, which "certificate-error" does not.)
function pinCertificate() {
  const c = readConnection();
  if (c.mode !== "remote" || !c.fingerprint) return;
  const host = new URL(c.url).hostname;
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    if (request.hostname === host && request.certificate.fingerprint === c.fingerprint) callback(0);
    else callback(-3); // anything else: Chromium's normal verification
  });
}

// AppImage: "download and double-click" leaves Penteos in the
// applications menu like an installed app - once, and again only if the file was moved. Installed
// from .deb or .rpm there is nothing to do (no APPIMAGE variable).
function integrateAppImage() {
  const image = process.env.APPIMAGE;
  if (!image || process.platform !== "linux") return;
  try {
    const share = process.env.XDG_DATA_HOME || path.join(homedir(), ".local", "share");
    const desktopFile = path.join(share, "applications", "penteos.desktop");
    const iconFile = path.join(share, "icons", "hicolor", "512x512", "apps", "penteos.png");
    const exec = `"${image.replace(/"/g, '\\"')}" %U`;
    const entry = [
      "[Desktop Entry]",
      "Name=Penteos",
      "Comment=Agentic workbench for penetration testing",
      "Comment[es]=Entorno de trabajo agéntico para pruebas de penetración",
      `Exec=${exec}`,
      "Icon=penteos",
      "Type=Application",
      "Terminal=false",
      "Categories=Development;Security;",
      // The window's class (from productName, lowercased by Electron): GNOME matches it exactly.
      "StartupWMClass=penteos",
      "X-Penteos-AppImage=true",
      "",
    ].join("\n");
    const current = existsSync(desktopFile) ? readFileSync(desktopFile, "utf8") : "";
    // An entry the user (or a package) made is theirs: only ours is kept up to date.
    if (current && !current.includes("X-Penteos-AppImage=true")) return;
    // Penteos installed from a .deb/.rpm too: its menu entry stays the one (ours would hide it).
    if (!current && ["/usr/share/applications/penteos.desktop", "/usr/local/share/applications/penteos.desktop"].some((f) => existsSync(f))) return;
    if (current === entry && existsSync(iconFile)) return;
    mkdirSync(path.dirname(desktopFile), { recursive: true });
    mkdirSync(path.dirname(iconFile), { recursive: true });
    const icon = path.join(process.resourcesPath, "icon.png");
    if (existsSync(icon)) writeFileSync(iconFile, readFileSync(icon));
    writeFileSync(desktopFile, entry, { mode: 0o644 });
  } catch {
    /* a desktop without these folders: Penteos still runs */
  }
}


app.whenReady().then(() => { pathReady = adoptShellPath().catch(() => undefined); pinCertificate(); integrateAppImage(); warnLowDisk(); return createWindow(); }).catch((error) => {
  console.error(error);
  return startFailed(error);
});
app.on("window-all-closed", () => app.quit());
app.on("will-quit", () => core && core.kill("SIGTERM"));
