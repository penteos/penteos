// The project browser: Chromium inside Penteos, with its own session per project. Its traffic
// goes through Penteos's proxy (scope, history, evidence) and it trusts Penteos's certificate
// authority only inside that session: nothing is installed in the system.
const { app, BaseWindow, WebContentsView, ipcMain, screen, session } = require("electron");
// Screenshot mode (from the repository only, never in an installed app).
const SHOT = !app.isPackaged ? process.env.PENTEOS_SCREENSHOT : undefined;
const SHOT_BROWSER = !app.isPackaged ? process.env.PENTEOS_SCREENSHOT_BROWSER : undefined;

/** The project browser loads web pages only (http and https). */
function isWeb(url) {
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}
const path = require("node:path");

const BAR_HEIGHT = 44;
/** webContents id of each page → its proxy credentials. */
const credentials = new Map();
/** Sessions already prepared (one per project). */
const prepared = new Set();
/** Open browser windows by project: a second "open" focuses and navigates the existing one. */
const windows = new Map();
/** Where the operator's answer to a Maestro note goes (the workbench window). */
let onNoteAction = () => {};
function setNoteActionHandler(fn) {
  onNoteAction = fn;
}
/** Where the operator's way out of a block goes (the workbench, which holds the core's client). */
let onBlockAction = () => {};
function setBlockActionHandler(fn) {
  onBlockAction = fn;
}
const BLOCK_HEIGHT = 52;
const BLOCK_KINDS = new Set(["out_of_scope", "stop_work", "outside_window", "other"]);

/** The proxy's answer for a page says why it was blocked (packages/core/src/proxy/server.ts). */
function blockOf(headers) {
  const get = (name) => {
    for (const [k, v] of Object.entries(headers || {})) if (k.toLowerCase() === name) return Array.isArray(v) ? v[0] : v;
    return undefined;
  };
  const kind = get("x-penteos-block");
  if (!kind || !BLOCK_KINDS.has(kind)) return undefined;
  const dec = (v) => {
    try {
      return v ? decodeURIComponent(v) : "";
    } catch {
      return "";
    }
  };
  return { kind, host: dec(get("x-penteos-host")), detail: dec(get("x-penteos-detail")) };
}

app.on("login", (event, webContents, _details, authInfo, callback) => {
  const creds = webContents && credentials.get(webContents.id);
  if (!authInfo.isProxy || !creds) return;
  event.preventDefault();
  callback(creds.username, creds.password);
});

async function prepareSession(opts) {
  const partition = `persist:penteos-${opts.engagementId}`;
  const ses = session.fromPartition(partition);
  if (!prepared.has(partition)) {
    prepared.add(partition);
    // "<-loopback>": localhost and 127.0.0.1 also go through the proxy (labs often live there).
    await ses.setProxy({ proxyRules: `http=127.0.0.1:${opts.port};https=127.0.0.1:${opts.port}`, proxyBypassRules: "<-loopback>" });
    ses.setCertificateVerifyProc((request, callback) => {
      const issuer = request.certificate && request.certificate.issuerCert;
      // Certificates made by Penteos's CA are trusted here; anything else, as Chromium decides.
      callback(issuer && issuer.fingerprint === opts.caFingerprint ? 0 : -3);
    });
    // A plain Chrome to the target: no "Electron" or "@penteos/desktop" in the User-Agent.
    ses.setUserAgent(ses.getUserAgent().replace(/\s+Electron\/\S+/, "").replace(/\s+@?penteos[^\s]*\/\S+/i, ""));
    ses.setPermissionRequestHandler((_wc, permission, cb) => cb(["clipboard-sanitized-write", "fullscreen"].includes(permission)));
    // A page the proxy refused: remember why, so the window can offer the way out once it shows.
    ses.webRequest.onHeadersReceived((details, cb) => {
      if (details.resourceType === "mainFrame") {
        const w = windows.get(opts.engagementId);
        if (w && w.page.webContents.id === details.webContentsId) {
          const b = blockOf(details.responseHeaders);
          w.pendingBlock = b && { ...b, url: details.url };
        }
      }
      cb({});
    });
  } else {
    await ses.setProxy({ proxyRules: `http=127.0.0.1:${opts.port};https=127.0.0.1:${opts.port}`, proxyBypassRules: "<-loopback>" });
  }
  return partition;
}

async function openBrowser(opts) {
  const existing = windows.get(opts.engagementId);
  if (existing && !existing.win.isDestroyed()) {
    existing.labels = opts.labels || existing.labels;
    if (opts.note) showNote(existing, opts.note);
    if (opts.url) existing.page.webContents.loadURL(opts.url).catch(() => {});
    existing.win.focus();
    return;
  }
  const partition = await prepareSession(opts);
  // Fits the work area of the screen it opens on, like the main window.
  const area = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
  const size = { width: Math.min(1280, area.width - 80), height: Math.min(860, area.height - 140) };
  const win = new BaseWindow({ ...size, x: area.x + Math.round((area.width - size.width) / 2), y: area.y + Math.round((area.height - size.height) / 2), title: `${(opts.labels && opts.labels.window) || "Browser"} · ${opts.title || "Penteos"}`, backgroundColor: "#0c0a10", ...(SHOT ? { x: -4000, y: -4000, skipTaskbar: true } : {}) });
  const bar = new WebContentsView({
    webPreferences: { preload: path.join(__dirname, "bar-preload.cjs"), contextIsolation: true, sandbox: true },
  });
  const page = new WebContentsView({ webPreferences: { partition, contextIsolation: true, sandbox: true } });
  // The Maestro's request, between the toolbar and the page, only while there is one.
  const note = new WebContentsView({ webPreferences: { preload: path.join(__dirname, "note-preload.cjs"), contextIsolation: true, sandbox: true } });
  note.setBackgroundColor("#0c0a10");
  // Why the proxy refused this page, and the way out the operator has (only while there is one).
  const block = new WebContentsView({ webPreferences: { preload: path.join(__dirname, "block-preload.cjs"), contextIsolation: true, sandbox: true } });
  block.setBackgroundColor("#0c0a10");
  credentials.set(page.webContents.id, { username: opts.engagementId, password: opts.token });
  win.contentView.addChildView(bar);
  win.contentView.addChildView(block);
  win.contentView.addChildView(note);
  win.contentView.addChildView(page);
  const entry = { win, page, bar, note, block, noteHeight: 0, noteTask: undefined, blocked: undefined, pendingBlock: undefined, labels: opts.labels || {}, engagementId: opts.engagementId, exchanges: undefined };
  const layout = () => {
    const { width, height } = win.getContentBounds();
    const bh = entry.blocked ? BLOCK_HEIGHT : 0;
    const nh = entry.noteTask ? entry.noteHeight : 0;
    bar.setBounds({ x: 0, y: 0, width, height: BAR_HEIGHT });
    block.setBounds({ x: 0, y: BAR_HEIGHT, width, height: bh });
    note.setBounds({ x: 0, y: BAR_HEIGHT + bh, width, height: nh });
    page.setBounds({ x: 0, y: BAR_HEIGHT + bh + nh, width, height: Math.max(0, height - BAR_HEIGHT - bh - nh) });
  };
  entry.layout = layout;
  layout();
  win.on("resize", layout);
  windows.set(opts.engagementId, entry);

  const wc = page.webContents;
  const state = (extra = {}) => {
    if (bar.webContents.isDestroyed() || wc.isDestroyed()) return;
    bar.webContents.send("bb:state", {
      url: wc.getURL(),
      title: wc.getTitle(),
      canGoBack: wc.navigationHistory.canGoBack(),
      canGoForward: wc.navigationHistory.canGoForward(),
      loading: wc.isLoading(),
      project: opts.title || "",
      labels: entry.labels.bar || {},
      ...(entry.exchanges !== undefined ? { exchanges: entry.exchanges } : {}),
      ...extra,
    });
  };
  for (const ev of ["did-navigate", "did-navigate-in-page", "page-title-updated", "did-start-loading", "did-stop-loading"]) wc.on(ev, () => state());
  // Each page that loads says whether it was blocked: the band appears or goes with it.
  wc.on("did-navigate", () => {
    const b = entry.pendingBlock;
    entry.pendingBlock = undefined;
    showBlock(entry, b);
  });
  wc.on("did-fail-load", (_e, code, description, url, isMainFrame) => {
    if (isMainFrame && code !== -3) state({ error: `${description} (${code})`, url });
  });
  // Pop-ups stay in this window and this session (so they also go through the proxy).
  // Only web pages: a page under test must not open file:// or other schemes through us.
  wc.setWindowOpenHandler(({ url }) => {
    if (isWeb(url)) wc.loadURL(url).catch(() => {});
    return { action: "deny" };
  });
  wc.on("before-input-event", (event, input) => {
    if (input.type !== "keyDown") return;
    const mod = input.control || input.meta;
    if (input.key === "F12") (wc.toggleDevTools(), event.preventDefault());
    else if (mod && input.key.toLowerCase() === "l") (bar.webContents.focus(), bar.webContents.send("bb:focus"), event.preventDefault());
    else if ((mod && input.key.toLowerCase() === "r") || input.key === "F5") (wc.reload(), event.preventDefault());
    else if (input.alt && input.key === "ArrowLeft") (wc.navigationHistory.goBack(), event.preventDefault());
    else if (input.alt && input.key === "ArrowRight") (wc.navigationHistory.goForward(), event.preventDefault());
  });

  entry.state = state;
  win.on("closed", () => {
    credentials.delete(page.webContents.id);
    windows.delete(opts.engagementId);
    for (const v of [page, bar, note, block]) if (!v.webContents.isDestroyed()) v.webContents.close();
  });

  await Promise.all([bar.webContents.loadFile(path.join(__dirname, "bar.html")), note.webContents.loadFile(path.join(__dirname, "note.html")), block.webContents.loadFile(path.join(__dirname, "block.html"))]);
  state();
  if (opts.note) showNote(entry, opts.note);
  // Screenshot mode (tests): capture the browser once the page has loaded.
  if (SHOT_BROWSER) {
    wc.once("did-stop-loading", () =>
      setTimeout(async () => {
        try {
          const fs = require("node:fs");
          const top = await bar.webContents.capturePage();
          const body = await wc.capturePage();
          fs.writeFileSync(SHOT_BROWSER, body.toPNG());
          fs.writeFileSync(SHOT_BROWSER.replace(/\.png$/, "-bar.png"), top.toPNG());
          if (entry.blocked) fs.writeFileSync(SHOT_BROWSER.replace(/\.png$/, "-block.png"), (await block.webContents.capturePage()).toPNG());
          if (entry.noteTask) fs.writeFileSync(SHOT_BROWSER.replace(/\.png$/, "-note.png"), (await note.webContents.capturePage()).toPNG());
        } catch (e) {
          console.error("browser screenshot:", e.message);
        }
      }, 1500),
    );
  }
  if (opts.url) wc.loadURL(opts.url).catch(() => {});
}

ipcMain.handle("browser:open", (_e, opts) => {
  if (!opts || typeof opts.engagementId !== "string" || !/^[0-9A-Z]{26}$/.test(opts.engagementId)) throw new Error("bad engagement");
  if (!Number.isInteger(opts.port) || typeof opts.token !== "string" || !String(opts.caFingerprint).startsWith("sha256/")) throw new Error("bad proxy settings");
  return openBrowser(opts);
});

/** The toolbar talks only to the page of its own window. */
function pageFor(sender) {
  for (const w of windows.values()) if (w.bar.webContents.id === sender.id) return w.page.webContents;
  return undefined;
}
ipcMain.on("bb:navigate", (e, raw) => {
  const wc = pageFor(e.sender);
  if (!wc) return;
  let url = String(raw || "").trim();
  if (!url) return;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = /^(localhost|\d{1,3}(\.\d{1,3}){3})(:\d+)?(\/|$)/i.test(url) ? `http://${url}` : `https://${url}`;
  if (!isWeb(url)) return;
  wc.loadURL(url).catch(() => {});
});
ipcMain.on("bb:back", (e) => pageFor(e.sender)?.navigationHistory.goBack());
ipcMain.on("bb:forward", (e) => pageFor(e.sender)?.navigationHistory.goForward());
ipcMain.on("bb:reload", (e) => pageFor(e.sender)?.reload());
ipcMain.on("bb:stop", (e) => pageFor(e.sender)?.stop());
ipcMain.on("bb:devtools", (e) => pageFor(e.sender)?.toggleDevTools());

/** Shows (or replaces) the Maestro's request in a window. */
function showNote(entry, n) {
  entry.noteTask = n.taskId;
  entry.noteHeight = entry.noteHeight || 180;
  entry.exchanges = n.exchanges || 0;
  if (!entry.note.webContents.isDestroyed()) entry.note.webContents.send("bn:show", { ...n, labels: entry.labels.note || {} });
  entry.layout();
  entry.state && entry.state();
}

function entryForNote(sender) {
  for (const w of windows.values()) if (w.note.webContents.id === sender.id) return w;
  return undefined;
}
ipcMain.on("bn:height", (e, h) => {
  const w = entryForNote(e.sender);
  if (!w || !Number.isFinite(h)) return;
  w.noteHeight = Math.max(32, Math.min(420, Math.round(h)));
  w.layout();
});
ipcMain.on("bn:action", (e, action) => {
  const w = entryForNote(e.sender);
  if (!w || !w.noteTask) return;
  if (action === "done") onNoteAction({ engagementId: w.engagementId, taskId: w.noteTask, action: "done" });
});
ipcMain.on("bb:show-note", (e) => {
  for (const w of windows.values()) if (w.bar.webContents.id === e.sender.id && w.noteTask) w.note.webContents.send("bn:expand");
});

/**
 * The workbench reports progress (exchanges recorded since the request) and closes the note once
 * the Maestro has been told.
 */
ipcMain.handle("browser:note", (_e, p) => {
  const w = p && windows.get(p.engagementId);
  if (!w || w.win.isDestroyed() || !w.noteTask || (p.taskId && p.taskId !== w.noteTask)) return;
  if (typeof p.exchanges === "number") {
    w.exchanges = p.exchanges;
    w.note.webContents.send("bn:progress", { exchanges: p.exchanges, hosts: p.hosts || [] });
    w.state && w.state();
  }
  if (p.sent) {
    w.note.webContents.send("bn:sent", p.sent);
    setTimeout(() => {
      if (w.win.isDestroyed() || w.noteTask !== p.taskId) return;
      w.noteTask = undefined;
      w.exchanges = undefined;
      w.layout();
      w.state && w.state();
    }, 2200);
  }
});

/** Shows the band for a blocked page, or hides it (b undefined). */
function showBlock(entry, b) {
  entry.blocked = b;
  entry.blockBusy = false;
  if (b && !entry.block.webContents.isDestroyed()) entry.block.webContents.send("bk:show", { ...b, labels: entry.labels.block || {} });
  entry.layout();
}

function entryForBlock(sender) {
  for (const w of windows.values()) if (w.block.webContents.id === sender.id) return w;
  return undefined;
}
ipcMain.on("bk:action", (e, action) => {
  const w = entryForBlock(e.sender);
  if (!w || !w.blocked) return;
  if (action === "dismiss") return showBlock(w, undefined);
  if (!["add_scope", "let_through", "resume", "open_scope"].includes(action) || w.blockBusy) return;
  w.blockBusy = action !== "open_scope";
  onBlockAction({ engagementId: w.engagementId, action, host: w.blocked.host, url: w.blocked.url, kind: w.blocked.kind });
});

/** The workbench did what the operator asked (or could not): reload the page, or say why. */
ipcMain.handle("browser:block", (_e, p) => resolveBlock(p));
function resolveBlock(p) {
  const w = p && windows.get(p.engagementId);
  if (!w || w.win.isDestroyed()) return;
  if (p.error) {
    w.blockBusy = false;
    w.block.webContents.send("bk:error", String(p.error).slice(0, 300));
    return;
  }
  if (p.done) {
    const url = w.blocked && w.blocked.url;
    showBlock(w, undefined);
    if (url) w.page.webContents.loadURL(url).catch(() => {});
    else w.page.webContents.reload();
  }
}

module.exports = { openBrowser, setNoteActionHandler, setBlockActionHandler, resolveBlock, windows };
