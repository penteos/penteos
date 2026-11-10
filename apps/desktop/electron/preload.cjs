// The only bridge between the workbench and Electron: connection settings and the project browser.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("penteosDesktop", {
  getConnection: () => ipcRenderer.invoke("connection:get"),
  /** { mode: "local" } or { mode: "remote", url, token }; the app restarts to apply it. */
  setConnection: (connection) => ipcRenderer.invoke("connection:set", connection),
  /** Opens the project browser (through Penteos's proxy). */
  openBrowser: (options) => ipcRenderer.invoke("browser:open", options),
  /** Where projects live on disk: { dataDir, home, remote }. */
  projectDir: () => ipcRenderer.invoke("project:dir"),
  /** Save dialog for exporting a .penteos; returns the chosen path or null. */
  exportProject: (suggestedName) => ipcRenderer.invoke("project:export-dialog", suggestedName),
  /** Open dialog for importing a .penteos; returns the chosen path or null. */
  importProject: () => ipcRenderer.invoke("project:import-dialog"),
  /** Where to write a tool kit for a network without internet, and which kit to install. */
  exportToolsKit: (suggestedName) => ipcRenderer.invoke("tools:export-dialog", suggestedName),
  importToolsKit: () => ipcRenderer.invoke("tools:import-dialog"),
  /** Pick a project folder to open; returns the chosen directory or null. */
  openProjectDialog: () => ipcRenderer.invoke("project:open-dialog"),
  /** Pick the folder where new projects are created; returns the chosen directory or null. */
  chooseProjectsRoot: () => ipcRenderer.invoke("project:choose-root"),
  /** Saves the deliverable as a PDF (the core's print-ready document, laid out page by page). */
  savePdf: (html, fileName) => ipcRenderer.invoke("report:pdf", { html, fileName }),
  /** Opens a file a plugin made with the system's program for it (documents, data, images only). */
  openFile: (path) => ipcRenderer.invoke("file:open", path),
  /** Shows a file in its folder, or opens a folder, in the OS file manager. */
  revealFile: (path) => ipcRenderer.invoke("file:reveal", path),
  // Plugins: restart the app in safe mode (every plugin off) or out of it.
  restart: (opts) => ipcRenderer.invoke("app:restart", opts),
  isSafeMode: () => ipcRenderer.invoke("app:safe-mode"),
  /** The operator's interface language, so start-up dialogs speak it before the workbench loads. */
  setLanguage: (language) => ipcRenderer.invoke("language:set", language),
  /** Updates: the state, a manual check, install, automatic checks on or off, and changes as they happen. */
  updates: {
    state: () => ipcRenderer.invoke("update:state"),
    check: () => ipcRenderer.invoke("update:check"),
    apply: () => ipcRenderer.invoke("update:apply"),
    setAutomatic: (on) => ipcRenderer.invoke("update:automatic", on),
    onState: (listener) => {
      const handler = (_e, s) => listener(s);
      ipcRenderer.on("update:state", handler);
      return () => ipcRenderer.removeListener("update:state", handler);
    },
  },
  /** The workbench is connected to the core: the splash can give way to it. */
  appReady: () => ipcRenderer.send("app:ready"),
  /** Progress of the Maestro's note in the project browser ({ engagementId, taskId, exchanges, hosts, sent }). */
  updateBrowserNote: (update) => ipcRenderer.invoke("browser:note", update),
  /** The operator answered the note inside the browser. */
  onBrowserNoteAction: (cb) => {
    const listener = (_e, p) => cb(p);
    ipcRenderer.on("browser:note-action", listener);
    return () => ipcRenderer.removeListener("browser:note-action", listener);
  },
  /** The operator chose a way out of a blocked page in the browser ({ engagementId, action, host, url, kind }). */
  onBrowserBlockAction: (cb) => {
    const listener = (_e, p) => cb(p);
    ipcRenderer.on("browser:block-action", listener);
    return () => ipcRenderer.removeListener("browser:block-action", listener);
  },
  /** Tells the browser it was done ({ engagementId, done: true }) or why not ({ engagementId, error }). */
  resolveBrowserBlock: (p) => ipcRenderer.invoke("browser:block", p),
});
