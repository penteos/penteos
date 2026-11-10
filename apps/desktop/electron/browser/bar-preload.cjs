// Toolbar of the project browser: navigation only.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("bar", {
  navigate: (url) => ipcRenderer.send("bb:navigate", url),
  back: () => ipcRenderer.send("bb:back"),
  forward: () => ipcRenderer.send("bb:forward"),
  reload: () => ipcRenderer.send("bb:reload"),
  stop: () => ipcRenderer.send("bb:stop"),
  devtools: () => ipcRenderer.send("bb:devtools"),
  showNote: () => ipcRenderer.send("bb:show-note"),
  onState: (cb) => ipcRenderer.on("bb:state", (_e, s) => cb(s)),
  onFocus: (cb) => ipcRenderer.on("bb:focus", () => cb()),
});
