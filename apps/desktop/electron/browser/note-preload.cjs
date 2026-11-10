// The Maestro's note inside the project browser: it only reports its height and the operator's choice.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("note", {
  height: (h) => ipcRenderer.send("bn:height", h),
  action: (a) => ipcRenderer.send("bn:action", a),
  onShow: (cb) => ipcRenderer.on("bn:show", (_e, n) => cb(n)),
  onProgress: (cb) => ipcRenderer.on("bn:progress", (_e, p) => cb(p)),
  onExpand: (cb) => ipcRenderer.on("bn:expand", () => cb()),
  onSent: (cb) => ipcRenderer.on("bn:sent", (_e, text) => cb(text)),
});
