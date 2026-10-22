const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("forensiRansomDesktop", {
  isDesktop: true,
  version: "1.0.0",
  platform: process.platform,
  arch: process.arch,
  getProductionBackendUrl: () => "https://intelligent-ransomeware-detection-using-jmsr.onrender.com",
  getLocalBackendUrl: () => "http://127.0.0.1:8000"
});
