const { app, BrowserWindow, Menu, shell, dialog } = require("electron");
const path = require("path");
const http = require("http");
const fs = require("fs");

let mainWindow = null;
let staticServer = null;
let serverPort = null;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf"
};

function getStaticDir() {
  const embeddedDist = path.join(__dirname, "app-dist");
  if (fs.existsSync(embeddedDist)) {
    return embeddedDist;
  }
  const rootFrontendDist = path.join(__dirname, "..", "frontend", "dist");
  if (fs.existsSync(rootFrontendDist)) {
    return rootFrontendDist;
  }
  const rootBackendStatic = path.join(__dirname, "..", "backend", "static");
  if (fs.existsSync(rootBackendStatic)) {
    return rootBackendStatic;
  }
  return embeddedDist;
}

function startStaticServer() {
  return new Promise((resolve, reject) => {
    const staticDir = getStaticDir();

    staticServer = http.createServer((req, res) => {
      const cleanUrl = req.url.split("?")[0].split("#")[0];
      let filePath = path.join(staticDir, cleanUrl);

      // Security check: ensure path is within staticDir
      if (!filePath.startsWith(staticDir)) {
        res.statusCode = 403;
        res.end("Forbidden");
        return;
      }

      fs.stat(filePath, (err, stats) => {
        // If file exists and is a file, serve it
        if (!err && stats.isFile()) {
          const ext = path.extname(filePath).toLowerCase();
          const contentType = MIME_TYPES[ext] || "application/octet-stream";
          res.setHeader("Content-Type", contentType);
          fs.createReadStream(filePath).pipe(res);
        } else {
          // SPA fallback: serve index.html for all client-side routes
          const indexPath = path.join(staticDir, "index.html");
          if (fs.existsSync(indexPath)) {
            res.setHeader("Content-Type", "text/html; charset=utf-8");
            fs.createReadStream(indexPath).pipe(res);
          } else {
            res.statusCode = 404;
            res.end("ForensiRansom AI UI bundle not found. Please run npm run build.");
          }
        }
      });
    });

    staticServer.listen(0, "127.0.0.1", () => {
      serverPort = staticServer.address().port;
      console.log(`ForensiRansom AI desktop UI server listening on http://127.0.0.1:${serverPort}`);
      resolve(serverPort);
    });

    staticServer.on("error", (err) => {
      reject(err);
    });
  });
}

function createMainWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 900,
    minWidth: 1080,
    minHeight: 720,
    title: "ForensiRansom AI — Digital Forensic Investigation & Ransomware Detection",
    backgroundColor: "#0b1329",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  const appUrl = `http://127.0.0.1:${port}/`;
  mainWindow.loadURL(appUrl);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http:") || url.startsWith("https:")) {
      shell.openExternal(url);
    }
    return { action: "deny" };
  });

  const menuTemplate = [
    {
      label: "File",
      submenu: [
        {
          label: "Reload Interface",
          accelerator: "CmdOrCtrl+R",
          click: () => mainWindow.reload()
        },
        { type: "separator" },
        {
          label: "Exit",
          accelerator: "CmdOrCtrl+Q",
          click: () => app.quit()
        }
      ]
    },
    {
      label: "Backend",
      submenu: [
        {
          label: "Switch to Production Cloud (Render)",
          click: () => {
            mainWindow.webContents.executeJavaScript(
              `localStorage.removeItem("forensiransom_backend_url"); window.location.reload();`
            );
          }
        },
        {
          label: "Switch to Local Server (127.0.0.1:8000)",
          click: () => {
            mainWindow.webContents.executeJavaScript(
              `localStorage.setItem("forensiransom_backend_url", "http://127.0.0.1:8000"); window.location.reload();`
            );
          }
        },
        { type: "separator" },
        {
          label: "Test Backend Health",
          click: async () => {
            try {
              const res = await fetch("https://intelligent-ransomeware-detection-using-jmsr.onrender.com/health");
              const ok = res.ok;
              dialog.showMessageBox(mainWindow, {
                type: ok ? "info" : "warning",
                title: "Render Cloud Health",
                message: ok ? "Render Cloud Backend is ONLINE and healthy!" : "Render Backend returned non-200 status."
              });
            } catch (err) {
              dialog.showMessageBox(mainWindow, {
                type: "error",
                title: "Render Cloud Status",
                message: `Connection failed: ${err.message}`
              });
            }
          }
        }
      ]
    },
    {
      label: "View",
      submenu: [
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
        {
          label: "Toggle Developer Tools",
          accelerator: "F12",
          click: () => mainWindow.webContents.toggleDevTools()
        }
      ]
    },
    {
      label: "Help",
      submenu: [
        {
          label: "MITRE ATT&CK Framework",
          click: () => shell.openExternal("https://attack.mitre.org/")
        },
        {
          label: "CISA StopRansomware",
          click: () => shell.openExternal("https://www.cisa.gov/stopransomware")
        },
        { type: "separator" },
        {
          label: "About ForensiRansom AI",
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: "info",
              title: "About ForensiRansom AI",
              message: "ForensiRansom AI — Digital Forensic Investigation & Ransomware Detection\nVersion: 1.0.0\nInvestigator Edition (Windows Desktop Application)",
              detail: "AI-powered digital memory forensics, YARA pattern matching, dynamic risk assessment, and incident response recommendations."
            });
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  try {
    const port = await startStaticServer();
    createMainWindow(port);
  } catch (err) {
    console.error("Failed to start ForensiRansom AI desktop application:", err);
    app.quit();
  }

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0 && serverPort) {
      createMainWindow(serverPort);
    }
  });
});

app.on("window-all-closed", () => {
  if (staticServer) {
    staticServer.close();
  }
  if (process.platform !== "darwin") {
    app.quit();
  }
});
