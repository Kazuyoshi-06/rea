/* oxlint-disable -- fixture is CommonJS on purpose: it is packed as-is into app.asar */
// lodash 4.17.20: CVE-2021-23337 (template command injection)
const { app, BrowserWindow } = require("electron");
const _ = require("lodash");
const ms = require("ms");

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 400, height: 300 });
  win.loadURL(
    "data:text/html," + encodeURIComponent(_.join(["REA", ms(60000)], " ")),
  );
});
