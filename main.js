// Windows desktop version: the same app files in their own window. Try: npm run app. Build the .exe: npm run exe
import { app, BrowserWindow, shell } from 'electron';
import { fileURLToPath } from 'node:url';

const here = (f) => fileURLToPath(new URL(f, import.meta.url));

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 480, height: 900, title: 'SecPulse', backgroundColor: '#0f172a', autoHideMenuBar: true, icon: here('icon-512.png') });
  // CVE links open in the normal browser, never inside the app window.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.loadFile(here('index.html'));
});
app.on('window-all-closed', () => app.quit());
