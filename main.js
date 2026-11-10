// Windows desktop version: the same app files in their own window. Try: npm run app. Build the .exe: npm run exe
import { app, BrowserWindow, shell, session } from 'electron';
import { fileURLToPath } from 'node:url';

const here = (f) => fileURLToPath(new URL(f, import.meta.url));

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 480, height: 900, title: 'SecPulse', backgroundColor: '#0f172a', autoHideMenuBar: true, icon: here('icon-512.png') });
  // CVE links open in the normal browser, never inside the app window.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  // The window only ever shows the app's own page: a link or file dropped on it can't replace it with a look-alike.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  // The app needs no camera, microphone, location or notifications, so every such request is refused.
  session.defaultSession.setPermissionRequestHandler((contents, permission, allow) => allow(false));
  win.loadFile(here('index.html'));
});
app.on('window-all-closed', () => app.quit());
