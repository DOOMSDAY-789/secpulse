# SecPulse: how to get it on your phone

SecPulse is a web app (PWA). It installs from the browser like an app, with an icon and no browser bars.

## The catch: it has to be on an https address
A phone will only install it, and the password check only works, when the app comes from an **https://** address.
Your PC serves it as `http://localhost:8080`, and that only counts as safe on the PC itself.
So it has to be put online once. The free, boring way is **GitHub Pages** on your GitHub account
(about 5 minutes; Claude can do it once you say yes). It's a static page: no server, no accounts, no data collected.

## Android (Chrome)
1. Open the https address in **Chrome**.
2. Tap **⋮** (top right), then **Install app** (or **Add to Home screen**).
3. Open SecPulse from the new icon.

## iPhone (Safari)
1. Open the https address in **Safari** (it has to be Safari).
2. Tap **Share** (square with an arrow), then **Add to Home Screen**, then **Add**.
3. Open SecPulse from the new icon.

## Phone alerts (optional)
1. Install the free **ntfy** app (Play Store / App Store). No account needed.
2. In SecPulse go to **Alerts** and copy the topic name (it looks like `secpulse-1a2b3c...`).
3. In ntfy tap **+**, paste the topic, **Subscribe**.
4. In SecPulse tap **Send test alert**. It should buzz your phone.
5. Tap **Push what's new and mark read** whenever you want a summary sent.

Anyone who knows the topic name can read the alerts, so keep the random one. They only ever contain public breach and CVE news.

## Use it on the PC right now
In a terminal: `cd C:\Users\Entro\Documents\SecPulse` then `npm start`, and open http://localhost:8080 in Chrome.
Chrome shows an install icon in the address bar, so it works as a desktop app too.
Self-test for the password check: `npm test`.

## What it does NOT do (yet)
- **Check while it's closed.** A web app can't wake itself up. A scheduled check needs something always on
  (a Windows scheduled task on your PC, or a free GitHub scheduled job). Ask if you want that.
- **.apk / .exe / iPhone app files.** An Android .apk (Capacitor) and a Windows .exe (Electron) can be built on this PC.
  A real iPhone app file (.ipa) needs a Mac, or a paid cloud build service plus an Apple developer account ($99/year).
  On iPhone, Add to Home Screen above is the practical route.
