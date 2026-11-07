# SecPulse: how to install it

**Phone address:** https://doomsday-789.github.io/secpulse/

## Android (Chrome)
1. Open the address above in **Chrome**.
2. Tap **⋮** (top right), then **Install app** (or **Add to Home screen**).
3. Open SecPulse from the new icon.

### Or the Android app file (APK)
`dist\SecPulse.apk` in this folder (4 MB).
1. Copy it to the phone (USB cable, Google Drive, or email it to yourself).
2. Tap it on the phone. Android asks to allow installs from that app (Files / Drive / Gmail): allow it, then **Install**.
3. If Play Protect warns "unknown developer", tap **More details**, then **Install anyway**. It's yours; it just isn't from the Play Store.
It asks for internet access only. Rebuild after app changes with `npm run apk`.

## iPhone (Safari)
1. Open the address above in **Safari** (it has to be Safari).
2. Tap **Share** (square with an arrow), then **Add to Home Screen**, then **Add**.
3. Open SecPulse from the new icon.

## Windows PC
- **The .exe:** `dist\SecPulse 1.1.0.exe` in this folder. Double-click it; nothing to install.
  The first time, Windows may say "Windows protected your PC" because the file isn't signed (signing costs money).
  Click **More info**, then **Run anyway**.
- Or open the phone address in Chrome on the PC and click the install icon in the address bar.

## Phone alerts
Your PC checks every 3 hours (Task Scheduler task "SecPulse check", no window) and sends anything new to your phone.
1. Install the free **ntfy** app (Play Store / App Store). No account needed.
2. In ntfy tap **+**, type your topic, then **Subscribe**. The topic is the `"topic"` line in `check-config.json`
   in this folder (kept off GitHub on purpose, since anyone with the name can read the alerts).
3. Test it from a terminal in this folder: `node check.mjs --test`.

Only runs while the PC is on and the F: drive is connected (your `node` lives at F:\N8N).
What it watches: `check-config.json` in this folder (topic, stack, watch, severity). `lastRun`/`lastResult` there show the last check.
The app's own **Alerts** tab has its own random topic. Paste the topic above into it to get everything on one ntfy topic.
Anyone who knows the topic name can read the alerts; they only ever contain public breach and CVE news.

## Commands (in this folder)
- `npm test`: password-check and "what's new" self-test
- `npm run check`: run the PC check now
- `npm run exe`: rebuild the .exe after changing the app
- `npm start`: serve the app at http://localhost:8080
- To update the phone version: commit and push to GitHub; the page updates within a minute.

## Not done
- **iPhone app file (.ipa):** needs a Mac, or a paid cloud build plus an Apple developer account ($99/year). Add to Home Screen is the practical route.
- **Play Store release:** the APK is debug-signed, fine for your own phones. The Play Store needs a release key and a $25 developer account.
