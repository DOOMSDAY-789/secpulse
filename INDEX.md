# SecPulse index

Start here. Read in this order, then stop and work:
1. notes/handover.md: where things stand
2. notes/decisions.md: rules and why (don't break these)
3. notes/tasks.md: what to do next; move your task to "Doing", then to "Done" with the date

(notes/ is on this PC only, not on GitHub. Long-range plan: notes/roadmap.md.)

## Files
| File | What it is |
|---|---|
| index.html | The whole page: layout, styles, tabs |
| app.js | Screen logic: tabs, cards, settings, buttons |
| feeds.js | Data: loads HIBP / CISA / NVD, filters, help links, "Get the fix", breach advice, checklist. Shared by app, check and tests |
| pwned.js | Password leak check (k-anonymity) |
| ads.js | Android ads (AdMob): banner + watch-an-ad. Test ads switch is at the top |
| sw.js | Offline cache (bump CACHE on every change) |
| check.mjs | The PC's 3-hourly check that pushes news to ntfy |
| check-config.json | Settings for check.mjs, incl. the ntfy topic. Private, not on GitHub |
| test.mjs | Self-test, run with npm test |
| main.js | Windows app (Electron) window |
| apk.mjs | Builds the Android APK (npm run apk) |
| privacy.html | Privacy policy, live on the website |
| manifest.webmanifest, icon-*.png | Install name and icons |
| package.json | Scripts, version, and build.files (the files that go into the apk and exe) |
| capacitor.config.json | Android app ID and name |
| INSTALL-ON-PHONE.md | How Ryan installs each version |

## Folders
| Folder | What it is | Edit? |
|---|---|---|
| notes/ | Handover, decisions, tasks, roadmap | Yes |
| android/ | Android project. Hand-edited: app/build.gradle (version), app/src/main/AndroidManifest.xml, res/values/strings.xml (AdMob app ID), app icons | Only those files |
| dist/ | Built exe and apk | No, it's rebuilt |
| www/ | Copy of the web files for the APK | No, apk.mjs rebuilds it |
| node_modules/ | Installed packages | No |
