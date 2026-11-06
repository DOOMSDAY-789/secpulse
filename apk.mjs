// Builds the Android app: dist/SecPulse.apk.  Run: npm run apk
// Uses the JDK and Android SDK on E:\Android (change the paths here if they move).
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const ANDROID = 'E:/Android';
const jdk = fs.readdirSync(ANDROID).find((d) => d.startsWith('jdk-21'));
if (!jdk) throw new Error(`No jdk-21* folder in ${ANDROID}`);
const env = { ...process.env, JAVA_HOME: `${ANDROID}/${jdk}`, ANDROID_HOME: `${ANDROID}/sdk`, GRADLE_USER_HOME: `${ANDROID}/gradle` };
const run = (cmd, cwd = '.') => execSync(cmd, { cwd, env, stdio: 'inherit' });

// Same web files the .exe ships (package.json "build.files"), minus the Electron-only ones.
const { build } = JSON.parse(fs.readFileSync('package.json', 'utf8'));
fs.rmSync('www', { recursive: true, force: true });
fs.mkdirSync('www');
for (const f of build.files.filter((f) => !['main.js', 'package.json'].includes(f))) fs.copyFileSync(f, `www/${f}`);

if (!fs.existsSync('android')) run('npx cap add android');
fs.writeFileSync('android/local.properties', `sdk.dir=${env.ANDROID_HOME}\n`);
run('npx cap sync android');
// ponytail: debug-signed APK, fine for installing on your own phone; the Play Store would need a release key.
run(`"${path.resolve('android/gradlew.bat')}" assembleDebug`, 'android'); // full path: cmd may not search the current folder
fs.mkdirSync('dist', { recursive: true });
fs.copyFileSync('android/app/build/outputs/apk/debug/app-debug.apk', 'dist/SecPulse.apk');
console.log('Built dist/SecPulse.apk');
