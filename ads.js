// Ads: Android app only (Google AdMob through Capacitor). The web app and the Windows .exe never load this plugin.
// TESTING = Google's demo ads, which earn nothing and are safe to tap. Set it to false only after putting the real
// banner unit ID from your AdMob account in BANNER_ID, and the real app ID in android/app/src/main/res/values/strings.xml.
const TESTING = true;
const BANNER_ID = '';
const AD_TABS = new Set(['breaches', 'vulns', 'checklist']); // never on the Password tab or More

const cap = window.Capacitor;
const AdMob = cap?.isNativePlatform?.() && (TESTING || BANNER_ID) ? cap.registerPlugin('AdMob') : null;
let ready = null; // Promise<boolean>: consent asked + SDK started
let shown = false;
let height = 0;
let current = '';

const pad = () => document.body.style.setProperty('--ad', `${AD_TABS.has(current) ? height : 0}px`);

async function start() {
  try { // Google's consent popup (UK/EU) has to come before any ad request
    let info = await AdMob.requestConsentInfo();
    if (info.isConsentFormAvailable && info.status === 'REQUIRED') info = await AdMob.showConsentForm();
    document.querySelector('#ad-privacy').hidden = info.privacyOptionsRequirementStatus !== 'REQUIRED';
    if (!info.canRequestAds) return false;
  } catch {
    if (!TESTING) return false; // no consent answer, no real ads. The demo app ID has no consent form, so tests carry on.
  }
  await AdMob.initialize();
  AdMob.addListener('bannerAdSizeChanged', (s) => { if (s.height) height = s.height; pad(); });
  return true;
}

export async function bannerFor(tab) {
  if (!AdMob) return;
  current = tab;
  ready ??= start().catch(() => false);
  if (!(await ready)) return;
  pad();
  const want = AD_TABS.has(current); // the tab may have changed while consent was showing
  try {
    if (want && !shown) {
      shown = true;
      await AdMob.showBanner({ adId: BANNER_ID, isTesting: TESTING, adSize: 'ADAPTIVE_BANNER', position: 'BOTTOM_CENTER' });
    } else if (want) await AdMob.resumeBanner();
    else if (shown) await AdMob.hideBanner();
  } catch { /* no fill or offline: the app works without the banner */ }
}

export const privacyChoices = () => AdMob?.showPrivacyOptionsForm().catch(() => {});
