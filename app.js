import { pwnedCount } from './pwned.js';
import { DEFAULTS, SOURCES, loadBreaches, loadKev, loadNvd, cvss, idOf, filter, isNew, summary, ntfy } from './feeds.js';

const $ = (s) => document.querySelector(s);
const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode: just don't remember */ } },
};
const randomHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');

const settings = Object.assign({ ...DEFAULTS, topic: `secpulse-${randomHex(6)}` }, store.get('settings', {}));
store.set('settings', settings); // keeps the random topic stable
const seen = store.get('seen', {}); // { breaches: [Name], kev: [cveID], nvd: [cveID] }
const data = { breaches: [], kev: [], nvd: [] };
const loaders = { breaches: loadBreaches, kev: loadKev, nvd: () => loadNvd(settings.stack) };
const day = (iso) => (iso || '').slice(0, 10);

// Builds elements from text only. Third-party data never goes through innerHTML.
function el(tag, props = {}, ...kids) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...kids.filter((k) => k != null && k !== false && k !== ''));
  return e;
}
const tag = (text, cls = '') => el('span', { className: `tag ${cls}`, textContent: text });
const link = (href, text) => el('a', { href, textContent: text, target: '_blank', rel: 'noopener' });
const plain = (html) => new DOMParser().parseFromString(html || '', 'text/html').body.textContent; // inert parse, no scripts run
const trim = (s, n) => (s.length > n ? `${s.slice(0, n)}…` : s);

function say(id, text, err = false) {
  $(`#${id}-msg`).replaceChildren(text ? el('div', { className: `msg${err ? ' err' : ''}`, textContent: text }) : '');
}

const cards = {
  breaches: (b) => el('div', { className: 'card' },
    el('b', {}, isNew(seen, 'breaches', b.Name) && tag('NEW', 'new'), `${b.Title}${b.Domain ? ` (${b.Domain})` : ''}`),
    el('div', { className: 'meta', textContent: `Added ${day(b.AddedDate)} · breached ${b.BreachDate} · ${b.PwnCount.toLocaleString()} accounts${b.IsVerified ? '' : ' · unverified'}` }),
    el('div', { className: 'meta', textContent: `Leaked: ${b.DataClasses.join(', ')}` }),
    el('div', { textContent: trim(plain(b.Description), 280) })),
  kev: (v) => el('div', { className: 'card' },
    el('b', {}, isNew(seen, 'kev', v.cveID) && tag('NEW', 'new'), v.knownRansomwareCampaignUse === 'Known' && tag('RANSOMWARE', 'Known'), `${v.vendorProject} ${v.product}`),
    el('div', {}, link(`https://nvd.nist.gov/vuln/detail/${v.cveID}`, v.cveID), ` ${v.vulnerabilityName}`),
    el('div', { className: 'meta', textContent: `Added ${v.dateAdded} · fix by ${v.dueDate}` }),
    el('div', { className: 'meta', textContent: trim(v.requiredAction, 160) })),
  nvd: (c) => {
    const { score, sev } = cvss(c);
    return el('div', { className: 'card' },
      el('b', {}, isNew(seen, 'nvd', c.id) && tag('NEW', 'new'), tag(`${sev} ${score}`, sev), link(`https://nvd.nist.gov/vuln/detail/${c.id}`, c.id)),
      el('div', { className: 'meta', textContent: `Published ${day(c.published)}` }),
      el('div', { textContent: trim(c.descriptions.find((d) => d.lang === 'en')?.value || '', 300) }));
  },
};

function render(src) {
  const items = filter(src, data[src], settings);
  const fresh = items.filter((x) => isNew(seen, src, idOf[src](x))).length;
  $(`#${src}-list`).replaceChildren(...items.slice(0, 100).map(cards[src]));
  say(src, `${items.length} shown${items.length > 100 ? ' (first 100)' : ''}${fresh ? ` · ${fresh} new since you last marked read` : ''}`);
}

async function load(src) {
  say(src, 'Loading…');
  try {
    data[src] = await loaders[src]();
    if (!seen[src]) { seen[src] = data[src].map(idOf[src]); store.set('seen', seen); } // first run: don't call everything new
    render(src);
  } catch (e) {
    $(`#${src}-list`).replaceChildren();
    say(src, e.message, true);
  }
}
const loadAll = () => Promise.all(SOURCES.map(load));

// ---------- password ----------
$('#pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#pw');
  const pw = input.value;
  input.value = ''; // don't leave it sitting in the field
  if (!crypto.subtle) return say('pw', 'The password check only works when the app is opened over https (or on localhost).', true);
  say('pw', 'Checking…');
  try {
    const n = await pwnedCount(pw);
    say('pw', n ? `Leaked ${n.toLocaleString()} times. Stop using this password anywhere.` : 'Not found in any known leak. Good, but that does not prove it is strong.', n > 0);
  } catch (err) { say('pw', err.message, true); }
});

$('#selfcheck').addEventListener('click', async () => {
  if (!crypto.subtle) return say('pw', 'Self-check failed: open the app over https (or on localhost).', true);
  try {
    const n = await pwnedCount('password');
    say('pw', n > 1000 ? `Self-check passed: "password" is known leaked (${n.toLocaleString()} times).` : `Self-check failed: got ${n}.`, n <= 1000);
  } catch (err) { say('pw', `Self-check failed: ${err.message}`, true); }
});

// ---------- alerts ----------
$('#test-push').addEventListener('click', async () => {
  try { await ntfy(settings.topic, 'SecPulse test', 'If you can read this on your phone, alerts work.'); say('alerts', `Sent to topic ${settings.topic}.`); } catch (e) { say('alerts', e.message, true); }
});

$('#push-new').addEventListener('click', async () => {
  const lines = summary(data, settings, seen);
  try {
    if (lines.length) await ntfy(settings.topic, `SecPulse: ${lines.length} update(s)`, lines.join('\n'));
    for (const src of SOURCES) if (data[src].length) seen[src] = data[src].map(idOf[src]);
    store.set('seen', seen);
    SOURCES.forEach(render);
    say('alerts', lines.length ? `Pushed:\n${lines.join('\n')}` : 'Nothing new. All marked read.');
  } catch (e) { say('alerts', e.message, true); }
});

// ---------- settings + tabs ----------
for (const key of ['watch', 'stack', 'severity', 'topic']) {
  const input = $(`#${key}`);
  input.value = settings[key];
  input.addEventListener('change', () => {
    settings[key] = input.value.trim();
    store.set('settings', settings);
    if (key === 'watch') render('breaches');
    if (key === 'stack') { render('kev'); load('nvd'); }
    if (key === 'severity') render('nvd');
  });
}

function showTab(name) {
  document.querySelectorAll('main > section').forEach((s) => { s.hidden = s.id !== `tab-${name}`; });
  document.querySelectorAll('nav button').forEach((b) => b.setAttribute('aria-selected', b.dataset.tab === name));
  store.set('tab', name);
}
document.querySelectorAll('nav button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
showTab(store.get('tab', 'breaches'));

$('#refresh').addEventListener('click', loadAll);
loadAll();
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => { /* file:// or http on LAN: no offline mode */ });
