import { pwnedCount } from './pwned.js';
import {
  DEFAULTS, SOURCES, loadBreaches, loadKev, loadNvd, loadNvdKev, cvss, idOf, filter, isNew, summary, ntfy,
  cveLinks, kevLinks, breachLinks, checklist, day,
} from './feeds.js';

const $ = (s) => document.querySelector(s);
const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode: just don't remember */ } },
};
const randomHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
const today = () => day(new Date().toISOString());

const settings = Object.assign({ ...DEFAULTS, topic: `secpulse-${randomHex(6)}`, checklist: false }, store.get('settings', {}));
store.set('settings', settings); // keeps the random topic stable
const seen = store.get('seen', {}); // { breaches: [Name], kev: [cveID], nvd: [cveID] }
const ticks = store.get('ticks', {}); // experimental checklist: { cveId: 'YYYY-MM-DD' ticked }
const data = { breaches: [], kev: [], nvd: [], nvdKev: null };
const loaders = { breaches: loadBreaches, kev: loadKev, nvd: () => loadNvd(settings.stack) };
let nvdDone = Promise.resolve(); // last NVD load, so the checklist can wait out NVD's rate limit
let nvdLastAt = 0;

// Builds elements from text only. Third-party data never goes through innerHTML.
function el(tag, props = {}, ...kids) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...kids.filter((k) => k != null && k !== false && k !== ''));
  return e;
}
const tag = (text, cls = '') => el('span', { className: `tag ${cls}`, textContent: text });
const link = (href, text, cls = '') => el('a', { href, textContent: text, target: '_blank', rel: 'noopener', className: cls });
const links = (list) => el('div', { className: 'links' }, ...list.map((l) => link(l.url, l.label, 'btn')));
const plain = (html) => new DOMParser().parseFromString(html || '', 'text/html').body.textContent; // inert parse, no scripts run
const trim = (s, n) => (s.length > n ? `${s.slice(0, n)}…` : s);
const english = (c) => c.descriptions.find((d) => d.lang === 'en')?.value || '';

function say(id, text, err = false, extra = []) {
  $(`#${id}-msg`).replaceChildren(text ? el('div', { className: `msg${err ? ' err' : ''}` }, text, extra.length > 0 && links(extra)) : '');
}

const breachAdvice = () => el('details', {},
  el('summary', { textContent: 'What to do' }),
  el('ol', {},
    el('li', { textContent: 'If you had an account there, change that password, and anywhere you reused it.' }),
    el('li', { textContent: 'Turn on 2-step login for your email and important accounts.' }),
    el('li', { textContent: 'Expect phishing emails that use the leaked details. Don\'t click links in them.' })),
  links([{ label: '2-step login guide (NCSC)', url: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/activate-2-step-verification-on-your-email' }]));

const cards = {
  breaches: (b) => el('div', { className: 'card' },
    el('b', {}, isNew(seen, 'breaches', b.Name) && tag('NEW', 'new'), `${b.Title}${b.Domain ? ` (${b.Domain})` : ''}`),
    el('div', { className: 'meta', textContent: `Added ${day(b.AddedDate)} · breached ${b.BreachDate} · ${b.PwnCount.toLocaleString()} accounts${b.IsVerified ? '' : ' · unverified'}` }),
    el('div', { className: 'meta', textContent: `Leaked: ${b.DataClasses.join(', ')}` }),
    el('div', { textContent: trim(plain(b.Description), 280) }),
    links(breachLinks(b)),
    breachAdvice()),
  kev: (v) => el('div', { className: 'card' },
    el('b', {}, isNew(seen, 'kev', v.cveID) && tag('NEW', 'new'), v.knownRansomwareCampaignUse === 'Known' && tag('RANSOMWARE', 'Known'), `${v.vendorProject} ${v.product}`),
    el('div', { textContent: `${v.cveID} ${v.vulnerabilityName}` }),
    el('div', { className: 'meta', textContent: `Added ${v.dateAdded} · fix by ${v.dueDate}` }),
    el('div', { className: 'meta', textContent: trim(v.requiredAction, 160) }),
    links(kevLinks(v))),
  nvd: (c) => {
    const { score, sev } = cvss(c);
    return el('div', { className: 'card' },
      el('b', {}, isNew(seen, 'nvd', c.id) && tag('NEW', 'new'), tag(`${sev} ${score}`, sev), c.id),
      el('div', { className: 'meta', textContent: `Published ${day(c.published)}` }),
      el('div', { textContent: trim(english(c), 300) }),
      links(cveLinks(c)));
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
function loadAll() {
  nvdDone = load('nvd').finally(() => { nvdLastAt = Date.now(); });
  return Promise.all([load('breaches'), load('kev'), nvdDone]);
}

// ---------- experimental patch checklist ----------
const STATUS = {
  pending: ['🔴', 'No fix link yet'], unchecked: ['⚪', 'Not checked by NVD: open the links to see'],
  semi: ['🟡', 'Advisory or workaround only'], patched: ['🟢', 'Patch available'],
};

function renderChecklist() {
  if (!data.nvdKev) return;
  const rows = checklist([...data.nvdKev, ...filter('nvd', data.nvd, settings)], ticks, today());
  const count = (s) => rows.filter((r) => !r.ticked && r.status === s).length;
  say('checklist', `${rows.length} items · open: 🔴 ${count('pending')} ⚪ ${count('unchecked')} 🟡 ${count('semi')} 🟢 ${count('patched')} · ticked ${rows.filter((r) => r.ticked).length}`);
  $('#checklist-list').replaceChildren(...rows.map((r) => {
    const box = el('input', { type: 'checkbox', checked: !!r.ticked });
    box.addEventListener('change', () => {
      if (box.checked) ticks[r.id] = today(); else delete ticks[r.id];
      store.set('ticks', ticks);
      renderChecklist();
    });
    const [icon, label] = STATUS[r.status];
    return el('div', { className: `card${r.ticked ? ' done' : ''}` },
      el('b', {}, `${icon} `, r.kevAdded && tag('EXPLOITED', 'Known'), r.overdue && tag('OVERDUE', 'CRITICAL'), r.id),
      el('div', { className: 'meta', textContent: `${label} · published ${r.published}${r.kevAdded ? ` · CISA added ${r.kevAdded}` : ''}${r.kevDue ? ` · CISA fix-by ${r.kevDue}` : ''}` }),
      el('div', { textContent: trim(english(r.cve), 160) }),
      links(cveLinks(r.cve)),
      el('label', { className: 'tick' }, box, r.ticked ? ` I've patched this (ticked ${r.ticked})` : " I've patched this"));
  }));
}

async function loadChecklist() {
  $('#checklist-list').replaceChildren();
  try {
    await nvdDone;
    const wait = nvdLastAt + 31000 - Date.now(); // NVD allows 5 requests per 30 s; the main feed just used 3
    if (wait > 0) { say('checklist', `Waiting ${Math.ceil(wait / 1000)} s for NVD's rate limit…`); await new Promise((r) => setTimeout(r, wait)); }
    say('checklist', 'Loading…');
    data.nvdKev = await loadNvdKev(settings.stack);
    nvdLastAt = Date.now();
    renderChecklist();
  } catch (e) { say('checklist', e.message, true); }
}

function applyExperimental() {
  $('#nav-checklist').hidden = !settings.checklist;
  if (!settings.checklist && store.get('tab') === 'checklist') showTab('more');
}

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
    if (n) say('pw', `Leaked ${n.toLocaleString()} times. Stop using this password anywhere.`, true,
      [{ label: 'How to pick a strong one (NCSC)', url: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/three-random-words' }]);
    else say('pw', 'Not found in any known leak. Good, but that does not prove it is strong.');
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
    if (key === 'stack') { render('kev'); nvdDone = load('nvd').finally(() => { nvdLastAt = Date.now(); }); data.nvdKev = null; }
    if (key === 'severity') { render('nvd'); renderChecklist(); }
  });
}
$('#exp-checklist').checked = settings.checklist;
$('#exp-checklist').addEventListener('change', (e) => {
  settings.checklist = e.target.checked;
  store.set('settings', settings);
  applyExperimental();
});

function showTab(name) {
  document.querySelectorAll('main > section').forEach((s) => { s.hidden = s.id !== `tab-${name}`; });
  document.querySelectorAll('nav button').forEach((b) => b.setAttribute('aria-selected', b.dataset.tab === name));
  store.set('tab', name);
  if (name === 'checklist' && !data.nvdKev) loadChecklist();
}
document.querySelectorAll('nav button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
$('#refresh').addEventListener('click', () => { data.nvdKev = null; loadAll(); if (store.get('tab') === 'checklist') loadChecklist(); });

loadAll();
applyExperimental();
const startTab = store.get('tab', 'breaches');
showTab(startTab === 'alerts' ? 'more' : startTab);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => { /* file:// or http on LAN: no offline mode */ });
