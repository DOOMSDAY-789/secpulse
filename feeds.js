// Feed loading, filtering and "what's new" logic. Shared by the app (app.js) and the scheduled PC check (check.mjs).

export const DEFAULTS = { watch: '', stack: 'php, wordpress, mysql', severity: 'CRITICAL' };
export const SOURCES = ['breaches', 'kev', 'nvd'];

export const keywords = (s) => (s || '').split(',').map((w) => w.trim().toLowerCase()).filter(Boolean);
const hits = (text, words) => !words.length || words.some((w) => text.toLowerCase().includes(w));

async function getJSON(url, what) {
  let res;
  try { res = await fetch(url); } catch {
    // NVD's 429 rate-limit reply has no CORS header, so a browser reports it as a network failure.
    throw new Error(`Could not reach ${what}. Either you are offline or it is rate limiting (NVD allows 5 requests per 30 s). Wait a minute and press Refresh.`);
  }
  if (!res.ok) throw new Error(`${what} answered ${res.status}${[403, 429].includes(res.status) ? ': rate limited, wait a minute and press Refresh.' : '.'}`);
  return res.json();
}

export async function loadBreaches() {
  const list = await getJSON('https://haveibeenpwned.com/api/v3/breaches', 'Have I Been Pwned');
  return list.sort((a, b) => b.AddedDate.localeCompare(a.AddedDate));
}

export async function loadKev() {
  // cisa.gov's own copy sends no CORS header; CISA's official GitHub mirror does.
  const j = await getJSON('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json', 'CISA KEV');
  return j.vulnerabilities.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
}

// ponytail: one request per keyword; NVD allows 5 per 30 s without an API key, so keep the stack list short.
async function nvdByKeyword(stack, extra) {
  const found = new Map();
  for (const word of keywords(stack)) {
    const q = new URLSearchParams({ keywordSearch: word, resultsPerPage: '2000', ...extra });
    const j = await getJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?${q}`, 'NVD');
    for (const v of j.vulnerabilities) found.set(v.cve.id, v.cve);
  }
  return [...found.values()].sort((a, b) => b.published.localeCompare(a.published));
}

// CVEs published in the last 14 days. No server-side cvssV3Severity filter: it only sees NVD's own scores and
// misses ~95% of WordPress CVEs (those are scored by Wordfence etc.), so severity is filtered here from every scorer.
export function loadNvd(stack) {
  const end = new Date();
  return nvdByKeyword(stack, { pubStartDate: new Date(end - 14 * 864e5).toISOString(), pubEndDate: end.toISOString() });
}

// NVD's copy of the CISA exploited list for the stack: tagged links plus cisaExploitAdd / cisaActionDue dates.
export const loadNvdKev = (stack) => nvdByKeyword(stack, { hasKev: '' });

// Highest score any scorer (NVD or the CNA, e.g. Wordfence) gave this CVE.
export function cvss(c) {
  const m = c.metrics || {};
  const all = [...(m.cvssMetricV40 || []), ...(m.cvssMetricV31 || []), ...(m.cvssMetricV30 || [])].map((x) => x.cvssData);
  const d = all.sort((a, b) => b.baseScore - a.baseScore)[0];
  return d ? { score: d.baseScore, sev: d.baseSeverity } : { score: 0, sev: 'UNRATED' };
}

export const idOf = { breaches: (b) => b.Name, kev: (v) => v.cveID, nvd: (c) => c.id };

export function filter(src, items, s) {
  if (src === 'breaches') return items.filter((b) => hits(`${b.Name} ${b.Title} ${b.Domain}`, keywords(s.watch)));
  if (src === 'kev') return items.filter((v) => hits(`${v.vendorProject} ${v.product} ${v.vulnerabilityName}`, keywords(s.stack)));
  return items.filter((c) => cvss(c).score >= ({ CRITICAL: 9, HIGH: 7, ANY: -1 }[s.severity] ?? 9));
}

// seen = { breaches: [ids], ... }. A source with no seen list yet has nothing "new" (the first load seeds it).
export const isNew = (seen, src, id) => !!seen[src] && !seen[src].includes(id);

// One line per source that has new, matching items. Used for the ntfy message.
export function summary(data, s, seen) {
  const label = { breaches: 'new breach(es)', kev: 'newly exploited', nvd: 'new CVE(s)' };
  const name = { breaches: (b) => b.Title, kev: (v) => `${v.cveID} ${v.product}`, nvd: (c) => `${c.id} (${cvss(c).score})` };
  const lines = [];
  for (const src of SOURCES) {
    const fresh = filter(src, data[src], s).filter((x) => isNew(seen, src, idOf[src](x)));
    if (fresh.length) lines.push(`${fresh.length} ${label[src]}: ${fresh.slice(0, 5).map(name[src]).join(', ')}${fresh.length > 5 ? ', …' : ''}`);
  }
  return lines;
}

// ---------- help links: only real http(s) links that came with the data ----------
const web = (u) => /^https?:\/\//i.test(u || '');
const nvdLink = (id) => ({ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` });
export const day = (iso) => (iso || '').slice(0, 10);

export function cveLinks(c) {
  const out = [];
  const used = new Set();
  for (const [tag, label] of [['Patch', 'Patch'], ['Vendor Advisory', 'Vendor advisory'], ['Mitigation', 'Mitigation']]) {
    let n = 0;
    for (const r of c.references || []) {
      if (n < 2 && web(r.url) && !used.has(r.url) && (r.tags || []).includes(tag)) { used.add(r.url); out.push({ label, url: r.url }); n++; }
    }
  }
  return [...out, nvdLink(c.id)];
}

export function kevLinks(v) {
  const urls = [...new Set(((v.notes || '').match(/https?:\/\/[^\s;]+/g) || []).map((u) => u.replace(/[.,)]+$/, '')))];
  const links = [];
  for (const url of urls.slice(0, 3)) {
    try {
      const label = new URL(url).hostname.replace(/^www\./, '');
      if (!links.some((l) => l.label === label)) links.push({ label, url }); // one button per site
    } catch { /* not a real URL */ }
  }
  return [...links, nvdLink(v.cveID)];
}

export const breachLinks = (b) => [{ label: 'Breach details', url: `https://haveibeenpwned.com/Breach/${encodeURIComponent(b.Name)}` }];

// ---------- "Get the fix": where to download the update ----------
const fix = (url) => ({ label: 'Get the fix', url });
const wpSearch = (kind, name) => fix(`https://wordpress.org/${kind}/search/${encodeURIComponent(name.trim())}/`);
const OFFICIAL = [ // [matches "vendor product" (KEV) or the description (NVD), official update page]
  [/^wordpress (wordpress )?core\b|^wordpress (core )?(is|before|through|versions?|prior)\b/i, 'https://wordpress.org/documentation/article/updating-wordpress/'],
  [/\bphpmyadmin\b/i, 'https://www.phpmyadmin.net/downloads/'],
  [/\bphpmailer\b/i, 'https://github.com/PHPMailer/PHPMailer/releases'],
  [/\bmysql\b/i, 'https://dev.mysql.com/downloads/mysql/'],
  [/^php( group)? php\b|^php fastcgi|^(in )?php versions?\b|^php (before|through)\b/i, 'https://www.php.net/downloads.php'],
];

export function fixLink(x) {
  if (x.cveID) { // CISA KEV entry
    const name = `${x.vendorProject} ${x.product}`;
    if (/^wordpress\b/i.test(x.vendorProject) && /plugin/i.test(x.product)) return wpSearch('plugins', x.product.replace(/\s*plugin\s*$/i, ''));
    const known = OFFICIAL.find(([re]) => re.test(name));
    if (known) return fix(known[1]);
    const vendor = ((x.notes || '').match(/https?:\/\/[^\s;]+/g) || []).map((u) => u.replace(/[.,)]+$/, ''))
      .find((u) => { try { return !/(^|\.)(cisa\.gov|nist\.gov)$/.test(new URL(u).hostname); } catch { return false; } });
    return vendor ? fix(vendor) : null;
  }
  const text = (x.descriptions || []).find((d) => d.lang === 'en')?.value || '';
  // Wordfence writes "The X plugin for WordPress", WPScan "The X WordPress plugin"
  const wp = text.match(/^The (.+?) (?:(plugin|theme)s? for WordPress|WordPress (plugin|theme)s?)\b/);
  if (wp) return wpSearch(`${wp[2] || wp[3]}s`, wp[1].split(/\s[–—:|-]\s/)[0]); // "Name – tagline": search the name only
  const known = OFFICIAL.find(([re]) => re.test(text));
  if (known) return fix(known[1]);
  const patch = (x.references || []).find((r) => web(r.url) && (r.tags || []).includes('Patch'));
  return patch ? fix(patch.url) : null;
}

// ---------- breach advice that matches what leaked ----------
const NCSC = 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online';
export function breachSteps(b) {
  const has = (...names) => names.some((n) => (b.DataClasses || []).includes(n));
  const site = b.Title || b.Name || 'that site';
  const steps = [];
  const links = [{ label: 'Am I in it? (HIBP)', url: 'https://haveibeenpwned.com/' }];
  if (b.IsStealerLog || b.IsMalware) {
    steps.push('This data was stolen by malware on people\'s own devices. Run a virus scan, then change the passwords saved in your browser.');
    links.push({ label: 'Hacked device help (NCSC)', url: 'https://www.ncsc.gov.uk/guidance/hacked-device-action-to-take' });
  }
  if (has('Passwords')) {
    steps.push(`Change your ${site} password, and every other site where you used the same one. A password manager makes a different password for each site easy.`);
    links.push({ label: 'Password managers (NCSC)', url: `${NCSC}/password-managers` });
  } else if (!b.IsStealerLog && !b.IsSpamList) steps.push('Passwords weren\'t in this leak, so changing yours there is optional.');
  if (has('Auth tokens')) steps.push(`Log out of ${site} on all devices: leaked login tokens can get in without your password.`);
  if (has('Security questions and answers')) steps.push(`Change your security questions and answers on ${site}, and anywhere you gave the same answers.`);
  if (has('Credit cards', 'Partial credit card data', 'Bank account numbers', 'Payment histories', 'Account balances')) {
    steps.push(`Check your bank and card statements for payments you don't recognise, and tell your bank straight away.${has('Credit cards') ? ' Ask for a new card.' : ''}`);
  }
  if (has('Government issued IDs', 'Passport numbers', 'Social security numbers', 'Dates of birth')) {
    steps.push('Check your credit report (free in the UK from Experian, Equifax and TransUnion) for accounts or loans you didn\'t open.');
  }
  if (has('Phone numbers')) steps.push('Expect scam texts and calls. Ask your mobile provider to put a PIN or password on your account, so nobody can move your number to their SIM.');
  if (has('Private messages', 'Email messages', 'Sexual orientations') || b.IsSensitive) {
    steps.push('Private details leaked. If someone emails demanding money to keep them quiet, don\'t reply or pay: report it.');
  }
  steps.push(`Turn on 2-step login for ${site} if it has it, and always for your email.`);
  links.push({ label: '2-step login guide (NCSC)', url: `${NCSC}/activate-2-step-verification-on-your-email` },
    { label: 'Which sites have 2-step login', url: 'https://2fa.directory/' });
  if (has('Email addresses', 'Phone numbers', 'Names') || b.IsSpamList) {
    steps.push('Expect scam emails that use the leaked details to look real. Don\'t click their links; go to the site yourself.');
    links.push({ label: 'Spotting scam emails (NCSC)', url: 'https://www.ncsc.gov.uk/guidance/phishing' });
  }
  return { steps, links };
}

// ---------- "How this affects you": one plain line per card ----------
const IMPACT = [ // [matches the bug's name or description, what an attacker gets]. First match wins, so order matters.
  [/cross-site request forgery|\bcsrf\b/i, 'trick a logged-in admin into changing settings just by getting them to click a link'],
  [/sql injection/i, 'read or change its database: user emails, password hashes, orders'],
  [/remote code execution|code injection|command injection|arbitrary (file upload|code)|unrestricted upload|deserialization/i, 'take over the server, steal its data and plant malware for visitors'],
  [/(arbitrary|limited) file deletion/i, 'delete its files, which on WordPress can hand them the whole site'],
  [/cross-site scripting|\bxss\b/i, 'run scripts in visitors\' browsers to steal logins or send them to scam pages'],
  [/verify (that a payment|the authenticity of)/i, 'send it fake requests, such as marking an order paid without paying'],
  [/arbitrary shortcode/i, 'run the site\'s built-in features without permission, which can expose private content'],
  // Wordfence: "missing capability check", "authorization bypass"; WPScan: "does not perform an authorisation check", "verify that a user"
  [/authentication bypass|improper authentication|privilege escalation|capability(,| check| or)|authori[sz](ation|e)|access control|insecure direct object|\bidor\b|(verify|check) (that|whether) (a|the) (user|requester)|restrict (access|who)|verify ownership|permission check/i, 'get in as an admin or another user, or change things only they should'],
  [/path traversal|directory traversal|file inclusion|arbitrary file (read|download)|file download|information (disclosure|exposure)|sensitive information/i, 'read private files, such as the passwords in its config files'],
  [/server-side request forgery|\bssrf\b/i, 'use the server to reach its private network'],
  [/denial of service|\bdos\b/i, 'knock it offline'],
];

// Breach (HIBP), KEV or NVD item -> one sentence, or null when the bug type isn't recognised (never guess).
export function affects(x) {
  if (x.DataClasses) {
    const has = (...n) => n.some((c) => x.DataClasses.includes(c));
    if (x.IsStealerLog || x.IsMalware) return 'If you\'re in it, malware on your own device sent your saved logins to criminals.';
    if (has('Passwords')) return 'If you had an account here, criminals may have your password and will try it on your other accounts.';
    if (has('Credit cards', 'Partial credit card data', 'Bank account numbers')) return 'If you had an account here, your card or bank details may be out there.';
    if (x.IsSpamList) return 'If your email is in it, expect more spam and scam emails.';
    return 'If you had an account here, expect scam emails and calls that use these details to look real.';
  }
  const text = x.cveID ? `${x.vulnerabilityName} ${x.shortDescription || ''}` : (x.descriptions || []).find((d) => d.lang === 'en')?.value || '';
  const hit = IMPACT.find(([re]) => re.test(text));
  return hit ? `If a website (yours, or one you use) runs this without the update, attackers can ${hit[1]}.` : null;
}

// ---------- site check: past leaks (HIBP list, on device) + Mozilla Observatory grade ----------
// "shop.com", "www.shop.com/x" or "https://shop.com" -> "shop.com"-style host, or null if it isn't a web address.
export function hostOf(input) {
  const s = (input || '').trim();
  try {
    const u = new URL(/^[a-z][\w+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    const host = u.hostname.toLowerCase();
    return /^https?:$/.test(u.protocol) && /^([a-z0-9-]+\.)+[a-z][a-z0-9-]+$/.test(host) ? host : null;
  } catch { return null; }
}

export function pastLeaks(host, breaches) {
  const h = host.replace(/^www\./, '');
  return breaches.filter((b) => { const d = (b.Domain || '').toLowerCase(); return d && (h === d || h.endsWith(`.${d}`)); });
}

// Only the host name goes to Mozilla. Scans are cached by Mozilla for a minute, so repeats are cheap.
export async function observatory(host, get = fetch) {
  let res;
  try { res = await get(`https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(host)}`, { method: 'POST' }); } catch {
    throw new Error('Could not reach Mozilla Observatory. Are you offline?');
  }
  const j = await res.json().catch(() => ({}));
  if (!res.ok || j.error || !j.grade) throw new Error(`Mozilla couldn't scan ${host}${j.message ? ` (${j.message})` : ''}. Check the spelling, or the site may be down.`);
  return j;
}

// leaks = null when the HIBP list didn't load. Leaks from the last 3 years make a site "careful"; older ones are only listed.
export function siteReport(host, scan, leaks, today) {
  const g = scan.grade[0]; // "A+" -> "A"
  const since = `${Number(today.slice(0, 4)) - 3}${today.slice(4)}`;
  const recent = (leaks || []).filter((b) => b.BreachDate >= since);
  const level = 'DEF'.includes(g) ? 'weak' : g === 'C' || recent.length ? 'careful' : 'good';
  const head = {
    good: `🟢 ${host} looks well looked after.`,
    careful: `🟡 Be careful with ${host}.`,
    weak: `🔴 ${host} has weak security. Stay away, or at least don't enter card details or a password you use anywhere else.`,
  }[level];
  const meaning = { A: 'strong protections switched on', B: 'most protections switched on', C: 'some protections missing' }[g] || 'most basic protections missing';
  const lines = [head, `Mozilla security grade ${scan.grade} (${scan.tests_passed} of ${scan.tests_quantity} checks passed): ${meaning}.`];
  if (leaks === null) lines.push('The leak list didn\'t load, so past leaks weren\'t checked. Press Refresh and try again.');
  else if (!leaks.length) lines.push('No known data leaks (Have I Been Pwned).');
  else for (const b of leaks.slice(0, 3)) lines.push(`Leaked data in ${b.BreachDate.slice(0, 4)}: ${b.DataClasses.slice(0, 4).join(', ').toLowerCase()}.`);
  lines.push('No check can prove a site is safe, and this one can\'t see whether the site runs an old PHP or WordPress version.');
  return { level, text: lines.join('\n') };
}

// ---------- experimental patch checklist ----------
// patched =NVD links to a patch; semi = only a vendor advisory or mitigation; pending = NVD tagged the links, no fix among them;
// unchecked = NVD never tagged the links (new, or "Deferred": ~95% of recent WordPress CVEs), so they say nothing either way.
// "Patched" means a fix exists, not that your own sites have it.
export function patchStatus(c) {
  const tags = new Set((c.references || []).flatMap((r) => r.tags || []));
  if (tags.has('Patch')) return 'patched';
  if (tags.has('Mitigation') || tags.has('Vendor Advisory')) return 'semi';
  return tags.size ? 'pending' : 'unchecked';
}

// ticks = { cveId: 'YYYY-MM-DD' you ticked it }. Open items first (pending, semi, patched), ticked ones last.
// Overdue = CISA's fix-by date passed in the last 30 days; older ones are all past due, so flagging them is noise.
export function checklist(items, ticks, today) {
  const order = { pending: 0, unchecked: 1, semi: 2, patched: 3 };
  const recent = day(new Date(new Date(today) - 30 * 864e5).toISOString());
  const byId = new Map();
  for (const c of items) if (!byId.has(c.id)) byId.set(c.id, c);
  return [...byId.values()].map((c) => {
    const ticked = ticks[c.id] || null;
    return { id: c.id, cve: c, status: patchStatus(c), published: day(c.published), kevAdded: c.cisaExploitAdd || null,
      kevDue: c.cisaActionDue || null, ticked, overdue: !ticked && !!c.cisaActionDue && c.cisaActionDue < today && c.cisaActionDue >= recent };
  }).sort((a, b) => (!!a.ticked - !!b.ticked) || order[a.status] - order[b.status] || b.published.localeCompare(a.published));
}

export async function ntfy(topic, title, message) {
  if (!/^[\w-]{1,64}$/.test(topic || '')) throw new Error('Set a topic first (letters, numbers, - and _ only).');
  let res;
  try {
    res = await fetch(`https://ntfy.sh/${topic}`, { method: 'POST', body: message, headers: { Title: title, Tags: 'shield' } });
  } catch { throw new Error('Could not reach ntfy.sh.'); }
  if (!res.ok) throw new Error(`ntfy answered ${res.status}.`);
}
