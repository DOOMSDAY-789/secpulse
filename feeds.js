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

export async function loadNvd(stack) {
  const end = new Date();
  const start = new Date(end - 14 * 864e5);
  const found = new Map();
  // ponytail: one request per keyword; NVD allows 5 per 30 s without an API key, so keep the stack list short.
  // No server-side cvssV3Severity filter: it only sees NVD's own scores and misses ~95% of WordPress CVEs
  // (those are scored by Wordfence etc.), so severity is filtered here from every scorer instead.
  for (const word of keywords(stack)) {
    const q = new URLSearchParams({ keywordSearch: word, pubStartDate: start.toISOString(), pubEndDate: end.toISOString(), resultsPerPage: '2000' });
    const j = await getJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?${q}`, 'NVD');
    for (const v of j.vulnerabilities) found.set(v.cve.id, v.cve);
  }
  return [...found.values()].sort((a, b) => b.published.localeCompare(a.published));
}

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

export async function ntfy(topic, title, message) {
  if (!/^[\w-]{1,64}$/.test(topic || '')) throw new Error('Set a topic first (letters, numbers, - and _ only).');
  let res;
  try {
    res = await fetch(`https://ntfy.sh/${topic}`, { method: 'POST', body: message, headers: { Title: title, Tags: 'shield' } });
  } catch { throw new Error('Could not reach ntfy.sh.'); }
  if (!res.ok) throw new Error(`ntfy answered ${res.status}.`);
}
