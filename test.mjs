// Self-check for the password leak check. Run: node test.mjs
import assert from 'node:assert/strict';
import { sha1Hex, countInRange, pwnedCount } from './pwned.js';
import { cvss, summary, filter, cveLinks, kevLinks, breachLinks, patchStatus, checklist, fixLink, breachSteps, affects, hostOf, pastLeaks, observatory, siteReport } from './feeds.js';

// Known SHA-1 of "password".
assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');

const body = 'AAAA0000000000000000000000000000000:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nFFFF0000000000000000000000000000000:7';
assert.equal(countInRange(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 42);
assert.equal(countInRange(body, 'AAAA0000000000000000000000000000000'), 0, 'padding row counts as not found');
assert.equal(countInRange(body, 'NOTTHERE'), 0);

// Only the 5-char prefix goes over the wire; the password and the rest of the hash never do.
const secret = 'Tr0ub4dor&3-zebra';
const hash = await sha1Hex(secret);
let sent = '';
const fake = async (url, opts) => { sent = url + JSON.stringify(opts); return { ok: true, text: async () => body }; };
assert.equal(await pwnedCount(secret, fake), 0);
assert.ok(sent.startsWith(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}{`), sent);
assert.ok(!sent.includes(secret), 'password must not be sent');
assert.ok(!sent.includes(hash.slice(5, 15)), 'hash suffix must not be sent');

// "What's new" logic used by the alerts and the scheduled PC check.
const crit = { id: 'CVE-1', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 6.1, baseSeverity: 'MEDIUM' } }, { cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }] } };
const low = { id: 'CVE-2', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5, baseSeverity: 'MEDIUM' } }] } };
assert.deepEqual(cvss(crit), { score: 9.8, sev: 'CRITICAL' }, 'takes the highest score from any scorer');
assert.equal(cvss({ id: 'x' }).score, 0);
const feed = {
  breaches: [{ Name: 'Old', Title: 'Old', Domain: 'old.com' }, { Name: 'Fresh', Title: 'Fresh Co', Domain: 'fresh.com' }],
  kev: [{ cveID: 'CVE-9', vendorProject: 'WordPress', product: 'Core', vulnerabilityName: 'x' }, { cveID: 'CVE-8', vendorProject: 'Cisco', product: 'IOS', vulnerabilityName: 'y' }],
  nvd: [crit, low],
};
const s = { watch: '', stack: 'wordpress', severity: 'CRITICAL' };
assert.deepEqual(summary(feed, s, {}), [], 'nothing is new before the first seed');
const lines = summary(feed, s, { breaches: ['Old'], kev: [], nvd: [] });
assert.equal(lines.length, 3);
assert.match(lines[0], /^1 new breach\(es\): Fresh Co$/);
assert.match(lines[1], /^1 newly exploited: CVE-9 Core$/, 'Cisco is outside the stack filter');
assert.match(lines[2], /^1 new CVE\(s\): CVE-1 \(9\.8\)$/, 'medium CVE is below the severity filter');
assert.deepEqual(summary(feed, s, { breaches: ['Old', 'Fresh'], kev: ['CVE-9', 'CVE-8'], nvd: ['CVE-1', 'CVE-2'] }), [], 'all seen');
assert.equal(filter('breaches', feed.breaches, { ...s, watch: 'fresh.com' }).length, 1);

// Help links: only real http(s) links from the feeds, labelled by NVD's tags.
const refCve = { id: 'CVE-7', references: [
  { url: 'https://example.com/fix', tags: ['Patch'] },
  { url: 'https://example.com/fix', tags: ['Patch', 'Vendor Advisory'] },
  { url: 'javascript:alert(1)', tags: ['Patch'] },
  { url: 'https://vendor.example/advisory', tags: ['Vendor Advisory'] },
  { url: 'https://blog.example/post', tags: ['Third Party Advisory'] },
] };
assert.deepEqual(cveLinks(refCve).map((l) => `${l.label} ${l.url}`), [
  'Patch https://example.com/fix',
  'Vendor advisory https://vendor.example/advisory',
  'NVD https://nvd.nist.gov/vuln/detail/CVE-7',
], 'dedupes, drops non-web links and untagged blogs, NVD last');
assert.deepEqual(kevLinks({ cveID: 'CVE-8', notes: 'See: https://www.php.net/ ; https://www.cisa.gov/a/b. Also javascript:x' }).map((l) => l.label),
  ['php.net', 'cisa.gov', 'NVD'], 'notes links by site name, trailing dot trimmed');
assert.equal(breachLinks({ Name: 'Big Co' })[0].url, 'https://haveibeenpwned.com/Breach/Big%20Co');

// Patch status from tags.
assert.equal(patchStatus(refCve), 'patched');
assert.equal(patchStatus({ references: [{ url: 'https://x', tags: ['Mitigation'] }] }), 'semi');
assert.equal(patchStatus({ references: [{ url: 'https://x', tags: ['Vendor Advisory'] }] }), 'semi');
assert.equal(patchStatus({ references: [{ url: 'https://x', tags: ['Exploit'] }] }), 'pending');
assert.equal(patchStatus({ vulnStatus: 'Deferred', references: [{ url: 'https://x' }] }), 'unchecked', 'untagged links say nothing');

// Checklist: open items first (pending, then semi, then patched), ticked at the bottom, overdue CISA dates flagged.
const rows = checklist([
  { id: 'A', published: '2026-11-01', references: [{ url: 'https://x', tags: ['Patch'] }] },
  { id: 'B', published: '2026-11-02', references: [] },
  { id: 'C', published: '2026-10-01', cisaExploitAdd: '2026-10-29', cisaActionDue: '2026-11-01', references: [{ url: 'https://x', tags: ['Mitigation'] }] },
  { id: 'D', published: '2026-11-03', references: [] },
  { id: 'B', published: '2026-11-02', references: [] },
], { D: '2026-11-07' }, '2026-11-07');
assert.deepEqual(rows.map((r) => r.id), ['B', 'C', 'A', 'D'], 'deduped and ordered');
assert.equal(rows.find((r) => r.id === 'C').overdue, true);
assert.equal(rows.find((r) => r.id === 'D').ticked, '2026-11-07');
assert.equal(checklist([{ id: 'OLD', published: '2021-01-01', cisaActionDue: '2021-11-17', references: [] }], {}, '2026-11-07')[0].overdue, false, 'years-old deadline is not flagged');

// "Get the fix": the official update page for known products, else the vendor's own link, else nothing.
const kev = (vendorProject, product, notes = '') => ({ cveID: 'CVE-1', vendorProject, product, notes });
const desc = (text, references = []) => ({ id: 'CVE-2', descriptions: [{ lang: 'en', value: text }], references });
assert.equal(fixLink(kev('WordPress', 'Core', 'https://wordpress.org/news/x/ ; https://www.cisa.gov/y')).url, 'https://wordpress.org/documentation/article/updating-wordpress/');
assert.equal(fixLink(kev('WordPress', 'Snap Creek Duplicator Plugin')).url, 'https://wordpress.org/plugins/search/Snap%20Creek%20Duplicator/');
assert.equal(fixLink(kev('PHP Group', 'PHP')).url, 'https://www.php.net/downloads.php');
assert.equal(fixLink(kev('phpMyAdmin', 'phpMyAdmin')).url, 'https://www.phpmyadmin.net/downloads/');
assert.equal(fixLink(kev('WebPros', 'cPanel', 'https://www.cisa.gov/a ; https://support.cpanel.net/fix ; https://nvd.nist.gov/b')).url, 'https://support.cpanel.net/fix', 'vendor link, not CISA/NVD');
assert.equal(fixLink(kev('ThinkPHP', 'ThinkPHP', 'https://nvd.nist.gov/vuln/detail/CVE-1')), null, 'no fix link known');
assert.equal(fixLink(desc('The WS Form LITE – Drag & Drop Contact Form Builder plugin for WordPress is vulnerable to XSS')).url, 'https://wordpress.org/plugins/search/WS%20Form%20LITE/');
assert.equal(fixLink(desc('The Astra theme for WordPress is vulnerable')).url, 'https://wordpress.org/themes/search/Astra/');
assert.equal(fixLink(desc('The WHIZZ WordPress plugin through 1.1.8 does not validate')).url, 'https://wordpress.org/plugins/search/WHIZZ/', 'WPScan wording');
assert.equal(fixLink(kev('WordPress', 'WordPress Core', 'https://wordpress.org/news/x/')).url, 'https://wordpress.org/documentation/article/updating-wordpress/');
assert.equal(fixLink(desc('Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB).')).url, 'https://dev.mysql.com/downloads/mysql/');
assert.equal(fixLink(desc('In PHP versions 8.1.* before 8.1.29, a bug', [])).url, 'https://www.php.net/downloads.php');
assert.equal(fixLink(desc('Some library bug', [{ url: 'https://x.example/patch', tags: ['Patch'] }])).url, 'https://x.example/patch');
assert.equal(fixLink(desc('Some library bug', [{ url: 'javascript:alert(1)', tags: ['Patch'] }])), null);

// Breach advice depends on what leaked.
const steps = (b) => breachSteps({ Title: 'Acme', DataClasses: [], ...b }).steps.join('\n');
assert.match(steps({ DataClasses: ['Email addresses', 'Passwords'] }), /Change your Acme password/);
assert.match(steps({ DataClasses: ['Email addresses'] }), /Passwords weren't in this leak/);
assert.match(steps({ DataClasses: ['Partial credit card data'] }), /statements/);
assert.match(steps({ DataClasses: ['Phone numbers'] }), /SIM/);
assert.match(steps({ DataClasses: ['Security questions and answers'] }), /security questions/);
assert.match(steps({ DataClasses: ['Government issued IDs'] }), /credit report/);
assert.match(steps({ IsStealerLog: true }), /malware/);
assert.ok(!/statements|SIM|credit report/.test(steps({ DataClasses: ['Email addresses', 'Passwords'] })), 'no advice for things that did not leak');
assert.ok(breachSteps({ Title: 'Acme', DataClasses: ['Passwords'] }).links.every((l) => /^https:\/\//.test(l.url)));

// "How this affects you": from what leaked, or from the bug type; nothing when the type isn't known.
assert.match(affects({ DataClasses: ['Email addresses', 'Passwords'] }), /your password/);
assert.match(affects({ DataClasses: ['Credit cards'] }), /card or bank/);
assert.match(affects({ DataClasses: ['Email addresses'] }), /scam emails/);
assert.match(affects({ DataClasses: [], IsStealerLog: true }), /malware/);
assert.match(affects({ cveID: 'C', vulnerabilityName: 'WordPress File Manager Remote Code Execution Vulnerability' }), /take over the server/);
assert.match(affects(desc('The X plugin for WordPress is vulnerable to SQL Injection via the id parameter')), /database/);
assert.match(affects(desc('The X plugin for WordPress is vulnerable to Cross-Site Request Forgery ... to inject malicious web scripts')), /click a link/, 'CSRF wins over the script wording');
assert.match(affects(desc('The X plugin for WordPress is vulnerable to Stored Cross-Site Scripting')), /visitors' browsers/);
assert.match(affects(desc('The X plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check')), /admin or another user/);
assert.equal(affects(desc('Some odd bug nobody has named')), null);

// Site check: host parsing, past leaks, the verdict, and only the host goes to Mozilla.
assert.equal(hostOf('https://www.Shop.example.com/cart?x=1'), 'www.shop.example.com');
assert.equal(hostOf(' shop.example.com '), 'shop.example.com');
assert.equal(hostOf('javascript:alert(1)'), null);
assert.equal(hostOf('ftp://files.example.com'), null);
assert.equal(hostOf('not a site'), null);
assert.equal(hostOf('localhost'), null);
const leakList = [{ Name: 'A', Domain: 'adobe.com', BreachDate: '2013-10-04', DataClasses: ['Passwords'] }, { Name: 'B', Domain: 'notadobe.com', BreachDate: '2025-01-01', DataClasses: [] }];
assert.deepEqual(pastLeaks('www.adobe.com', leakList).map((b) => b.Name), ['A'], 'www and subdomains match, look-alikes do not');
assert.deepEqual(pastLeaks('shop.adobe.com', leakList).map((b) => b.Name), ['A']);
const scan = (grade) => ({ grade, tests_passed: 8, tests_quantity: 12 });
assert.equal(siteReport('a.com', scan('A+'), [], '2026-11-08').level, 'good');
assert.equal(siteReport('a.com', scan('A'), leakList.slice(0, 1), '2026-11-08').level, 'good', 'a 2013 leak alone is old news');
assert.equal(siteReport('a.com', scan('B'), [{ ...leakList[1], DataClasses: ['Email addresses'] }], '2026-11-08').level, 'careful', 'recent leak');
assert.equal(siteReport('a.com', scan('C'), [], '2026-11-08').level, 'careful');
assert.equal(siteReport('a.com', scan('F'), [], '2026-11-08').level, 'weak');
assert.match(siteReport('a.com', scan('B'), null, '2026-11-08').text, /leak list didn't load/);
let asked = '';
const fakeMoz = async (url, opts) => { asked = `${opts.method} ${url}`; return { ok: true, json: async () => scan('B') }; };
assert.equal((await observatory('shop.example.com', fakeMoz)).grade, 'B');
assert.equal(asked, 'POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=shop.example.com');
await assert.rejects(observatory('x.example', async () => ({ ok: false, json: async () => ({ error: 'invalid-hostname', message: 'Invalid hostname' }) })), /Invalid hostname/);

// Live call against the real API.
const live = await pwnedCount('password');
assert.ok(live > 1000, `"password" should be heavily leaked, got ${live}`);
console.log(`ok - 80 checks passed (live: "password" seen ${live.toLocaleString()} times)`);
