// Self-check for the password leak check. Run: node test.mjs
import assert from 'node:assert/strict';
import { sha1Hex, countInRange, pwnedCount } from './pwned.js';
import { cvss, summary, filter } from './feeds.js';

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

// Live call against the real API.
const live = await pwnedCount('password');
assert.ok(live > 1000, `"password" should be heavily leaked, got ${live}`);
console.log(`ok - 18 checks passed (live: "password" seen ${live.toLocaleString()} times)`);
