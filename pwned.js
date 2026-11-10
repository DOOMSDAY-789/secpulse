// Password leak check by k-anonymity: only the first 5 hex chars of the SHA-1 hash leave the device.
// Never log or store the password or the full hash.

export async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// body is "SUFFIX:COUNT" per line. Padding rows (Add-Padding) carry count 0, so they read as not found.
export function countInRange(body, suffix) {
  for (const line of body.split('\n')) {
    const [s, n] = line.trim().split(':');
    if (s === suffix) return Number(n) || 0;
  }
  return 0;
}

export async function pwnedCount(password, fetchFn = fetch) {
  const hash = await sha1Hex(password);
  const res = await fetchFn(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { 'Add-Padding': 'true' },
  });
  if (!res.ok) throw new Error(`Pwned Passwords answered ${res.status}`);
  const body = await res.text();
  // A real reply is hundreds of SUFFIX:COUNT rows. Anything else (a network filter's block page, an empty reply)
  // must never read as "not found", or the app would call a leaked password fine.
  if (!/^[0-9A-F]{35}:\d+\s*$/m.test(body)) throw new Error('Pwned Passwords sent an unexpected reply, so this password was NOT checked. A network filter may be blocking it.');
  return countInRange(body, hash.slice(5));
}
