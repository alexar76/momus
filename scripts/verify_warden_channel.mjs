// Verify the MOMUS → WARDEN channel against a LIVE deployment, using ARGUS's OWN code.
//
//   node momus/scripts/verify_warden_channel.mjs [base-url]
//
// Why this exists as a script and not only as a test: the unit tests prove our own code agrees with
// itself, and the interesting failures were all in the deployment — a truncated asset, a proxy that
// cached a dead container IP, a route exposed publicly that should not have been. Two of the fixes in
// docs/warden-channel.md came from running this, not from reading code.
//
// It imports argus/dist/warden/jcs.js so the canonical bytes come from the CONSUMER's implementation,
// and verifies with node:crypto exactly as WARDEN does. Requires the argus dist to be built.
//
// Exit code is non-zero if any check fails, so it can gate a deploy.

import { verify, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const here = path.dirname(fileURLToPath(import.meta.url));
const { canonicalize } = await import(
  path.resolve(here, '../../argus/dist/warden/jcs.js'));

const BASE = (process.argv[2] || 'https://momus.modelmarket.dev').replace(/\/$/, '');
const pass = [], fail = [];
const ok = (c, m) => (c ? pass : fail).push(m);

const sum = await (await fetch(`${BASE}/warden/threat-feed/summary`)).json();
const doc = await (await fetch(`${BASE}/warden/threat-feed`)).json();

ok(typeof sum.feed_public_key_spki_hex === 'string' && sum.feed_public_key_spki_hex.length === 88,
   'summary publishes an 88-hex SPKI key');
ok(Number.isInteger(doc.timestamp), 'timestamp is an integer (WARDEN requires it)');
ok(Array.isArray(doc.records), 'records is an array');
ok(/^[0-9a-f]{128}$/.test(doc.signature), 'signature is 128 hex chars');

const payload = canonicalize({ records: doc.records, timestamp: doc.timestamp });
const pub = createPublicKey({ key: Buffer.from(sum.feed_public_key_spki_hex, 'hex'),
                              format: 'der', type: 'spki' });
ok(verify(null, Buffer.from(payload, 'utf8'), pub, Buffer.from(doc.signature, 'hex')),
   "ARGUS's own canonicalizer + node:crypto accept the LIVE signature");

// Tamper: one record added, one field flipped — both must fail.
const t1 = { records: [...doc.records, { pattern: 'injected.example.com', severity: 'critical',
             code: 'X', reason: 'r', source: 's', scope: 'any' }], timestamp: doc.timestamp };
ok(!verify(null, Buffer.from(canonicalize(t1), 'utf8'), pub, Buffer.from(doc.signature, 'hex')),
   'an injected record breaks the signature');
const t2 = { records: doc.records, timestamp: doc.timestamp + 1 };
ok(!verify(null, Buffer.from(canonicalize(t2), 'utf8'), pub, Buffer.from(doc.signature, 'hex')),
   'a shifted timestamp breaks the signature (no replay with a fresh date)');

// Freshness: WARDEN refuses a snapshot older than 24 h by default.
const ageMin = Math.round((Date.now() - doc.timestamp) / 60000);
ok(ageMin >= -5 && ageMin < 24 * 60, `snapshot is ${ageMin} min old — inside WARDEN's window`);

// The triage queue must NOT be public: it holds unverified accusations against named third
// parties, and MOMUS's reputation as an auditor is exactly what would make one devastating.
const q = await fetch(`${BASE}/warden/reports`);
const qBody = await q.text();
let isJsonQueue = false;
try { isJsonQueue = Array.isArray(JSON.parse(qBody).leads); } catch { /* html = not the queue */ }
ok(!isJsonQueue, 'the triage queue is NOT served publicly (unverified accusations stay private)');

// Intake IS public — any field install must be able to report.
const intake = await fetch(`${BASE}/warden/report`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ identity: 'verify-probe.example.com',
                         reason: 'liveness check from the verification script' }) });
const intakeBody = await intake.json().catch(() => ({}));
ok(intake.status === 200 && intakeBody.accepted === true, 'public intake accepts a report');
ok(intakeBody.verified === false, 'the intake reply states plainly that nothing was verified');

// A category-wide pattern must be refused even through intake.
const wide = await fetch(`${BASE}/warden/report`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ identity: 'server', reason: 'attempting a category-wide denial' }) });
ok(wide.status === 422, `a category pattern is refused at intake (${wide.status})`);

// And nothing reported appears in the signed feed.
ok(!doc.records.some(r => String(r.pattern).includes('example.com')),
   'no reported lead appears in the signed feed (reports are not evidence)');

// Control routes must stay refused at the public edge.
for (const [path, method] of [['/scan', 'POST'], ['/retest', 'POST'], ['/remediate', 'POST'],
                              ['/intel/refresh', 'POST'], ['/a2a/tasks', 'POST']]) {
  const r = await fetch(BASE + path, { method, headers: { 'content-type': 'application/json' },
                                       body: '{}' });
  ok(r.status === 404 || r.status === 403 || r.status === 503,
     `${method} ${path} refused at the edge (${r.status})`);
}
// Treasury payout routes must not be public.
for (const p of ['/treasury/authorize', '/treasury/deposit', '/treasury/vault/fund']) {
  const r = await fetch(BASE + p, { method: 'POST', body: '{}',
                                    headers: { 'content-type': 'application/json' } });
  ok(r.status === 404, `POST ${p} is not public (${r.status})`);
}

console.log(`\n✓ ${pass.length} passed`);
pass.forEach(m => console.log('  ✓', m));
if (fail.length) { console.log(`\n✗ ${fail.length} FAILED`); fail.forEach(m => console.log('  ✗', m)); }
process.exit(fail.length ? 1 : 0);
