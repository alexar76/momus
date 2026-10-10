// Live measurement through WARDEN's actual classifier. Data only, never tool execution.
// Credentials come exclusively from process environment; neither headers nor keys are recorded.
import { readFileSync, writeFileSync, appendFileSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

const [buildArg, corpusArg, outArg, limitArg] = process.argv.slice(2);
if (!buildArg || !corpusArg || !outArg) throw Error('Usage: coverage_semantic.mjs WARDEN CASES.jsonl.gz OUT_DIR [PILOT_LIMIT]');
const build = resolve(buildArg), out = resolve(outArg);
const { inspectTools, CLASSIFIER_SYSTEM_PROMPT } = await import(pathToFileURL(join(build, 'dist/classifier.js')).href);
const { Warden, ThreatFeed } = await import(pathToFileURL(join(build, 'dist/index.js')).href);
const url = process.env.WARDEN_CLASSIFIER_URL, model = process.env.WARDEN_CLASSIFIER_MODEL;
const reasoningEffort = process.env.WARDEN_CLASSIFIER_REASONING_EFFORT;
if (reasoningEffort && !['none', 'low', 'medium', 'high'].includes(reasoningEffort)) throw Error('Invalid reasoning effort');
if (!url || !model || !process.env.WARDEN_CLASSIFIER_API_KEY) throw Error('Configure WARDEN_CLASSIFIER_URL, MODEL and API_KEY');
const endpoint = new URL(url);
if (endpoint.username || endpoint.password || endpoint.search) throw Error('Endpoint must not contain credentials or query parameters');
const sha = data => createHash('sha256').update(data).digest('hex');
const bytes = gunzipSync(readFileSync(corpusArg));
let cases = bytes.toString('utf8').trim().split('\n').map(s => JSON.parse(s));
if (cases.some(v => v.tools.length !== 1) || new Set(cases.map(v => v.id)).size !== cases.length) throw Error('Expected unique single-tool fixtures');
cases.sort((a, b) => sha(a.id).localeCompare(sha(b.id)));
if (limitArg) {
  const limit = Number(limitArg);
  if (!Number.isInteger(limit) || limit < 2 || limit > cases.length) throw Error('Invalid pilot size');
  cases = [...cases.filter(v => v.label === 'malicious').slice(0, Math.ceil(limit / 2)),
    ...cases.filter(v => v.label === 'benign').slice(0, Math.floor(limit / 2))].sort((a, b) => sha(a.id).localeCompare(sha(b.id)));
}
const buildHash = createHash('sha256');
for (const name of readdirSync(join(build, 'dist')).filter(n => n.endsWith('.js')).sort())
  buildHash.update(name + '\0').update(readFileSync(join(build, 'dist', name))).update('\0');
const identity = { protocol: 'field-references-v5-bound-ambiguity-review', reasoningEffort: reasoningEffort ?? 'provider-default', endpoint: endpoint.origin + endpoint.pathname, model, corpusSha256: sha(bytes),
  selectedIdsSha256: sha(JSON.stringify(cases.map(v => v.id))), cases: cases.length,
  buildDigest: buildHash.digest('hex'), promptSha256: sha(CLASSIFIER_SYSTEM_PROMPT),
  batchSize: 8, concurrency: 4, requireComplete: true, blockThreshold: 'high',
  note: 'Independent synthetic fixtures batched without changing their names or contents. Labels and intents never sent to the model. Failures are not detections. Model judgments are not operator approval.' };
mkdirSync(out, { recursive: true });
const metaPath = join(out, 'identity.json'), rowsPath = join(out, 'decisions.jsonl');
if (existsSync(metaPath) && readFileSync(metaPath, 'utf8') !== JSON.stringify(identity, null, 2) + '\n')
  throw Error('Existing output belongs to a different corpus, model, prompt or build');
writeFileSync(metaPath, JSON.stringify(identity, null, 2) + '\n');
const rows = existsSync(rowsPath) ? readFileSync(rowsPath, 'utf8').trim().split('\n').filter(Boolean).map(s => JSON.parse(s)) : [];
const done = new Set(rows.map(r => r.id));
const pending = cases.filter(v => !done.has(v.id));
const batches = Array.from({ length: Math.ceil(pending.length / identity.batchSize) }, (_, i) => pending.slice(i * identity.batchSize, (i + 1) * identity.batchSize));
let cursor = 0, finished = rows.length;
async function worker() {
  while (cursor < batches.length) {
    const batch = batches[cursor++];
    let answers;
    try {
      const inspection = await inspectTools(batch.map(v => v.tools[0]), { url, model,
        apiKey: process.env.WARDEN_CLASSIFIER_API_KEY, requireComplete: true, timeoutMs: 120000, reasoningEffort,
        onResponse: (content, inspected, metadata) => appendFileSync(join(out, 'responses.jsonl'), JSON.stringify({ ids: inspected.map(t => batch.find(v => v.tools[0] === t)?.id), content, ...metadata }) + '\n') });
      answers = await Promise.all(batch.map(async (v, i) => {
        const warden = Warden.create({ semanticReview: inspection, threatFeed: new ThreatFeed(),
          policy: { blockAtSeverity: 'high', sensitiveToolPatterns: [], allowUnknownServers: true, pinToolDefs: true },
          store: { getPin: async () => undefined, putPin: async () => {} } });
        const vetted = await warden.vet({ id: 'coverage-fixture', name: 'coverage-fixture', transport: 'stdio', command: 'node', args: ['fixture.mjs'] }, v.tools);
        const incomplete = inspection.incomplete.find(f => f.index === i);
        return { id: v.id, reviewedStatic: { status: vetted.findings.some(f => f.code === 'GATE_ERROR') ? 'error' : 'scanned', allow: vetted.allow, findings: vetted.findings }, status: incomplete ? 'incomplete' : 'scanned', findings: inspection.findings.filter(f => f.index === i),
          ...(incomplete ? { error: incomplete.error } : {}) };
      }));
    } catch (error) {
      // Library errors contain transport/validation descriptions, never a provider body.
      const safe = String(error.message).replaceAll(process.env.WARDEN_CLASSIFIER_API_KEY, '[redacted]').slice(0, 240);
      answers = batch.map(v => ({ id: v.id, status: 'incomplete', findings: [], error: safe }));
    }
    rows.push(...answers);
    appendFileSync(rowsPath, answers.map(r => JSON.stringify(r) + '\n').join(''));
    finished += batch.length;
    if (finished % 80 === 0 || finished === cases.length) console.log(JSON.stringify({ finished, total: cases.length, incomplete: rows.filter(r => r.status !== 'scanned').length }));
  }
}
await Promise.all(Array.from({ length: identity.concurrency }, worker));
const byId = new Map(rows.map(r => [r.id, r]));
function counts(selected) {
  const count = { total: selected.length, inspected: 0, high: 0, flagged: 0, incomplete: 0 };
  for (const v of selected) {
    const r = byId.get(v.id);
    if (!r || r.status !== 'scanned') { count.incomplete++; continue; }
    count.inspected++;
    if (r.findings.length) count.flagged++;
    if (r.findings.some(f => f.severity === 'high')) count.high++;
  }
  return count;
}
const report = { identity, attacks: counts(cases.filter(v => v.label === 'malicious')), benign: counts(cases.filter(v => v.label === 'benign')),
  byLanguage: Object.fromEntries([...new Set(cases.map(v => v.language))].sort().map(lang => [lang, {
    attacks: counts(cases.filter(v => v.language === lang && v.label === 'malicious')),
    benign: counts(cases.filter(v => v.language === lang && v.label === 'benign')) }])) };
writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ attacks: report.attacks, benign: report.benign }));
