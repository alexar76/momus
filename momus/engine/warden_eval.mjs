// Data-only bridge: import a local WARDEN build, never start MCP servers or call tools.
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

const lib = resolve(process.argv[2]);
const entry = existsSync(join(lib, 'dist/index.js')) ? join(lib, 'dist/index.js') : lib;
const { Warden, ThreatFeed, staticScanRulesetRef } = await import(pathToFileURL(entry).href);
const request = JSON.parse(readFileSync(0, 'utf8'));
const mode = request.mode ?? 'detection';
if (!['detection', 'unapproved', 'approved', 'drift'].includes(mode)) throw Error('invalid evaluation mode');
const policy = { blockAtSeverity: 'high', sensitiveToolPatterns: [], allowUnknownServers: true, pinToolDefs: true, ...(mode !== 'detection' ? { requireApproval: true } : {}) };
const buildHash = createHash('sha256');
for (const name of readdirSync(dirname(entry)).filter(n => n.endsWith('.js')).sort()) {
  buildHash.update(name + '\0').update(readFileSync(join(dirname(entry), name))).update('\0');
}
let version = 'unknown';
const pkg = join(dirname(entry), '../package.json');
if (existsSync(pkg)) version = JSON.parse(readFileSync(pkg, 'utf8')).version;
const report = { protocol: 1, version, ruleset: staticScanRulesetRef(),
  buildDigest: buildHash.digest('hex'), policy, mode, results: [] };
if (!Array.isArray(request.variants) || request.variants.length > 10000) throw Error('invalid batch size');
for (const v of request.variants) {
  try {
    // Same neutral identity for every input; neither labels nor fixture paths reach the gates.
    let pin;
    const w = Warden.create({ policy, threatFeed: new ThreatFeed(),
      store: { getPin: async () => pin, putPin: async value => { pin = value; } } });
    const server = { id: 'coverage-fixture', name: 'coverage-fixture',
      transport: 'stdio', command: 'node', args: ['fixture.mjs'] };
    if (mode === 'approved') await w.approve(server, v.tools);
    if (mode === 'drift') await w.approve(server, v.tools.map(t => ({ name: t.name, description: 'Reviewed clean tool.', inputSchema: { type: 'object' } })));
    const verdict = await w.vet(server, v.tools);
    const failed = verdict.findings.some(f => f.code === 'GATE_ERROR');
    report.results.push({ id: v.id, status: failed ? 'error' : 'scanned',
      allow: failed ? null : verdict.allow, findings: verdict.findings,
      decidedBy: verdict.decidedBy ?? null });
  } catch {
    report.results.push({ id: v.id, status: 'error', allow: null, findings: [], error: 'evaluation_failed' });
  }
}
process.stdout.write(JSON.stringify(report));
