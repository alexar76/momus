"""The native remediation target for host-signed WARDEN evaluations.

Only the trusted host judge publishes these receipts. Polling a receipt never runs
package code, labels a novel model proposal, or exposes the sealed holdout.
"""
import base64
import json
import re
import time
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from momus.findings import Outcome, Severity
from momus.targets.base import ProbeResult, ProbeStrategy, Target


def verified_receipt(envelope, *, candidate=False, now=None, public_key=None):
    now = time.time() if now is None else now
    if len(json.dumps(envelope)) > 128 * 1024:
        raise ValueError('oversized receipt')
    payload = base64.b64decode(envelope['payload'], validate=True)
    key = load_pem_public_key(public_key or Path(__file__).with_name('quality-public-key.pem').read_bytes())
    key.verify(base64.b64decode(envelope['signature'], validate=True), payload)
    report = json.loads(payload)
    if (report['type'] != 'momus.release-quality/v1' or report['policy'] != 'zero-regressions-v1'
            or report.get('phase') != ('candidate' if candidate else 'live')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', report.get('imageDigest', ''))
            or not re.fullmatch(r'[0-9a-f]{64}', report.get('buildDigest', ''))
            or not now - 48 * 3600 <= report['evaluatedAt'] <= now + 60 or report['expiresAt'] < now):
        raise ValueError('wrong, stale or unbound quality receipt')
    return report


def passed_receipt(r, now=None):
    now = time.time() if now is None else now
    def suite_ok(s):
        return s.get('passed') is True and all(s.get('counts', {}).get(k) == 0 for k in ('missed', 'falsePositives', 'incomplete'))
    def behaviour_ok(b, age):
        return (b.get('passed') is True and now - age <= b.get('evaluatedAt', 0) <= now + 60
                and all(b.get(k) == 0 for k in ('missed', 'falsePositives', 'incomplete')))
    try:
        suites, full, b, smoke = r['suites'], r['fullEvidence'], r['behaviour'], r['behaviourSmoke']
        return (r['status'] == 'passed' and full['status'] == 'passed'
                and full['buildDigest'] == r['buildDigest'] and full['holdoutSha256'] == r['holdoutSha256']
                and now - 35 * 86400 <= full['evaluatedAt'] <= now + 60
                and all(suite_ok(suites[n]) for n in ('development', 'holdout', 'candidates'))
                and all(suite_ok(s) for s in suites.values())
                and suites['holdout']['counts']['attacks'] >= 20 and suites['holdout']['counts']['benign'] >= 20
                and behaviour_ok(b, 35 * 86400) and b['cases'] == b['executed'] == 72
                and behaviour_ok(smoke, 48 * 3600) and smoke['executed'] >= 3
                and smoke['observerSha256'] == b['observerSha256'] and smoke['fixturesSha256'] == b['fixturesSha256']
                and r['discovery']['status'] == 'complete' and r['discovery']['generation']['status'] == 'ok')
    except (KeyError, TypeError, ValueError):
        return False


class QualityProbe(ProbeStrategy):
    probe_id = 'warden_release_quality'
    category = 'prompt-injection'

    async def run(self, target, ctx, discovery):
        report = discovery
        cases = report.get('repairCases', [])
        actionable = (report.get('status') == 'failed' and isinstance(cases, list) and bool(cases)
                      and all(c.get('suite') in ('development', 'regressions')
                              and c.get('fixture', {}).get('label') in ('malicious', 'benign')
                              and c.get('failure', {}).get('reason') in ('missed', 'falsePositives') for c in cases))
        outcome = Outcome.NO_FINDING if passed_receipt(report) else Outcome.FINDING if actionable else Outcome.INCONCLUSIVE
        return [ProbeResult(
            probe=self.probe_id, category=self.category, outcome=outcome, severity=Severity.HIGH,
            title='WARDEN confirmed detection regression',
            detail=('Fix detector behaviour for these established synthetic fixtures. Preserve multilingual semantic '
                    'inspection and benign use. The host runs the full corpus, sealed holdout and gVisor tests before deployment. '
                    + json.dumps(cases, ensure_ascii=False) if actionable else 'Signed quality evaluation: ' + report.get('status', 'unavailable')),
            request_summary='quality-run:' + str(report.get('run', 'unavailable')),
            reproducer=json.dumps(cases, ensure_ascii=False) if actionable else '',
            reference_artifacts=('warden/src/classifier.ts', 'warden/src/static-scan.ts', 'warden/src/result-screen.ts'),
            raw_response={'run': report.get('run'), 'imageDigest': report.get('imageDigest'), 'status': report.get('status')})]


class QualityTarget(Target):
    kind = 'quality'

    def __init__(self, name, base_url, *, transport=None, candidate=False):
        super().__init__(name, base_url, transport=transport)
        self.candidate = candidate

    def strategies(self):
        return [QualityProbe()]

    async def discover(self, ctx):
        path = '/security-quality/' + ('candidate.json' if self.candidate else 'latest.json')
        status, envelope, error = await ctx.client.request('GET', path)
        if status != 200 or error:
            return {}
        try:
            return verified_receipt(envelope, candidate=self.candidate)
        except Exception:
            return {}  # A corrupt/missing receipt blocks remediation, never invents a defect.
