"""Failures must block release rather than improve a detector's measured recall."""
import json
from pathlib import Path
import subprocess

import pytest

from momus.engine.quality_cycle import assess, build_digest, canonical, pinned_request, read_cases, verdict, write_cases


def row(case_id, *, allow=True, status='scanned'):
    return {'id': case_id, 'status': status, 'findings': [],
            'reviewedStatic': {'status': 'scanned', 'allow': allow}}


def test_partial_inspection_cannot_hide_behind_static_block():
    assert verdict(row('x', allow=False, status='incomplete')) == 'incomplete'
    broken = row('x')
    del broken['reviewedStatic']['allow']
    assert verdict(broken) == 'incomplete'


def test_histor_uses_identical_gate_and_trust_anchor():
    root = Path(__file__).parents[2]
    for name in ('check-quality-gate.mjs', 'quality-public-key.pem'):
        assert (root / 'warden/scripts' / name).read_bytes() == (root / 'histor/scanner/quality' / name).read_bytes()


def test_release_requires_correct_benign_and_attack_decisions():
    cases = [{'id': 'attack', 'label': 'malicious'}, {'id': 'normal', 'label': 'benign'}]
    result = assess(cases, [row('attack'), row('normal', allow=False)], {'attack': 'blocked', 'normal': 'allowed'})
    assert not result['passed']
    assert result['counts']['missed'] == result['counts']['falsePositives'] == 1
    assert set(result['regressions']) == {'attack', 'normal'}
    assert assess(cases, [row('attack', allow=False), row('normal')])['passed']


@pytest.mark.parametrize('rows', [[], [row('x'), row('x')], [row('unknown')]])
def test_missing_duplicate_and_unknown_rows_fail_closed(rows):
    with pytest.raises(ValueError):
        assess([{'id': 'x', 'label': 'malicious'}], rows)


def test_unreviewed_proposal_is_not_a_miss():
    result = assess([{'id': 'new', 'label': 'candidate'}], [row('new')])
    assert result['counts']['candidates'] == 1 and result['counts']['missed'] == 0


def test_frozen_corpus_roundtrip(tmp_path):
    cases = [{'id': 'x', 'label': 'benign', 'tools': []}]
    path = tmp_path / 'cases.gz'
    expected = write_cases(path, cases)
    assert read_cases(path) == (cases, expected)


def test_transfer_metadata_rejected_before_paid_evaluation(tmp_path):
    dist = tmp_path / 'dist'
    dist.mkdir()
    (dist / 'index.js').write_text('export const ok = true;')
    assert len(build_digest(tmp_path)) == 64
    (dist / '._index.js').write_bytes(b'AppleDouble')
    with pytest.raises(ValueError, match='AppleDouble'):
        build_digest(tmp_path)


def test_launcher_preserves_absolute_python_executable_and_keeps_keys_out_of_argv(monkeypatch, capsys):
    import runpy
    from types import SimpleNamespace
    values = {'DEEPSEEK_API_KEY': 'synthetic-key', 'HISTOR_SANDBOX_URL': 'https://sandbox.invalid',
              'HISTOR_SANDBOX_CERT_SHA256': '0' * 64, 'HISTOR_SANDBOX_TOKEN': 'synthetic-token'}
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(values)))
    executed = []
    monkeypatch.setattr('os.execve', lambda *args: executed.append(args))
    runpy.run_path(str(Path(__file__).parents[1] / 'deploy/quality-launch.py'))
    executable, argv, env = executed[0]
    assert executable == argv[0] == '/opt/momus-quality/venv/bin/python'
    assert env['WARDEN_CLASSIFIER_API_KEY'] == 'synthetic-key'
    assert all('synthetic-key' not in value for value in argv)
    assert capsys.readouterr().out == ''


def test_pin_checked_before_authorization(monkeypatch):
    class Socket:
        def getpeercert(self, **kwargs):
            return b'wrong-certificate'
    class Connection:
        sock = Socket()
        def __init__(self, *args, **kwargs): pass
        def connect(self): pass
        def request(self, *args): pytest.fail('credentials sent before pin validation')
        def close(self): pass
    monkeypatch.setattr('http.client.HTTPSConnection', Connection)
    with pytest.raises(ValueError, match='pin mismatch'):
        pinned_request('https://sandbox.invalid', '0' * 64, 'secret-token', {})


def test_signed_release_gate_rejects_tampering_staleness_and_wrong_build(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64
    private = Ed25519PrivateKey.generate()
    key = tmp_path / 'public.pem'
    key.write_bytes(private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    now = 10000000
    counts = dict(attacks=24, benign=24, missed=0, falsePositives=0, incomplete=0)
    report = {'type': 'momus.release-quality/v1', 'policy': 'zero-regressions-v1', 'status': 'passed',
              'evaluatedAt': now, 'expiresAt': now + 86400, 'buildDigest': 'build', 'holdoutSha256': 'sealed',
              'fullEvidence': {'status': 'passed', 'buildDigest': 'build', 'holdoutSha256': 'sealed', 'evaluatedAt': now},
              'suites': {n: {'passed': True, 'counts': counts} for n in ('development', 'holdout', 'candidates')},
              'discovery': {'status': 'complete', 'generation': {'status': 'ok'}},
              'behaviour': {'passed': True, 'cases': 72, 'executed': 72, 'evaluatedAt': now,
                            'missed': 0, 'falsePositives': 0, 'incomplete': 0}}
    report['behaviourSmoke'] = report['behaviour'].copy()
    gate = Path(__file__).parents[2] / 'warden/scripts/check-quality-gate.mjs'
    def check(document, *, expected='build', at=now, tamper=False):
        payload = canonical(document)
        signature = private.sign(payload)
        if tamper: payload += b' '
        evidence = tmp_path / 'evidence.json'
        evidence.write_text(json.dumps({'payload': base64.b64encode(payload).decode(),
                                       'signature': base64.b64encode(signature).decode()}))
        code = f"import {{checkEvidence}} from {json.dumps(gate.as_uri())}; import {{readFileSync}} from 'node:fs'; checkEvidence(JSON.parse(readFileSync(process.argv[1])),readFileSync(process.argv[2]),process.argv[3],Number(process.argv[4]));"
        return subprocess.run(['node', '--input-type=module', '-e', code, str(evidence), str(key), expected, str(at)], capture_output=True).returncode
    assert check(report) == 0
    assert check(report, tamper=True) != 0
    assert check(report, expected='other') != 0
    assert check(report, at=now + 200000) != 0
    report['behaviour']['incomplete'] = 1
    assert check(report) != 0
    report['behaviour']['incomplete'] = 0
    report['fullEvidence']['status'] = 'failed'
    assert check(report) != 0
    report['fullEvidence']['status'] = 'passed'
    report['behaviourSmoke']['passed'] = False
    assert check(report) != 0


def test_worker_cannot_redirect_root_log_to_a_private_file(tmp_path):
    from momus.engine.quality_cycle import command
    secret = tmp_path / 'private-key'
    secret.write_text('unchanged')
    log = tmp_path / 'process.log'
    log.symlink_to(secret)
    with pytest.raises(OSError):
        command(['true'], log)
    assert secret.read_text() == 'unchanged'
