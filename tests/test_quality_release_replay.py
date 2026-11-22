"""Exercise the real WARDEN release archives with local provider and observer doubles."""
import base64
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from momus.engine import quality_cycle
from momus.engine.behaviour_campaign import generate
from momus.targets.quality import passed_receipt, verified_receipt


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'warden/docs/evidence'
PROVIDER = r"""
const { EventEmitter } = require('node:events');
const { appendFileSync } = require('node:fs');
const { syncBuiltinESMExports } = require('node:module');
const { Readable } = require('node:stream');

const http = require('node:http');
const loopbackRequest = http.request;
http.request = (url, ...args) => {
  if (url.hostname !== '127.0.0.1') throw Error('unexpected HTTP request');
  return loopbackRequest(url, ...args);
};
globalThis.fetch = () => { throw Error('unexpected fetch request'); };
require('node:https').request = (url, options, receive) => {
  if (String(url) !== 'https://model.invalid/v1/chat/completions') throw Error('unexpected model endpoint');
  const request = new EventEmitter();
  const chunks = [];
  request.write = (part) => { chunks.push(Buffer.from(part)); };
  request.end = (body) => {
    if (body) request.write(body);
    const prompt = JSON.parse(Buffer.concat(chunks)).messages[1].content;
    const data = /\nBEGIN_TOOLS_([0-9a-f]{16})\n(.*)\nEND_TOOLS_\1$/.exec(prompt);
    const tools = JSON.parse(data[2]);
    appendFileSync(process.env.OFFLINE_PROVIDER_CALLS, JSON.stringify(tools.map(tool => tool.name)) + '\n');
    const decisions = tools.map(tool => tool.name.startsWith('flagged_') ? {
      i: tool.i, verdict: 'attack', severity: 'high', categories: ['instruction_to_model'],
      evidence: [tool.fields.find(field => field.key === 'description').id],
    } : { i: tool.i, verdict: 'clean' });
    queueMicrotask(() => {
      const content = JSON.stringify({ choices: [{
        finish_reason: 'stop', message: { content: JSON.stringify({ decisions }) },
      }] });
      const response = Readable.from([Buffer.from(content)]);
      response.statusCode = 200;
      response.headers = {'content-type': 'application/json'};
      receive(response);
    });
  };
  return request;
};
syncBuiltinESMExports();
"""


def fixture(name, label):
    prefix = 'flagged' if label == 'malicious' else 'plain'
    return {'id': name, 'label': label, 'language': 'en',
            'tools': [{'name': f'{prefix}_{name}', 'description': f'Fixture {name}.',
                       'inputSchema': {'type': 'object', 'properties': {}}}]}


def release(tmp_path, version):
    evidence = EVIDENCE / f'warden-release-{version}-2026-11-22'
    with tarfile.open(evidence / f'aimarket-warden-{version}.tgz') as archive:
        archive.extractall(tmp_path / version, filter='data')
    build = tmp_path / version / 'package'
    envelope = json.loads((evidence / 'quality/candidate-signed.json').read_text())
    report = json.loads(base64.b64decode(envelope['payload']))
    assert quality_cycle.build_digest(build) == report['buildDigest']
    return build, report['imageDigest']


def test_cli_patch_replays_model_responses_and_signs_the_new_image(tmp_path, monkeypatch):
    old_build, old_image = release(tmp_path, '0.37.0')
    new_build, new_image = release(tmp_path, '0.37.1')
    old_state, new_state = tmp_path / 'live', tmp_path / 'candidate'
    corpus, holdout = tmp_path / 'corpus.jsonl.gz', tmp_path / 'holdout.jsonl.gz'
    development_cases = [fixture(f'development_{i}', 'malicious' if i % 2 else 'benign') for i in range(10)]
    holdout_cases = [fixture(f'holdout_{i}', 'malicious' if i % 2 else 'benign') for i in range(40)]
    key = Ed25519PrivateKey.generate()
    private_file = tmp_path / 'key.pem'
    private_file.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    public_key = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    config = {'accepted': str(old_build), 'corpus': str(corpus), 'holdout': str(holdout),
              'corpusSha256': quality_cycle.write_cases(corpus, development_cases),
              'holdoutSha256': quality_cycle.write_cases(holdout, holdout_cases),
              'observerSha256': 'observer', 'fixturesSha256': 'fixtures', 'signingKey': str(private_file)}

    provider = tmp_path / 'provider.cjs'
    provider.write_text(PROVIDER)
    calls = tmp_path / 'calls.jsonl'
    observer_calls = []
    for variable, value in {
        'NODE_OPTIONS': f'--require={provider}', 'OFFLINE_PROVIDER_CALLS': str(calls),
        'WARDEN_CLASSIFIER_URL': 'https://model.invalid/v1', 'WARDEN_CLASSIFIER_MODEL': 'fixture',
        'WARDEN_CLASSIFIER_API_KEY': 'fixture', 'WARDEN_CLASSIFIER_REASONING_EFFORT': 'none',
        'HISTOR_SANDBOX_URL': 'https://observer.invalid', 'HISTOR_SANDBOX_TOKEN': 'fixture',
        'HISTOR_SANDBOX_CERT_SHA256': '0' * 64,
    }.items():
        monkeypatch.setenv(variable, value)

    fixture_plan = lru_cache(maxsize=2)(generate)

    def observer(url, pin, token, request):
        observer_calls.append(request['index'])
        case = fixture_plan(request['seed'])[request['index']]
        return {'observerSha256': config['observerSha256'], 'fixturesSha256': config['fixturesSha256'],
                'decision': {'id': case['id'], 'complete': True, 'status': 'observed'}}

    def worker(config, argv, folder, *, timeout=14400):
        if 'momus.engine.coverage_campaign' in argv:
            novel = fixture(f"novel_{config['phase']}", 'candidate')
            quality_cycle.atomic(folder / 'latest.json', {'round': 1, 'status': 'complete', 'candidates': 1,
                                                         'generation': {'status': 'ok'}})
            quality_cycle.atomic(folder / 'rounds/000001/cases.json', [{'variant': novel}])
            return
        result = subprocess.run(argv, capture_output=True, text=True, timeout=min(30, timeout))
        assert result.returncode == 0, result.stderr

    monkeypatch.setattr(quality_cycle, 'pinned_request', observer)
    monkeypatch.setattr(quality_cycle, 'worker', worker)

    def measure(build, state, image, phase, **extra):
        output = state / 'public' / ('candidate.json' if phase == 'candidate' else 'latest.json')
        settings = {**config, 'candidate': str(build), 'state': str(state), 'phase': phase,
                    'imageDigest': image, 'publication': str(output), **extra}
        result = quality_cycle.run(settings, full=True)
        report_path, = (state / 'runs').glob('*/report.json')
        error = report_path.parent / 'error.json'
        assert result == 0, error.read_text() if error.exists() else report_path.read_text()
        receipt = verified_receipt(json.loads(output.read_text()), candidate=phase == 'candidate',
                                   public_key=public_key)
        assert passed_receipt(receipt)
        assert receipt['buildDigest'] == quality_cycle.build_digest(build)
        assert receipt['imageDigest'] == image
        return json.loads(report_path.read_text()), receipt

    original, live = measure(old_build, old_state, old_image, 'live')
    assert sum(len(json.loads(batch)) for batch in calls.read_text().splitlines()) == 51
    new_state.mkdir()
    shutil.copyfile(old_state / 'baseline.json', new_state / 'baseline.json')
    calls.write_text('')
    replay, candidate = measure(new_build, new_state, new_image, 'candidate', reuseRoots=[str(old_state)])
    assert [json.loads(batch) for batch in calls.read_text().splitlines()] == [['plain_novel_candidate']]
    assert candidate['buildDigest'] != live['buildDigest']
    assert candidate['imageDigest'] != live['imageDigest']
    for name, cases, requests in [('development', development_cases, 2), ('holdout', holdout_cases, 5)]:
        suite = replay['suites'][name]
        assert suite['decisions'] == original['suites'][name]['decisions']
        reused = suite['identity']['reused']
        assert reused['rows'] == len(cases)
        assert reused['run'] == original['run']
        assert reused['measuredAt'] == original['evaluatedAt']
        assert candidate['semanticReuse'][name] == {**reused, 'requests': requests}
    assert replay['expiresAt'] == pytest.approx(original['evaluatedAt'] + 48 * 3600, abs=0.001)
    assert observer_calls == list(range(72)) * 2

    # Exercise the normal image authorization with the throwaway test trust anchor.
    shutil.copyfile(old_state / 'public/latest.json', new_state / 'public/latest.json')
    hook_path = ROOT / 'momus/deploy/skopos-warden-quality.py'
    spec = importlib.util.spec_from_file_location('replay_release_hook', hook_path)
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    monkeypatch.setattr(hook, 'CONFIG', tmp_path / 'hook.json')
    quality_cycle.atomic(hook.CONFIG, {'state': str(new_state)})
    monkeypatch.setattr(hook, 'verified_receipt', lambda report, **kwargs:
                        verified_receipt(report, public_key=public_key, **kwargs))
    hook.run('authorize', new_image)
    with pytest.raises(ValueError, match='does not authorize this image'):
        hook.run('authorize', old_image)

    changed_model_state = tmp_path / 'changed-model'
    changed_model_state.mkdir()
    shutil.copyfile(old_state / 'baseline.json', changed_model_state / 'baseline.json')
    monkeypatch.setenv('WARDEN_CLASSIFIER_MODEL', 'another-fixture')
    calls.write_text('')
    _, changed_model = measure(new_build, changed_model_state, new_image, 'candidate',
                               reuseRoots=[str(old_state)])
    assert sum(len(json.loads(batch)) for batch in calls.read_text().splitlines()) == 51
    assert 'semanticReuse' not in changed_model
