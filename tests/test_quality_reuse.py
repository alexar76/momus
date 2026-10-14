"""A paid measurement is bought once per identical input; a HISTOR image with the same WARDEN costs nothing."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest

from momus.engine import quality_cycle
from momus.engine.quality_cycle import REUSE_MAX_AGE_S, build_digest, reusable, write_cases

ROOT = Path(__file__).parents[1]
SEMANTIC = ROOT / 'momus/engine/coverage_semantic.mjs'
CLASSIFIER = """import { appendFileSync } from 'node:fs';
export const CLASSIFIER_SYSTEM_PROMPT = 'synthetic prompt';
export async function inspectTools(tools) {
  appendFileSync(process.env.FAKE_CALLS, 'call\\n');
  return { findings: tools.map((t, index) => ({ index, severity: 'high', categories: ['secret_request'] })), incomplete: [] };
}
"""
INDEX = """export class ThreatFeed {}
export const Warden = { create: () => ({ vet: async () => ({ allow: false, findings: [] }) }) };
"""


def fake_build(path, marker=''):
    (path / 'dist').mkdir(parents=True)
    (path / 'dist/classifier.js').write_text(CLASSIFIER + marker)
    (path / 'dist/index.js').write_text(INDEX)
    return path


def cases(n=10):
    return [{'id': f'case-{i}', 'label': 'malicious', 'language': 'en',
             'tools': [{'name': 'do_task', 'description': f'variant {i}'}]} for i in range(n)]


def measure(build, corpus, out, calls, *, model='synthetic-model'):
    env = {'PATH': os.environ['PATH'], 'WARDEN_CLASSIFIER_URL': 'https://classifier.invalid/v1',
           'WARDEN_CLASSIFIER_MODEL': model, 'WARDEN_CLASSIFIER_API_KEY': 'synthetic-key',
           'WARDEN_CLASSIFIER_EVAL_CONCURRENCY': '2', 'FAKE_CALLS': str(calls)}
    subprocess.run(['node', str(SEMANTIC), str(build), str(corpus), str(out)], env=env, check=True,
                   capture_output=True, timeout=60)
    return len(calls.read_text().splitlines()) if calls.exists() else 0


def seed(source, out):
    (out / 'reuse').mkdir(parents=True)
    for name in ('identity.json', 'decisions.jsonl'):
        shutil.copyfile(source / name, out / 'reuse' / name)


def test_identical_identity_reuses_every_finished_row_and_buys_nothing(tmp_path):
    build = fake_build(tmp_path / 'build')
    corpus = tmp_path / 'cases.jsonl.gz'
    write_cases(corpus, cases())
    calls = tmp_path / 'calls'
    assert measure(build, corpus, tmp_path / 'first', calls) == 2  # 10 cases, 8 per batch

    seed(tmp_path / 'first', tmp_path / 'second')
    assert measure(build, corpus, tmp_path / 'second', calls) == 2, 'no new paid call'
    assert json.loads((tmp_path / 'second/reuse.json').read_text()) == {'rows': 10}
    assert (json.loads((tmp_path / 'second/report.json').read_text())['attacks']
            == json.loads((tmp_path / 'first/report.json').read_text())['attacks'])


def test_another_model_or_build_never_reuses(tmp_path):
    build = fake_build(tmp_path / 'build')
    corpus = tmp_path / 'cases.jsonl.gz'
    write_cases(corpus, cases())
    calls = tmp_path / 'calls'
    measure(build, corpus, tmp_path / 'first', calls)
    seed(tmp_path / 'first', tmp_path / 'other-model')
    assert measure(build, corpus, tmp_path / 'other-model', calls, model='another-model') == 4
    assert not (tmp_path / 'other-model/reuse.json').exists()
    seed(tmp_path / 'first', tmp_path / 'other-build')
    assert measure(fake_build(tmp_path / 'build2', '// changed\n'), corpus, tmp_path / 'other-build', calls) == 6


def test_an_unfinished_row_is_measured_again(tmp_path):
    build = fake_build(tmp_path / 'build')
    corpus = tmp_path / 'cases.jsonl.gz'
    write_cases(corpus, cases())
    calls = tmp_path / 'calls'
    measure(build, corpus, tmp_path / 'first', calls)
    seed(tmp_path / 'first', tmp_path / 'second')
    rows = [json.loads(line) for line in (tmp_path / 'second/reuse/decisions.jsonl').read_text().splitlines()]
    rows[0]['status'] = 'incomplete'
    (tmp_path / 'second/reuse/decisions.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    assert measure(build, corpus, tmp_path / 'second', calls) == 3, 'exactly one batch for one row'
    assert json.loads((tmp_path / 'second/reuse.json').read_text()) == {'rows': 9}


def earlier(state, build, corpus_hash, *, at, suite='development', native=False, incomplete=0, stamp='r1'):
    run = (state / 'native' / 'stage' / 'runs' / stamp) if native else (state / 'runs' / stamp)
    folder = run / suite
    folder.mkdir(parents=True)
    (folder / 'identity.json').write_text(json.dumps({'corpusSha256': corpus_hash, 'buildDigest': build_digest(build)}))
    counts = {'total': 4, 'inspected': 4 - incomplete, 'high': 4, 'flagged': 4, 'incomplete': incomplete}
    (folder / 'report.json').write_text(json.dumps({'attacks': counts, 'benign': {**counts, 'total': 0, 'inspected': 0,
                                                                                   'incomplete': 0}}))
    (folder / 'decisions.jsonl').write_text('')
    (run / 'report.json').write_text(json.dumps({'evaluatedAt': at}))
    return folder


def test_only_a_complete_same_day_measurement_of_the_same_inputs_is_reused(tmp_path):
    build = fake_build(tmp_path / 'build')
    state = tmp_path / 'state'
    now = time.time()
    config = {'state': str(state)}
    assert reusable(config, build, 'corpus', 'development', now=now) is None
    old = earlier(state, build, 'corpus', at=now - REUSE_MAX_AGE_S - 60, stamp='old')
    assert reusable(config, build, 'corpus', 'development', now=now) is None, 'older than twelve hours'
    earlier(state, build, 'corpus', at=now - 60, stamp='partial', incomplete=1)
    assert reusable(config, build, 'corpus', 'development', now=now) is None, 'a partial measurement'
    assert reusable(config, build, 'other-corpus', 'development', now=now) is None
    fresh = earlier(state, build, 'corpus', at=now - 120, stamp='fresh')
    assert reusable(config, build, 'corpus', 'development', now=now) == (fresh, now - 120)
    assert reusable(config, build, 'corpus', 'holdout', now=now) is None, 'suites never mix'
    assert reusable(config, fake_build(tmp_path / 'other'  , '//x'), 'corpus', 'development', now=now) is None
    stage = earlier(state, build, 'corpus', at=now - 30, stamp='staged', native=True)
    assert reusable(config, build, 'corpus', 'development', now=now) == (stage, now - 30), 'candidate stages count'
    # a candidate stage looks into the live state through reuseRoots
    assert reusable({'state': str(tmp_path / 'empty'), 'reuseRoots': [str(state)]}, build, 'corpus',
                    'development', now=now)[0] == stage
    assert old.exists()


def test_semantic_seeds_the_worker_and_the_report_expires_with_the_original(tmp_path, monkeypatch):
    build = fake_build(tmp_path / 'build')
    state = tmp_path / 'state'
    config = {'state': str(state)}
    cs = cases(4)
    corpus_hash = write_cases(tmp_path / 'probe.gz', cs)
    measured_at = time.time() - 3600
    source = earlier(state, build, corpus_hash, at=measured_at)
    (source / 'decisions.jsonl').write_text('{"id":"case-0"}\n')

    def fake_worker(config, argv, folder, timeout=14400):
        assert (folder / 'reuse/decisions.jsonl').read_text() == '{"id":"case-0"}\n'
        (folder / 'identity.json').write_text(json.dumps({'buildDigest': build_digest(build), 'corpusSha256': corpus_hash}))
        (folder / 'decisions.jsonl').write_text('')
        (folder / 'reuse.json').write_text('{"rows": 4}')
    monkeypatch.setattr(quality_cycle, 'worker', fake_worker)
    rows, identity = quality_cycle.semantic(config, build, cs, tmp_path / 'run' / 'development')
    assert identity['reused'] == {'run': 'r1', 'measuredAt': measured_at, 'rows': 4}


def load_hook():
    spec = importlib.util.spec_from_file_location('warden_quality_hook', ROOT / 'deploy/skopos-warden-quality.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def hook(tmp_path, monkeypatch):
    module = load_hook()
    state, source = tmp_path / 'state', tmp_path / 'source'
    (state / 'public').mkdir(parents=True)
    (source / 'trees' / ('a' * 64)).mkdir(parents=True)
    (source / 'trees' / ('a' * 64) / 'index.ts').write_text('accepted source')
    (source / ('a' * 64 + '.json')).write_text(json.dumps({'commit': 'c' * 40, 'imageDigest': 'sha256:' + 'a' * 64}))
    (state / 'live-image.json').write_text(json.dumps({'imageDigest': 'sha256:' + 'a' * 64, 'buildDigest': 'build'}))
    (state / 'public/latest.json').write_text('{}')
    monkeypatch.setattr(module, 'SOURCE_DIR', source)
    world = {'running': 'sha256:' + 'b' * 64, 'build': 'build', 'receipt': {'buildDigest': 'build'}, 'passed': True}
    monkeypatch.setattr(module, 'docker', lambda *a: world['running'])
    monkeypatch.setattr(module, 'extract', lambda image, dest: world['build'])
    monkeypatch.setattr(module, 'verified_receipt', lambda envelope: world['receipt'])
    monkeypatch.setattr(module, 'passed_receipt', lambda report: world['passed'])
    return module, state, source, world


def test_rebind_moves_the_binding_and_source_pointer_without_measuring(hook):
    module, state, source, world = hook
    image = world['running']
    module.rebind({}, state, image)
    assert json.loads((state / 'live-image.json').read_text()) == {'imageDigest': image, 'buildDigest': 'build'}
    assert json.loads((source / 'source.json').read_text()) == {'commit': 'c' * 40, 'imageDigest': image}
    assert json.loads((source / (image[7:] + '.json')).read_text())['commit'] == 'c' * 40
    assert (source / 'trees' / image[7:] / 'index.ts').read_text() == 'accepted source'
    record = json.loads(next((state / 'promotions').glob('*/promotion.json')).read_text())
    assert record['reboundFrom'] == 'sha256:' + 'a' * 64
    assert not list(state.glob('runs/*')), 'nothing was measured'


@pytest.mark.parametrize('change,message', [
    ({'build': 'other'}, 'WARDEN build changed'),
    ({'passed': False}, 'no fresh passing'),
    ({'receipt': {'buildDigest': 'other'}}, 'no fresh passing'),
])
def test_rebind_refuses_a_changed_warden_or_a_failing_evaluation(hook, change, message):
    module, state, source, world = hook
    world.update(change)
    before = (state / 'live-image.json').read_text()
    with pytest.raises(ValueError, match=message):
        module.rebind({}, state, world['running'])
    assert (state / 'live-image.json').read_text() == before


def test_rebind_refuses_an_image_that_is_not_running_or_a_run_in_progress(hook):
    module, state, source, world = hook
    with pytest.raises(ValueError, match='does not run'):
        module.rebind({}, state, 'sha256:' + 'd' * 64)
    with (state / 'cycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with pytest.raises(RuntimeError, match='in progress'):
            module.rebind({}, state, world['running'])
    assert json.loads((state / 'live-image.json').read_text())['imageDigest'] == 'sha256:' + 'a' * 64
