"""Trusted model-response reuse and same-build HISTOR rebinding."""
import fcntl
import importlib.util
import json
import time
from hashlib import sha256
from pathlib import Path

import pytest

from momus.engine import quality_cycle
from momus.engine.quality_cycle import REUSE_MAX_AGE_S, build_digest, reusable, write_cases

ROOT = Path(__file__).parents[1]
RESPONSES = b'{"requestSha256":"example","content":"recorded response"}\n'


def fake_build(path, marker):
    (path / 'dist').mkdir(parents=True)
    (path / 'dist/classifier.js').write_text('// Classifier\n')
    (path / 'dist/scan.js').write_text(marker)
    return path


def earlier(state, build, corpus_hash, *, at, suite='development', native=False, passed=True,
            status='passed', reused=None, stamp='r1'):
    run = (state / 'native' / 'stage' / 'runs' / stamp) if native else (state / 'runs' / stamp)
    folder = run / suite
    folder.mkdir(parents=True)
    (folder / 'model-responses.jsonl').write_bytes(RESPONSES)
    identity = {'corpusSha256': corpus_hash, 'buildDigest': build_digest(build),
                'modelResponsesSha256': sha256(RESPONSES).hexdigest()}
    if reused is not None:
        identity['reused'] = reused
    (run / 'report.json').write_text(json.dumps({
        'evaluatedAt': at, 'run': stamp, 'buildDigest': build_digest(build), 'status': status,
        'suites': {suite: {'passed': passed, 'identity': identity}},
    }))
    return folder


def test_fresh_matching_responses_can_seed_a_different_build(tmp_path):
    before = fake_build(tmp_path / 'before', '// original scan')
    after = fake_build(tmp_path / 'after', '// updated scan')
    state = tmp_path / 'state'
    now = 65_000
    earlier(state, before, 'corpus', at=now - 120)
    stage = earlier(state, before, 'corpus', at=now - 30, stamp='staged', native=True)
    earlier(state, before, 'different-corpus', at=now - 20, stamp='different-corpus')
    earlier(state, before, 'corpus', at=now - 10, suite='holdout', stamp='holdout')
    config = {'state': str(tmp_path / 'next-stage'), 'reuseRoots': [str(state)]}

    assert build_digest(before) != build_digest(after)
    assert reusable(config, 'corpus', 'development', now=now) == (stage, now - 30, RESPONSES)


@pytest.mark.parametrize('sample', ['expired', 'future', 'failed-run', 'failed-suite', 'replayed', 'tampered',
                                    'unbound', 'symlink', 'candidates'])
def test_host_rejects_ineligible_response_archives(tmp_path, sample):
    build = fake_build(tmp_path / 'build', '// scan')
    state = tmp_path / 'state'
    now = 65_000
    measured = {'expired': now - REUSE_MAX_AGE_S - 1, 'future': now + 1}.get(sample, now - 60)
    suite = 'candidates' if sample == 'candidates' else 'development'
    reused = {'run': 'old', 'measuredAt': now - REUSE_MAX_AGE_S - 1, 'rows': 4, 'requests': 1}
    source = earlier(
        state, build, 'corpus', at=measured, suite=suite, passed=sample != 'failed-suite',
        status='failed' if sample == 'failed-run' else 'passed',
        reused=reused if sample == 'replayed' else None,
    )
    if sample == 'tampered':
        (source / 'model-responses.jsonl').write_bytes(b'{}\n')
    elif sample == 'unbound':
        report = source.parent / 'report.json'
        document = json.loads(report.read_text())
        del document['suites'][suite]['identity']['modelResponsesSha256']
        report.write_text(json.dumps(document))
    elif sample == 'symlink':
        contents = tmp_path / 'linked-responses'
        (source / 'model-responses.jsonl').rename(contents)
        (source / 'model-responses.jsonl').symlink_to(contents)

    assert reusable({'state': str(state)}, 'corpus', suite, now=now) is None


def test_semantic_records_response_provenance_and_the_current_build(tmp_path, monkeypatch):
    before = fake_build(tmp_path / 'before', '// original scan')
    after = fake_build(tmp_path / 'after', '// updated scan')
    state = tmp_path / 'state'
    config = {'state': str(state)}
    cs = [{'id': 'case-0', 'label': 'benign', 'language': 'en', 'tools': [{'name': 'lookup'}]}]
    corpus_hash = write_cases(tmp_path / 'probe.gz', cs)
    measured_at = time.time() - 3600
    earlier(state, before, corpus_hash, at=measured_at)
    row = {'id': 'case-0', 'status': 'scanned', 'findings': [], 'reviewedStatic': {'allow': True}}

    def fake_worker(config, argv, folder, timeout=14400):
        assert (folder / 'reuse/model-responses.jsonl').read_bytes() == RESPONSES
        assert not (folder / 'reuse/decisions.jsonl').exists()
        (folder / 'identity.json').write_text(json.dumps({'buildDigest': build_digest(after), 'corpusSha256': corpus_hash}))
        (folder / 'decisions.jsonl').write_text(json.dumps(row) + '\n')
        (folder / 'reuse.json').write_text('{"rows": 1, "requests": 1}')
        (folder / 'model-responses.jsonl').write_bytes(RESPONSES)

    monkeypatch.setattr(quality_cycle, 'worker', fake_worker)
    rows, identity = quality_cycle.semantic(config, after, cs, tmp_path / 'run' / 'development')
    assert rows == [row]
    assert identity['buildDigest'] == build_digest(after)
    assert identity['reused'] == {'run': 'r1', 'measuredAt': measured_at, 'rows': 1, 'requests': 1}
    assert identity['modelResponsesSha256'] == sha256(RESPONSES).hexdigest()


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
