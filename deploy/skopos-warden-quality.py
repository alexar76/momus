#!/opt/momus-quality/venv/bin/python
"""Root-owned SKOPOS hook. Immutable image in; isolated evaluation or live promotion out.

The Factory cannot edit this hook, the judge, corpora, key, or build recipe.
No commands or paths are accepted from tickets. Candidate failures never overwrite
live evidence. The ordinary agent still owns Docker promotion and rollback.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, '/opt/momus-quality/source')
from momus.engine.quality_cycle import atomic, build_digest, publish
from momus.targets.quality import passed_receipt, verified_receipt


CONFIG = Path('/etc/momus-quality/config.json')
SOURCE_DIR = Path('/var/lib/skopos-deploy-hand/warden/source')
LIVE_CONTAINER = 'histor-histor-1'


def docker(*args):
    r = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError('Docker operation failed: ' + args[0])
    return r.stdout.strip()


def extract(image, destination):
    cid = docker('create', '--network', 'none', image)
    try:
        destination.mkdir()
        docker('cp', cid + ':/app/scanner/node_modules/@aimarket/warden/.', str(destination))
        # Never follow a symlink supplied by an image into host files or signing keys.
        if any(p.is_symlink() for p in destination.rglob('*')):
            raise ValueError('scanner artifact contains symlinks')
        for p in [destination, *destination.rglob('*')]:
            p.chmod(0o755 if p.is_dir() else 0o644)
        return build_digest(destination)
    finally:
        docker('rm', '-v', cid)


def public_report(report):
    value = {k: v for k, v in report.items() if k not in ('suites', 'discovery')}
    value['suites'] = {k: {f: v[f] for f in ('counts', 'passed')} for k, v in report['suites'].items()}
    value['discovery'] = {k: report['discovery'].get(k) for k in ('round', 'status', 'candidates', 'generation')}
    return value


def rebind(config, state, image):
    """Bind the live evaluation to a new HISTOR image whose vendored WARDEN is byte-identical.

    HISTOR is redeployed for its own code far more often than WARDEN changes. Such an image changes
    nothing the measurement looked at, so it inherits the live binding, the accepted source pointer
    and the daily schedule without a paid re-measurement. Any difference in the WARDEN build — or a
    live receipt that is not fresh and passing for exactly that build — refuses: then the full
    candidate evaluation is the only way in.
    """
    if docker('inspect', '--format', '{{.Image}}', LIVE_CONTAINER) != image:
        raise ValueError('live container does not run the requested image')
    binding = json.loads((state / 'live-image.json').read_text())
    if binding['imageDigest'] == image:
        return
    with tempfile.TemporaryDirectory(dir=state, prefix='artifact-') as scratch:
        actual = extract(image, Path(scratch) / 'warden')
    if actual != binding['buildDigest']:
        raise ValueError('the WARDEN build changed: run the full candidate evaluation')
    live = verified_receipt(json.loads((state / 'public/latest.json').read_text()))
    if live['buildDigest'] != actual or not passed_receipt(live):
        raise ValueError('no fresh passing live evaluation of this build')
    commit = json.loads((SOURCE_DIR / (binding['imageDigest'][7:] + '.json')).read_text())['commit']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('the live image has no enrolled source commit')
    with (state / 'cycle.lock').open('a') as cycle_lock:
        try:
            fcntl.flock(cycle_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('a quality run is in progress; rebind after it') from None
        tree = SOURCE_DIR / 'trees' / binding['imageDigest'][7:]
        if tree.exists() and not (SOURCE_DIR / 'trees' / image[7:]).exists():
            shutil.copytree(tree, SOURCE_DIR / 'trees' / image[7:])
        atomic(SOURCE_DIR / (image[7:] + '.json'), {'commit': commit, 'imageDigest': image})
        atomic(SOURCE_DIR / 'source.json', {'commit': commit, 'imageDigest': image})
        (SOURCE_DIR / 'source.json').chmod(0o644)
        backup = state / 'promotions' / str(time.time_ns())
        backup.mkdir(parents=True)
        atomic(backup / 'promotion.json', {'at': time.time(), 'imageDigest': image, 'buildDigest': actual,
                                           'reboundFrom': binding['imageDigest']})
        atomic(state / 'live-image.json', {'imageDigest': image, 'buildDigest': actual})


def run(phase, image):
    if phase not in ('candidate', 'authorize', 'live', 'rebind') or not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('phase and immutable Docker image digest required')
    config = json.loads(CONFIG.read_text())
    state = Path(config['state'])
    with (state / 'native.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if phase == 'authorize':
            report = verified_receipt(json.loads((state / 'public/candidate.json').read_text()), candidate=True)
            if report['imageDigest'] != image or not passed_receipt(report):
                raise ValueError('latest candidate evidence does not authorize this image')
            live = verified_receipt(json.loads((state / 'public/latest.json').read_text()))
            if (live['buildDigest'] == report['buildDigest'] and live['status'] != 'passed'
                    and live['evaluatedAt'] > report['evaluatedAt']):
                raise ValueError('a newer live evaluation revoked this build')
            return
        if phase == 'rebind':
            return rebind(config, state, image)
        if phase == 'live' and docker('inspect', '--format', '{{.Image}}', LIVE_CONTAINER) != image:
            raise ValueError('live container does not run the requested image')
        with tempfile.TemporaryDirectory(dir=state, prefix='artifact-') as scratch:
            tree = Path(scratch) / 'warden'
            actual = extract(image, tree)
            if phase == 'candidate':
                # Separate root state and public channel; daily live checks may continue.
                stage = state / 'native' / (image[7:] + '-' + str(time.time_ns()))
                stage.mkdir(parents=True)
                stage.chmod(0o711)
                (state / 'native').chmod(0o711)
                build = stage / 'build'
                shutil.copytree(tree, build)
                for parent in [build, *build.rglob('*')]:
                    parent.chmod(0o755 if parent.is_dir() else 0o644)
                for name in ('baseline.json',):
                    shutil.copy2(state / name, stage / name)
                if (state / 'regressions').exists():
                    shutil.copytree(state / 'regressions', stage / 'regressions')
                # Reviewed discovery cases are part of the gate too, not just the initial corpus.
                if (state / 'discovery').exists():
                    shutil.copytree(state / 'discovery', stage / 'discovery', symlinks=True)
                # The stage may reuse a complete same-day measurement of the identical build from the
                # live state (quality_cycle.reusable); a different build always measures afresh.
                staged = {**config, 'state': str(stage), 'candidate': str(build), 'phase': 'candidate',
                          'reuseRoots': [str(state)],
                          'imageDigest': image, 'publication': str(state / 'public' / 'candidate.json')}
                atomic(stage / 'config.json', staged)
                result = subprocess.run(['/usr/bin/python3', '/opt/momus-quality/quality-launch.py',
                                         '--config', str(stage / 'config.json'), '--full'], timeout=14000,
                                        stdout=subprocess.DEVNULL)
                if result.returncode:
                    raise RuntimeError('candidate full quality campaign failed')
                return
            # A live promotion (or rollback) must match fresh COMPLETE evidence from a prior full run.
            reports = list((state / 'runs').glob('*/report.json')) + list((state / 'native').glob('*/runs/*/report.json'))
            valid = []
            for path in reports:
                report = json.loads(path.read_text())
                if (report.get('buildDigest') == actual
                        and report.get('holdoutSha256') == config['holdoutSha256']
                        and report.get('corpusSha256') == config['corpusSha256']
                        and report.get('expiresAt', 0) >= time.time() and passed_receipt(report)):
                    valid.append(report)
            if not valid:
                raise ValueError('no passing full evaluation for the live image')
            report = max(valid, key=lambda r: r['evaluatedAt'])
            with (state / 'cycle.lock').open('a') as cycle_lock:
                fcntl.flock(cycle_lock, fcntl.LOCK_EX)
                # Backups remain private and immutable, including prior accepted source and baseline.
                backup = state / 'promotions' / str(time.time_ns())
                backup.mkdir(parents=True)
                for key in ('candidate', 'accepted'):
                    dst = Path(config[key])
                    shutil.copytree(dst, backup / key)
                    next_tree = dst.with_name(dst.name + '.native-next')
                    shutil.copytree(tree, next_tree)
                    shutil.rmtree(dst)
                    next_tree.rename(dst)
                for name in ('baseline.json', 'full-latest.json'):
                    if (state / name).exists():
                        shutil.copy2(state / name, backup / name)
                # Preserve an accepted source pointer for the next Factory patch, without
                # granting the conductor permission to merge into the protected default branch.
                source_dir = SOURCE_DIR
                source_dir.mkdir(parents=True, exist_ok=True)
                mapping = source_dir / (image[7:] + '.json')
                labels = json.loads(docker('image', 'inspect', '--format', '{{json .Config.Labels}}', image)) or {}
                commit = labels.get('skopos.source.commit', '')
                if not commit and mapping.exists():
                    commit = json.loads(mapping.read_text())['commit']
                if not re.fullmatch(r'[0-9a-f]{40}', commit):
                    raise ValueError('live image has no enrolled source commit')
                # The source is built into candidates by the trusted Dockerfile. Bootstrap
                # images predate that recipe; their mapping is enrolled explicitly by the host.
                if labels.get('skopos.source.commit'):
                    cid = docker('create', '--network', 'none', image)
                    src = Path(scratch) / 'source'
                    try:
                        docker('cp', cid + ':/opt/warden-source/src', str(src))
                    finally:
                        docker('rm', '-v', cid)
                    if any(p.is_symlink() for p in src.rglob('*')):
                        raise ValueError('source symlink refused')
                    current_source = Path('/root/aicom/warden/src')
                    shutil.copytree(current_source, backup / 'source')
                    for file in src.rglob('*'):
                        if file.is_file():
                            relative = file.relative_to(src)
                            destination = current_source / relative
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(file, destination)
                            destination.chmod(0o644)
                elif (source_dir / 'trees' / image[7:]).exists():
                    current_source = Path('/root/aicom/warden/src')
                    shutil.copytree(current_source, backup / 'source')
                    shutil.copytree(source_dir / 'trees' / image[7:], current_source, dirs_exist_ok=True)
                snapshot = source_dir / 'trees' / image[7:]
                if not snapshot.exists():
                    shutil.copytree('/root/aicom/warden/src', snapshot)
                atomic(mapping, {'commit': commit, 'imageDigest': image})
                atomic(source_dir / 'source.json', {'commit': commit, 'imageDigest': image})
                (source_dir / 'source.json').chmod(0o644)
                report = {**report, 'phase': 'live', 'imageDigest': image, 'sourceCommit': commit}
                # A rollback may rely on a fresh daily report plus its still-valid full
                # evaluation. Preserve the full per-case baseline instead of shrinking it
                # to that day's sample.
                full_reports = [json.loads(p.read_text()) for p in reports]
                full_reports = [r for r in full_reports if r.get('full') and r.get('status') == 'passed'
                                and r.get('buildDigest') == actual and passed_receipt(r)]
                if not full_reports:
                    raise ValueError('full baseline unavailable')
                baseline = max(full_reports, key=lambda r: r['evaluatedAt'])
                atomic(state / 'baseline.json', baseline)
                atomic(state / 'full-latest.json', baseline)
                # Existing held-out rows stay private; the public receipt only has counts.
                publish(config, public_report(report))
                atomic(state / 'live-image.json', {'imageDigest': image, 'buildDigest': actual})
                atomic(backup / 'promotion.json', {'at': time.time(), 'imageDigest': image, 'buildDigest': actual})


if __name__ == '__main__':
    os.umask(0o077)
    try:
        run(*sys.argv[1:])
    except Exception as exc:
        print('WARDEN quality hook refused: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
