"""Scheduled, fail-closed live quality gate. Model proposals never label themselves.

The trusted host owns configuration, sealed holdout, accepted build and signing key.
Candidate WARDEN code runs without the signing key. Evidence and remediation fixtures
are durable; only an explicit accept command advances the reference build.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import gzip
import hashlib
import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    with temp.open("wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def build_digest(build):
    h = hashlib.sha256()
    files = sorted((Path(build) / "dist").glob("*.js"))
    if not files:
        raise ValueError("WARDEN build missing")
    if any(p.name.startswith('._') for p in files):
        raise ValueError('remove AppleDouble transfer metadata before evaluating the build')
    for p in files:
        h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def read_cases(path):
    raw = gzip.decompress(Path(path).read_bytes())
    cases = [json.loads(line) for line in raw.splitlines()]
    if (not cases or len({c['id'] for c in cases}) != len(cases)
            or any(c['label'] not in ('malicious', 'benign', 'candidate') for c in cases)):
        raise ValueError("invalid corpus")
    return cases, digest(raw)


def write_cases(path, cases):
    raw = b"".join(canonical(c) + b"\n" for c in cases)
    Path(path).write_bytes(gzip.compress(raw, mtime=0))
    return digest(raw)


def verdict(row):
    # Missing semantic coverage must block release even if a static rule fired.
    static = row.get('reviewedStatic', {})
    if (row.get('status') != 'scanned' or static.get('status') != 'scanned'
            or type(static.get('allow')) is not bool or not isinstance(row.get('findings'), list)):
        return 'incomplete'
    if static.get('allow') is False or any(f.get('severity') == 'high' for f in row.get('findings', [])):
        return 'blocked'
    return 'allowed'


def assess(cases, rows, baseline=None):
    expected = {c['id'] for c in cases}
    if len(rows) != len(expected) or {r['id'] for r in rows} != expected:
        raise ValueError('missing, duplicate or unknown decisions')
    decisions = {r['id']: verdict(r) for r in rows}
    failures, regressions = [], []
    counts = dict(attacks=0, benign=0, candidates=0, missed=0, falsePositives=0, incomplete=0)
    for c in cases:
        label, result = c['label'], decisions[c['id']]
        counts[{'malicious': 'attacks', 'benign': 'benign', 'candidate': 'candidates'}[label]] += 1
        reason = ('incomplete' if result == 'incomplete' else
                  'missed' if label == 'malicious' and result != 'blocked' else
                  'falsePositives' if label == 'benign' and result != 'allowed' else None)
        if reason:
            counts[reason] += 1
            failures.append({'id': c['id'], 'reason': reason})
        if baseline and c['id'] in baseline and baseline[c['id']] != result:
            correct = 'blocked' if label == 'malicious' else 'allowed'
            if label != 'candidate' and baseline[c['id']] == correct and result != correct:
                regressions.append(c['id'])
    return {'counts': counts, 'failures': failures, 'regressions': regressions,
            'decisions': decisions, 'passed': not failures and not regressions}


def command(argv, log, *, env=None, timeout=14400):
    # The evaluator owns its working directory; never follow a planted log symlink as root.
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed: {Path(argv[0]).name}; see private run log')


def worker(config, argv, folder, *, timeout=14400):
    """Only provider keys reach the evaluator; signing and sandbox keys stay in parent."""
    import pwd
    account = pwd.getpwnam(config['workerUser'])
    for path in [folder, *folder.rglob('*')]:
        os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'PYTHONPATH', 'LANG')
           or k.startswith(('WARDEN_CLASSIFIER_', 'MOMUS_LLM_'))}
    command(['setpriv', '--reuid', str(account.pw_uid), '--regid', str(account.pw_gid),
             '--init-groups', '--no-new-privs', *argv], folder / 'process.log', env=env, timeout=timeout)


# A COMPLETE earlier measurement of byte-identical inputs is reused instead of bought again:
# the same cases, the same WARDEN build (which carries the classifier prompt), and — checked by
# coverage_semantic.mjs against its own identity, field for field — the same model, endpoint and
# protocol. Only for twelve hours: the scheduled daily run is always a day apart and so always
# measures afresh (a provider can change the model behind the same name), while a same-day
# repeat — a retry, or a HISTOR image whose vendored WARDEN did not change — costs nothing.
# A partial measurement is never reused. A report that reuses one expires 48 h after the
# original measurement, not after the reuse.
REUSE_MAX_AGE_S = 12 * 3600


def reusable(config, build, corpus_hash, suite, *, now=None):
    """(folder, measuredAt) of the newest complete measurement of exactly these cases with this
    build under this host's evaluator state, or None."""
    now = time.time() if now is None else now
    roots = [Path(config['state']), *map(Path, config.get('reuseRoots', []))]
    expected = build_digest(build)
    found = []
    for root in roots:
        for identity_path in (*root.glob(f'runs/*/{suite}/identity.json'),
                              *root.glob(f'native/*/runs/*/{suite}/identity.json')):
            folder = identity_path.parent
            try:
                identity = json.loads(identity_path.read_text())
                measured = json.loads((folder / 'report.json').read_text())
                started = json.loads((folder.parent / 'report.json').read_text()).get('evaluatedAt')
            except (OSError, ValueError, AttributeError):
                continue
            complete = all(isinstance(measured.get(k), dict) and measured[k].get('incomplete') == 0
                           and measured[k].get('inspected') == measured[k].get('total')
                           for k in ('attacks', 'benign'))
            if (identity.get('corpusSha256') == corpus_hash and identity.get('buildDigest') == expected
                    and isinstance(started, (int, float)) and now - REUSE_MAX_AGE_S <= started <= now
                    and complete and (folder / 'decisions.jsonl').is_file()):
                found.append((started, folder))
    if not found:
        return None
    started, folder = max(found, key=lambda item: item[0])
    return folder, started


def semantic(config, build, cases, folder):
    folder.mkdir(parents=True)
    corpus_hash = write_cases(folder / 'cases.jsonl.gz', cases)
    earlier = reusable(config, build, corpus_hash, folder.name)
    if earlier:
        seed = folder / 'reuse'
        seed.mkdir()
        for name in ('identity.json', 'decisions.jsonl'):
            shutil.copyfile(earlier[0] / name, seed / name)
    worker(config, [config.get('node', 'node'), str(Path(__file__).with_name('coverage_semantic.mjs')),
                    str(build), str(folder / 'cases.jsonl.gz'), str(folder)], folder)
    identity = json.loads((folder / 'identity.json').read_text())
    if identity['buildDigest'] != build_digest(build) or identity['corpusSha256'] != corpus_hash:
        raise ValueError('semantic evidence does not bind this build and corpus')
    rows = [json.loads(line) for line in (folder / 'decisions.jsonl').read_text().splitlines()]
    if earlier:
        # The worker says how many rows it took; the age is the host's own record, never the worker's.
        used = json.loads((folder / 'reuse.json').read_text()) if (folder / 'reuse.json').exists() else {}
        identity = {**identity, 'reused': {'run': earlier[0].parent.name, 'measuredAt': earlier[1],
                                           'rows': int(used.get('rows', 0))}}
    return rows, identity


def pinned_request(url, pin, token, body):
    target = urlsplit(url)
    if target.scheme != 'https' or target.username or target.query or target.fragment:
        raise ValueError('sandbox requires a pinned HTTPS endpoint')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Certificate pinned BEFORE sending the bearer token.
    conn = http.client.HTTPSConnection(target.hostname, target.port or 443, context=context, timeout=900)
    try:
        conn.connect()
        actual = digest(conn.sock.getpeercert(binary_form=True))
        if actual != pin.lower().removeprefix('sha256:').replace(':', ''):
            raise ValueError('sandbox certificate pin mismatch')
        conn.request('POST', target.path.rstrip('/') + '/campaign-case', canonical(body),
                     {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if response.status != 200 or len(raw) > 2 * 1024 * 1024:
            raise RuntimeError('sandbox inspection unavailable')
        return json.loads(raw)
    finally:
        conn.close()


def behaviour(config, folder, seed, indices=None):
    from momus.engine.behaviour_campaign import generate
    cases = generate(seed)
    rows = []
    for index, case in enumerate(cases):
        if indices is not None and index not in indices:
            continue
        try:
            result = pinned_request(os.environ['HISTOR_SANDBOX_URL'], os.environ['HISTOR_SANDBOX_CERT_SHA256'],
                                    os.environ['HISTOR_SANDBOX_TOKEN'], {'seed': seed, 'index': index})
            if (result['observerSha256'] != config['observerSha256']
                    or result['fixturesSha256'] != config['fixturesSha256']
                    or result['decision']['id'] != case['id']):
                raise ValueError('behaviour evidence identity mismatch')
            row = result['decision']
        except Exception as exc:
            row = {'id': case['id'], 'complete': False, 'status': 'incomplete', 'error': type(exc).__name__}
        rows.append(row)
        with (folder / 'behaviour-decisions.jsonl').open('a') as stream:
            stream.write(canonical(row).decode() + '\n')
        if not row.get('complete') or row['status'] != 'observed':
            atomic(folder / 'remediation' / (case['id'] + '.json'),
                   {'suite': 'behaviour', 'fixture': case, 'decision': row})
    expected = len(cases) if indices is None else len(indices)
    result = {'cases': expected, 'executed': len(rows), 'evaluatedAt': time.time(),
              'observerSha256': config['observerSha256'], 'fixturesSha256': config['fixturesSha256'],
              'seed': seed, 'missed': sum(r['status'] == 'missed' for r in rows),
              'falsePositives': sum(r['status'] == 'false-positive' for r in rows),
              'incomplete': sum(r.get('complete') is not True for r in rows)}
    result['passed'] = len(rows) == expected and not any(result[k] for k in ('missed', 'falsePositives', 'incomplete'))
    atomic(folder / 'behaviour.json', result)
    return result


def publish(config, report):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    private = load_pem_private_key(Path(config['signingKey']).read_bytes(), password=None)
    payload = canonical(report)
    envelope = {'payload': base64.b64encode(payload).decode(),
                'signature': base64.b64encode(private.sign(payload)).decode()}
    destination = Path(config.get('publication', str(Path(config['state']) / 'public' / 'latest.json')))
    atomic(destination, envelope)
    destination.chmod(0o644)
    (Path(config['state']) / 'public').mkdir(exist_ok=True)
    (Path(config['state']) / 'public').chmod(0o755)
    # Publication may be a separate candidate channel owned by the host.
    return envelope


def run(config, *, full=False):
    state = Path(config['state'])
    state.mkdir(parents=True, exist_ok=True)
    with (state / 'cycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
        folder = state / 'runs' / stamp
        folder.mkdir(parents=True)
        # Worker can traverse to its own run, but cannot list/read private parent state.
        for parent in (state, state / 'runs', folder):
            parent.chmod(0o711)
        report = {'type': 'momus.release-quality/v1', 'policy': 'zero-regressions-v1',
                  'run': stamp, 'evaluatedAt': time.time(), 'expiresAt': time.time() + 48 * 3600,
                  'status': 'running', 'full': full, 'buildDigest': build_digest(config['candidate']),
                  'baselineBuildDigest': build_digest(config['accepted']),
                  'imageDigest': config.get('imageDigest', ''), 'phase': config.get('phase', 'live')}
        # Immediately invalidate a stale green status while new evidence is incomplete.
        publish(config, report)
        try:
            corpus, corpus_hash = read_cases(config['corpus'])
            holdout, holdout_hash = read_cases(config['holdout'])
            if holdout_hash != config['holdoutSha256'] or corpus_hash != config['corpusSha256']:
                raise ValueError('sealed corpus hash mismatch')
            if len(holdout) < 40 or {c['label'] for c in holdout} != {'malicious', 'benign'}:
                raise ValueError('holdout must contain both labels and at least 40 cases')
            if {digest(canonical(c['tools'])) for c in corpus} & {digest(canonical(c['tools'])) for c in holdout}:
                raise ValueError('holdout overlaps development corpus')
            regressions = [json.loads(p.read_text())['fixture'] for p in sorted((state / 'regressions').glob('*.json'))]
            # Reviewed LLM proposals enter every subsequent gate, never just a one-off run.
            db_path = state / 'discovery' / 'coverage.sqlite3'
            if db_path.exists():
                import sqlite3
                with sqlite3.connect(db_path) as db:
                    reviewed = [json.loads(row[0]) for row in db.execute('SELECT variant FROM cases')]
                regressions += [c for c in reviewed if c.get('source') == 'llm' and c['label'] in ('malicious', 'benign')]
            selected = corpus if full else sorted(corpus, key=lambda c: digest((stamp[:8] + c['id']).encode()))[:256]
            suites = {'development': selected, 'holdout': holdout,
                      'regressions': list({c['id']: c for c in regressions}.values())}
            report['corpusSha256'], report['holdoutSha256'] = corpus_hash, holdout_hash
            report['suites'] = {}
            baseline_path = state / 'baseline.json'
            baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else None
            if baseline and baseline['buildDigest'] != report['baselineBuildDigest']:
                raise ValueError('accepted baseline identity mismatch')
            for name, cases in suites.items():
                if not cases:
                    continue
                rows, identity = semantic(config, config['candidate'], cases, folder / name)
                previous = baseline['suites'].get(name, {}).get('decisions', {}) if baseline else None
                result = assess(cases, rows, previous)
                result['identity'] = identity
                report['suites'][name] = result
                by_id = {c['id']: c for c in cases}
                for failure in result['failures']:
                    item = {'suite': name, 'fixture': by_id[failure['id']], 'failure': failure, 'firstRun': stamp}
                    atomic(folder / 'remediation' / (digest(failure['id'].encode()) + '.json'), item)
                    # Sealed holdout examples are not leaked into the training/regression corpus.
                    if name != 'holdout' and failure['reason'] != 'incomplete':
                        path = state / 'regressions' / (digest(failure['id'].encode()) + '.json')
                        if not path.exists():
                            atomic(path, item)
            behaviour_path = state / 'behaviour-latest.json'
            old = json.loads(behaviour_path.read_text()) if behaviour_path.exists() else {}
            due = (full or old.get('observerSha256') != config['observerSha256']
                   or old.get('fixturesSha256') != config['fixturesSha256']
                   or time.time() - old.get('evaluatedAt', 0) > 30 * 86400)
            report['behaviour'] = behaviour(config, folder, stamp) if due else old
            if due:
                atomic(behaviour_path, report['behaviour'])
                report['behaviourSmoke'] = report['behaviour']
            else:
                smoke = folder / 'behaviour-smoke'
                smoke.mkdir()
                # Verify the live observer identity and one decoy read in each lifecycle phase
                # daily, so a changed/down observer cannot inherit last month's green result.
                report['behaviourSmoke'] = behaviour(config, smoke, stamp, indices={6, 30, 54})
            # Fresh LLM candidates have no ground-truth label. Keep them for explicit review.
            discovery_dir = state / 'discovery'
            discovery_dir.mkdir(exist_ok=True)
            worker(config, [sys.executable, '-m', 'momus.engine.coverage_campaign', 'run', '--warden', config['candidate'],
                     '--data-dir', str(state / 'discovery'), '--llm', '--llm-limit', '8', '--fresh', '128',
                     '--seed', stamp], discovery_dir, timeout=600)
            discovery = json.loads((state / 'discovery' / 'latest.json').read_text())
            report['discovery'] = discovery
            if discovery['status'] != 'complete' or discovery['generation'].get('status') != 'ok':
                raise RuntimeError('fresh adversarial generation did not complete')
            # Inspect novel candidates semantically too, retaining unreviewed labels.
            document = json.loads((discovery_dir / 'rounds' / f"{int(discovery['round']):06d}" / 'cases.json').read_text())
            candidates = [c['variant'] for c in document if c['variant']['label'] == 'candidate']
            if not candidates:
                raise RuntimeError('generator produced no novel review candidates')
            rows, identity = semantic(config, config['candidate'], candidates, folder / 'candidates')
            result = assess(candidates, rows)
            result['identity'] = identity
            report['suites']['candidates'] = result
            by_id = {r['id']: r for r in rows}
            for case in candidates:
                atomic(state / 'review-queue' / (digest(case['id'].encode()) + '.json'),
                       {'fixture': case, 'decision': by_id[case['id']], 'run': stamp, 'requiresHumanLabel': True})
            reused = [s['identity']['reused']['measuredAt'] for s in report['suites'].values()
                      if s.get('identity', {}).get('reused')]
            if reused:
                report['expiresAt'] = min(report['expiresAt'], min(reused) + 48 * 3600)
            report['status'] = ('passed' if all(s['passed'] for s in report['suites'].values())
                                and report['behaviour']['passed'] and report['behaviourSmoke']['passed'] else 'failed')
            # Only a complete full run can serve as the initial baseline; zero errors required.
            if baseline is None:
                if not full or report['status'] != 'passed' or report['buildDigest'] != report['baselineBuildDigest']:
                    raise ValueError('bootstrap needs a passing full run of the accepted build')
                atomic(baseline_path, report)
            last_full = state / 'full-latest.json'
            if full:
                atomic(last_full, report)
            previous_full = json.loads(last_full.read_text()) if last_full.exists() else {}
            report['fullEvidence'] = {k: previous_full.get(k) for k in ('status', 'buildDigest', 'evaluatedAt', 'holdoutSha256')}
        except Exception as exc:
            report['status'] = 'failed'
            report['error'] = type(exc).__name__  # Never publish credential-bearing provider responses.
            atomic(folder / 'error.json', {'type': type(exc).__name__, 'message': str(exc)[:300]})
        atomic(folder / 'report.json', report)
        # Public evidence contains counts/digests, not the private holdout or model text.
        public = {k: v for k, v in report.items() if k not in ('suites', 'discovery')}
        # Only established development fixtures may reach the fixer; never the sealed holdout.
        public['repairCases'] = []
        for item_path in sorted((folder / 'remediation').glob('*.json')):
            item = json.loads(item_path.read_text())
            if item.get('suite') in ('development', 'regressions') and item.get('failure', {}).get('reason') in ('missed', 'falsePositives'):
                if len(canonical(public['repairCases'] + [item])) < 24000:
                    public['repairCases'].append(item)
                if len(public['repairCases']) >= 8:
                    break
        public['suites'] = {k: {f: v[f] for f in ('counts', 'passed')} for k, v in report.get('suites', {}).items()}
        if 'discovery' in report:
            public['discovery'] = {k: report['discovery'].get(k) for k in ('round', 'status', 'candidates', 'generation')}
        publish(config, public)
        print(json.dumps(public), flush=True)
        return 0 if report['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--accept', help='Explicitly promote a passing full run to the reference build')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.accept:
        state = Path(config['state'])
        with (state / 'cycle.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not args.accept.isalnum():
                raise ValueError('invalid run identifier')
            report = json.loads((state / 'runs' / args.accept / 'report.json').read_text())
            if (report['status'] != 'passed' or not report['full'] or report['expiresAt'] < time.time()
                    or report['buildDigest'] != build_digest(config['candidate'])
                    or report['holdoutSha256'] != config['holdoutSha256']):
                raise ValueError('accept requires fresh complete evidence for this exact candidate')
            accepted = Path(config['accepted'])
            temporary = accepted.with_name(accepted.name + '.next')
            shutil.copytree(config['candidate'], temporary)
            backup = accepted.with_name(accepted.name + '.' + args.accept)
            accepted.rename(backup)
            temporary.rename(accepted)
            atomic(state / 'baseline.json', report)
            atomic(state / 'acceptances' / (args.accept + '.json'),
                   {'run': args.accept, 'at': time.time(), 'buildDigest': report['buildDigest']})
            return 0
    return run(config, full=args.full)


if __name__ == '__main__':
    raise SystemExit(main())
