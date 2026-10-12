"""Persistent WARDEN red-team worker. Run with ``python -m momus.engine.coverage_campaign``.

SQLite is the source of truth. An advisory lock serializes rounds and reviews across
processes. Completed rounds retain exact inputs/decisions; exports can be rebuilt
from the database after interruption. No service, feed, payout or deploy is changed.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import json
import math
import os
import signal
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from momus.engine.coverage import (
    GENERATOR_VERSION, Variant, benign_controls, generate, measure, round_report, unique,
)
from momus.engine.coverage_proposals import propose
from momus.engine.warden_eval import Evaluation, EvaluationError, evaluate
from momus.providers import LLMProvider, create_provider


@dataclass(frozen=True)
class CampaignOptions:
    warden: str
    node: str = 'node'
    seed: str = 'momus'
    fresh: int = 256
    replay: int = 128
    max_cases: int = 20000
    llm_limit: int = 8
    timeout: float = 120
    suite: str = "expanded"

    def __post_init__(self):
        if self.suite not in ("baseline", "expanded"):
            raise ValueError("unknown corpus suite")
        if not 0 <= self.fresh <= 8000 or not 1 <= self.replay <= 4000 or self.fresh + self.replay > 9800:
            raise ValueError('fresh must be 0..8000, replay 1..4000 and their sum at most 9800')
        if not 100 <= self.max_cases <= 100000 or not 1 <= self.llm_limit <= 16:
            raise ValueError('max_cases must be 100..100000 and llm_limit must be 1..16')
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 600:
            raise ValueError('timeout must be positive and at most 600 seconds')


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.coverage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(_json(value) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Campaign:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.directory / 'coverage.sqlite3', timeout=30)
        self.async_runner = asyncio.Runner()
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS cases (
                fingerprint TEXT PRIMARY KEY, variant TEXT NOT NULL,
                first_round INTEGER NOT NULL, last_round INTEGER NOT NULL,
                decision TEXT, seen INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS rounds (
                id INTEGER PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, label TEXT NOT NULL,
                note TEXT NOT NULL, reviewed_at TEXT NOT NULL);
        ''')

    def close(self):
        self.db.close()
        self.async_runner.close()

    @contextlib.contextmanager
    def locked(self):
        with (self.directory / '.coverage.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError('another coverage worker is using this data directory') from exc
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def read_round(self, round_id: int | None = None) -> dict[str, Any]:
        row = (self.db.execute('SELECT document FROM rounds ORDER BY id DESC LIMIT 1').fetchone()
               if round_id is None else self.db.execute('SELECT document FROM rounds WHERE id=?', (round_id,)).fetchone())
        if row is None:
            raise ValueError('round does not exist')
        return json.loads(row['document'])

    def review(self, fingerprint: str, label: str, note: str) -> None:
        if label not in ('malicious', 'benign') or not note.strip() or len(note) > 2000:
            raise ValueError('review requires a malicious/benign label and a note of 1..2000 characters')
        with self.locked(), self.db:
            row = self.db.execute('SELECT variant FROM cases WHERE fingerprint=?', (fingerprint,)).fetchone()
            if not row:
                raise ValueError('unknown case fingerprint')
            variant = Variant(**json.loads(row['variant']))
            if variant.source != 'llm':
                raise ValueError('only model proposals can be relabelled through review')
            changed = variant.label != label
            variant = replace(variant, label=label)
            # Decisions made under another label are not evidence of a regression.
            self.db.execute('UPDATE cases SET variant=?, decision=CASE WHEN ? THEN NULL ELSE decision END '
                            'WHERE fingerprint=?', (_json(variant.to_dict()), changed, fingerprint))
            self.db.execute('INSERT INTO reviews(fingerprint,label,note,reviewed_at) VALUES(?,?,?,?)',
                            (fingerprint, label, note.strip(), _stamp()))

    def export(self, document: dict[str, Any]) -> Path:
        report = document['report']
        folder = self.directory / 'rounds' / f"{int(report['round']):06d}"
        _atomic_json(folder / 'report.json', report)
        _atomic_json(folder / 'cases.json', document['cases'])
        for case in document['cases']:
            v, status = case['variant'], case['decision']
            group = ('misses' if v['label'] == 'malicious' and status == 'allowed' else
                     'false-positives' if v['label'] == 'benign' and status == 'blocked' else
                     'candidates' if v['label'] == 'candidate' and status == 'allowed' else None)
            if group:
                _atomic_json(folder / group / (case['fingerprint'] + '.json'),
                             {'name': v['id'], 'tools': v['tools']})
        latest = self.db.execute('SELECT MAX(id) FROM rounds').fetchone()[0]
        if int(report['round']) == latest:
            _atomic_json(self.directory / 'latest.json', report)
        return folder

    def run_round(self, options: CampaignOptions, *, provider: LLMProvider | None = None,
                  evaluator: Callable[..., Evaluation] = evaluate,
                  replay_round: int | None = None) -> dict[str, Any]:
        with self.locked():
            return self._run_locked(options, provider, evaluator, replay_round)

    def _run_locked(self, options, provider, evaluator, replay_round):
        started = _stamp()
        round_id = self.db.execute('SELECT COALESCE(MAX(id),0)+1 FROM rounds').fetchone()[0]
        rows = self.db.execute('SELECT * FROM cases ORDER BY last_round, fingerprint').fetchall()
        known = {row['fingerprint']: row for row in rows}
        generation: dict[str, Any] = {'status': 'disabled', 'accepted': 0, 'rejected': 0}
        cohorts: dict[str, str] = {}
        if replay_round is not None:
            old = self.read_round(replay_round)
            variants = [Variant(**c['variant']) for c in old['cases']]
            # Replaying a round preserves its labels and inputs exactly, independently of reviews.
            cohorts = {v.fingerprint: 'replay' for v in variants}
        else:
            baseline = unique(generate(placements=['description'], encodings=['plain']) + benign_controls())
            baseline_keys = {v.fingerprint for v in baseline}
            pending = [Variant(**json.loads(r['variant'])) for r in rows if r['fingerprint'] not in baseline_keys]
            # Both misses and previous blocks get recurring coverage; old inputs cannot starve.
            misses = [v for v in pending if known[v.fingerprint]['decision'] == 'allowed' and v.label != 'benign']
            miss_keys = {v.fingerprint for v in misses}
            others = [v for v in pending if v.fingerprint not in miss_keys]
            chosen = misses[:max(1, options.replay // 2)] + others[:options.replay // 2]
            if options.replay == 1:
                chosen = pending[:1]  # a one-slot budget must still revisit prior blocks
            chosen_keys = {v.fingerprint for v in chosen}
            chosen += [v for v in pending if v.fingerprint not in chosen_keys][:options.replay - len(chosen)]
            if options.suite == "expanded":
                from momus.engine.coverage_extended import expanded_attacks, expanded_benign
                pool = unique(expanded_attacks() + expanded_benign())
            else:
                pool = unique(generate())
            pool = [v for v in pool if v.fingerprint not in known and v.fingerprint not in baseline_keys]
            seed = f'{options.seed}:{round_id}:{GENERATOR_VERSION}'
            pool.sort(key=lambda v: hashlib.sha256((seed + v.fingerprint).encode()).digest())
            capacity = max(0, options.max_cases - len(known) - len(baseline_keys - known.keys()))
            proposals = []
            if provider is not None and capacity:
                proposals, generation = self.async_runner.run(propose(provider, seed=seed, parents=misses[:4], limit=options.llm_limit))
                template_keys = {v.fingerprint for v in pool} | baseline_keys
                proposals = [v for v in proposals if v.fingerprint not in known and v.fingerprint not in template_keys]
            # Reserve room for genuine proposals; never store duplicates under new identities.
            fresh = unique(proposals + pool[:options.fresh])[:capacity]
            generation['admitted'] = sum(v.source == 'llm' for v in fresh)
            generation['unseenTemplates'] = len(pool)
            generation['capacityRemaining'] = capacity - len(fresh)
            cohorts = {v.fingerprint: group for group, values in
                       [('baseline', baseline), ('replay', chosen), ('fresh', fresh)] for v in values}
            variants = unique(baseline + chosen + fresh)
        before = {}
        for v in variants:
            row = known.get(v.fingerprint)
            if row and json.loads(row['variant'])['label'] == v.label:
                before[v.fingerprint] = row['decision']
        failure = None
        try:
            evaluation = evaluator(variants, options.warden, node=options.node, timeout=options.timeout)
        except EvaluationError as exc:
            failure = str(exc)
            evaluation = Evaluation({'version': 'unknown'}, {})
        recall = measure(variants, evaluation.blocks)
        report = round_report(variants, recall, warden_version=evaluation.metadata.get('version', 'unknown'),
                              round_id=str(round_id))
        cases = []
        transitions: dict[str, list[str]] = {k: [] for k in
            ('newMisses', 'fixed', 'regressed', 'newFalsePositives', 'resolvedFalsePositives')}
        for v in variants:
            hit = evaluation.blocks(v)
            decision = 'error' if hit is None else 'blocked' if hit else 'allowed'
            previous = before.get(v.fingerprint)
            key = None
            if v.label == 'malicious':
                if decision == 'allowed':
                    key = 'regressed' if previous == 'blocked' else 'newMisses' if previous is None else None
                elif decision == 'blocked' and previous == 'allowed':
                    key = 'fixed'
            elif v.label == 'benign':
                if decision == 'blocked' and previous != 'blocked':
                    key = 'newFalsePositives'
                elif decision == 'allowed' and previous == 'blocked':
                    key = 'resolvedFalsePositives'
            if key:
                transitions[key].append(v.fingerprint)
            cases.append({'fingerprint': v.fingerprint, 'variant': v.to_dict(), 'decision': decision,
                          'previous': previous, 'cohort': cohorts[v.fingerprint],
                          'result': evaluation.results.get(v.id)})
        errors = sum(c['decision'] == 'error' for c in cases)
        controls = [c for c in cases if c['variant']['label'] == 'benign']
        valid_controls = [c for c in controls if c['decision'] != 'error']
        fp = sum(c['decision'] == 'blocked' for c in valid_controls)
        candidates = [c for c in cases if c['variant']['label'] == 'candidate']
        report.update({
            'status': 'failed' if failure else 'partial' if errors else 'complete',
            'startedAt': started, 'finishedAt': _stamp(), 'seed': options.seed,
            'replayOf': replay_round, 'evaluator': evaluation.metadata, 'generation': generation,
            'errors': errors, 'failure': failure, 'transitions': transitions,
            'controls': {'total': len(controls), 'evaluated': len(valid_controls), 'falsePositives': fp,
                         'falsePositiveRate': fp / len(valid_controls) if valid_controls else None},
            'candidates': {'total': len(candidates),
                           'allowed': sum(c['decision'] == 'allowed' for c in candidates),
                           'inconclusive': sum(c['decision'] == 'error' for c in candidates)},
            'cohorts': {group: round_report(subset, measure(subset, evaluation.blocks),
                                             warden_version=report['wardenVersion'], round_id=str(round_id))
                        for group in ('baseline', 'fresh', 'replay')
                        if (subset := [v for v in variants if cohorts[v.fingerprint] == group])},
            'corpusSize': len(set(known) | {v.fingerprint for v in variants}),
        })
        document = {'report': report, 'cases': cases}
        with self.db:
            for c in cases:
                # Historical replay must not revert a later human review in the live corpus.
                v = c['variant']
                row = known.get(c['fingerprint'])
                changed_label = row and json.loads(row['variant'])['label'] != v['label']
                if changed_label:
                    continue
                decision = None if c['decision'] == 'error' else c['decision']
                self.db.execute('''INSERT INTO cases(fingerprint,variant,first_round,last_round,decision)
                    VALUES(?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
                    last_round=excluded.last_round, seen=cases.seen+1,
                    decision=COALESCE(excluded.decision,cases.decision)''',
                    (c['fingerprint'], _json(v), round_id, round_id, decision))
            self.db.execute('INSERT INTO rounds(id,document) VALUES(?,?)', (round_id, _json(document)))
        self.export(document)
        return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('run', 'replay', 'export', 'review'):
        sub = commands.add_parser(name)
        sub.add_argument('--data-dir', type=Path, default=Path('data/warden-coverage'))
        if name in ('run', 'replay'):
            sub.add_argument('--warden', required=True, help='local WARDEN package directory or dist/index.js')
            sub.add_argument('--node', default='node')
            sub.add_argument('--timeout', type=float, default=120)
        if name in ('export', 'replay'):
            sub.add_argument('--round', type=int, required=name == 'replay')
        if name == 'run':
            sub.add_argument('--seed', default='momus')
            sub.add_argument('--suite', choices=['baseline', 'expanded'], default='expanded')
            sub.add_argument('--fresh', type=int, default=256)
            sub.add_argument('--replay', type=int, default=128)
            sub.add_argument('--max-cases', type=int, default=20000)
            sub.add_argument('--llm', action='store_true', help='use the configured MOMUS_LLM provider')
            sub.add_argument('--llm-limit', type=int, default=8)
            sub.add_argument('--rounds', type=int, default=1, help='0 runs continuously')
            sub.add_argument('--interval', type=float, default=3600)
            sub.add_argument('--fail-on-regression', action='store_true')
        if name == 'review':
            sub.add_argument('--fingerprint', required=True)
            sub.add_argument('--label', choices=['malicious', 'benign'], required=True)
            sub.add_argument('--note', required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    campaign = None
    provider = None
    old_signal = None
    if threading.current_thread() is threading.main_thread():
        old_signal = signal.signal(signal.SIGTERM, _stop)
    try:
        if args.command == 'run' and (args.rounds < 0 or not math.isfinite(args.interval) or args.interval < 1):
            raise ValueError('rounds must be nonnegative and interval at least one second')
        campaign = Campaign(args.data_dir)
        if args.command == 'review':
            campaign.review(args.fingerprint, args.label, args.note)
            print('Review saved; historical reports are unchanged.')
            return 0
        if args.command == 'export':
            with campaign.locked():
                print(campaign.export(campaign.read_round(args.round)))
            return 0
        if args.command == 'replay':
            report = campaign.run_round(CampaignOptions(args.warden, node=args.node, timeout=args.timeout),
                                        replay_round=args.round)
            print(_json(report))
            return 0 if report['status'] == 'complete' else 2
        options = CampaignOptions(args.warden, node=args.node, seed=args.seed, fresh=args.fresh,
                                  replay=args.replay, max_cases=args.max_cases, llm_limit=args.llm_limit,
                                  timeout=args.timeout, suite=args.suite)
        provider = create_provider() if args.llm else None
        count, exit_code = 0, 0
        while args.rounds == 0 or count < args.rounds:
            report = campaign.run_round(options, provider=provider)
            print(_json(report), flush=True)
            if report['status'] != 'complete':
                exit_code = 2
            elif args.fail_on_regression and (report['transitions']['regressed'] or report['transitions']['newFalsePositives']):
                exit_code = max(exit_code, 1)
            count += 1
            if args.rounds == 0 or count < args.rounds:
                time.sleep(args.interval)
        return exit_code
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
        print(f'coverage: {exc}', file=sys.stderr)
        return 2
    finally:
        if provider is not None:
            campaign.async_runner.run(provider.aclose())
        if campaign is not None:
            campaign.close()
        if old_signal is not None:
            signal.signal(signal.SIGTERM, old_signal)


def _stop(_signal, _frame):
    raise KeyboardInterrupt


if __name__ == '__main__':
    raise SystemExit(main())
