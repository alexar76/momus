"""Freeze and compare expanded data-only coverage on two local WARDEN builds.

Run: python -m momus.engine.coverage_compare --before PATH --after PATH --out DIR
No server processes, tool calls, external providers, or secrets are used.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

from momus.engine.coverage import Variant, generate, measure, round_report, unique
from momus.engine.coverage_extended import expanded_attacks, expanded_benign
from momus.engine.warden_eval import Evaluation, evaluate


def batched(variants: list[Variant], build: str, mode: str = 'detection') -> Evaluation:
    metadata, results = None, {}
    for offset in range(0, len(variants), 1000):
        chunk = evaluate(variants[offset:offset + 1000], build, mode=mode)
        if metadata is not None and metadata != chunk.metadata:
            raise RuntimeError('WARDEN build changed during evaluation')
        metadata = chunk.metadata
        results.update(chunk.results)
    return Evaluation(metadata or {}, results)


def metrics(cases: list[Variant], result: Evaluation) -> dict:
    recall = measure(cases, result.blocks)
    report = round_report(cases, recall, warden_version=result.metadata.get('version', 'unknown'), round_id='comparison')
    benign = [v for v in cases if v.label == 'benign']
    report['benign'] = {'total': len(benign), 'blocked': sum(result.blocks(v) is True for v in benign),
                        'inconclusive': sum(result.blocks(v) is None for v in benign)}
    return report


def compare(before: str, after: str, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    cases = unique(expanded_attacks() + expanded_benign())
    # Freeze inputs and labels BEFORE observing either detector's results.
    frozen = ''.join(json.dumps(v.to_dict(), ensure_ascii=False, sort_keys=True) + '\n' for v in cases).encode()
    (out / 'cases.jsonl.gz').write_bytes(gzip.compress(frozen, mtime=0))
    corpus_hash = hashlib.sha256(frozen).hexdigest()
    previous = batched(cases, before)
    current = batched(cases, after)
    replay = batched(cases, after)
    original = unique(generate())
    baseline_ids = {v.id for v in original}
    additions = [v for v in cases if v.id not in baseline_ids]
    unapproved = batched(cases, after, 'unapproved')
    drift = batched(cases, after, 'drift')
    benign = [v for v in cases if v.label == 'benign']
    approved = batched(benign, after, 'approved')
    summary = {
        'corpusSha256': corpus_hash, 'cases': len(cases), 'languages': sorted({v.language for v in cases}),
        'before': {'build': previous.metadata, 'original': metrics(original, previous), 'expanded': metrics(cases, previous)},
        'after': {'build': current.metadata, 'original': metrics(original, current), 'expanded': metrics(cases, current), 'newInputs': metrics(additions, current)},
        'transitions': {
            'newDetections': sum(v.label == 'malicious' and previous.blocks(v) is False and current.blocks(v) is True for v in cases),
            'regressions': sum(v.label == 'malicious' and previous.blocks(v) is True and current.blocks(v) is False for v in cases),
            'newFalseBlocks': [v.id for v in benign if previous.blocks(v) is False and current.blocks(v) is True],
            'replayDifferences': sum(current.results[v.id] != replay.results[v.id] for v in cases),
        },
        'admission': {
            'unapproved': metrics(cases, unapproved), 'changedAfterApproval': metrics(cases, drift),
            'approvedBenign': metrics(benign, approved),
            'note': 'Admission refusals are not attack recognition. Unapproved benign definitions are withheld too; operator approval is a trust decision, not evidence of safety.',
        },
        'semantic': {'status': 'separate_run', 'reason': 'This offline comparison does not call a model. Use coverage_semantic.mjs for live evidence; stub tests do not measure semantic recall.'},
        'limitations': 'Synthetic author-labelled fixtures, related transformations, no independent human language review. New inputs are a stress set, not a held-out natural distribution. No tool execution or exploit success is measured.',
    }
    (out / 'report.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    with gzip.open(out / 'decisions.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for v in cases:
            stream.write(json.dumps({'id': v.id, 'fingerprint': v.fingerprint, 'before': previous.results[v.id],
                                     'after': current.results[v.id], 'unapproved': unapproved.results[v.id],
                                     'drift': drift.results[v.id]}, ensure_ascii=False) + '\n')
    return summary


def compare_public(path: Path, before: str, after: str, out: Path) -> dict:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in gzip.decompress(raw).decode().splitlines()]
    rows = [r for r in rows if isinstance(r.get('tools'), list) and r['tools']]
    cases = [Variant(f'public.{i}', 'unlabelled', 'unlabelled', 'unknown', 'server',
                     'original', r['tools'], label='candidate', source='public-corpus')
             for i, r in enumerate(rows)]
    previous, current = batched(cases, before), batched(cases, after)
    report = {
        'source': path.name, 'sourceSha256': hashlib.sha256(raw).hexdigest(),
        'note': 'Real unlabelled snapshots: block count is not a false-positive rate.',
        'total': len(cases), 'before': previous.metadata, 'after': current.metadata,
        'blockedBefore': sum(previous.blocks(v) is True for v in cases),
        'blockedAfter': sum(current.blocks(v) is True for v in cases),
        'errorsBefore': sum(previous.blocks(v) is None for v in cases),
        'errorsAfter': sum(current.blocks(v) is None for v in cases),
        'changed': [{'name': rows[i].get('name'), 'before': previous.results[v.id], 'after': current.results[v.id]}
                    for i, v in enumerate(cases) if previous.blocks(v) != current.blocks(v)],
    }
    (out / 'public-corpus.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--public-corpus', type=Path, help='optional saved public JSONL gzip; never fetches live servers')
    args = parser.parse_args()
    report = compare(args.before, args.after, args.out)
    print(json.dumps({k: report[k] for k in ('cases', 'languages', 'transitions')}, ensure_ascii=False))
    for version in ('before', 'after'):
        for cohort in ('original', 'expanded'):
            row = report[version][cohort]
            print(version, cohort, row['blocked'], '/', row['attacks'], 'benign', row['benign'])
    if args.public_corpus:
        public = compare_public(args.public_corpus, args.before, args.after, args.out)
        print('public snapshots', public['total'], 'blocked', public['blockedBefore'], '->', public['blockedAfter'],
              'changed', len(public['changed']))


if __name__ == '__main__':
    main()
