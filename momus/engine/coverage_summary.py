"""Join frozen static and live semantic evidence, without counting failures as detections."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

from momus.engine.coverage import generate, unique


def decision(static: dict, semantic: dict) -> str:
    static = semantic.get("reviewedStatic", static)
    if (static.get('status') == 'scanned' and static.get('allow') is False) or (
        semantic.get('status') == 'scanned' and any(f.get('severity') == 'high' for f in semantic.get('findings', []))
    ):
        return 'detected'
    if static.get('status') != 'scanned' or semantic.get('status') != 'scanned':
        return 'incomplete'
    return 'allowed'


def summarize(static_dir: Path, semantic_dir: Path) -> dict:
    static = json.loads((static_dir / 'report.json').read_text())
    semantic = json.loads((semantic_dir / 'report.json').read_text())
    raw = gzip.decompress((static_dir / 'cases.jsonl.gz').read_bytes())
    cases = [json.loads(line) for line in raw.splitlines()]
    identity = semantic['identity']
    if hashlib.sha256(raw).hexdigest() != static['corpusSha256'] or static['corpusSha256'] != identity['corpusSha256']:
        raise ValueError('corpus hashes differ')
    if static['after']['build']['buildDigest'] != identity['buildDigest']:
        raise ValueError('build hashes differ')
    if identity['cases'] != len(cases):
        raise ValueError('expected a full semantic run, not a pilot')
    stat_rows = [json.loads(line) for line in gzip.decompress((static_dir / 'decisions.jsonl.gz').read_bytes()).splitlines()]
    sem_rows = [json.loads(line) for line in (semantic_dir / 'decisions.jsonl').read_text().splitlines()]
    expected = {c['id'] for c in cases}
    for rows in (stat_rows, sem_rows):
        if len(rows) != len(expected) or {r['id'] for r in rows} != expected:
            raise ValueError('missing, duplicate or unknown decisions')
    stat_by_id, sem_by_id = ({r['id']: r for r in rows} for rows in (stat_rows, sem_rows))
    combined = {c['id']: decision(stat_by_id[c['id']]['after'], sem_by_id[c['id']]) for c in cases}
    original = {v.id for v in unique(generate())}

    def counts(selected: list[dict]) -> dict:
        result = {}
        for label in ('malicious', 'benign'):
            ids = [c['id'] for c in selected if c['label'] == label]
            count = Counter(combined[i] for i in ids)
            result['attacks' if label == 'malicious' else 'benign'] = {
                'total': len(ids), 'detected' if label == 'malicious' else 'falseBlocks': count['detected'],
                'allowed': count['allowed'], 'incomplete': count['incomplete'],
            }
        return result

    responses = [json.loads(line) for line in (semantic_dir / 'responses.jsonl').read_text().splitlines()]
    return {
        'corpusSha256': static['corpusSha256'], 'cases': len(cases), 'languages': static['languages'],
        'static': {side: {key: static[side][key] for key in ('build', 'original', 'expanded')} for side in ('before', 'after')},
        'transitions': static['transitions'], 'admission': static['admission'],
        'semantic': semantic,
        'combined': {'original': counts([c for c in cases if c['id'] in original]), 'expanded': counts(cases),
                     'byLanguage': {lang: counts([c for c in cases if c['language'] == lang]) for lang in static['languages']}},
        'errors': dict(Counter(r.get('error', 'unknown') for r in sem_rows if r['status'] != 'scanned')),
        'missedAttackIds': [c['id'] for c in cases if c['label'] == 'malicious' and combined[c['id']] == 'allowed'],
        'falseBlockIds': [c['id'] for c in cases if c['label'] == 'benign' and combined[c['id']] == 'detected'],
        'requests': {'answered': len(responses), 'singletonAnswers': sum(len(r['ids']) == 1 for r in responses),
                     'finishReasons': dict(Counter(r.get('finishReason', 'unknown') for r in responses)),
                     'promptTokens': sum(r.get('promptTokens', 0) for r in responses),
                     'completionTokens': sum(r.get('completionTokens', 0) for r in responses)},
        'limitations': static['limitations'] + ' Combined recognition is a block from the real WARDEN gates (with byte-bound complete semantic clearance of readable BASE64_BLOB and structured quotation ambiguity only) OR a completed semantic high finding. '
            'Unknown inspections are separate; strict approval refusals are not recognition. '
            'The pilot influenced protocol tuning; this is not an independently held-out evaluation. '
            'Semantic results are one provider run and may vary with batch composition or future model changes.',
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--static', required=True, type=Path)
    parser.add_argument('--semantic', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = summarize(args.static, args.semantic)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report['combined'], ensure_ascii=False))


if __name__ == '__main__':
    main()
