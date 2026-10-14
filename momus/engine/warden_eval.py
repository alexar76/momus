"""Strict subprocess boundary. Missing, duplicate, crashed or malformed results are not recall."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from momus.engine.coverage import Variant


class EvaluationError(RuntimeError):
    pass


@dataclass
class Evaluation:
    metadata: dict[str, Any]
    results: dict[str, dict[str, Any]]

    def blocks(self, v: Variant) -> bool | None:
        row = self.results.get(v.id)
        if not row or row['status'] != 'scanned':
            return None
        return not row['allow']


def parse_report(data: Any, variants: list[Variant]) -> Evaluation:
    if not isinstance(data, dict) or data.get('protocol') != 1:
        raise EvaluationError('invalid evaluator protocol')
    ref = data.get('ruleset')
    if (not isinstance(ref, dict) or not isinstance(ref.get('version'), str)
            or not isinstance(ref.get('digest'), str) or not ref['digest']
            or not isinstance(data.get('buildDigest'), str) or not data['buildDigest']
            or not isinstance(data.get('policy'), dict)):
        raise EvaluationError('evaluator did not identify its build and policy')
    expected = {v.id for v in variants}
    rows = data.get('results')
    if not isinstance(rows, list):
        raise EvaluationError('invalid evaluator results')
    results = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str):
            raise EvaluationError('invalid result identity')
        key = row['id']
        if key not in expected or key in results:
            raise EvaluationError('duplicate or unexpected evaluator result')
        if (row.get('status') not in ('scanned', 'error')
                or not isinstance(row.get('findings'), list)
                or not all(isinstance(f, dict) for f in row['findings'])
                or (row['status'] == 'scanned' and type(row.get('allow')) is not bool)):
            raise EvaluationError('invalid evaluator decision')
        if any(f.get('code') == 'GATE_ERROR' for f in row['findings']):
            row = {**row, 'status': 'error', 'allow': None}
        results[key] = row
    for key in expected - results.keys():
        results[key] = {'id': key, 'status': 'error', 'allow': None,
                        'findings': [], 'error': 'missing_result'}
    return Evaluation({k: v for k, v in data.items() if k != 'results'}, results)


def evaluate(variants: list[Variant], warden_lib: str, *, node: str = 'node',
             timeout: float = 120, script: str | None = None, mode: str = 'detection') -> Evaluation:
    if mode not in ('detection', 'unapproved', 'approved', 'drift'):
        raise ValueError('unknown evaluation mode')
    if len(variants) > 10000 or len({v.id for v in variants}) != len(variants):
        raise ValueError('batch must have at most 10000 unique ids')
    bridge = Path(script) if script else Path(__file__).with_suffix('.mjs')
    try:
        proc = subprocess.run([node, str(bridge.resolve()), str(Path(warden_lib).resolve())],
                              input=json.dumps({'mode': mode, 'variants': [{'id': v.id, 'tools': v.tools} for v in variants]}),
                              text=True, capture_output=True, timeout=timeout, check=True)
        data = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        # Avoid echoing provider payloads, tool strings or subprocess output to a service log.
        raise EvaluationError(f'local WARDEN evaluation failed: {type(exc).__name__}') from exc
    return parse_report(data, variants)
