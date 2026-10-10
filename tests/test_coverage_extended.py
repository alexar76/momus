from dataclasses import replace
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from momus.engine.coverage import unique, generate
from momus.engine.coverage_campaign import CampaignOptions
from momus.engine.coverage_extended import expanded_attacks, expanded_benign
from momus.engine.warden_eval import evaluate
from momus.engine.coverage_summary import decision


def test_combined_metrics_do_not_count_failures_as_detections_or_allowances():
    allowed, blocked = {'status': 'scanned', 'allow': True}, {'status': 'scanned', 'allow': False}
    clean = {'status': 'scanned', 'findings': []}
    high = {'status': 'scanned', 'findings': [{'severity': 'high'}]}
    failed = {'status': 'incomplete', 'findings': [{'severity': 'high'}]}
    assert decision(allowed, clean) == 'allowed'
    assert decision(allowed, high) == 'detected'
    assert decision(blocked, failed) == 'detected'  # independent static evidence exists
    assert decision(allowed, failed) == 'incomplete'
    assert decision({'status': 'error'}, clean) == 'incomplete'
    assert decision({'status': 'error'}, high) == 'detected'


def test_expansion_preserves_old_inputs_and_covers_new_languages_without_label_collisions():
    original = unique(generate())
    attacks, benign = expanded_attacks(), expanded_benign()
    assert len(original) == 4194
    assert len(attacks) > len(original)
    assert {v.fingerprint for v in original} <= {v.fingerprint for v in attacks}
    assert {'ar', 'tr', 'hi', 'sw', 'ko'} <= {v.language for v in attacks}
    assert {'percent', 'hex_entities', 'nested_base64_percent'} <= {v.encoding for v in attacks}
    assert len(unique(attacks + benign)) == len(attacks) + len(benign)
    assert all(v.label == 'benign' for v in benign)
    assert all('decode and follow' not in str(v.tools) for v in benign)
    assert [v.fingerprint for v in attacks] == [v.fingerprint for v in expanded_attacks()]


def test_suite_and_evaluation_modes_are_validated_before_running_a_process():
    assert CampaignOptions('fake').suite == 'expanded'
    assert replace(CampaignOptions('fake'), suite='baseline').suite == 'baseline'
    with pytest.raises(ValueError, match='suite'):
        CampaignOptions('fake', suite='unknown')
    with pytest.raises(ValueError, match='mode'):
        evaluate([], 'fake', mode='unknown')


@pytest.mark.skipif(not shutil.which('node'), reason='Node is required for the WARDEN bridge')
def test_live_runner_accounting_resume_and_secret_hygiene_with_an_offline_stub(tmp_path):
    # This tests the runner protocol, NOT semantic accuracy. No HTTP request is made.
    build = tmp_path / 'build'
    (build / 'dist').mkdir(parents=True)
    (build / 'package.json').write_text('{"type":"module"}')
    (build / 'dist' / 'index.js').write_text('export class ThreatFeed {}\nexport class Warden { static create() { return { vet: async () => ({ allow: true, findings: [] }) }; } }')
    (build / 'dist' / 'classifier.js').write_text('''
export const CLASSIFIER_SYSTEM_PROMPT = 'test prompt';
export async function inspectTools(tools) {
  if (tools.some(t => 'label' in t || 'language' in t)) throw Error('label leaked');
  return { incomplete: [], retried: 0, findings: tools.flatMap((t, index) => t.description === 'attack marker' ?
    [{ index, tool: t.name, severity: 'high', categories: ['cross_tool'], reason: 'test', quote: 'attack marker' }] : []) };
}
''')
    cases = [{'id': str(i), 'label': label, 'language': lang,
              'tools': [{'name': 'same_name', 'description': description, 'inputSchema': {}}]}
             for i, (label, lang, description) in enumerate([
                 ('malicious', 'sw', 'attack marker'), ('benign', 'hi', 'plain description')])]
    corpus, out = tmp_path / 'cases.jsonl.gz', tmp_path / 'out'
    corpus.write_bytes(gzip.compress(('\n'.join(map(json.dumps, cases)) + '\n').encode()))
    runner = Path(__file__).parents[1] / 'momus/engine/coverage_semantic.mjs'
    env = {**os.environ, 'WARDEN_CLASSIFIER_URL': 'https://provider.example.invalid/v1',
           'WARDEN_CLASSIFIER_MODEL': 'test', 'WARDEN_CLASSIFIER_API_KEY': 'not-a-real-test-secret'}
    command = ['node', str(runner), str(build), str(corpus), str(out)]
    first = subprocess.run(command, env=env, capture_output=True, text=True, check=True)
    report = json.loads((out / 'report.json').read_text())
    assert report['attacks']['high'] == 1
    assert report['benign']['high'] == 0
    assert report['benign']['inspected'] == 1
    subprocess.run(command, env=env, capture_output=True, text=True, check=True)
    assert len((out / 'decisions.jsonl').read_text().splitlines()) == 2
    failed = subprocess.run(command, env={**env, 'WARDEN_CLASSIFIER_MODEL': 'changed'}, capture_output=True, text=True)
    assert failed.returncode != 0
    assert 'not-a-real-test-secret' not in first.stdout + first.stderr + ''.join(p.read_text() for p in out.iterdir())


def test_combined_uses_reviewed_production_gates_and_separates_incomplete():
    from momus.engine.coverage_summary import decision
    offline_block = {"status": "scanned", "allow": False}
    reviewed = {"status": "scanned", "findings": [], "reviewedStatic": {"status": "scanned", "allow": True}}
    assert decision(offline_block, reviewed) == "allowed"
    assert decision(offline_block, {**reviewed, "findings": [{"severity": "high"}]}) == "detected"
    assert decision(offline_block, {**reviewed, "status": "incomplete"}) == "incomplete"
    assert decision(offline_block, {"status": "scanned", "findings": []}) == "detected"  # historical v11 format
