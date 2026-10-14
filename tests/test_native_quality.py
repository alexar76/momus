"""The actual native chain: signed judge -> MOMUS -> signed SKOPOS order -> host gate."""
import base64
import copy
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from momus.engine.quality_cycle import canonical
from momus.engine.remediation import Retester
from momus.engine.scanner import Scanner
from momus.findings import Outcome
from momus.store import FindingStore
from momus.targets.quality import QualityTarget, QualityProbe, passed_receipt, verified_receipt

sys.path.insert(0, str(Path(__file__).parents[2] / 'skopos'))
from oracle_core.signing import Signer
from skopos.remediation.deploy_order import DeployOrder, sign_deploy_order, verify_deploy_chain
from skopos.remediation.agent_executor import NodeDeployExecutor
from skopos.remediation.recipes import merge_build_map


def report():
    now = time.time()
    b = dict(passed=True, cases=72, executed=72, evaluatedAt=now, missed=0, falsePositives=0,
             incomplete=0, observerSha256='observer', fixturesSha256='fixtures')
    return dict(type='momus.release-quality/v1', policy='zero-regressions-v1', status='passed',
                run='r1', phase='candidate', imageDigest='sha256:' + 'a'*64, buildDigest='b'*64,
                evaluatedAt=now, expiresAt=now+86400, holdoutSha256='sealed',
                fullEvidence=dict(status='passed', buildDigest='b'*64, holdoutSha256='sealed', evaluatedAt=now),
                suites={n:dict(passed=True, counts=dict(attacks=24, benign=24, missed=0, falsePositives=0, incomplete=0))
                        for n in ('development','holdout','candidates')}, behaviour=b, behaviourSmoke=b.copy(),
                discovery=dict(status='complete',generation=dict(status='ok')))


def test_signature_phase_expiry_and_identity():
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
    r = report()
    def envelope(value):
        payload=canonical(value)
        return dict(payload=base64.b64encode(payload).decode(),signature=base64.b64encode(key.sign(payload)).decode())
    assert verified_receipt(envelope(r),candidate=True,public_key=pem)==r
    for bad in [dict(r, phase='live'),dict(r,imageDigest=''),dict(r,expiresAt=0)]:
        with pytest.raises(ValueError): verified_receipt(envelope(bad),candidate=True,public_key=pem)
    e=envelope(r);e['payload']=base64.b64encode(canonical(dict(r,status='failed'))).decode()
    with pytest.raises(Exception): verified_receipt(e,candidate=True,public_key=pem)


@pytest.mark.parametrize('field', ['status','fullEvidence','behaviourSmoke','suites','discovery'])
def test_incomplete_or_failed_gate_cannot_be_a_fix(field):
    r=report();r[field]={} if field!='status' else 'failed'
    assert not passed_receipt(r)


@pytest.mark.asyncio
async def test_real_signed_verdict_cannot_be_transplanted_to_another_image(scanner, tmp_path):
    r=report()
    target=QualityTarget('warden','https://judge.invalid',candidate=True,
                         transport=httpx.MockTransport(lambda request:httpx.Response(404)))
    async def discover(ctx): return r
    target.discover=discover
    v=asdict(await Retester(scanner).retest(target, QualityProbe.probe_id,'finding1',gated='candidate'))
    assert v['fixed'] and v['artifact_digest']==r['imageDigest']
    conductor=Signer(str(tmp_path/'conductor'))
    def check(image):
        order=DeployOrder(finding_id='finding1', service='warden',host='warden',image=image,momus_verdict=v)
        sign_deploy_order(order,conductor)
        return verify_deploy_chain(order.to_dict(),conductor_pubkey=conductor.public_key_b64,
                                   momus_pubkey=scanner.pubkey,service_allowlist=['warden'])[0]
    assert check(r['imageDigest'])
    assert not check('sha256:'+'c'*64)
    assert not check('')


@pytest.mark.asyncio
async def test_only_established_fixture_failures_are_repair_tickets(scanner,tmp_path):
    target=QualityTarget('warden','https://judge.invalid')
    probe=QualityProbe()
    r=dict(report(),phase='live',status='failed',repairCases=[dict(suite='development',fixture=dict(label='malicious'),failure=dict(reason='missed'))])
    db=FindingStore(str(tmp_path/'db'))
    scan=Scanner(scanner)
    for run, expected in [('r1',1),('r1',1),('r2',2)]:
        r['run']=run
        result=(await probe.run(target,None,r))[0]
        assert result.outcome==Outcome.FINDING
        finding=scan._sign_finding(target,result)
        assert db.record_finding(finding)['seen_count']==expected
    r['repairCases'][0]['suite']='holdout'
    assert (await probe.run(target,None,r))[0].outcome==Outcome.INCONCLUSIVE
    r['repairCases'][0]['suite']='development';r['repairCases'][0]['fixture']['label']='candidate'
    assert (await probe.run(target,None,r))[0].outcome==Outcome.INCONCLUSIVE


def test_hook_is_mandatory_and_cannot_be_supplied_by_recipe():
    calls=[]
    def runner(argv, timeout): calls.append((argv,timeout));return 1,'',''
    executor=NodeDeployExecutor(conductor_pubkey='',momus_pubkey='',service_allowlist=['warden'],
                               build_map={'warden':{'quality_hook':'/bin/true'}},runner=runner)
    assert not executor._quality_gate('warden','candidate','sha256:abc')[0]
    assert calls==[(['/usr/local/sbin/skopos-warden-quality','candidate','sha256:abc'],14400)]
    assert executor._quality_gate('gaia','candidate','sha256:abc')[0]
    assert len(calls)==1


def test_candidate_environment_survives_local_recipe_merge():
    assert merge_build_map({'warden':{'env':{'HISTOR_CRAWL_ON_START':'0'}}})['warden']['env']=={'HISTOR_CRAWL_ON_START':'0'}
