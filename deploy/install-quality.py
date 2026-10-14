#!/usr/bin/env python3
"""Install the quality worker on HISTOR's host from a trusted extracted repository slice.

Usage: sudo python3 install-quality.py --source /opt/quality-release --corpus CASES.gz
  --holdout SEALED.gz --observer-sha SHA --fixtures-sha SHA
Does not replace the accepted build or signing key on repeat installation. Enable timers
after a complete acceptance run: systemctl enable --now momus-quality{,-full}.timer
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--corpus', required=True, type=Path)
    parser.add_argument('--holdout', required=True, type=Path)
    parser.add_argument('--observer-sha', required=True)
    parser.add_argument('--fixtures-sha', required=True)
    args = parser.parse_args()
    if os.getuid() != 0:
        raise SystemExit('Run on the trusted evaluator host as root')
    os.umask(0o022)
    base, state, private = map(Path, ('/opt/momus-quality', '/var/lib/momus-quality', '/etc/momus-quality'))
    base.mkdir(exist_ok=True)
    state.mkdir(mode=0o711, exist_ok=True)
    private.mkdir(mode=0o700, exist_ok=True)
    if subprocess.run(['id', '-u', 'momus-quality'], capture_output=True).returncode:
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'momus-quality'], check=True)
    subprocess.run(['python3', '-m', 'venv', '--system-site-packages', str(base / 'venv')], check=True)
    # Dependencies are already supplied by the host; fail before installing units if absent.
    subprocess.run([str(base / 'venv/bin/python'), '-c', 'import httpx, cryptography'], check=True)
    (base / 'bin').mkdir(exist_ok=True)
    node = shutil.which('node')
    if not node:
        raise SystemExit('Node 20+ required')
    if Path(node).resolve() != base / 'bin/node':
        shutil.copyfile(Path(node).resolve(), base / 'bin/node')
        (base / 'bin/node').chmod(0o755)
    for name in ('candidate', 'accepted'):
        if not (base / name).exists():
            shutil.copytree(args.source / 'warden', base / name, ignore=shutil.ignore_patterns('._*'))
    link = base / 'source'
    if link.exists() and link.resolve() != (args.source / 'momus').resolve():
        raise SystemExit('Existing source differs; switch releases explicitly after validation')
    if not link.exists():
        link.symlink_to((args.source / 'momus').resolve())
    keypath = private / 'signing.pem'
    if not keypath.exists():
        key = Ed25519PrivateKey.generate()
        keypath.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        keypath.chmod(0o600)
        (base / 'quality-public-key.pem').write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    for source, name in ((args.corpus, 'development'), (args.holdout, 'holdout')):
        target = state / (name + '.jsonl.gz')
        if target.exists() and gzip.decompress(target.read_bytes()) != gzip.decompress(source.read_bytes()):
            raise SystemExit(f'Refusing to replace sealed {name} corpus')
        if not target.exists():
            shutil.copyfile(source, target)
            target.chmod(0o600)
    config = dict(state=str(state), candidate=str(base / 'candidate'), accepted=str(base / 'accepted'),
                  workerUser='momus-quality', node=str(base / 'bin/node'), signingKey=str(keypath),
                  corpus=str(state / 'development.jsonl.gz'), holdout=str(state / 'holdout.jsonl.gz'),
                  observerSha256=args.observer_sha, fixturesSha256=args.fixtures_sha)
    for name, key in (('development', 'corpusSha256'), ('holdout', 'holdoutSha256')):
        config[key] = hashlib.sha256(gzip.decompress((state / (name + '.jsonl.gz')).read_bytes())).hexdigest()
    path = private / 'config.json'
    if path.exists() and json.loads(path.read_text()) != config:
        raise SystemExit('Existing evaluator configuration differs; review the change explicitly')
    path.write_text(json.dumps(config, indent=2) + '\n')
    shutil.copyfile(args.source / 'momus/deploy/quality-launch.py', base / 'quality-launch.py')
    for name in ('momus-quality.service', 'momus-quality.timer', 'momus-quality-full.service', 'momus-quality-full.timer'):
        shutil.copyfile(args.source / 'momus/deploy' / name, Path('/etc/systemd/system') / name)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    print('Installed. Pin the public key, publish only public/latest.json, run full acceptance, then enable timers.')


if __name__ == '__main__':
    main()
