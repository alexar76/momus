#!/usr/bin/env python3
"""Read existing production keys into process memory only; never persist/print them."""
import json
import os
import subprocess
import sys


def credentials(container, names):
    source = 'import json,os; print(json.dumps({k:os.environ.get(k, "") for k in ' + repr(names) + '}))'
    result = subprocess.run(['docker', 'exec', container, 'python', '-c', source], capture_output=True, text=True)
    if result.returncode:
        raise SystemExit('Credential source unavailable; output withheld')
    return json.loads(result.stdout)


# A candidate invocation has its own root-owned config and immutable image binding.
# Normal scheduled runs use the enrolled live build and verify that production has not drifted.
if '--config' not in sys.argv[1:]:
    from pathlib import Path
    path = Path('/var/lib/momus-quality/live-image.json')
    if path.exists():
        binding = json.loads(path.read_text())
        actual = subprocess.run(['docker', 'inspect', '--format', '{{.Image}}', 'histor-histor-1'],
                                capture_output=True, text=True, check=True).stdout.strip()
        if actual != binding['imageDigest']:
            raise SystemExit('Production image changed outside the guarded SKOPOS path')
        # Ephemeral root-owned configuration: no secrets are written here.
        config = json.loads(Path('/etc/momus-quality/config.json').read_text())
        config.update(binding, phase='live')
        runtime = Path('/var/lib/momus-quality/live-config.json')
        runtime.write_text(json.dumps(config))
        sys.argv += ['--config', str(runtime)]

keys = credentials('momus-backend', ['DEEPSEEK_API_KEY'])
sandbox = credentials('histor-histor-1', ['HISTOR_SANDBOX_URL', 'HISTOR_SANDBOX_CERT_SHA256', 'HISTOR_SANDBOX_TOKEN'])
if not keys['DEEPSEEK_API_KEY'] or not all(sandbox.values()):
    raise SystemExit('Required production credentials are missing')
env = {**os.environ, **sandbox,
       'PATH': '/opt/momus-quality/bin:/usr/local/bin:/usr/bin:/bin',
       'WARDEN_CLASSIFIER_API_KEY': keys['DEEPSEEK_API_KEY'],
       'WARDEN_CLASSIFIER_URL': 'https://api.deepseek.com/v1',
       'WARDEN_CLASSIFIER_MODEL': 'deepseek-flash', 'WARDEN_CLASSIFIER_REASONING_EFFORT': 'none',
       'WARDEN_CLASSIFIER_EVAL_CONCURRENCY': '8',
       'MOMUS_LLM_PROVIDER': 'deepseek', 'MOMUS_LLM_API_KEY': keys['DEEPSEEK_API_KEY'],
       'MOMUS_LLM_BASE_URL': 'https://api.deepseek.com/v1', 'MOMUS_LLM_MODEL': 'deepseek-flash',
       'PYTHONPATH': '/opt/momus-quality/source'}
os.execve('/opt/momus-quality/venv/bin/python',
          ['/opt/momus-quality/venv/bin/python', '-m', 'momus.engine.quality_cycle', '--config', '/etc/momus-quality/config.json', *sys.argv[1:]], env)
