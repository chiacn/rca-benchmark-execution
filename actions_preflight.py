"""Unscored Linux-runner capability check; no model/auth credentials."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import time
import urllib.request

started = time.time()
root = pathlib.Path(os.environ['RUNNER_TEMP']) / 'rca-preflight'
root.mkdir(exist_ok=True)
receipt = {'stage': 'unscored_actions_environment_preflight', 'scored_trials_launched': 0, 'gates': {}, 'commands': []}

def command(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    receipt['commands'].append({'argv': args, 'exit_code': result.returncode, 'stdout': result.stdout[-3000:], 'stderr': result.stderr[-2000:]})
    return result

try:
    receipt['resources'] = {'disk_free_bytes': shutil.disk_usage(root).free, 'cpu_count': os.cpu_count(), 'meminfo': pathlib.Path('/proc/meminfo').read_text().splitlines()[:3]}
    result = command(['docker', 'info', '--format', '{{json .ServerVersion}}'])
    receipt['gates']['docker_daemon'] = result.returncode == 0
    if result.returncode == 0:
        result = command(['docker', 'run', '--rm', 'alpine:3.21', 'echo', 'preflight-ok'])
        receipt['gates']['functional_container'] = result.returncode == 0 and 'preflight-ok' in result.stdout
    manifest = json.loads(pathlib.Path('source_manifest.json').read_text())
    downloaded = []
    for case, spec in manifest.items():
        target = root / 'operator-sources' / case
        target.mkdir(parents=True, exist_ok=True)
        for name, expected in spec['public_file_sha256'].items():
            url = spec['base_url'] + name
            entry = {'case': case, 'file': name, 'expected_sha256': expected}
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    data = response.read()
                actual = hashlib.sha256(data).hexdigest()
                entry.update(bytes=len(data), actual_sha256=actual, matches=actual == expected)
                if actual != expected:
                    raise ValueError('source hash mismatch')
                (target / name).write_bytes(data)
            except Exception as error:
                entry.update(matches=False, error=str(error))
            downloaded.append(entry)
    receipt['source_downloads'] = downloaded
    receipt['gates']['selected_sources_match'] = bool(downloaded) and all(row['matches'] for row in downloaded)
    bench = root / 'benchmark'
    if command(['git', 'clone', '--filter=blob:none', 'https://github.com/GreptimeTeam/agent-rca-bench.git', str(bench)]).returncode:
        raise RuntimeError('benchmark clone failed')
    if command(['git', 'checkout', '--detach', 'fdfbca65c87c36c6b06bddfa6d611544f13bfa34'], cwd=bench).returncode:
        raise RuntimeError('pinned benchmark checkout failed')
    receipt['benchmark_revision'] = command(['git', 'rev-parse', 'HEAD'], cwd=bench).stdout.strip()
    if command(['uv', 'sync', '--extra', 'dev', '--frozen'], cwd=bench).returncode:
        raise RuntimeError('frozen dependencies failed')
    result = command(['uv', 'run', 'pytest', '-q', 'tests/test_transfer_scorer.py', 'tests/test_transfer_protocol.py'], cwd=bench)
    receipt['gates']['scorer_schema_tests'] = result.returncode == 0
except Exception as error:
    receipt['error'] = str(error)
finally:
    receipt['elapsed_seconds'] = round(time.time() - started, 3)
    receipt['environment_smoke_passed'] = all(receipt['gates'].get(key) is True for key in ['docker_daemon', 'functional_container', 'selected_sources_match', 'scorer_schema_tests'])
    receipt['full_official_preflight_passed'] = False
    receipt['harness_treatment_ready'] = False
    pathlib.Path('preflight_receipt.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps({'gates': receipt['gates'], 'error': receipt.get('error'), 'elapsed_seconds': receipt['elapsed_seconds'], 'scored_trials_launched': 0}))
    raise SystemExit(0 if receipt['environment_smoke_passed'] else 1)
