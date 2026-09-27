"""Check public upstream build access using only this runner's GitHub token."""
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import zipfile

root = pathlib.Path(os.environ['RUNNER_TEMP']) / 'pinned-greptime-artifact'
root.mkdir(exist_ok=True)
receipt = {'exact_source_revision': '15317a131bc63a680d3571e5f681bee4acc86228', 'profile': 'upstream CI debug, extra features; deliberate candidate adaptation', 'scored_trials_launched': 0}
try:
    result = subprocess.run(['gh', 'api', 'repos/GreptimeTeam/greptimedb/actions/artifacts/9878363652/zip'], capture_output=True)
    receipt['upstream_access_exit'] = result.returncode
    if result.returncode:
        raise RuntimeError('runner_token_cannot_read_upstream_artifact')
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        expected = archive.read('bins.sha256sum').decode().strip()
    if expected != '46d2fbf6e7f3c873c57f43dd6bb4f358bbf1dcde6e9b782d8c9e987344344f6c':
        raise RuntimeError('upstream_checksum_binding_changed')
    zip_path = root / 'bins.zip'
    with zip_path.open('wb') as output:
        result = subprocess.run(['gh', 'api', 'repos/GreptimeTeam/greptimedb/actions/artifacts/9878363388/zip'], stdout=output, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('backend_archive_download_failed')
    tar_path = root / 'bins.tar.gz'
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open('bins.tar.gz') as source, tar_path.open('wb') as output:
            digest = hashlib.sha256()
            while block := source.read(1024 * 1024):
                digest.update(block)
                output.write(block)
    if digest.hexdigest() != expected:
        raise RuntimeError('backend_tar_checksum_mismatch')
    receipt['tar_sha256'] = digest.hexdigest()
    binary = root / 'greptime'
    with tarfile.open(tar_path, 'r:gz') as archive:
        member = archive.getmember('bins/greptime')
        if not member.isfile():
            raise RuntimeError('backend_binary_not_regular_file')
        with archive.extractfile(member) as source, binary.open('wb') as output:
            digest = hashlib.sha256()
            while block := source.read(1024 * 1024):
                digest.update(block)
                output.write(block)
    binary.chmod(0o755)
    receipt['binary_sha256'] = digest.hexdigest()
    result = subprocess.run([str(binary), '--version'], capture_output=True, text=True)
    receipt.update(binary_version_exit=result.returncode, binary_version=result.stdout[:3000], binary_version_error=result.stderr[:1000])
    receipt['binary_version_callable'] = result.returncode == 0
    receipt['backend_tar_path'] = str(tar_path)
except Exception as error:
    receipt['error'] = str(error)
finally:
    (root / 'artifact_probe.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt))
    # A missing upstream cross-repository token permission must not prevent
    # independent encrypted relay testing; readiness is reported separately.
