"""Encrypt allowlisted operator reports before public artifact upload."""
import base64
import io
import json
import os
from pathlib import Path
import zipfile
from mailbox_crypto import derive_key, generate_keypair, seal

root = Path(os.environ['RUNNER_TEMP']) / 'rca-selected-backend'
output = Path('encrypted_backend_reports.json')
allowed = ('operator_output.log', 'checkout.log', 'derived_condition_registration.json',
           'binary_checkout_observation.json', 'semantic-rca-transfer-011_operator_audit.json',
           'semantic-rca-transfer-006_operator_audit.json')
archive_bytes = io.BytesIO()
with zipfile.ZipFile(archive_bytes, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for name in allowed:
        path = root / name
        if path.is_file():
            archive.writestr(name, path.read_bytes())
raw = archive_bytes.getvalue()
if len(raw) > 20 * 1024 * 1024:
    raise RuntimeError('encrypted_operator_bundle_limit_exceeded')
session = os.environ['RCA_REPORT_SESSION']
private, public = generate_keypair()
key = derive_key(private, os.environ['RCA_REPORT_RECIPIENT'], session)
chunks = [seal(key, session, i + 1, 'response',
               {'chunk': base64.b64encode(raw[offset:offset + 32768]).decode('ascii')})
          for i, offset in enumerate(range(0, len(raw), 32768))]
output.write_text(json.dumps({'session': session, 'server_public_key': public,
                             'chunks': chunks}), encoding='utf-8')
print('Operator reports encrypted; no plaintext report uploaded.')
