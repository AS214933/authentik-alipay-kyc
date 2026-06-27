#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/decrypt-pii-sm2.sh <sm2-private-key.pem> <kyc-pii-record-file>

Example:
  scripts/decrypt-pii-sm2.sh ./pii-private.pem ./alipay-kyc-data/kyc_pii/<id_hash>

Requires an OpenSSL build with SM2 support.
The record file is the per-user file under KYC_PII_DIR. Its filename is the
same id_hash value written to authentik.
EOF
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

private_key=$1
record_file=$2
openssl_bin=${OPENSSL_BIN:-openssl}

if [[ ! -r "$private_key" ]]; then
  echo "private key is not readable: $private_key" >&2
  exit 1
fi

if [[ ! -r "$record_file" ]]; then
  echo "record file is not readable: $record_file" >&2
  exit 1
fi

if ! command -v "$openssl_bin" >/dev/null 2>&1; then
  echo "openssl is not available: $openssl_bin" >&2
  exit 1
fi

python3 - "$private_key" "$record_file" "$openssl_bin" <<'PY'
import base64
import json
import os
import subprocess
import sys
import tempfile

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError:
    print("missing Python package: cryptography", file=sys.stderr)
    print("install it with: python3 -m pip install cryptography", file=sys.stderr)
    sys.exit(1)

private_key_path, record_path, openssl_bin = sys.argv[1], sys.argv[2], sys.argv[3]

with open(record_path, "rb") as f:
    records = json.load(f)

if not isinstance(records, list):
    raise SystemExit("record file must contain a JSON array")

with tempfile.TemporaryDirectory() as tmpdir:
    for index, record in enumerate(records):
        envelope = record.get("envelope") or {}
        if envelope.get("key_algorithm") != "sm2-asn1":
            raise SystemExit(f"record {index}: unsupported key_algorithm {envelope.get('key_algorithm')!r}")
        if envelope.get("data_algorithm") != "aes-256-gcm":
            raise SystemExit(f"record {index}: unsupported data_algorithm {envelope.get('data_algorithm')!r}")

        encrypted_key = base64.b64decode(envelope["encrypted_key"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])

        encrypted_key_path = os.path.join(tmpdir, f"encrypted-key-{index}.der")
        with open(encrypted_key_path, "wb") as f:
            f.write(encrypted_key)

        proc = subprocess.run(
            [
                openssl_bin,
                "pkeyutl",
                "-decrypt",
                "-inkey",
                private_key_path,
                "-in",
                encrypted_key_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            message = proc.stderr.decode("utf-8", errors="replace").strip()
            raise SystemExit(f"record {index}: openssl sm2 decrypt failed: {message}")

        plaintext = AESGCM(proc.stdout).decrypt(nonce, ciphertext, None)
        pii = json.loads(plaintext)

        output = {
            "index": index,
            "created_at": record.get("created_at"),
            "user_id": record.get("user_id"),
            "username": record.get("username", ""),
            "state": record.get("state"),
            "provider": record.get("provider", ""),
            "certify_id": record.get("certify_id"),
            "outer_order_no": record.get("outer_order_no"),
            "id_hash": record.get("id_hash"),
            "name": pii.get("name"),
            "id_number": pii.get("id_number"),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
PY
