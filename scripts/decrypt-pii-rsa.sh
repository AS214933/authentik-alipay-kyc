#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/decrypt-pii-rsa.sh <rsa-private-key.pem> <kyc-pii-record-file>

Example:
  scripts/decrypt-pii-rsa.sh ./pii-private.pem ./alipay-kyc-data/kyc_pii/<id_hash>

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

if [[ ! -r "$private_key" ]]; then
  echo "private key is not readable: $private_key" >&2
  exit 1
fi

if [[ ! -r "$record_file" ]]; then
  echo "record file is not readable: $record_file" >&2
  exit 1
fi

python3 - "$private_key" "$record_file" <<'PY'
import base64
import json
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError:
    print("missing Python package: cryptography", file=sys.stderr)
    print("install it with: python3 -m pip install cryptography", file=sys.stderr)
    sys.exit(1)

private_key_path, record_path = sys.argv[1], sys.argv[2]

with open(private_key_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open(record_path, "rb") as f:
    records = json.load(f)

if not isinstance(records, list):
    raise SystemExit("record file must contain a JSON array")

for index, record in enumerate(records):
    envelope = record.get("envelope") or {}
    if envelope.get("key_algorithm") != "rsa-oaep-sha256":
        raise SystemExit(f"record {index}: unsupported key_algorithm {envelope.get('key_algorithm')!r}")
    if envelope.get("data_algorithm") != "aes-256-gcm":
        raise SystemExit(f"record {index}: unsupported data_algorithm {envelope.get('data_algorithm')!r}")

    encrypted_key = base64.b64decode(envelope["encrypted_key"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    data_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, None)
    pii = json.loads(plaintext)

    output = {
        "index": index,
        "created_at": record.get("created_at"),
        "user_id": record.get("user_id"),
        "username": record.get("username", ""),
        "state": record.get("state"),
        "certify_id": record.get("certify_id"),
        "outer_order_no": record.get("outer_order_no"),
        "id_hash": record.get("id_hash"),
        "name": pii.get("name"),
        "id_number": pii.get("id_number"),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
PY
