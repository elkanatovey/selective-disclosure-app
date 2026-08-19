from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path

import cbor2
import ccf.cose
import requests
import sd_cwt
from cbor2 import CBORSimpleValue, CBORTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.keys import CoseKey

RCK = CBORSimpleValue(59)


def parts(data: bytes):
    value = cbor2.loads(data)
    if not isinstance(value, CBORTag) or value.tag != 18:
        raise ValueError("expected COSE Sign1")
    return list(value.value)


def bare(statement: bytes) -> bytes:
    protected, _, payload, signature = parts(statement)
    return cbor2.dumps(CBORTag(18, [protected, {}, payload, signature]), canonical=True)


def service_key(ca: Path):
    return x509.load_pem_x509_certificate(ca.read_bytes()).public_key()


def verify_receipt(receipt: bytes, statement: bytes, key) -> str:
    ccf.cose.verify_receipt(receipt, key, hashlib.sha256(statement).digest())
    for encoded in parts(receipt)[1].get(396, {}).get(-1, []):
        evidence = cbor2.loads(encoded).get(1, [None, ""])[1]
        if isinstance(evidence, str) and evidence.startswith("ce:"):
            return evidence.split(":", 2)[1]
    raise AssertionError("receipt has no registration transaction ID")


def submit(args):
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    token = (output / "statement.cose").read_bytes()
    registry_url = args.researcher_url or args.url
    registry_verify = args.cacert if args.researcher_url is None else True
    response = requests.post(
        f"{registry_url}/entries?waitForCommit=true",
        data=token,
        headers={"content-type": "application/cose"},
        verify=registry_verify,
        timeout=30,
    )
    response.raise_for_status()
    if response.status_code != 201:
        raise AssertionError(f"unexpected registration status {response.status_code}")
    if args.researcher_url and response.headers.get("x-receipt-verified") != "true":
        raise AssertionError("researcher did not verify the standalone receipt")
    txid = response.headers["x-ms-ccf-transaction-id"]
    key = service_key(args.cacert)
    if verify_receipt(response.content, token, key) != txid:
        raise AssertionError("standalone receipt transaction ID does not match")
    transparent = None
    for _ in range(100):
        fetched = requests.get(
            f"{registry_url}/entries/{txid}/statement",
            verify=registry_verify,
            timeout=30,
        )
        if fetched.status_code == 200:
            if args.researcher_url and fetched.headers.get("x-receipt-verified") != "true":
                raise AssertionError("researcher did not verify the embedded receipt")
            transparent = fetched.content
            break
        if fetched.status_code not in (202, 503):
            fetched.raise_for_status()
        time.sleep(0.1)
    if transparent is None:
        raise TimeoutError(f"historical transaction {txid} remained uncached")
    if bare(transparent) != token:
        raise AssertionError("SCITT did not preserve exact signed bytes")
    receipts = parts(transparent)[1].get(394, [])
    if len(receipts) != 1:
        raise AssertionError("transparent statement does not contain one receipt")
    if verify_receipt(receipts[0], token, key) != txid:
        raise AssertionError("embedded receipt transaction ID does not match")
    seqno = txid.split(".")[1]
    indexed = requests.get(
        f"{args.url}/entries/txIds?from={seqno}&to={seqno}",
        verify=args.cacert,
        timeout=30,
    )
    indexed.raise_for_status()
    if indexed.json()["transactionIds"] != [txid]:
        raise AssertionError("registration is absent from SCITT index")
    (output / "receipt.cose").write_bytes(response.content)
    (output / "transparent.cose").write_bytes(transparent)
    (output / "scitt.json").write_text(json.dumps({"txid": txid}, indent=2))
    print(json.dumps({"phase": "submit", "txid": txid, "receiptVerified": True}))


def reject(args):
    token = (args.output / "statement.cose").read_bytes()
    response = requests.post(
        f"{args.url}/entries?waitForCommit=true",
        data=token,
        headers={"content-type": "application/cose"},
        verify=args.cacert,
        timeout=30,
    )
    if response.status_code != 400:
        raise AssertionError(f"foreign issuer returned {response.status_code}, expected 400")
    try:
        error = cbor2.loads(response.content)
    except cbor2.CBORDecodeError:
        error = response.text
    if "MSRC CA" not in str(error):
        raise AssertionError(f"foreign issuer was not rejected by the MSRC CA policy: {error}")
    print(json.dumps({"phase": "reject", "foreignIssuerRejected": True}))


def verify_certificates(phdr, issuer):
    if phdr.get(1) != -7 or phdr.get(16) != 293 or phdr.get(170) != -16:
        raise AssertionError("unsupported SD-CWT profile")
    leaf = x509.load_der_x509_certificate(phdr[33][0])
    root = x509.load_der_x509_certificate(phdr[33][1])
    root.public_key().verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(root.signature_hash_algorithm))
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    now = datetime.now(UTC)
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        raise AssertionError("issuer certificate is outside its validity period")
    if not root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
        raise AssertionError("root cannot sign certificates")
    expected = base64.urlsafe_b64decode(re.match(r"did:x509:0:sha256:([^:]+)", issuer).group(1) + "==")
    if root.fingerprint(hashes.SHA256()) != expected:
        raise AssertionError("did:x509 root fingerprint mismatch")
    return leaf


def verify(args):
    output = args.output
    metadata = json.loads((output / "expected.json").read_text())
    kbt = (output / "disclosure.kbt.cose").read_bytes()
    kbt_protected, _, _, _ = parts(kbt)
    kbt_phdr = cbor2.loads(kbt_protected)
    if kbt_phdr.get(1) != -7 or kbt_phdr.get(16) != 294 or not isinstance(kbt_phdr.get(13), CBORTag):
        raise AssertionError("invalid KBT profile")
    statement = cbor2.dumps(kbt_phdr[13], canonical=True)
    protected, uhdr, payload_bytes, _ = parts(statement)
    payload = cbor2.loads(payload_bytes)
    leaf = verify_certificates(cbor2.loads(protected), payload[1])
    issuer_pem = leaf.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    issuer_key = CoseKey.from_pem_public_key(issuer_pem)
    result = sd_cwt.kbt_verify(kbt, issuer_key, expected_aud=metadata["audience"])
    if len(payload[RCK]) != 9:
        raise AssertionError("report shape is invalid")
    receipt_list = uhdr.get(394, [])
    if len(receipt_list) != 1:
        raise AssertionError("real SCITT receipt missing from KBT")
    txid = verify_receipt(receipt_list[0], bare(statement), service_key(args.cacert))
    claims = result.kbt_claims or {}
    if not isinstance(claims.get(6), int):
        raise AssertionError("KBT proof, audience, or iat is invalid")
    selected = dict(result.claims.disclosed)
    if set(selected) != {1001, 1002, 1006}:
        raise AssertionError(f"unexpected disclosed fields: {sorted(selected)}")
    if selected[1001] != metadata["title"] or selected[1002] != {0: metadata["firstBodyChunk"]} or selected[1006] != [metadata["reference"]]:
        raise AssertionError("selective disclosure values are inconsistent")
    print(json.dumps({"phase": "verify", "txid": txid, "fields": sorted(selected), "actualReceipt": True, "kbtVerified": True, "sdCwtVerifier": "reference"}))


parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="command", required=True)
for command, function in (("submit", submit), ("verify", verify), ("reject", reject)):
    child = sub.add_parser(command)
    child.add_argument("--url", default="https://127.0.0.1:8000")
    child.add_argument("--cacert", type=Path, required=True)
    child.add_argument("--output", type=Path, required=True)
    if command == "submit":
        child.add_argument("--researcher-url")
    child.set_defaults(function=function)
arguments = parser.parse_args()
arguments.function(arguments)