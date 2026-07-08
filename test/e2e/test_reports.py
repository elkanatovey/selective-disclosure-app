# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end smoke test: submit a report, retrieve the transparent statement,
and verify it with the ``sd_cwt`` reference verifier against the published issuer
key. Proves the full on-chain pipeline (token core + endpoints + receipt) works
on a live node, and that the harness reports green on known-good behaviour.
"""

from hashlib import sha256

import cbor2
import pytest
from sd_cwt import statement as st

SERVICE_ISS = "https://selective-disclosure.example/service"
RECEIPTS_LABEL = 394  # unprotected header: embedded CCF receipt(s)


def _ec2_key_from_pem(pem: bytes):
    """Build a pycose EC2Key from a PEM public key (curve inferred from name)."""
    from cryptography.hazmat.primitives import serialization
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256, P384, P521

    pub = serialization.load_pem_public_key(pem)
    mapping = {
        "secp256r1": (P256, 32),
        "secp384r1": (P384, 48),
        "secp521r1": (P521, 66),
    }
    name = pub.curve.name
    if name not in mapping:
        raise ValueError(f"unsupported EC curve: {name}")
    crv, size = mapping[name]
    nums = pub.public_numbers()
    return EC2Key(
        crv=crv,
        x=nums.x.to_bytes(size, "big"),
        y=nums.y.to_bytes(size, "big"),
    )


def _uhdr(token: bytes) -> dict:
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj
    return arr[1] or {}


def _bare_statement(transparent: bytes) -> bytes:
    """Reconstruct the original signed statement (empty unprotected header) from a
    transparent statement, by dropping the embedded receipt. The CCF claims digest
    was bound over these bytes, so this is what the receipt attests."""
    obj = cbor2.loads(transparent)
    arr = list(obj.value)
    arr[1] = {}  # issued.token carried an empty unprotected header
    return cbor2.dumps(cbor2.CBORTag(obj.tag, arr))


def _verify_receipt(transparent: bytes, service_cert_pem: bytes) -> None:
    """Cryptographically verify the embedded CCF receipt: the Merkle inclusion
    proof ties the statement's claims digest to a tree root the service identity
    signed. Raises on any failure."""
    import ccf.cose
    from cryptography.x509 import load_pem_x509_certificate

    receipts = _uhdr(transparent)[RECEIPTS_LABEL]
    service_key = load_pem_x509_certificate(service_cert_pem).public_key()
    claim_digest = sha256(_bare_statement(transparent)).digest()
    ccf.cose.verify_receipt(receipts[0], service_key, claim_digest)


def _service_key(service_cert_pem: bytes):
    from cryptography.x509 import load_pem_x509_certificate

    return load_pem_x509_certificate(service_cert_pem).public_key()


def _verify_endorsed_key(resp_body: bytes, service_cert_pem: bytes) -> bytes:
    """Parse GET /signing-key ({key, receipt} CBOR); verify the receipt endorses
    the key (claims digest = hash(pubkey)) against the service identity; return
    the key PEM. This is what lets a verifier trust the issuer key — and thus a
    statement's own signature — without the statement's receipt."""
    import ccf.cose

    obj = cbor2.loads(resp_body)
    key_pem, receipt = obj["key"], obj["receipt"]
    ccf.cose.verify_receipt(
        receipt, _service_key(service_cert_pem), sha256(key_pem).digest()
    )
    return key_pem


def test_submit_retrieve_verify(network):
    client = network.client()

    # 1. Submit a report as CBOR (native types; fingerprint is a byte string).
    report = {
        "title": "heap overflow in parser",
        "body": "crafted input overflows the token buffer",
        "component": "parser",
        "severity": "high",
        "fingerprint": b"\xde\xad\xbe\xef",
        "references": ["CVE-2025-9999"],
    }
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    assert resp.status == 204, resp.body
    txid = resp.tx_id
    assert txid, "no transaction id header on submit"

    # 2. Fetch the issuer key AND verify its on-ledger endorsement against the
    #    service identity, then build a verification key from the endorsed PEM.
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key_resp = client.get_historical("/signing-key")
    assert key_resp.status == 200, key_resp.body
    key_pem = _verify_endorsed_key(key_resp.body, service_cert)
    key = _ec2_key_from_pem(key_pem)

    # 3. Retrieve the transparent statement (historical query; retries on 202).
    stmt_resp = client.get_historical(f"/statements/{txid}")
    assert stmt_resp.status == 200, stmt_resp.body
    assert "application/cose" in stmt_resp.content_type
    token = stmt_resp.body

    # 4. Verify: the service signature verifies under the published key, and the
    #    schema holds (clear iss/iat, all content redacted).
    out = st.validate_statement(token, key)
    assert out.clear[st.ISS] == SERVICE_ISS
    assert st.IAT in out.clear

    # 5. The statement is transparent: the CCF receipt is embedded (uhdr 394)
    #    AND it cryptographically verifies (Merkle proof + service signature).
    assert RECEIPTS_LABEL in _uhdr(token)
    with open(network.service_cert, "rb") as f:
        _verify_receipt(token, f.read())

    # 6. Strict uniformity: all content fields are redacted.
    _, n_redacted = st.redacted_shape(token)
    assert n_redacted == len(st.CONTENT_FIELDS)


def test_receipt_rejects_wrong_digest(network):
    """Negative control: the embedded receipt must NOT verify against a wrong
    claims digest — proving the receipt check in the round-trip test is real,
    not a no-op."""
    import ccf.cose
    from cryptography.x509 import load_pem_x509_certificate

    client = network.client()
    resp = client.post("/reports", cbor2.dumps({"title": "x"}), "application/cbor")
    txid = resp.tx_id
    token = client.get_historical(f"/statements/{txid}").body

    receipts = _uhdr(token)[RECEIPTS_LABEL]
    with open(network.service_cert, "rb") as f:
        key = load_pem_x509_certificate(f.read()).public_key()

    # The real digest verifies; a corrupted one must be rejected.
    _verify_receipt(token, open(network.service_cert, "rb").read())
    with pytest.raises(Exception):
        ccf.cose.verify_receipt(receipts[0], key, b"\x00" * 32)


def test_signing_key_is_endorsed(network):
    """GET /signing-key returns the issuer key + its on-ledger endorsement; the
    endorsement receipt verifies against the service identity (claims digest =
    hash(pubkey)), and a wrong-key digest is rejected (real, not a no-op)."""
    import ccf.cose

    client = network.client()
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()

    resp = client.get_historical("/signing-key")
    assert resp.status == 200, resp.body
    key_pem = _verify_endorsed_key(resp.body, service_cert)  # positive
    assert b"BEGIN PUBLIC KEY" in key_pem

    # Negative: the endorsement must not verify for a different key.
    receipt = cbor2.loads(resp.body)["receipt"]
    with pytest.raises(Exception):
        ccf.cose.verify_receipt(
            receipt, _service_key(service_cert), sha256(b"not-the-key").digest()
        )


def test_operator_discloses_subset(network):
    """The Operator reveals a chosen subset of a statement's fields. The result
    is a presented + transparent statement: it verifies under the endorsed key,
    the CCF receipt still verifies, exactly the requested fields are disclosed,
    and the rest stay redacted (the confidential store never leaks them)."""
    client = network.client()
    report = {
        "title": "heap overflow in parser",
        "body": "secret exploit details",
        "component": "parser",
        "severity": "high",
    }
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    assert resp.status == 204, resp.body
    txid = resp.tx_id

    # The Operator (a CCF user) selectively discloses two fields.
    op = network.client(user="user0")
    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["title", "component"]}),
        "application/cbor",
    )
    assert disc.status == 200, disc.body
    assert "application/cose" in disc.content_type
    presented = disc.body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key_pem = _verify_endorsed_key(
        client.get_historical("/signing-key").body, service_cert
    )
    key = _ec2_key_from_pem(key_pem)

    # Signature verifies; exactly the requested fields are revealed.
    out = st.validate_statement(presented, key)
    assert out.disclosed[st.TITLE] == "heap overflow in parser"
    assert out.disclosed[st.COMPONENT] == "parser"
    assert st.BODY not in out.disclosed
    assert st.SEVERITY not in out.disclosed

    # Privacy at the WIRE level: undisclosed field values are cryptographically
    # absent from the artifact, not merely dropped by the resolver.
    assert b"heap overflow in parser" in presented  # disclosed
    assert b"secret exploit details" not in presented  # body, undisclosed
    assert b"high" not in presented  # severity, undisclosed

    # Still transparent: the embedded receipt verifies against the service.
    assert RECEIPTS_LABEL in _uhdr(presented)
    _verify_receipt(presented, service_cert)


def test_disclosure_requires_operator(network):
    """The disclosure endpoint is Operator-gated: an anonymous caller (no client
    certificate) is rejected before any confidential state is touched."""
    client = network.client()
    resp = client.post("/reports", cbor2.dumps({"title": "x"}), "application/cbor")
    txid = resp.tx_id

    anon = client.post(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["title"]}),
        "application/cbor",
    )
    assert anon.status in (401, 403), anon.body


def _sd_claims(token: bytes) -> list:
    """The presented disclosures (sd_claims, unprotected header label 17)."""
    return _uhdr(token).get(17, [])


def _references_container_on_wire(token: bytes):
    """The on-wire value of the disclosed `references` array (a list still
    containing tag(60) placeholders for undisclosed elements), or None."""
    for enc in _sd_claims(token):
        d = cbor2.loads(enc)
        if len(d) == 3 and d[2] == st.REFERENCES:  # [salt, value, key]
            return d[1]
    return None


def _drop_sd_claim(token: bytes, predicate) -> bytes:
    """Return the token with every sd_claim matching `predicate(decoded)` removed
    from the unprotected header — for building malformed presentations."""
    obj = cbor2.loads(token)
    arr = list(obj.value)
    uhdr = dict(arr[1])
    uhdr[17] = [e for e in uhdr[17] if not predicate(cbor2.loads(e))]
    arr[1] = uhdr
    return cbor2.dumps(cbor2.CBORTag(obj.tag, arr))


def test_operator_discloses_array_element(network):
    """Recursive/subfield disclosure: the Operator reveals a single `references`
    element. The sibling *values* are cryptographically absent from the artifact
    (only element 1's opening is attached); the array length/positions ARE
    visible once the container is disclosed (inherent to array disclosure —
    hiding those would need length padding, which we do not do)."""
    client = network.client()
    report = {
        "title": "heap overflow",
        "references": ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"],
    }
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    assert resp.status == 204, resp.body
    txid = resp.tx_id

    op = network.client(user="user0")
    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": [["references", 1]]}),  # only element 1
        "application/cbor",
    )
    assert disc.status == 200, disc.body
    presented = disc.body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key_pem = _verify_endorsed_key(
        client.get_historical("/signing-key").body, service_cert
    )
    key = _ec2_key_from_pem(key_pem)

    out = st.validate_statement(presented, key)
    # Only element 1 resolves; siblings are dropped from the resolved value.
    assert out.disclosed[st.REFERENCES] == ["CVE-2025-0002"]
    assert st.TITLE not in out.disclosed  # unrelated field stays redacted

    # Privacy at the WIRE level: the disclosed value is present, the sibling
    # values are cryptographically absent (their openings were never attached).
    assert b"CVE-2025-0002" in presented
    assert b"CVE-2025-0001" not in presented
    assert b"CVE-2025-0003" not in presented

    # Honest about what IS revealed. The container disclosure keeps ALL elements
    # as tag(60) placeholders; the disclosed value rides in a SEPARATE opening
    # blob that matches one placeholder by digest. So an observer of the artifact
    # learns the array length (3) and can match the opening to its position —
    # only the sibling *values* are hidden.
    container = _references_container_on_wire(presented)
    assert container is not None and len(container) == 3
    placeholders = [
        e for e in container if isinstance(e, cbor2.CBORTag) and e.tag == 60
    ]
    assert len(placeholders) == 3  # count leaks; every slot is a placeholder
    # Exactly one array-element opening ([salt, value]) is attached: element 1.
    openings = [
        cbor2.loads(e)[1] for e in _sd_claims(presented) if len(cbor2.loads(e)) == 2
    ]
    assert openings == ["CVE-2025-0002"]

    assert RECEIPTS_LABEL in _uhdr(presented)
    _verify_receipt(presented, service_cert)


def test_nested_disclosure_without_ancestor_is_rejected(network):
    """The ancestor rule is load-bearing: strip the array-container disclosure
    from a valid element presentation and the verifier MUST reject it (the
    element's hash is no longer reachable). Proves `select_disclosures` pulling
    the ancestor is necessary, not decorative."""
    client = network.client()
    report = {"references": ["CVE-A", "CVE-B", "CVE-C"]}
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    txid = resp.tx_id

    op = network.client(user="user0")
    presented = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": [["references", 1]]}),
        "application/cbor",
    ).body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )

    # Sanity: as issued (with ancestor) it verifies.
    assert st.validate_statement(presented, key).disclosed[st.REFERENCES] == ["CVE-B"]

    # Remove the whole-array {1006} disclosure, keeping the element {1006,1}.
    orphaned = _drop_sd_claim(
        presented, lambda d: len(d) == 3 and d[2] == st.REFERENCES
    )
    with pytest.raises(Exception):
        st.validate_statement(orphaned, key)


def test_operator_discloses_whole_array(network):
    """Disclosing the whole `references` field reveals all its elements (the
    field's descendants are pulled in), in contrast to element-level disclosure."""
    client = network.client()
    report = {"references": ["CVE-A", "CVE-B"]}
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    txid = resp.tx_id

    op = network.client(user="user0")
    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["references"]}),
        "application/cbor",
    )
    assert disc.status == 200, disc.body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )
    out = st.validate_statement(disc.body, key)
    assert out.disclosed[st.REFERENCES] == ["CVE-A", "CVE-B"]


def test_at_rest_shape_is_uniform_regardless_of_references(network):
    """At-rest privacy: two reports with wildly different `references` (none vs
    many) must yield an identical redacted shape in the signed token — the whole
    array is a single top-level Redacted Claim Hash, so element-level redaction
    leaks nothing about the reference count until the array is disclosed."""
    client = network.client()
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )

    def shape(report):
        txid = client.post("/reports", cbor2.dumps(report), "application/cbor").tx_id
        token = client.get_historical(f"/statements/{txid}").body
        st.validate_statement(token, key)  # well-formed under the key
        return st.redacted_shape(token)

    none_refs = shape({"title": "a"})
    many_refs = shape({"title": "a", "references": ["x", "y", "z", "w", "v"]})
    assert none_refs == many_refs
    # And it is the strict-uniformity shape: all content fields redacted.
    _, n_redacted = none_refs
    assert n_redacted == len(st.CONTENT_FIELDS)


def test_operator_appends_follow_up(network):
    """A follow-up is a child statement whose redacted `parent` field is
    SHA-256(parent token) — i.e. the parent's claims digest, so it commits to
    exactly the statement the parent's receipt attests. The link is hidden at
    rest and revealed only when the Operator discloses `parent`."""
    client = network.client()
    op = network.client(user="user0")
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )

    parent_txid = client.post(
        "/reports", cbor2.dumps({"title": "root bug"}), "application/cbor"
    ).tx_id

    # Operator-gated; uses a read-write historical adapter (retry on 202/503).
    fu = op.post_historical(
        f"/reports/{parent_txid}/follow-ups",
        cbor2.dumps({"body": "patched in v1.2.3", "patch": "abc123"}),
        "application/cbor",
    )
    assert fu.status == 204, fu.body
    fu_txid = fu.tx_id
    assert fu_txid

    # The follow-up is a normal, uniform statement (all content redacted).
    fu_token = client.get_historical(f"/statements/{fu_txid}").body
    st.validate_statement(fu_token, key)
    _, n_redacted = st.redacted_shape(fu_token)
    assert n_redacted == len(st.CONTENT_FIELDS)

    # The expected link: SHA-256(parent's bare token) = the parent claims digest.
    parent_transparent = client.get_historical(f"/statements/{parent_txid}").body
    parent_link = sha256(_bare_statement(parent_transparent)).digest()
    assert parent_link not in fu_token  # hidden at rest

    # Operator discloses the follow-up's `parent`; the revealed link matches.
    disc = op.post_historical(
        f"/operator/statements/{fu_txid}/disclosure",
        cbor2.dumps({"fields": ["parent"]}),
        "application/cbor",
    )
    assert disc.status == 200, disc.body
    out = st.validate_statement(disc.body, key)
    assert out.disclosed[st.PARENT] == parent_link


def test_follow_up_requires_operator(network):
    """The follow-up endpoint is Operator-gated: anonymous callers are rejected."""
    client = network.client()
    parent_txid = client.post(
        "/reports", cbor2.dumps({"title": "x"}), "application/cbor"
    ).tx_id
    anon = client.post(
        f"/reports/{parent_txid}/follow-ups",
        cbor2.dumps({"body": "y"}),
        "application/cbor",
    )
    assert anon.status in (401, 403), anon.body


def test_follow_up_rejects_non_statement_parent(network):
    """A follow-up whose {parent_txid} is committed but is NOT a statement (here
    genesis) is rejected — the claims-digest check guards against linking to a
    stale per-tx Value read at an unrelated seqno."""
    client = network.client()
    op = network.client(user="user0")
    parent_txid = client.post(
        "/reports", cbor2.dumps({"title": "x"}), "application/cbor"
    ).tx_id
    view = parent_txid.split(".")[0]
    non_statement = f"{view}.1"  # genesis tx: committed, not a statement
    resp = op.post_historical(
        f"/reports/{non_statement}/follow-ups",
        cbor2.dumps({"body": "y"}),
        "application/cbor",
    )
    assert resp.status in (400, 404), resp.body


def _redacted_hashes(token: bytes) -> list:
    """The top-level Redacted Claim Hashes (simple(59) array) of a token's
    payload — what an at-rest observer of the public statement sees."""
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj
    payload = cbor2.loads(arr[2])
    return payload.get(cbor2.CBORSimpleValue(59), [])


def test_follow_up_parent_link_is_salted(network):
    """The child->parent link is salted, and that is load-bearing: the parent
    hash is derived from the PUBLIC parent token, so without a per-field random
    salt an observer could brute-force the link by hashing every public
    statement. Proof: two follow-ups of the SAME parent have DISJOINT redacted
    hashes at rest (uncorrelatable), yet both disclose to the SAME parent link
    (the value is deterministic; only the disclosure wrapper is salted)."""
    client = network.client()
    op = network.client(user="user0")
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )

    parent_txid = client.post(
        "/reports", cbor2.dumps({"title": "root"}), "application/cbor"
    ).tx_id

    def follow_up(body):
        return op.post_historical(
            f"/reports/{parent_txid}/follow-ups",
            cbor2.dumps({"body": body}),
            "application/cbor",
        ).tx_id

    fu1, fu2 = follow_up("a"), follow_up("b")
    tok1 = client.get_historical(f"/statements/{fu1}").body
    tok2 = client.get_historical(f"/statements/{fu2}").body

    # At rest: every redacted claim is independently salted, so the two
    # siblings share no redacted hash — the shared parent is not correlatable.
    h1 = {bytes(h) for h in _redacted_hashes(tok1)}
    h2 = {bytes(h) for h in _redacted_hashes(tok2)}
    assert h1 and h2 and h1.isdisjoint(h2)

    # On disclosure: both reveal the SAME parent identity (deterministic value).
    def disclosed_parent(fu_txid):
        body = op.post_historical(
            f"/operator/statements/{fu_txid}/disclosure",
            cbor2.dumps({"fields": ["parent"]}),
            "application/cbor",
        ).body
        return st.validate_statement(body, key).disclosed[st.PARENT]

    assert disclosed_parent(fu1) == disclosed_parent(fu2)
