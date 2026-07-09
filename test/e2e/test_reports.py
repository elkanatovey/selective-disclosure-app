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
        service_cert = f.read()
    key = load_pem_x509_certificate(service_cert).public_key()

    # The real digest verifies; a corrupted one must be rejected.
    _verify_receipt(token, service_cert)
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


def _operator_stream_ids(op, start=1):
    """All statement txids from the Operator stream, following the `next` cursor."""
    ids = []
    frm = start
    while True:
        page = cbor2.loads(op.get(f"/operator/statements?from={frm}").body)
        ids.extend(page["statements"])
        if "next" not in page:
            break
        frm = page["next"]
    return ids


def _wait_in_stream(op, txid, timeout_s=10):
    """Poll the stream until `txid` is indexed (the seqno index is async)."""
    import time

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if txid in _operator_stream_ids(op):
            return True
        time.sleep(0.2)
    return False


def test_operator_gets_unredacted_statement(network):
    """GET /operator/statements/{txid} returns the fully-unredacted statement:
    EVERY submitted field type round-trips back in the clear (strings, a byte
    string, an int, an array), and the CCF receipt still verifies."""
    client = network.client()
    op = network.client(user="user0")
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )

    report = {
        "title": "heap overflow",
        "body": "full body text",
        "component": "parser",
        "severity": "high",
        "fingerprint": b"\xde\xad\xbe\xef",  # bstr
        "references": ["CVE-2025-1", "CVE-2025-2"],  # array
        "patch": "fixed in 1.2.3",
        "patch_date": 1700100000,  # int
    }
    txid = client.post("/reports", cbor2.dumps(report), "application/cbor").tx_id

    resp = op.get_historical(f"/operator/statements/{txid}")
    assert resp.status == 200, resp.body
    assert "application/cose" in resp.content_type
    out = st.validate_statement(resp.body, key)

    # Every submitted field comes back in the clear, with its exact value/type.
    assert out.disclosed[st.TITLE] == "heap overflow"
    assert out.disclosed[st.BODY] == "full body text"
    assert out.disclosed[st.COMPONENT] == "parser"
    assert out.disclosed[st.SEVERITY] == "high"
    assert out.disclosed[st.FINGERPRINT] == b"\xde\xad\xbe\xef"
    assert out.disclosed[st.REFERENCES] == ["CVE-2025-1", "CVE-2025-2"]
    assert out.disclosed[st.PATCH] == "fixed in 1.2.3"
    assert out.disclosed[st.PATCH_DATE] == 1700100000

    assert RECEIPTS_LABEL in _uhdr(resp.body)
    _verify_receipt(resp.body, service_cert)


def test_operator_statement_requires_operator(network):
    """The unredacted single-statement endpoint is Operator-gated."""
    client = network.client()
    txid = client.post(
        "/reports", cbor2.dumps({"title": "x"}), "application/cbor"
    ).tx_id
    anon = client.get_historical(f"/operator/statements/{txid}")
    assert anon.status in (401, 403), anon.body


def test_operator_stream_lists_in_seqno_order(network):
    """The Operator stream lists statement txids in seqno order; each txid
    resolves via the single-statement endpoint."""
    client = network.client()
    op = network.client(user="user0")
    a = client.post("/reports", cbor2.dumps({"title": "A"}), "application/cbor").tx_id
    b = client.post("/reports", cbor2.dumps({"title": "B"}), "application/cbor").tx_id
    c = client.post("/reports", cbor2.dumps({"title": "C"}), "application/cbor").tx_id

    assert _wait_in_stream(op, c)  # wait for the async index to catch up
    ids = _operator_stream_ids(op)
    assert ids.index(a) < ids.index(b) < ids.index(c)

    # A listed txid resolves to a real unredacted statement.
    r = op.get_historical(f"/operator/statements/{a}")
    assert r.status == 200, r.body


def test_operator_stream_advances_by_seqno_range(network):
    """The stream is a seqno-range window (SCITT /entries/txIds model): each page
    reports the range it covers (`from`..`to`) and the ledger `watermark`, and
    the Operator drains it by polling `from = to + 1`. Re-polling is
    replay-idempotent and never repeats an already-consumed statement."""
    client = network.client()
    op = network.client(user="user0")
    a = client.post("/reports", cbor2.dumps({"title": "a1"}), "application/cbor").tx_id
    b = client.post("/reports", cbor2.dumps({"title": "a2"}), "application/cbor").tx_id
    assert _wait_in_stream(op, b)

    # First drain from the start: covers up to the current watermark, and since
    # the whole ledger fits one page (span >> a sandbox ledger) there is no
    # `next` cursor and `to == watermark` (the "caught up" signal).
    page1 = cbor2.loads(op.get("/operator/statements?from=1").body)
    assert a in page1["statements"] and b in page1["statements"]
    assert page1["to"] == page1["watermark"]
    assert "next" not in page1
    caught_up = page1["to"]

    # Polling again from just past the consumed range yields nothing new until
    # more is submitted (no repeats).
    empty = cbor2.loads(op.get(f"/operator/statements?from={caught_up + 1}").body)
    assert empty["statements"] == []
    assert empty["watermark"] == caught_up

    # A new submission shows up on the next incremental poll, and only it.
    c = client.post("/reports", cbor2.dumps({"title": "a3"}), "application/cbor").tx_id
    assert _wait_in_stream(op, c)
    page2 = cbor2.loads(op.get(f"/operator/statements?from={caught_up + 1}").body)
    assert page2["statements"] == [c]
    assert page2["watermark"] > caught_up


def test_operator_stream_reports_watermark_block_count(network):
    """`watermark` is the ledger tip (the Operator's block count): it is
    monotonic and advances as statements are committed."""
    client = network.client()
    op = network.client(user="user0")
    first = client.post(
        "/reports", cbor2.dumps({"title": "w1"}), "application/cbor"
    ).tx_id
    assert _wait_in_stream(op, first)
    wm1 = cbor2.loads(op.get("/operator/statements?from=1").body)["watermark"]
    assert wm1 > 0

    second = client.post(
        "/reports", cbor2.dumps({"title": "w2"}), "application/cbor"
    ).tx_id
    assert _wait_in_stream(op, second)
    wm2 = cbor2.loads(op.get("/operator/statements?from=1").body)["watermark"]
    assert wm2 > wm1


def test_operator_stream_requires_operator(network):
    """The Operator stream is Operator-gated."""
    anon = network.client().get("/operator/statements?from=1")
    assert anon.status in (401, 403), anon.body


def test_read_endpoints_reject_non_statement_txid(network):
    """A committed-but-non-statement txid (genesis) is rejected with 404 by the
    read endpoints — they verify the tx's claims digest equals hash(the token
    read), so a stale per-tx Value read can't masquerade as a statement."""
    client = network.client()
    op = network.client(user="user0")
    parent_txid = client.post(
        "/reports", cbor2.dumps({"title": "x"}), "application/cbor"
    ).tx_id
    view = parent_txid.split(".")[0]
    genesis = f"{view}.1"  # committed, but not a statement

    assert client.get_historical(f"/statements/{genesis}").status == 404
    assert op.get_historical(f"/operator/statements/{genesis}").status == 404
    assert (
        op.post_historical(
            f"/operator/statements/{genesis}/disclosure",
            cbor2.dumps({"fields": ["title"]}),
            "application/cbor",
        ).status
        == 404
    )


def test_signing_key_registration_is_member_gated(network):
    """Key registration is control-plane: an anonymous caller and a plain user
    (non-member) are both rejected. (The key is already initialised by the
    member fixture, so this only checks the auth gate, not a re-init.)"""
    anon = network.client().post("/signing-key", b"", "application/cbor")
    assert anon.status in (401, 403), anon.body
    user = network.client(user="user0").post("/signing-key", b"", "application/cbor")
    assert user.status in (401, 403), user.body


def test_signing_key_rotation(network):
    """Rotate the issuer key and prove the endorsement chain holds across it:
    - GET /signing-key returns the NEW key after ?rotate=true (endorsed).
    - a statement signed BEFORE the rotation still verifies, under the key
      resolved at its seqno (GET /signing-key?at={seqno}), not the new key.
    - a statement signed AFTER verifies under the new key.
    """
    member = network.client(user="member0")
    client = network.client()
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()

    # key1 is already initialised by the fixture.
    key1_pem = _verify_endorsed_key(
        client.get_historical("/signing-key").body, service_cert
    )

    # A statement signed under key1.
    a_txid = client.post(
        "/reports", cbor2.dumps({"title": "A"}), "application/cbor"
    ).tx_id
    a_seqno = int(a_txid.split(".")[1])

    # Rotate -> key2 (member-gated, explicit).
    rot = member.post("/signing-key?rotate=true", b"", "application/cbor")
    assert rot.status == 204, rot.body

    # GET /signing-key now returns the new, endorsed key.
    key2_pem = _verify_endorsed_key(
        client.get_historical("/signing-key").body, service_cert
    )
    assert key2_pem != key1_pem

    # A statement signed under key2.
    b_txid = client.post(
        "/reports", cbor2.dumps({"title": "B"}), "application/cbor"
    ).tx_id
    b_tok = client.get_historical(f"/statements/{b_txid}").body
    st.validate_statement(b_tok, _ec2_key_from_pem(key2_pem))  # verifies under key2

    # The pre-rotation statement resolves the key active at its seqno = key1,
    # and still verifies under it — but NOT under the new key.
    key_at_a = _verify_endorsed_key(
        client.get_historical(f"/signing-key?at={a_seqno}").body, service_cert
    )
    assert key_at_a == key1_pem
    a_tok = client.get_historical(f"/statements/{a_txid}").body
    st.validate_statement(a_tok, _ec2_key_from_pem(key1_pem))
    with pytest.raises(Exception):
        st.validate_statement(a_tok, _ec2_key_from_pem(key2_pem))


def test_receipt_only_endpoint(network):
    """GET /statements/{txid}/receipt returns just the COSE receipt (no token),
    and it cryptographically verifies against the service identity for the
    statement's claim digest. A wrong digest is rejected; a non-statement txid
    is 404."""
    import ccf.cose
    from cryptography.x509 import load_pem_x509_certificate

    client = network.client()
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    service_key = load_pem_x509_certificate(service_cert).public_key()

    txid = client.post(
        "/reports", cbor2.dumps({"title": "r"}), "application/cbor"
    ).tx_id

    resp = client.get_historical(f"/statements/{txid}/receipt")
    assert resp.status == 200, resp.body
    assert "application/cose" in resp.content_type
    receipt = resp.body

    # The receipt attests the statement's claim digest = SHA-256(bare token).
    transparent = client.get_historical(f"/statements/{txid}").body
    claim_digest = sha256(_bare_statement(transparent)).digest()
    ccf.cose.verify_receipt(receipt, service_key, claim_digest)  # raises on fail

    with pytest.raises(Exception):
        ccf.cose.verify_receipt(receipt, service_key, b"\x00" * 32)

    view = txid.split(".")[0]
    assert client.get_historical(f"/statements/{view}.1/receipt").status == 404


def test_async_submission(network):
    """`?wait=false` returns 202 immediately with the txid header (no blocking on
    global commit); the receipt becomes available by polling. The default
    (blocking) path still returns 204."""
    submitter = network.client()

    resp = submitter.post(
        "/reports?wait=false", cbor2.dumps({"title": "async"}), "application/cbor"
    )
    assert resp.status == 202, resp.body
    txid = resp.tx_id
    assert txid, "async submit must still return the txid header"

    # The txid is the only thing carried from submit to poll. The receipt
    # endpoint is public, so an INDEPENDENT client (not the submitter) can poll
    # it once the tx is globally committed — the two roles are decoupled.
    poller = network.client()
    r = poller.get_historical(f"/statements/{txid}/receipt")
    assert r.status == 200, r.body

    # The default path is unchanged (blocking, 204).
    d = submitter.post("/reports", cbor2.dumps({"title": "sync"}), "application/cbor")
    assert d.status == 204, d.body
    assert d.tx_id


def test_async_follow_up(network):
    """Follow-ups honour ?wait=false too."""
    client = network.client()
    op = network.client(user="user0")
    parent = client.post(
        "/reports", cbor2.dumps({"title": "p"}), "application/cbor"
    ).tx_id
    fu = op.post_historical(
        f"/reports/{parent}/follow-ups?wait=false",
        cbor2.dumps({"body": "note"}),
        "application/cbor",
    )
    assert fu.status == 202, fu.body
    assert fu.tx_id
    assert client.get_historical(f"/statements/{fu.tx_id}/receipt").status == 200


def test_operator_discloses_fingerprint_only(network):
    """The canonical duplicate-proof: the Operator discloses ONLY the fingerprint
    (a byte string) of an earlier report, proving the duplicate, while every
    other field — including on the wire — stays hidden."""
    client = network.client()
    op = network.client(user="user0")
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )

    fp = b"\x01\x02\x03\x04" * 8  # 32-byte fingerprint
    report = {"title": "secret bug title", "body": "secret", "fingerprint": fp}
    txid = client.post("/reports", cbor2.dumps(report), "application/cbor").tx_id

    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["fingerprint"]}),
        "application/cbor",
    )
    assert disc.status == 200, disc.body
    out = st.validate_statement(disc.body, key)
    assert out.disclosed[st.FINGERPRINT] == fp  # bstr round-trips
    assert st.TITLE not in out.disclosed
    assert st.BODY not in out.disclosed
    assert b"secret bug title" not in disc.body  # other fields hidden on the wire
    _verify_receipt(disc.body, service_cert)
