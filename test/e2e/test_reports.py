# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end tests: submit reports, retrieve transparent statements, and verify
them with the ``sd_cwt`` reference verifier against the published issuer key.
Proves the full on-chain pipeline (token core + endpoints + receipt) works on a
live node.

Shared trust-bootstrap (service cert, endorsed issuer key, role clients) comes
from fixtures in conftest.py (``anon``, ``operator``, ``issuer_key``,
``service_cert_pem``); reusable request/verify helpers live in helpers.py.
"""

from hashlib import sha256

import cbor2
import pytest
from helpers import (
    RECEIPTS_LABEL,
    SERVICE_ISS,
    bare_statement,
    disclose,
    ec2_key_from_pem,
    follow_up,
    service_key,
    submit_report,
    uhdr,
    verify_endorsed_key,
    verify_receipt,
)
from sd_cwt import statement as st


def test_submit_retrieve_verify(anon, issuer_key, service_cert_pem):
    # Submit a report as CBOR (native types; fingerprint is a byte string).
    report = {
        "title": "heap overflow in parser",
        "body": "crafted input overflows the token buffer",
        "component": "parser",
        "severity": "high",
        "fingerprint": b"\xde\xad\xbe\xef",
        "references": ["CVE-2025-9999"],
    }
    txid = submit_report(anon, report)

    # Retrieve the transparent statement (historical query; retries on 202).
    stmt_resp = anon.get_historical(f"/statements/{txid}")
    assert stmt_resp.status == 200, stmt_resp.body
    assert "application/cose" in stmt_resp.content_type
    token = stmt_resp.body

    # The service signature verifies under the published (endorsed) issuer key,
    # and the schema holds (clear iss/iat, all content redacted).
    out = st.validate_statement(token, issuer_key)
    assert out.clear[st.ISS] == SERVICE_ISS
    assert st.IAT in out.clear

    # The statement is transparent: the CCF receipt is embedded (uhdr 394) AND
    # it cryptographically verifies (Merkle proof + service signature).
    assert RECEIPTS_LABEL in uhdr(token)
    verify_receipt(token, service_cert_pem)

    # Strict uniformity: all content fields are redacted.
    _, n_redacted = st.redacted_shape(token)
    assert n_redacted == len(st.CONTENT_FIELDS)


def test_receipt_rejects_wrong_digest(anon, service_cert_pem):
    """Negative control: the embedded receipt must NOT verify against a wrong
    claims digest — proving the receipt check in the round-trip test is real,
    not a no-op."""
    import ccf.cose

    txid = submit_report(anon, {"title": "x"})
    token = anon.get_historical(f"/statements/{txid}").body

    receipts = uhdr(token)[RECEIPTS_LABEL]
    key = service_key(service_cert_pem)

    # The real digest verifies; a corrupted one must be rejected.
    verify_receipt(token, service_cert_pem)
    with pytest.raises(Exception):
        ccf.cose.verify_receipt(receipts[0], key, b"\x00" * 32)


def test_signing_key_is_endorsed(anon, service_cert_pem):
    """GET /signing-key returns the issuer key + its on-ledger endorsement; the
    endorsement receipt verifies against the service identity (claims digest =
    hash(pubkey)), and a wrong-key digest is rejected (real, not a no-op)."""
    import ccf.cose

    resp = anon.get_historical("/signing-key")
    assert resp.status == 200, resp.body
    key_pem = verify_endorsed_key(resp.body, service_cert_pem)  # positive
    assert b"BEGIN PUBLIC KEY" in key_pem

    # Negative: the endorsement must not verify for a different key.
    receipt = cbor2.loads(resp.body)["receipt"]
    with pytest.raises(Exception):
        ccf.cose.verify_receipt(
            receipt, service_key(service_cert_pem), sha256(b"not-the-key").digest()
        )


def test_operator_discloses_subset(anon, operator, issuer_key, service_cert_pem):
    """The Operator reveals a chosen subset of a statement's fields. The result
    is a presented + transparent statement: it verifies under the endorsed key,
    the CCF receipt still verifies, exactly the requested fields are disclosed,
    and the rest stay redacted (the confidential store never leaks them)."""
    report = {
        "title": "heap overflow in parser",
        "body": "secret exploit details",
        "component": "parser",
        "severity": "high",
    }
    txid = submit_report(anon, report)

    disc = disclose(operator, txid, ["title", "component"])
    assert disc.status == 200, disc.body
    assert "application/cose" in disc.content_type
    presented = disc.body

    # Signature verifies; exactly the requested fields are revealed.
    out = st.validate_statement(presented, issuer_key)
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
    assert RECEIPTS_LABEL in uhdr(presented)
    verify_receipt(presented, service_cert_pem)


def _req_disclosure(client, txid):
    return client.post(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["title"]}),
        "application/cbor",
    )


def _req_follow_up(client, txid):
    return client.post(
        f"/reports/{txid}/follow-ups", cbor2.dumps({"body": "y"}), "application/cbor"
    )


def _req_operator_statement(client, txid):
    return client.get_historical(f"/operator/statements/{txid}")


def _req_operator_stream(client, txid):
    return client.get("/operator/statements?from=1")


@pytest.mark.parametrize(
    "make_request",
    [_req_disclosure, _req_follow_up, _req_operator_statement, _req_operator_stream],
    ids=["disclosure", "follow_up", "operator_statement", "operator_stream"],
)
def test_operator_endpoints_require_operator(anon, make_request):
    """Every Operator-gated endpoint (disclosure, follow-up, unredacted statement,
    stream) rejects an anonymous caller (no client certificate) before any
    confidential state is touched. The authenticated-non-Operator case is
    deferred until a config-pinned Operator identity exists — today the app
    accepts any CCF user via user_cert_auth."""
    txid = submit_report(anon, {"title": "x"})
    denied = make_request(anon, txid)
    assert denied.status in (401, 403), denied.body


def _sd_claims(token: bytes) -> list:
    """The presented disclosures (sd_claims, unprotected header label 17)."""
    return uhdr(token).get(17, [])


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
    uhdr_map = dict(arr[1])
    uhdr_map[17] = [e for e in uhdr_map[17] if not predicate(cbor2.loads(e))]
    arr[1] = uhdr_map
    return cbor2.dumps(cbor2.CBORTag(obj.tag, arr))


def test_operator_discloses_array_element(anon, operator, issuer_key, service_cert_pem):
    """Recursive/subfield disclosure: the Operator reveals a single `references`
    element. The sibling *values* are cryptographically absent from the artifact
    (only element 1's opening is attached); the array length/positions ARE
    visible once the container is disclosed (inherent to array disclosure —
    hiding those would need length padding, which we do not do)."""
    report = {
        "title": "heap overflow",
        "references": ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"],
    }
    txid = submit_report(anon, report)

    disc = disclose(operator, txid, [["references", 1]])  # only element 1
    assert disc.status == 200, disc.body
    presented = disc.body

    out = st.validate_statement(presented, issuer_key)
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

    assert RECEIPTS_LABEL in uhdr(presented)
    verify_receipt(presented, service_cert_pem)


def test_nested_disclosure_without_ancestor_is_rejected(anon, operator, issuer_key):
    """The ancestor rule is load-bearing: strip the array-container disclosure
    from a valid element presentation and the verifier MUST reject it (the
    element's hash is no longer reachable). Proves `select_disclosures` pulling
    the ancestor is necessary, not decorative."""
    txid = submit_report(anon, {"references": ["CVE-A", "CVE-B", "CVE-C"]})

    presented = disclose(operator, txid, [["references", 1]]).body

    # Sanity: as issued (with ancestor) it verifies.
    assert st.validate_statement(presented, issuer_key).disclosed[st.REFERENCES] == [
        "CVE-B"
    ]

    # Remove the whole-array {1006} disclosure, keeping the element {1006,1}.
    orphaned = _drop_sd_claim(
        presented, lambda d: len(d) == 3 and d[2] == st.REFERENCES
    )
    with pytest.raises(Exception):
        st.validate_statement(orphaned, issuer_key)


def test_operator_discloses_whole_array(anon, operator, issuer_key):
    """Disclosing the whole `references` field reveals all its elements (the
    field's descendants are pulled in), in contrast to element-level disclosure."""
    txid = submit_report(anon, {"references": ["CVE-A", "CVE-B"]})

    disc = disclose(operator, txid, ["references"])
    assert disc.status == 200, disc.body

    out = st.validate_statement(disc.body, issuer_key)
    assert out.disclosed[st.REFERENCES] == ["CVE-A", "CVE-B"]


def test_at_rest_shape_is_uniform_regardless_of_references(anon, issuer_key):
    """At-rest privacy: two reports with wildly different `references` (none vs
    many) must yield an identical redacted shape in the signed token — the whole
    array is a single top-level Redacted Claim Hash, so element-level redaction
    leaks nothing about the reference count until the array is disclosed."""

    def shape(report):
        txid = submit_report(anon, report)
        token = anon.get_historical(f"/statements/{txid}").body
        st.validate_statement(token, issuer_key)  # well-formed under the key
        return st.redacted_shape(token)

    none_refs = shape({"title": "a"})
    many_refs = shape({"title": "a", "references": ["x", "y", "z", "w", "v"]})
    assert none_refs == many_refs
    # And it is the strict-uniformity shape: all content fields redacted.
    _, n_redacted = none_refs
    assert n_redacted == len(st.CONTENT_FIELDS)


def test_operator_appends_follow_up(anon, operator, issuer_key):
    """A follow-up is a child statement whose redacted `parent` field is
    SHA-256(parent token) — i.e. the parent's claims digest, so it commits to
    exactly the statement the parent's receipt attests. The link is hidden at
    rest and revealed only when the Operator discloses `parent`."""
    parent_txid = submit_report(anon, {"title": "root bug"})

    # Operator-gated; uses a read-write historical adapter (retry on 202/503).
    fu = follow_up(
        operator, parent_txid, {"body": "patched in v1.2.3", "patch": "abc123"}
    )
    assert fu.status == 204, fu.body
    fu_txid = fu.tx_id
    assert fu_txid

    # The follow-up is a normal, uniform statement (all content redacted).
    fu_token = anon.get_historical(f"/statements/{fu_txid}").body
    st.validate_statement(fu_token, issuer_key)
    _, n_redacted = st.redacted_shape(fu_token)
    assert n_redacted == len(st.CONTENT_FIELDS)

    # The expected link: SHA-256(parent's bare token) = the parent claims digest.
    parent_transparent = anon.get_historical(f"/statements/{parent_txid}").body
    parent_link = sha256(bare_statement(parent_transparent)).digest()
    assert parent_link not in fu_token  # hidden at rest

    # Operator discloses the follow-up's `parent`; the revealed link matches.
    disc = disclose(operator, fu_txid, ["parent"])
    assert disc.status == 200, disc.body
    out = st.validate_statement(disc.body, issuer_key)
    assert out.disclosed[st.PARENT] == parent_link


def test_follow_up_rejects_non_statement_parent(anon, operator):
    """A follow-up whose {parent_txid} is committed but is NOT a statement (here
    genesis) is rejected — the claims-digest check guards against linking to a
    stale per-tx Value read at an unrelated seqno."""
    parent_txid = submit_report(anon, {"title": "x"})
    view = parent_txid.split(".")[0]
    non_statement = f"{view}.1"  # genesis tx: committed, not a statement
    resp = follow_up(operator, non_statement, {"body": "y"})
    assert resp.status in (400, 404), resp.body


def _redacted_hashes(token: bytes) -> list:
    """The top-level Redacted Claim Hashes (simple(59) array) of a token's
    payload — what an at-rest observer of the public statement sees."""
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj
    payload = cbor2.loads(arr[2])
    return payload.get(cbor2.CBORSimpleValue(59), [])


def test_follow_up_parent_link_is_salted(anon, operator, issuer_key):
    """The child->parent link is salted, and that is load-bearing: the parent
    hash is derived from the PUBLIC parent token, so without a per-field random
    salt an observer could brute-force the link by hashing every public
    statement. Proof: two follow-ups of the SAME parent have DISJOINT redacted
    hashes at rest (uncorrelatable), yet both disclose to the SAME parent link
    (the value is deterministic; only the disclosure wrapper is salted)."""
    parent_txid = submit_report(anon, {"title": "root"})

    def do_follow_up(body):
        return follow_up(operator, parent_txid, {"body": body}).tx_id

    fu1, fu2 = do_follow_up("a"), do_follow_up("b")
    tok1 = anon.get_historical(f"/statements/{fu1}").body
    tok2 = anon.get_historical(f"/statements/{fu2}").body

    # At rest: every redacted claim is independently salted, so the two
    # siblings share no redacted hash — the shared parent is not correlatable.
    h1 = {bytes(h) for h in _redacted_hashes(tok1)}
    h2 = {bytes(h) for h in _redacted_hashes(tok2)}
    assert h1 and h2 and h1.isdisjoint(h2)

    # On disclosure: both reveal the SAME parent identity (deterministic value).
    def disclosed_parent(fu_txid):
        body = disclose(operator, fu_txid, ["parent"]).body
        return st.validate_statement(body, issuer_key).disclosed[st.PARENT]

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


def test_operator_gets_unredacted_statement(
    anon, operator, issuer_key, service_cert_pem
):
    """GET /operator/statements/{txid} returns the fully-unredacted statement:
    EVERY submitted field type round-trips back in the clear (strings, a byte
    string, an int, an array), and the CCF receipt still verifies."""
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
    txid = submit_report(anon, report)

    resp = operator.get_historical(f"/operator/statements/{txid}")
    assert resp.status == 200, resp.body
    assert "application/cose" in resp.content_type
    out = st.validate_statement(resp.body, issuer_key)

    # Every submitted field comes back in the clear, with its exact value/type.
    assert out.disclosed[st.TITLE] == "heap overflow"
    assert out.disclosed[st.BODY] == "full body text"
    assert out.disclosed[st.COMPONENT] == "parser"
    assert out.disclosed[st.SEVERITY] == "high"
    assert out.disclosed[st.FINGERPRINT] == b"\xde\xad\xbe\xef"
    assert out.disclosed[st.REFERENCES] == ["CVE-2025-1", "CVE-2025-2"]
    assert out.disclosed[st.PATCH] == "fixed in 1.2.3"
    assert out.disclosed[st.PATCH_DATE] == 1700100000

    assert RECEIPTS_LABEL in uhdr(resp.body)
    verify_receipt(resp.body, service_cert_pem)


def test_operator_stream_lists_in_seqno_order(anon, operator):
    """The Operator stream lists statement txids in seqno order; each txid
    resolves via the single-statement endpoint."""
    a = submit_report(anon, {"title": "A"})
    b = submit_report(anon, {"title": "B"})
    c = submit_report(anon, {"title": "C"})

    assert _wait_in_stream(operator, c)  # wait for the async index to catch up
    ids = _operator_stream_ids(operator)
    assert ids.index(a) < ids.index(b) < ids.index(c)

    # A listed txid resolves to a real unredacted statement.
    r = operator.get_historical(f"/operator/statements/{a}")
    assert r.status == 200, r.body


def test_operator_stream_advances_by_seqno_range(anon, operator):
    """The stream is a seqno-range window: each page reports the range it covers
    (`from`..`to`) and the ledger `watermark`, and the Operator drains it by
    polling `from = to + 1`. Re-polling is replay-idempotent and never repeats an
    already-consumed statement."""
    a = submit_report(anon, {"title": "a1"})
    b = submit_report(anon, {"title": "a2"})
    assert _wait_in_stream(operator, b)

    # First drain from the start: covers up to the current watermark, and since
    # the whole ledger fits one page (span >> a sandbox ledger) there is no
    # `next` cursor and `to == watermark` (the "caught up" signal).
    page1 = cbor2.loads(operator.get("/operator/statements?from=1").body)
    assert a in page1["statements"] and b in page1["statements"]
    assert page1["to"] == page1["watermark"]
    assert "next" not in page1
    caught_up = page1["to"]

    # Polling again from just past the consumed range yields nothing new until
    # more is submitted (no repeats).
    empty = cbor2.loads(operator.get(f"/operator/statements?from={caught_up + 1}").body)
    assert empty["statements"] == []
    assert empty["watermark"] == caught_up

    # A new submission shows up on the next incremental poll, and only it.
    c = submit_report(anon, {"title": "a3"})
    assert _wait_in_stream(operator, c)
    page2 = cbor2.loads(operator.get(f"/operator/statements?from={caught_up + 1}").body)
    assert page2["statements"] == [c]
    assert page2["watermark"] > caught_up


def test_operator_stream_reports_watermark_block_count(anon, operator):
    """`watermark` is the ledger tip (the Operator's block count): it is
    monotonic and advances as statements are committed."""
    first = submit_report(anon, {"title": "w1"})
    assert _wait_in_stream(operator, first)
    wm1 = cbor2.loads(operator.get("/operator/statements?from=1").body)["watermark"]
    assert wm1 > 0

    second = submit_report(anon, {"title": "w2"})
    assert _wait_in_stream(operator, second)
    wm2 = cbor2.loads(operator.get("/operator/statements?from=1").body)["watermark"]
    assert wm2 > wm1


def test_operator_stream_rejects_malformed_cursor(operator):
    """A present-but-unparseable `from`/`to` cursor is a client error (400), not
    silently defaulted — a bad cursor must never masquerade as 'caught up'. An
    absent cursor still defaults (from=1 / to=watermark)."""
    assert operator.get("/operator/statements?from=abc").status == 400
    assert operator.get("/operator/statements?to=xyz").status == 400
    # Absent params remain valid (defaulted), so the baseline call still works.
    assert operator.get("/operator/statements?from=1").status == 200


def test_confidential_egress_is_not_cacheable(anon, operator):
    """Confidential-egress responses (unredacted statement, selective disclosure,
    the Operator-only enumeration) carry `Cache-Control: no-store` so no client,
    proxy, or diagnostic cache retains sensitive plaintext. Public transparency
    responses are deliberately NOT forced no-store (caching them is fine)."""
    txid = submit_report(anon, {"title": "cacheable?"})

    # Confidential egress: unredacted read, disclosure, and the stream.
    unred = operator.get_historical(f"/operator/statements/{txid}")
    assert unred.status == 200, unred.body
    assert "no-store" in unred.headers.get("cache-control", "")

    disc = disclose(operator, txid, ["title"])
    assert disc.status == 200, disc.body
    assert "no-store" in disc.headers.get("cache-control", "")

    stream = operator.get("/operator/statements?from=1")
    assert "no-store" in stream.headers.get("cache-control", "")

    # Public (redacted, non-confidential) reads are not forced no-store.
    pub = anon.get_historical(f"/statements/{txid}")
    assert pub.status == 200
    assert "no-store" not in pub.headers.get("cache-control", "")


def test_read_endpoints_reject_non_statement_txid(anon, operator):
    """A committed-but-non-statement txid (genesis) is rejected with 404 by the
    read endpoints — they verify the tx's claims digest equals hash(the token
    read), so a stale per-tx Value read can't masquerade as a statement."""
    parent_txid = submit_report(anon, {"title": "x"})
    view = parent_txid.split(".")[0]
    genesis = f"{view}.1"  # committed, but not a statement

    assert anon.get_historical(f"/statements/{genesis}").status == 404
    assert operator.get_historical(f"/operator/statements/{genesis}").status == 404
    assert disclose(operator, genesis, ["title"]).status == 404


def test_signing_key_registration_is_member_gated(anon, operator):
    """Key registration is control-plane: an anonymous caller and a plain user
    (non-member) are both rejected. (The key is already initialised by the
    member fixture, so this only checks the auth gate, not a re-init.)"""
    denied_anon = anon.post("/signing-key", b"", "application/cbor")
    assert denied_anon.status in (401, 403), denied_anon.body
    denied_user = operator.post("/signing-key", b"", "application/cbor")
    assert denied_user.status in (401, 403), denied_user.body


def test_signing_key_rotation(network, anon, service_cert_pem):
    """Rotate the issuer key and prove the endorsement chain holds across it:
    - GET /signing-key returns the NEW key after ?rotate=true (endorsed).
    - a statement signed BEFORE the rotation still verifies, under the key
      resolved at its seqno (GET /signing-key?at={seqno}), not the new key.
    - a statement signed AFTER verifies under the new key.
    """
    member = network.client(user="member0")

    # key1 is already initialised by the fixture.
    key1_pem = verify_endorsed_key(
        anon.get_historical("/signing-key").body, service_cert_pem
    )

    # A statement signed under key1.
    a_txid = submit_report(anon, {"title": "A"})
    a_seqno = int(a_txid.split(".")[1])

    # Rotate -> key2 (member-gated, explicit).
    rot = member.post("/signing-key?rotate=true", b"", "application/cbor")
    assert rot.status == 204, rot.body

    # GET /signing-key now returns the new, endorsed key.
    key2_pem = verify_endorsed_key(
        anon.get_historical("/signing-key").body, service_cert_pem
    )
    assert key2_pem != key1_pem

    # A statement signed under key2.
    b_txid = submit_report(anon, {"title": "B"})
    b_tok = anon.get_historical(f"/statements/{b_txid}").body
    st.validate_statement(b_tok, ec2_key_from_pem(key2_pem))  # verifies under key2

    # The pre-rotation statement resolves the key active at its seqno = key1,
    # and still verifies under it — but NOT under the new key.
    key_at_a = verify_endorsed_key(
        anon.get_historical(f"/signing-key?at={a_seqno}").body, service_cert_pem
    )
    assert key_at_a == key1_pem
    a_tok = anon.get_historical(f"/statements/{a_txid}").body
    st.validate_statement(a_tok, ec2_key_from_pem(key1_pem))
    with pytest.raises(Exception):
        st.validate_statement(a_tok, ec2_key_from_pem(key2_pem))


def test_receipt_only_endpoint(anon, service_cert_pem):
    """GET /statements/{txid}/receipt returns just the COSE receipt (no token),
    and it cryptographically verifies against the service identity for the
    statement's claim digest. A wrong digest is rejected; a non-statement txid
    is 404."""
    import ccf.cose

    svc_key = service_key(service_cert_pem)

    txid = submit_report(anon, {"title": "r"})

    resp = anon.get_historical(f"/statements/{txid}/receipt")
    assert resp.status == 200, resp.body
    assert "application/cose" in resp.content_type
    receipt = resp.body

    # The receipt attests the statement's claim digest = SHA-256(bare token).
    transparent = anon.get_historical(f"/statements/{txid}").body
    claim_digest = sha256(bare_statement(transparent)).digest()
    ccf.cose.verify_receipt(receipt, svc_key, claim_digest)  # raises on fail

    with pytest.raises(Exception):
        ccf.cose.verify_receipt(receipt, svc_key, b"\x00" * 32)

    view = txid.split(".")[0]
    assert anon.get_historical(f"/statements/{view}.1/receipt").status == 404


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


def test_async_follow_up(anon, operator):
    """Follow-ups honour ?wait=false too."""
    parent = submit_report(anon, {"title": "p"})
    fu = follow_up(operator, parent, {"body": "note"}, wait=False)
    assert fu.status == 202, fu.body
    assert fu.tx_id
    assert anon.get_historical(f"/statements/{fu.tx_id}/receipt").status == 200


def test_operator_discloses_fingerprint_only(
    anon, operator, issuer_key, service_cert_pem
):
    """The canonical duplicate-proof: the Operator discloses ONLY the fingerprint
    (a byte string) of an earlier report, proving the duplicate, while every
    other field — including on the wire — stays hidden."""
    fp = b"\x01\x02\x03\x04" * 8  # 32-byte fingerprint
    report = {"title": "secret bug title", "body": "secret", "fingerprint": fp}
    txid = submit_report(anon, report)

    disc = disclose(operator, txid, ["fingerprint"])
    assert disc.status == 200, disc.body
    out = st.validate_statement(disc.body, issuer_key)
    assert out.disclosed[st.FINGERPRINT] == fp  # bstr round-trips
    assert st.TITLE not in out.disclosed
    assert st.BODY not in out.disclosed
    assert b"secret bug title" not in disc.body  # other fields hidden on the wire
    verify_receipt(disc.body, service_cert_pem)


# --- Adversarial-input robustness -------------------------------------------
# Our submission endpoint decodes attacker-controlled CBOR in C++ *inside the
# TEE*, so malformed input must always be a clean client error (4xx), never a
# 5xx (an uncaught server-side error = a bug) and never a node crash (a dropped
# connection or a subsequently-dead node). These tests assert that contract.


def _post_raw(client, body: bytes):
    """POST bytes to /reports as application/cbor, returning the Response or the
    exception if the connection was dropped (which would signal a node crash)."""
    try:
        return client.post("/reports", body, "application/cbor"), None
    except Exception as e:  # requests ConnectionError etc. => node went away
        return None, e


# Hand-crafted payloads that can never be a valid content map, so each MUST be a
# 400 (deterministic, high-signal — a regression here is a real parser bug).
_MALFORMED = [
    b"",  # empty body
    b"not cbor at all",  # not CBOR
    b"\xff",  # bare CBOR "break" — invalid as a top-level item
    b"\xa1",  # map header claiming 1 pair, but truncated (no key/value)
    cbor2.dumps({"title": "x"})[:-1],  # a valid map, truncated by one byte
    cbor2.dumps([1, 2, 3]),  # valid CBOR, wrong top-level type (array not map)
    cbor2.dumps(42),  # valid CBOR, wrong top-level type (int)
    cbor2.dumps("just a string"),  # valid CBOR, wrong top-level type (tstr)
    cbor2.dumps(b"\x00\x01\x02"),  # valid CBOR, wrong top-level type (bstr)
    cbor2.dumps({"title": 123}),  # right shape, wrong field type (int for tstr)
    cbor2.dumps({"references": "not-an-array"}),  # references must be an array
    cbor2.dumps({"references": [1, 2, 3]}),  # references elements must be tstr
    # A deeply-nested CBOR value (nesting "bomb"): the decoder must reject it by
    # depth limit, not overflow the stack.
    b"\x9f" * 200 + b"\xff" * 200,  # 200 nested indefinite-length arrays
]


def test_submit_rejects_malformed_payloads(anon):
    """Every clearly-invalid payload is a 400 client error — never a 5xx, never a
    dropped connection. The node stays alive and healthy throughout."""
    for i, body in enumerate(_MALFORMED):
        resp, err = _post_raw(anon, body)
        assert err is None, f"payload #{i} dropped the connection: {err!r}"
        assert resp.status == 400, f"payload #{i} => {resp.status} (want 400): {body!r}"
    # The node is unharmed: a well-formed submission still commits.
    submit_report(anon, {"title": "alive"})


def test_submit_fuzz_random_payloads_never_500(anon):
    """A seeded battery of random byte blobs never yields a 5xx or a node crash.
    A blob may occasionally decode to a valid submission (2xx) or be rejected
    (4xx) — both are fine; the contract is only 'no server error, no crash'."""
    import random

    rng = random.Random(0x5D_C_7)  # seeded => reproducible
    for i in range(96):
        n = rng.randint(0, 256)
        body = bytes(rng.getrandbits(8) for _ in range(n))
        resp, err = _post_raw(anon, body)
        assert err is None, f"fuzz #{i} (len {n}) dropped the connection: {err!r}"
        assert resp.status < 500, f"fuzz #{i} => {resp.status} (5xx): {body!r}"
    # Still healthy after the whole battery.
    submit_report(anon, {"title": "alive"})


def test_concurrent_submissions_all_commit_and_verify(
    anon, operator, issuer_key, service_cert_pem
):
    """Concurrency-correctness smoke test: many submissions in flight at once
    must each commit, retrieve their OWN content, and verify. This exercises
    races that single-threaded tests can't — concurrent writes to the
    single-Value StatementTable + the claims-digest staleness guard, the
    confidential DisclosureTable, and the seqno index. It is NOT a benchmark (no
    timing asserted); the contract is correctness under concurrency."""
    import concurrent.futures
    import time

    n = 48

    def submit(i: int) -> tuple[int, str]:
        # A unique int field (patch_date=i) lets us later prove each txid
        # retrieves ITS OWN statement, not a concurrent neighbour's.
        r = anon.post(
            "/reports",
            cbor2.dumps({"title": f"concurrent-{i}", "patch_date": i}),
            "application/cbor",
        )
        assert r.status == 204, (i, r.status, r.body)
        assert r.tx_id
        return i, r.tx_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(submit, range(n)))

    # Every submission committed to a distinct transaction.
    txids = {i: txid for i, txid in results}
    assert len(txids) == n
    assert len(set(txids.values())) == n, "duplicate txids under concurrency"

    # Each txid resolves to ITS OWN content (the claims-digest guard must not let
    # a neighbour's token masquerade under load) and its receipt verifies.
    for i, txid in txids.items():
        resp = operator.get_historical(f"/operator/statements/{txid}")
        assert resp.status == 200, resp.body
        out = st.validate_statement(resp.body, issuer_key)
        assert out.disclosed[st.PATCH_DATE] == i, f"{txid} returned the wrong statement"
        verify_receipt(resp.body, service_cert_pem)

    # The seqno index stays consistent under concurrent writes: every txid shows
    # up in the Operator stream (waiting for the async index to catch up).
    want = set(txids.values())
    deadline = time.time() + 20
    seen: set = set()
    while time.time() < deadline:
        seen = set(_operator_stream_ids(operator))
        if want <= seen:
            break
        time.sleep(0.3)
    assert (
        want <= seen
    ), f"index missing {len(want - seen)} of {n} concurrent submissions"


def test_version_endpoint(anon):
    """GET /version is public service-discovery metadata: this app's semantic
    version, the compile-time statement SCHEMA version (so a client knows which
    schema the live service speaks, DESIGN §12.1), and the CCF platform version."""
    import re

    resp = anon.get("/version")
    assert resp.status == 200, resp.body
    assert "application/cbor" in resp.content_type
    v = cbor2.loads(resp.body)
    assert re.match(r"^\d+\.\d+\.\d+", v["app_version"]), v
    assert isinstance(v["schema_version"], int) and v["schema_version"] >= 1
    assert v["ccf_version"].startswith("ccf-"), v
