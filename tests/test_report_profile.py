import json
from pathlib import Path

import cbor2
import pytest

from webapp.crypto import unb64
from webapp.report import RCK, check_payload, resolve_all, resolve_selected

CONTRACTS = json.loads((Path(__file__).parent / "fixtures" / "report-profile.json").read_text())


@pytest.mark.parametrize("contract", CONTRACTS, ids=lambda contract: contract["name"])
def test_python_resolves_browser_report_contract(contract):
    payload = {RCK: [unb64(digest) for digest in contract["digests"]]}
    disclosures = [unb64(encoded) for encoded in contract["disclosures"]]
    resolved = resolve_all(payload, disclosures)
    assert set(resolved) == set(range(1000, 1009))
    assert resolved[1001] == contract["report"]["title"]
    assert resolved[1002] == "".join(contract["bodyChunks"])
    assert resolved[1006] == contract["report"]["references"]
    assert resolve_selected(payload, disclosures)[1002] == dict(enumerate(contract["bodyChunks"]))
    assert isinstance(resolved[1000], bytes)
    assert len(resolved[1000]) == 16


@pytest.mark.parametrize("contract", CONTRACTS, ids=lambda contract: contract["name"])
@pytest.mark.parametrize("key", [1001, 1005], ids=["title", "fingerprint"])
def test_selected_field_does_not_expose_other_report_contents(contract, key):
    payload = {RCK: [unb64(digest) for digest in contract["digests"]]}
    opening = next(
        encoded
        for encoded in map(unb64, contract["disclosures"])
        if len(claim := cbor2.loads(encoded)) == 3 and claim[2] == key
    )
    assert resolve_selected(payload, [opening]) == {key: cbor2.loads(opening)[1]}


def test_live_report_rejects_unexpected_clear_claim():
    payload = {
        1: "contract-issuer",
        6: 1_700_000_000,
        8: {},
        RCK: [unb64(digest) for digest in CONTRACTS[0]["digests"]],
    }
    check_payload(payload)
    with pytest.raises(ValueError, match="uniform report shape"):
        check_payload({**payload, 999: "unexpected"})
