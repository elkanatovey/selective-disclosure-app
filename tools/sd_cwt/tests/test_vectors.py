# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Interop test vectors from the reference-generated draft-ietf-spice-sd-cwt-08
examples (examples/issuer_cwt.edn), cross-checked byte-for-byte.

The Redacted Claim Hash is the hash of the `bstr-encoded-salted` disclosure --
the CBOR byte string wrapping the salted array (CDDL
`bstr-encoded-salted = bstr .cbor salted-entry`; the Appendix G matching
algorithm hashes that byte string). Every reference-generated example token uses
this wrapped form. (The lone Figure 8 walkthrough hashes the *unwrapped* array,
which disagrees with the CDDL and with all generated tokens; it is not used
here.) These digests are taken from the payload of the minimal issued SD-CWT and
must match our disclosure hashing exactly for interop.
"""

import cbor2

from sd_cwt import HashAlg
from sd_cwt.core import _disclosure_digest

SHA256 = HashAlg.SHA_256


def _map_digest(salt_hex: str, value, key) -> str:
    encoded = cbor2.dumps([bytes.fromhex(salt_hex), value, key])
    return _disclosure_digest(SHA256, encoded).hex()


def _elem_digest(salt_hex: str, value) -> str:
    encoded = cbor2.dumps([bytes.fromhex(salt_hex), value])
    return _disclosure_digest(SHA256, encoded).hex()


# Map-entry (Redacted Claim Key) disclosures: [salt, value, key] -> payload hash.
def test_region_disclosure_digest_matches_reference():
    assert _map_digest("ec615c3035d5a4ff2f5ae29ded683c8e", "ca", "region") == (
        "0d4b8c6123f287a1698ff2db15764564a976fb742606e8fd00e2140656ba0df3"
    )


def test_postal_code_disclosure_digest_matches_reference():
    assert _map_digest("37c23d4ec4db0806601e6b6dc6670df9", "94188", "postal_code") == (
        "c0b7747f960fc2e201c4d47c64fee141b78e3ab768ce941863dc8914e8f5815f"
    )


def test_license_disclosure_digest_matches_reference():
    assert _map_digest("bae611067bb823486797da1ebbb52f83", "ABCD-123456", 501) == (
        "af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693"
    )


# Array-element (Redacted Claim Element) disclosures: [salt, value] -> tag(60) hash.
def test_inspection_date_element_1_digest_matches_reference():
    assert _elem_digest("8de86a012b3043ae6e4457b9e1aaab80", 1549560720) == (
        "1b7fc8ecf4b1290712497d226c04b503b4aa126c603c83b75d2679c3c613f3fd"
    )


def test_inspection_date_element_2_digest_matches_reference():
    assert _elem_digest("7af7084b50badeb57d49ea34627c7a52", 1612560720) == (
        "64afccd3ad52da405329ad935de1fb36814ec48fdfd79e3a108ef858e291e146"
    )


def test_disclosure_wire_encoding_matches_draft_figure7():
    """Figure 7: the on-the-wire disclosure array(3) encoding is unchanged."""
    encoded = cbor2.dumps(
        [bytes.fromhex("bae611067bb823486797da1ebbb52f83"), "ABCD-123456", 501]
    )
    assert (
        encoded.hex()
        == "8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5"
    )
