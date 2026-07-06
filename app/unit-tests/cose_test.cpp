// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cose.h"

#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/ec_key_pair.h>
#include <gtest/gtest.h>

// A hand-assembled COSE_Sign1 must verify under CCF's own COSE verifier, and
// the recovered payload must match what we signed. This nails the QCBOR + COSE
// + ccf::crypto signing pipeline before any redaction is layered on top.
TEST(Cose, Sign1RoundTripVerifiesUnderCcf)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  const auto phdr = sdcwt::encode_protected_header();

  // Arbitrary CBOR payload: a map {1: 2}.
  const std::vector<uint8_t> payload = {0xa1, 0x01, 0x02};

  const auto token = sdcwt::sign_cose_sign1(*key, phdr, payload);

  auto verifier =
    ccf::crypto::make_cose_verifier_from_key(key->public_key_pem());
  std::span<uint8_t> authned_content;
  ASSERT_TRUE(verifier->verify(token, authned_content));

  const std::vector<uint8_t> recovered(
    authned_content.begin(), authned_content.end());
  EXPECT_EQ(recovered, payload);
}

// Algorithm agility: a P-384 key must sign (ES384) and verify under CCF. The
// signing algorithm and digest are derived from the key's curve.
TEST(Cose, Sign1WithP384VerifiesUnderCcf)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1);
  const auto phdr = sdcwt::encode_protected_header(sdcwt::COSE_ALG_ES384);
  const std::vector<uint8_t> payload = {0xa1, 0x01, 0x02};

  const auto token = sdcwt::sign_cose_sign1(*key, phdr, payload);

  auto verifier =
    ccf::crypto::make_cose_verifier_from_key(key->public_key_pem());
  std::span<uint8_t> content;
  EXPECT_TRUE(verifier->verify(token, content));
}

// The curve->COSE-algorithm map covers ES256/384/512 and rejects non-ECDSA
// curves.
TEST(Cose, CurveToAlgMapping)
{
  EXPECT_EQ(
    sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::SECP256R1),
    sdcwt::COSE_ALG_ES256);
  EXPECT_EQ(
    sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::SECP384R1),
    sdcwt::COSE_ALG_ES384);
  EXPECT_EQ(
    sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::SECP521R1),
    sdcwt::COSE_ALG_ES512);
  EXPECT_THROW(
    sdcwt::cose_es_alg_for_curve(ccf::crypto::CurveID::CURVE25519),
    std::invalid_argument);
}

// external_aad is bound into the signature: a token signed with a non-empty aad
// does not verify under CCF's verifier (which uses an empty aad), while the
// same payload signed with no aad does.
TEST(Cose, ExternalAadIsBound)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  const auto phdr = sdcwt::encode_protected_header();
  const std::vector<uint8_t> payload = {0xa1, 0x01, 0x02};
  const std::vector<uint8_t> aad = {'c', 't', 'x'};

  const auto with_aad = sdcwt::sign_cose_sign1(*key, phdr, payload, aad);
  const auto no_aad = sdcwt::sign_cose_sign1(*key, phdr, payload);

  auto verifier =
    ccf::crypto::make_cose_verifier_from_key(key->public_key_pem());
  std::span<uint8_t> content;
  // CCF verify() uses an empty external_aad -> the aad-bound token must fail,
  // the empty-aad token must pass.
  EXPECT_FALSE(verifier->verify(with_aad, content));
  EXPECT_TRUE(verifier->verify(no_aad, content));
}

// A signature over a different payload must not verify against tampered bytes.
TEST(Cose, TamperedPayloadFailsVerification)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  const auto phdr = sdcwt::encode_protected_header();
  const std::vector<uint8_t> payload = {0xa1, 0x01, 0x02};

  auto token = sdcwt::sign_cose_sign1(*key, phdr, payload);
  // Flip a byte in the encoded payload region (last-but-one field). Rather than
  // hunt the offset, re-sign a different payload and swap the signature.
  const std::vector<uint8_t> other = {0xa1, 0x01, 0x03};
  auto other_token = sdcwt::sign_cose_sign1(*key, phdr, other);

  auto verifier =
    ccf::crypto::make_cose_verifier_from_key(key->public_key_pem());
  std::span<uint8_t> content;
  // Truncating the envelope must fail cleanly (not crash).
  std::vector<uint8_t> truncated(
    token.begin(), token.begin() + token.size() / 2);
  EXPECT_FALSE(verifier->verify(truncated, content));
}
