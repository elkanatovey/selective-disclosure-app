// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/verification.h"

#include "token/cose.h"
#include "token/sd_cwt.h"

#include <gtest/gtest.h>

TEST(Verification, ReconstructsDisclosedAndClearClaims)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  const std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("https://issuer.example")},
    {501, sdcwt::value::text("RCE")},
  };
  const auto issued = sdcwt::issue(claims, {{int64_t{501}}}, *key);
  ASSERT_EQ(issued.disclosures.size(), 1u);
  const auto token =
    sdcwt::present(issued.token, {issued.disclosures[0].encoded});

  const auto plan = sdcwt::prepare_verification(token);
  EXPECT_EQ(plan.cose_algorithm, sdcwt::COSE_ALG_ES256);
  EXPECT_EQ(
    plan.disclosure_hash_algorithm,
    static_cast<int64_t>(sdcwt::HashAlg::SHA_256));
  ASSERT_EQ(plan.disclosure_hash_inputs.size(), 1u);

  const auto validated =
    sdcwt::finalize_verification(token, {issued.disclosures[0].digest}, true);
  EXPECT_EQ(
    validated.clear,
    sdcwt::encode_value(sdcwt::CborValue::Map(
      {{int64_t{1}, sdcwt::value::text("https://issuer.example")}})));
  EXPECT_EQ(
    validated.disclosed,
    sdcwt::encode_value(
      sdcwt::CborValue::Map({{int64_t{501}, sdcwt::value::text("RCE")}})));
}

TEST(Verification, RejectsFailedSignatureAndForeignDisclosure)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  const std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("issuer")},
    {501, sdcwt::value::text("RCE")},
  };
  const auto issued = sdcwt::issue(claims, {{int64_t{501}}}, *key);
  const auto token =
    sdcwt::present(issued.token, {issued.disclosures[0].encoded});

  EXPECT_THROW(
    (void)sdcwt::finalize_verification(
      token, {issued.disclosures[0].digest}, false),
    std::runtime_error);
  EXPECT_THROW(
    (void)sdcwt::finalize_verification(
      token, {std::vector<uint8_t>(32, 0xff)}, true),
    std::runtime_error);
}

TEST(Verification, RejectsDateOutsideExactIntegerRange)
{
  const auto protected_header = sdcwt::encode_protected_header();
  const auto payload = sdcwt::cbor::serialize(sdcwt::cbor::make_map(
    {{sdcwt::cbor::make_signed(6),
      sdcwt::cbor::make_signed((int64_t{1} << 53) + 1)}}));
  const auto token = sdcwt::finalize_cose_sign1_signature(
    protected_header, payload, std::vector<uint8_t>(64));

  EXPECT_THROW((void)sdcwt::prepare_verification(token), std::runtime_error);
}

TEST(Verification, RejectsShortDisclosureSalt)
{
  const auto disclosure = sdcwt::cbor::serialize(sdcwt::cbor::make_array(
    {sdcwt::cbor::make_bytes(std::vector<uint8_t>(15)),
     sdcwt::cbor::make_string("secret"),
     sdcwt::cbor::make_signed(501)}));
  auto payload = sdcwt::CborValue::Map({});
  payload.redacted_hashes.push_back(sdcwt::disclosure_digest(disclosure));
  const auto token = sdcwt::finalize_cose_sign1_signature(
    sdcwt::encode_sdcwt_protected_header(
      sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_256),
    sdcwt::encode_value(payload),
    std::vector<uint8_t>(64));
  const auto presented = sdcwt::present(token, {disclosure});

  EXPECT_THROW(
    (void)sdcwt::finalize_verification(
      presented, {sdcwt::disclosure_digest(disclosure)}, true),
    std::runtime_error);
}
