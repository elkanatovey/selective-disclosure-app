// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/sd_cwt.h"

#include "token/cbor.h"
#include "token/cose.h"

#include <gtest/gtest.h>
#include <qcbor/qcbor_decode.h>

namespace
{
  std::string to_hex(const std::vector<uint8_t>& v)
  {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (auto b : v)
    {
      s.push_back(d[b >> 4]);
      s.push_back(d[b & 0xf]);
    }
    return s;
  }
}

// The Redacted Claim Hash rule must be byte-identical to the Python reference
// (tools/sd_cwt). Vector: salt = 0x00..0f, value = "heap overflow" (tstr),
// key = 1002 -> digest computed by sd_cwt.core._disclosure_digest.
TEST(SdCwt, DisclosureDigestMatchesPythonReference)
{
  std::vector<uint8_t> salt(16);
  for (uint8_t i = 0; i < 16; ++i)
  {
    salt[i] = i;
  }

  const auto value = sdcwt::value::text("heap overflow");
  const auto encoded = sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArray(&ctx);
    QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(salt));
    QCBOREncode_AddEncoded(&ctx, sdcwt::to_ubc(value));
    QCBOREncode_AddInt64(&ctx, 1002);
    QCBOREncode_CloseArray(&ctx);
  });

  EXPECT_EQ(
    to_hex(encoded),
    "8350000102030405060708090a0b0c0d0e0f6d68656170206f766572666c6f771903ea");

  const auto digest = sdcwt::disclosure_digest(encoded);
  EXPECT_EQ(
    to_hex(digest),
    "dc679dce1b7b429c355edbdcf54c9c576485026c84962a93a1dac9b55def2818");
}

// Redacting a top-level claim must remove its value from the signed payload and
// leave exactly one Redacted Claim Hash, with a matching returned disclosure.
TEST(SdCwt, RedactedClaimIsHiddenAndDisclosed)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("https://issuer.example"), false},
    {1002, sdcwt::value::text("secret body"), true},
  };

  const auto issued = sdcwt::issue(claims, *key);

  // The secret must not appear anywhere in the signed token bytes.
  const std::string needle = "secret body";
  const std::string haystack(issued.token.begin(), issued.token.end());
  EXPECT_EQ(haystack.find(needle), std::string::npos);

  ASSERT_EQ(issued.disclosures.size(), 1u);
  EXPECT_EQ(issued.disclosures[0].key, 1002);
  EXPECT_EQ(issued.disclosures[0].salt.size(), sdcwt::SALT_LEN);
  EXPECT_EQ(
    issued.disclosures[0].digest,
    sdcwt::disclosure_digest(issued.disclosures[0].encoded));
}

// Redaction-hash agility: issuing with SHA-384 uses SHA-384 digests (48 bytes)
// and writes sd_alg = -43 into the protected header.
TEST(SdCwt, RedactionHashAgilitySha384)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("iss"), false},
    {1002, sdcwt::value::text("secret"), true},
  };

  const auto issued = sdcwt::issue(claims, *key, sdcwt::HashAlg::SHA_384);

  ASSERT_EQ(issued.disclosures.size(), 1u);
  EXPECT_EQ(issued.disclosures[0].digest.size(), 48u); // SHA-384 output
  EXPECT_EQ(
    issued.disclosures[0].digest,
    sdcwt::disclosure_digest(
      issued.disclosures[0].encoded, sdcwt::HashAlg::SHA_384));

  // sd_alg (-43) must be advertised in the protected header bytes.
  const auto expected_hdr = sdcwt::encode_sdcwt_protected_header(
    sdcwt::COSE_ALG_ES256, sdcwt::HashAlg::SHA_384);
  const std::string tok(issued.token.begin(), issued.token.end());
  const std::string hdr(expected_hdr.begin(), expected_hdr.end());
  EXPECT_NE(tok.find(hdr), std::string::npos);
}
