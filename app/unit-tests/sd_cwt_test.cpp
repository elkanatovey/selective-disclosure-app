// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/sd_cwt.h"

#include "cbor.h"
#include "token/cose.h"

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>

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
    sdcwt::encode_value(ctx, value);
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
  ASSERT_TRUE(issued.disclosures[0].key.has_value());
  EXPECT_EQ(std::get<int64_t>(*issued.disclosures[0].key), 1002);
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

namespace
{
  bool token_contains(const std::vector<uint8_t>& token, const std::string& s)
  {
    const std::string hay(token.begin(), token.end());
    return hay.find(s) != std::string::npos;
  }
}

// The salt length is configurable (default 16).
TEST(SdCwt, ConfigurableSaltLength)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1002, sdcwt::value::text("secret"), true},
  };
  const auto issued = sdcwt::issue(
    claims,
    *key,
    sdcwt::HashAlg::SHA_256,
    /*redact_paths=*/{},
    /*salt_len=*/32);
  ASSERT_EQ(issued.disclosures.size(), 1u);
  EXPECT_EQ(issued.disclosures[0].salt.size(), 32u);
}

// A standards-compliant issuer can bind the token to a holder key: passing a
// `holder` public key embeds the RFC 8747 `cnf` claim (clear) so the token is
// key-binding capable. The holder's public coordinates appear only when set.
TEST(SdCwt, CnfEmbedsHolderPublicKey)
{
  auto issuer = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  auto holder = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  auto holder_pub = ccf::crypto::make_ec_public_key(holder->public_key_pem());
  const auto coords = holder_pub->coordinates();

  std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("https://issuer.example"), false},
    {1002, sdcwt::value::text("secret body"), true},
  };

  const auto with_cnf = sdcwt::issue(
    claims,
    *issuer,
    sdcwt::HashAlg::SHA_256,
    /*redact_paths=*/{},
    sdcwt::SALT_LEN,
    /*pad_to=*/0,
    holder_pub.get());
  const auto without = sdcwt::issue(claims, *issuer);

  const auto contains = [](
                          const std::vector<uint8_t>& hay,
                          const std::vector<uint8_t>& needle) {
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) !=
      hay.end();
  };
  EXPECT_TRUE(contains(with_cnf.token, coords.x));
  EXPECT_TRUE(contains(with_cnf.token, coords.y));
  EXPECT_FALSE(contains(without.token, coords.x));
}

// present() attaches the selected disclosures to the SD-CWT unprotected header
// without disturbing the signed protected header / payload / signature.
TEST(SdCwt, PresentAttachesSelectedDisclosures)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("iss"), false},
    {1002, sdcwt::value::text("secret body"), true},
  };
  const auto issued = sdcwt::issue(claims, *key);
  ASSERT_EQ(issued.disclosures.size(), 1u);

  const auto contains = [](
                          const std::vector<uint8_t>& hay,
                          const std::vector<uint8_t>& needle) {
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) !=
      hay.end();
  };

  // The bare token does not carry the disclosure; the presented one does.
  EXPECT_FALSE(contains(issued.token, issued.disclosures[0].encoded));
  const auto presented =
    sdcwt::present(issued.token, {issued.disclosures[0].encoded});
  EXPECT_TRUE(contains(presented, issued.disclosures[0].encoded));
  // Presenting nothing yields a decodable token again (no sd_claims header).
  EXPECT_NO_THROW(sdcwt::present(issued.token, {}));
}

// present() must carry pre-existing unprotected-header entries (e.g. kid,
// x5chain) through untouched, only managing sd_claims — never silently dropping
// them (mirrors the Python reference's dict(arr[1]) passthrough).
TEST(SdCwt, PresentPreservesExistingUnprotectedHeader)
{
  const std::vector<uint8_t> kid = {0xAB, 0xCD};
  const std::vector<uint8_t> cert = {0x01, 0x02, 0x03};
  const std::vector<uint8_t> disclosure = {0x81, 0x40}; // [h'']

  // Hand-build a COSE_Sign1 whose unprotected header already carries kid (4)
  // and an x5chain-like array (33). The signature/payload are placeholders;
  // present does not verify them.
  const auto token = sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
    QCBOREncode_AddTag(&ctx, 18);
    QCBOREncode_OpenArray(&ctx);
    QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(std::vector<uint8_t>{})); // phdr
    QCBOREncode_OpenMap(&ctx);
    QCBOREncode_AddBytesToMapN(&ctx, 4, sdcwt::to_ubc(kid));
    QCBOREncode_OpenArrayInMapN(&ctx, 33);
    QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(cert));
    QCBOREncode_CloseArray(&ctx);
    QCBOREncode_CloseMap(&ctx);
    QCBOREncode_AddBytes(
      &ctx, sdcwt::to_ubc(std::vector<uint8_t>{})); // payload
    QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(std::vector<uint8_t>{})); // sig
    QCBOREncode_CloseArray(&ctx);
  });

  const auto presented = sdcwt::present(token, {disclosure});

  // The rebuilt unprotected header must still contain kid(4) and x5chain(33),
  // and now also sd_claims(17).
  QCBORDecodeContext dc;
  QCBORDecode_Init(
    &dc,
    UsefulBufC{presented.data(), presented.size()},
    QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterArray(&dc, nullptr);
  UsefulBufC phdr = NULLUsefulBufC;
  QCBORDecode_GetByteString(&dc, &phdr);
  QCBORDecode_EnterMap(&dc, nullptr);
  UsefulBufC got_kid = NULLUsefulBufC;
  QCBORDecode_GetByteStringInMapN(&dc, 4, &got_kid);
  QCBORDecode_EnterArrayFromMapN(&dc, 17); // sd_claims present
  QCBORDecode_ExitArray(&dc);
  UsefulBufC got_cert = NULLUsefulBufC;
  QCBORDecode_EnterArrayFromMapN(&dc, 33); // x5chain present
  QCBORDecode_GetByteString(&dc, &got_cert);
  QCBORDecode_ExitArray(&dc);
  QCBORDecode_ExitMap(&dc);
  QCBORDecode_ExitArray(&dc);
  ASSERT_EQ(QCBORDecode_Finish(&dc), QCBOR_SUCCESS);

  ASSERT_EQ(got_kid.len, kid.size());
  EXPECT_EQ(0, std::memcmp(got_kid.ptr, kid.data(), kid.size()));
  ASSERT_EQ(got_cert.len, cert.size());
  EXPECT_EQ(0, std::memcmp(got_cert.ptr, cert.data(), cert.size()));
}

// kbt_sign requires the draft-08 s8.1 freshness claim (iat or cti).
TEST(SdCwt, KbtSignRequiresIatOrCti)
{
  auto issuer = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  auto holder = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  auto holder_pub = ccf::crypto::make_ec_public_key(holder->public_key_pem());
  std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("iss"), false},
    {1002, sdcwt::value::text("secret"), true},
  };
  const auto issued = sdcwt::issue(
    claims,
    *issuer,
    sdcwt::HashAlg::SHA_256,
    /*redact_paths=*/{},
    sdcwt::SALT_LEN,
    /*pad_to=*/0,
    holder_pub.get());

  sdcwt::KbtParams params;
  params.aud = "https://vendor.example/verify"; // neither iat nor cti
  EXPECT_THROW(
    sdcwt::kbt_sign(issued.token, {}, *holder, params), std::invalid_argument);

  params.iat = 1700000500;
  EXPECT_NO_THROW(sdcwt::kbt_sign(issued.token, {}, *holder, params));
}

// Decoy padding: pad_to raises the top-level redacted-hash count to the target
// with salt-only decoy disclosures, without changing the real claim.
TEST(SdCwt, DecoyPadding)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1, sdcwt::value::text("iss"), false},
    {1002, sdcwt::value::text("secret"), true},
  };
  const auto issued = sdcwt::issue(
    claims,
    *key,
    sdcwt::HashAlg::SHA_256,
    /*redact_paths=*/{},
    sdcwt::SALT_LEN,
    /*pad_to=*/5);

  // 1 real redacted claim + 4 decoys = 5 disclosures, all with no key.
  ASSERT_EQ(issued.disclosures.size(), 5u);
  size_t decoys = 0;
  for (const auto& d : issued.disclosures)
  {
    if (!d.key.has_value())
    {
      ++decoys;
    }
  }
  EXPECT_EQ(decoys, 4u);
}

// A redact_path that resolves to nothing must be rejected (rather than silently
// producing no redaction).
TEST(SdCwt, UnmatchedRedactPathRejected)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1006, sdcwt::value::text_array({"A", "B"}), false},
  };
  // Wrong claim key, out-of-range index, and descending into a scalar.
  EXPECT_THROW(
    sdcwt::issue(claims, *key, sdcwt::HashAlg::SHA_256, {{int64_t{9999}}}),
    std::invalid_argument);
  EXPECT_THROW(
    sdcwt::issue(
      claims, *key, sdcwt::HashAlg::SHA_256, {{int64_t{1006}, int64_t{9}}}),
    std::invalid_argument);
  EXPECT_THROW(
    sdcwt::issue(
      claims,
      *key,
      sdcwt::HashAlg::SHA_256,
      {{int64_t{1006}, int64_t{0}, int64_t{0}}}),
    std::invalid_argument);
}

// Array-element redaction: a redact_path into an array element hides only that
// element (replaced by a tag(60) hash) and yields a keyless disclosure.
TEST(SdCwt, ArrayElementRedaction)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  std::vector<sdcwt::Claim> claims = {
    {1006,
     sdcwt::value::text_array({"REF_KEEP_A", "REF_HIDE_B", "REF_KEEP_C"}),
     false},
  };
  // Redact element 1 of claim 1006.
  const std::vector<sdcwt::Path> paths = {{int64_t{1006}, int64_t{1}}};

  const auto issued =
    sdcwt::issue(claims, *key, sdcwt::HashAlg::SHA_256, paths);

  ASSERT_EQ(issued.disclosures.size(), 1u);
  EXPECT_FALSE(issued.disclosures[0].key.has_value()); // array element
  EXPECT_FALSE(token_contains(issued.token, "REF_HIDE_B"));
  EXPECT_TRUE(token_contains(issued.token, "REF_KEEP_A"));
  EXPECT_TRUE(token_contains(issued.token, "REF_KEEP_C"));
  // tag(60) = 0xd8 0x3c precedes the redacted element hash.
  const std::string tok(issued.token.begin(), issued.token.end());
  EXPECT_NE(tok.find(std::string("\xd8\x3c", 2)), std::string::npos);
}

// Nested-map redaction: a redact_path into a nested map entry (text key) hides
// only that entry, keeping the sibling and the enclosing structure.
TEST(SdCwt, NestedMapRedaction)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  auto inner = sdcwt::CborValue::Map(
    {{std::string("keep"), sdcwt::value::text("INNER_KEEP")},
     {std::string("hide"), sdcwt::value::text("NESTED_HIDE")}});
  std::vector<sdcwt::Claim> claims = {{500, std::move(inner), false}};
  const std::vector<sdcwt::Path> paths = {{int64_t{500}, std::string("hide")}};

  const auto issued =
    sdcwt::issue(claims, *key, sdcwt::HashAlg::SHA_256, paths);

  ASSERT_EQ(issued.disclosures.size(), 1u);
  ASSERT_TRUE(issued.disclosures[0].key.has_value());
  EXPECT_EQ(std::get<std::string>(*issued.disclosures[0].key), "hide");
  EXPECT_FALSE(token_contains(issued.token, "NESTED_HIDE"));
  EXPECT_TRUE(token_contains(issued.token, "INNER_KEEP"));
}

// Deep nesting + ancestor-disclosure: redacting both a parent map and a child
// within it yields two disclosures; both values are absent from the token, and
// the parent's own disclosure carries the child as a still-redacted hash (so
// disclosing the parent alone does not reveal the child). Cross-validated
// against the Python reference in test_cpp_conformance.py.
TEST(SdCwt, NestedAncestorDisclosure)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  // claim 700 = { "a": { "b": "SECRET_CHILD", "c": "KEEP_SIBLING" } }
  auto grandchild = sdcwt::CborValue::Map(
    {{std::string("b"), sdcwt::value::text("SECRET_CHILD")},
     {std::string("c"), sdcwt::value::text("KEEP_SIBLING")}});
  auto child =
    sdcwt::CborValue::Map({{std::string("a"), std::move(grandchild)}});
  std::vector<sdcwt::Claim> claims = {{700, std::move(child), false}};
  // Redact the parent "a" AND the grandchild "b".
  const std::vector<sdcwt::Path> paths = {
    {int64_t{700}, std::string("a")},
    {int64_t{700}, std::string("a"), std::string("b")}};

  const auto issued =
    sdcwt::issue(claims, *key, sdcwt::HashAlg::SHA_256, paths);

  ASSERT_EQ(issued.disclosures.size(), 2u);
  EXPECT_FALSE(token_contains(issued.token, "SECRET_CHILD"));
  EXPECT_FALSE(
    token_contains(issued.token, "KEEP_SIBLING")); // inside redacted a

  // The parent "a" disclosure's value must still hide the child: its encoded
  // bytes contain the sibling but NOT the secret grandchild.
  const sdcwt::Disclosure* a_disc = nullptr;
  for (const auto& d : issued.disclosures)
  {
    if (
      d.key.has_value() && std::holds_alternative<std::string>(*d.key) &&
      std::get<std::string>(*d.key) == "a")
    {
      a_disc = &d;
    }
  }
  ASSERT_NE(a_disc, nullptr);
  const std::string a_enc(a_disc->encoded.begin(), a_disc->encoded.end());
  EXPECT_NE(a_enc.find("KEEP_SIBLING"), std::string::npos);
  EXPECT_EQ(a_enc.find("SECRET_CHILD"), std::string::npos);
}
