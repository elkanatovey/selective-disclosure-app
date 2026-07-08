// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/statement.h"

#include <algorithm>
#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/ec_key_pair.h>
#include <gtest/gtest.h>

namespace
{
  std::vector<int64_t> disclosure_keys(const sdcwt::IssuedToken& t)
  {
    std::vector<int64_t> keys;
    for (const auto& d : t.disclosures)
    {
      if (d.key.has_value() && std::holds_alternative<int64_t>(*d.key))
      {
        keys.push_back(std::get<int64_t>(*d.key));
      }
    }
    std::sort(keys.begin(), keys.end());
    return keys;
  }

  // Disclosures for whole top-level claims (path length 1) — the ones that
  // shape the at-rest redacted token. Nested disclosures (array elements, path
  // length >1) live inside a redacted claim and don't affect the at-rest shape.
  size_t top_level_disclosure_count(const sdcwt::IssuedToken& t)
  {
    size_t n = 0;
    for (const auto& d : t.disclosures)
    {
      if (d.path.size() == 1)
      {
        ++n;
      }
    }
    return n;
  }

  bool token_contains(const sdcwt::IssuedToken& t, const std::string& needle)
  {
    const std::string hay(t.token.begin(), t.token.end());
    return hay.find(needle) != std::string::npos;
  }
}

TEST(Statement, RoundTripVerifiesUnderCcf)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  sdcwt::statement::Fields f;
  f.body = "orig report";

  const auto issued = sdcwt::statement::issue_statement(
    "https://ledger.example/tee", 1700000000, f, *key);

  auto verifier =
    ccf::crypto::make_cose_verifier_from_key(key->public_key_pem());
  std::span<uint8_t> content;
  EXPECT_TRUE(verifier->verify(issued.token, content));
}

// A one-field note and a fully-populated report must have identical redacted
// shape: same count of redacted claims (9) and the same claim-key set.
TEST(Statement, StrictUniformityIdenticalShape)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

  sdcwt::statement::Fields minimal;
  minimal.fingerprint = std::vector<uint8_t>{0xab, 0xcd};

  sdcwt::statement::Fields full;
  full.parent = std::vector<uint8_t>(32, 0x11);
  full.title = "heap overflow";
  full.body = "details";
  full.component = "parser";
  full.severity = "high";
  full.fingerprint = std::vector<uint8_t>{0xab, 0xcd};
  full.references = std::vector<std::string>{"CVE-2025-0001", "https://x/y"};
  full.patch = "fixed in 1.2.3";
  full.patch_date = 1700100000;

  const auto a = sdcwt::statement::issue_statement("iss", 1, minimal, *key);
  const auto b = sdcwt::statement::issue_statement("iss", 1, full, *key);

  // At-rest uniformity: both have exactly the 9 whole-field (top-level)
  // disclosures with the same claim keys, so their signed tokens have an
  // identical redacted shape regardless of content.
  EXPECT_EQ(
    top_level_disclosure_count(a), sdcwt::statement::CONTENT_FIELD_COUNT);
  EXPECT_EQ(
    top_level_disclosure_count(b), sdcwt::statement::CONTENT_FIELD_COUNT);

  const std::vector<int64_t> expected = {
    1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008};
  EXPECT_EQ(disclosure_keys(a), expected);
  EXPECT_EQ(disclosure_keys(b), expected);
}

// `references` elements are additionally redacted individually so a single one
// can later be disclosed. This is nested (path length 2) and does not disturb
// the at-rest top-level shape (the whole array is still one redacted claim).
TEST(Statement, ReferencesElementsAreIndividuallyRedactable)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

  sdcwt::statement::Fields f;
  f.references = std::vector<std::string>{"CVE-1", "CVE-2", "CVE-3"};

  const auto issued = sdcwt::statement::issue_statement("iss", 1, f, *key);

  // Top level is still strictly uniform: 9 whole-field disclosures.
  EXPECT_EQ(
    top_level_disclosure_count(issued), sdcwt::statement::CONTENT_FIELD_COUNT);

  // One nested disclosure per reference element, at paths {1006,0}, {1006,1},
  // {1006,2} exactly (the indices, not just the count, must be right).
  std::vector<int64_t> element_indices;
  for (const auto& d : issued.disclosures)
  {
    if (d.path.size() == 2)
    {
      ASSERT_EQ(std::get<int64_t>(d.path[0]), sdcwt::statement::REFERENCES);
      element_indices.push_back(std::get<int64_t>(d.path[1]));
    }
  }
  std::sort(element_indices.begin(), element_indices.end());
  EXPECT_EQ(element_indices, (std::vector<int64_t>{0, 1, 2}));

  // Every reference value is hidden in the signed token.
  EXPECT_FALSE(token_contains(issued, "CVE-1"));
  EXPECT_FALSE(token_contains(issued, "CVE-2"));
  EXPECT_FALSE(token_contains(issued, "CVE-3"));
}

// An absent `references` field (garbage sentinel) yields no nested disclosures.
TEST(Statement, AbsentReferencesHasNoElementDisclosures)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  sdcwt::statement::Fields f;
  f.title = "no refs";

  const auto issued = sdcwt::statement::issue_statement("iss", 1, f, *key);
  EXPECT_EQ(
    top_level_disclosure_count(issued), sdcwt::statement::CONTENT_FIELD_COUNT);
  EXPECT_EQ(issued.disclosures.size(), sdcwt::statement::CONTENT_FIELD_COUNT);
}

TEST(Statement, ContentValuesAreHiddenInToken)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  sdcwt::statement::Fields f;
  f.title = "SENSITIVE_TITLE";
  f.body = "SENSITIVE_BODY";

  const auto issued = sdcwt::statement::issue_statement("iss", 1, f, *key);
  EXPECT_FALSE(token_contains(issued, "SENSITIVE_TITLE"));
  EXPECT_FALSE(token_contains(issued, "SENSITIVE_BODY"));
}

// A root (no parent) still carries a redacted parent slot -> strict uniformity.
TEST(Statement, RootStillHasParentDisclosure)
{
  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
  sdcwt::statement::Fields f;
  f.body = "root";

  const auto issued = sdcwt::statement::issue_statement("iss", 1, f, *key);
  const auto keys = disclosure_keys(issued);
  EXPECT_NE(
    std::find(keys.begin(), keys.end(), sdcwt::statement::PARENT), keys.end());
}
