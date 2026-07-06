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

  EXPECT_EQ(a.disclosures.size(), sdcwt::statement::CONTENT_FIELD_COUNT);
  EXPECT_EQ(b.disclosures.size(), sdcwt::statement::CONTENT_FIELD_COUNT);

  const std::vector<int64_t> expected = {
    1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008};
  EXPECT_EQ(disclosure_keys(a), expected);
  EXPECT_EQ(disclosure_keys(b), expected);
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
