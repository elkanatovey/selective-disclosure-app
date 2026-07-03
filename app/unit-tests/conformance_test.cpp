// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cbor.h"
#include "token/statement.h"

#include <ccf/crypto/ec_key_pair.h>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>

// Emit a C++-produced statement token + its disclosures + the signer's public
// key to files, for the Python conformance test (tools/sd_cwt) to validate.
// Only runs when SDCWT_ARTIFACT_DIR is set, so it is a no-op in normal runs.
//
// Field values here MUST stay in sync with test_cpp_conformance.py.
TEST(Conformance, EmitStatementArtifactsForPython)
{
  const char* dir = std::getenv("SDCWT_ARTIFACT_DIR");
  if (dir == nullptr)
  {
    GTEST_SKIP() << "SDCWT_ARTIFACT_DIR not set";
  }

  auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

  sdcwt::statement::Fields f;
  f.parent = std::vector<uint8_t>(32, 0x11);
  f.title = "conformance title";
  f.fingerprint = std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef};
  f.references = std::vector<std::string>{"CVE-2025-9999"};

  const auto issued = sdcwt::statement::issue_statement(
    "https://ledger.example/tee", 1700000000, f, *key);

  // Disclosures as a CBOR array of the encoded salted-disclosure byte strings.
  const auto disclosures = sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
    QCBOREncode_OpenArray(&ctx);
    for (const auto& d : issued.disclosures)
    {
      QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(d.encoded));
    }
    QCBOREncode_CloseArray(&ctx);
  });

  const std::string base = dir;
  const auto write = [&](const std::string& name, const void* p, size_t n) {
    std::ofstream out(base + "/" + name, std::ios::binary);
    out.write(static_cast<const char*>(p), static_cast<std::streamsize>(n));
  };

  write("statement.cbor", issued.token.data(), issued.token.size());
  write("disclosures.cbor", disclosures.data(), disclosures.size());
  const auto pem = key->public_key_pem().str();
  write("signer.pem", pem.data(), pem.size());

  SUCCEED();
}
