// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cbor.h"
#include "token/statement.h"

#include <ccf/crypto/ec_key_pair.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

namespace
{
  // Emit a C++-produced statement (token + disclosures + signer pubkey) for the
  // given curve + redaction hash into $SDCWT_ARTIFACT_DIR/<suite>/, for the
  // Python conformance test to validate. Field values MUST stay in sync with
  // test_cpp_conformance.py.
  void emit_suite(
    const std::string& base,
    const std::string& suite,
    ccf::crypto::CurveID curve,
    sdcwt::HashAlg sd_alg)
  {
    auto key = ccf::crypto::make_ec_key_pair(curve);

    sdcwt::statement::Fields f;
    f.parent = std::vector<uint8_t>(32, 0x11);
    f.title = "conformance title";
    f.fingerprint = std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef};
    f.references = std::vector<std::string>{"CVE-2025-9999"};

    const auto issued = sdcwt::statement::issue_statement(
      "https://ledger.example/tee", 1700000000, f, *key, sd_alg);

    const auto disclosures = sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      for (const auto& d : issued.disclosures)
      {
        QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(d.encoded));
      }
      QCBOREncode_CloseArray(&ctx);
    });

    const std::string dir = base + "/" + suite;
    std::filesystem::create_directories(dir);
    const auto write = [&](const std::string& name, const void* p, size_t n) {
      std::ofstream out(dir + "/" + name, std::ios::binary);
      out.write(static_cast<const char*>(p), static_cast<std::streamsize>(n));
    };

    write("statement.cbor", issued.token.data(), issued.token.size());
    write("disclosures.cbor", disclosures.data(), disclosures.size());
    const auto pem = key->public_key_pem().str();
    write("signer.pem", pem.data(), pem.size());
  }
  // Emit a fully-populated statement signed with a DETERMINISTIC salt source
  // (the i-th 16-byte salt is all-bytes-equal-to-i), so the Python reference
  // can byte-compare its own payload against this one. Values MUST stay in sync
  // with test_cpp_conformance.py::test_payload_byte_identical_to_python.
  void emit_deterministic(const std::string& base)
  {
    auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

    sdcwt::statement::Fields f;
    f.parent = std::vector<uint8_t>(32, 0x11);
    f.title = "conformance title";
    f.body = "body text";
    f.component = "parser";
    f.severity = "high";
    f.fingerprint = std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef};
    f.references = std::vector<std::string>{"CVE-2025-9999"};
    f.patch = "fixed";
    f.patch_date = 1700100000;

    // Counter-based salt source: call i returns n bytes all equal to i.
    auto counter = std::make_shared<uint8_t>(0);
    sdcwt::RandomSource det_rng = [counter](size_t n) {
      std::vector<uint8_t> v(n, *counter);
      ++(*counter);
      return v;
    };

    const auto issued = sdcwt::statement::issue_statement(
      "https://ledger.example/tee",
      1700000000,
      f,
      *key,
      sdcwt::HashAlg::SHA_256,
      det_rng);

    const std::string dir = base + "/det";
    std::filesystem::create_directories(dir);
    std::ofstream out(dir + "/statement.cbor", std::ios::binary);
    out.write(
      reinterpret_cast<const char*>(issued.token.data()),
      static_cast<std::streamsize>(issued.token.size()));
  }

  // Emit a generic token with a redacted ARRAY ELEMENT (tag 60), so the Python
  // reference can reconstruct it via the core verifier. Values MUST stay in
  // sync with
  // test_cpp_conformance.py::test_python_validates_cpp_array_redaction.
  void emit_array_redaction(const std::string& base)
  {
    auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("https://ledger.example/tee"), false},
      {1006, sdcwt::value::text_array({"REF_A", "REF_B", "REF_C"}), false},
    };
    // Redact element 1 of the array claim 1006.
    const std::vector<sdcwt::Path> paths = {{int64_t{1006}, int64_t{1}}};

    const auto issued =
      sdcwt::issue(claims, *key, sdcwt::HashAlg::SHA_256, paths);

    const auto disclosures = sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      for (const auto& d : issued.disclosures)
      {
        QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(d.encoded));
      }
      QCBOREncode_CloseArray(&ctx);
    });

    const std::string dir = base + "/array";
    std::filesystem::create_directories(dir);
    const auto write = [&](const std::string& name, const void* p, size_t n) {
      std::ofstream out(dir + "/" + name, std::ios::binary);
      out.write(static_cast<const char*>(p), static_cast<std::streamsize>(n));
    };
    write("statement.cbor", issued.token.data(), issued.token.size());
    write("disclosures.cbor", disclosures.data(), disclosures.size());
    const auto pem = key->public_key_pem().str();
    write("signer.pem", pem.data(), pem.size());
  }
}

// Emit conformance artifacts across signing/redaction-hash suites, so the
// Python reference can validate C++ output for each. Only runs when
// SDCWT_ARTIFACT_DIR is set (a no-op in normal runs).
TEST(Conformance, EmitStatementArtifactsForPython)
{
  const char* dir = std::getenv("SDCWT_ARTIFACT_DIR");
  if (dir == nullptr)
  {
    GTEST_SKIP() << "SDCWT_ARTIFACT_DIR not set";
  }

  emit_suite(
    dir, "es256", ccf::crypto::CurveID::SECP256R1, sdcwt::HashAlg::SHA_256);
  emit_suite(
    dir, "es384", ccf::crypto::CurveID::SECP384R1, sdcwt::HashAlg::SHA_384);
  emit_deterministic(dir);
  emit_array_redaction(dir);

  SUCCEED();
}
