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

  // Emit a token with DEEP NESTED redaction + ancestor disclosure: claim 700 =
  // { "a": { "b": <secret>, "c": <sibling> } } with both "a" and "a"."b"
  // redacted. The Python reference must reconstruct the full structure from all
  // disclosures. Values MUST stay in sync with
  // test_cpp_conformance.py::test_python_validates_cpp_nested_redaction.
  void emit_nested_redaction(const std::string& base)
  {
    auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

    auto grandchild = sdcwt::CborValue::Map(
      {{std::string("b"), sdcwt::value::text("SECRET_CHILD")},
       {std::string("c"), sdcwt::value::text("KEEP_SIBLING")}});
    auto child =
      sdcwt::CborValue::Map({{std::string("a"), std::move(grandchild)}});
    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("https://ledger.example/tee"), false},
      {700, std::move(child), false},
    };
    const std::vector<sdcwt::Path> paths = {
      {int64_t{700}, std::string("a")},
      {int64_t{700}, std::string("a"), std::string("b")}};

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

    const std::string dir = base + "/nested";
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

  // Emit a generic token with DECOY PADDING under a DETERMINISTIC salt
  // source, so the Python reference can byte-compare its own padded payload.
  // claim 1002 is redacted and the top-level redacted-hash count is padded to
  // 5 with salt-only decoys. Values MUST stay in sync with
  // test_cpp_conformance.py::test_decoy_padding_byte_identical_to_python.
  void emit_decoy(const std::string& base)
  {
    auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);

    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("https://ledger.example/tee"), false},
      {1002, sdcwt::value::text("secret body"), true},
    };

    // Counter-based salt source: call i returns n bytes all equal to i.
    auto counter = std::make_shared<uint8_t>(0);
    sdcwt::RandomSource det_rng = [counter](size_t n) {
      std::vector<uint8_t> v(n, *counter);
      ++(*counter);
      return v;
    };

    const auto issued = sdcwt::issue(
      claims,
      *key,
      sdcwt::HashAlg::SHA_256,
      /*redact_paths=*/{},
      det_rng,
      sdcwt::SALT_LEN,
      /*pad_to=*/5);

    const std::string dir = base + "/decoy";
    std::filesystem::create_directories(dir);
    std::ofstream out(dir + "/statement.cbor", std::ios::binary);
    out.write(
      reinterpret_cast<const char*>(issued.token.data()),
      static_cast<std::streamsize>(issued.token.size()));
  }

  // Emit a generic token that BINDS a holder key via the RFC 8747 `cnf`
  // claim, plus the holder's public key, so the Python reference can recover
  // the cnf key and confirm the C++-issued token is key-binding capable /
  // spec-correct. Values MUST stay in sync with
  // test_cpp_conformance.py::test_python_reads_cpp_cnf.
  void emit_cnf(const std::string& base)
  {
    auto issuer =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    auto holder =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    auto holder_pub = ccf::crypto::make_ec_public_key(holder->public_key_pem());

    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("https://ledger.example/tee"), false},
      {1002, sdcwt::value::text("secret body"), true},
    };

    const auto issued = sdcwt::issue(
      claims,
      *issuer,
      sdcwt::HashAlg::SHA_256,
      /*redact_paths=*/{},
      sdcwt::default_random_source(),
      sdcwt::SALT_LEN,
      /*pad_to=*/0,
      holder_pub.get());

    const auto disclosures = sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      for (const auto& d : issued.disclosures)
      {
        QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(d.encoded));
      }
      QCBOREncode_CloseArray(&ctx);
    });

    const std::string dir = base + "/cnf";
    std::filesystem::create_directories(dir);
    const auto write = [&](const std::string& name, const void* p, size_t n) {
      std::ofstream out(dir + "/" + name, std::ios::binary);
      out.write(static_cast<const char*>(p), static_cast<std::streamsize>(n));
    };
    write("statement.cbor", issued.token.data(), issued.token.size());
    write("disclosures.cbor", disclosures.data(), disclosures.size());
    const auto signer_pem = issuer->public_key_pem().str();
    write("signer.pem", signer_pem.data(), signer_pem.size());
    const auto holder_pem = holder_pub->public_key_pem().str();
    write("holder.pem", holder_pem.data(), holder_pem.size());
  }

  // Emit a holder-signed Key Binding Token (draft-08 s8) over a C++-issued,
  // cnf-bound SD-CWT, presenting one of two redacted claims. The Python
  // reference `kbt_verify` must accept it: verify the issuer signature, recover
  // the holder key from cnf and check proof-of-possession, match the audience +
  // cnonce, and reconstruct only the presented disclosure. Values MUST stay in
  // sync with test_cpp_conformance.py::test_python_verifies_cpp_kbt.
  void emit_kbt(const std::string& base)
  {
    auto issuer =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    auto holder =
      ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
    auto holder_pub = ccf::crypto::make_ec_public_key(holder->public_key_pem());

    std::vector<sdcwt::Claim> claims = {
      {1, sdcwt::value::text("https://ledger.example/tee"), false},
      {1002, sdcwt::value::text("secret body"), true},
      {1003, sdcwt::value::text("other secret"), true},
    };
    const auto issued = sdcwt::issue(
      claims,
      *issuer,
      sdcwt::HashAlg::SHA_256,
      /*redact_paths=*/{},
      sdcwt::default_random_source(),
      sdcwt::SALT_LEN,
      /*pad_to=*/0,
      holder_pub.get());

    // Present only the disclosure for claim 1002 (leave 1003 hidden).
    std::vector<std::vector<uint8_t>> selected;
    for (const auto& d : issued.disclosures)
    {
      if (
        d.key.has_value() && std::holds_alternative<int64_t>(*d.key) &&
        std::get<int64_t>(*d.key) == 1002)
      {
        selected.push_back(d.encoded);
      }
    }

    sdcwt::KbtParams params;
    params.aud = "https://vendor.example/verify";
    params.iat = 1700000500;
    params.cnonce = std::vector<uint8_t>{0xa1, 0xb2, 0xc3, 0xd4};
    const auto kbt = sdcwt::kbt_sign(issued.token, selected, *holder, params);

    const std::string dir = base + "/kbt";
    std::filesystem::create_directories(dir);
    const auto write = [&](const std::string& name, const void* p, size_t n) {
      std::ofstream out(dir + "/" + name, std::ios::binary);
      out.write(static_cast<const char*>(p), static_cast<std::streamsize>(n));
    };
    write("kbt.cbor", kbt.data(), kbt.size());
    const auto signer_pem = issuer->public_key_pem().str();
    write("signer.pem", signer_pem.data(), signer_pem.size());
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
  emit_nested_redaction(dir);
  emit_decoy(dir);
  emit_cnf(dir);
  emit_kbt(dir);

  SUCCEED();
}
