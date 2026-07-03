// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <ccf/crypto/ec_key_pair.h>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sdcwt
{
  // --- SD-CWT constants (mirror tools/sd_cwt/src/sd_cwt/core.py) ------------
  inline constexpr int64_t SD_ALG_LABEL = 170; // protected: redaction hash alg
  inline constexpr int64_t TYP_LABEL = 16; // protected: typ
  inline constexpr int64_t SD_CLAIMS_LABEL = 17; // unprotected: disclosures
  inline constexpr int64_t SD_CWT_TYP = 293; // application/sd-cwt
  inline constexpr uint8_t REDACTED_CLAIM_KEYS = 59; // CBOR simple(59)
  inline constexpr int64_t SD_ALG_SHA_256 = -16; // COSE hash alg id (SHA-256)
  inline constexpr size_t SALT_LEN = 16; // 128-bit CSPRNG salt

  // Source of salt/garbage bytes; overridable in tests for determinism.
  using RandomSource = std::function<std::vector<uint8_t>(size_t)>;
  RandomSource default_random_source();

  // --- CBOR value encoders (produce a single pre-encoded CBOR item) --------
  namespace value
  {
    std::vector<uint8_t> text(std::string_view s);
    std::vector<uint8_t> integer(int64_t n);
    std::vector<uint8_t> bytes(std::span<const uint8_t> b);
    std::vector<uint8_t> text_array(const std::vector<std::string>& items);
  }

  // A single top-level claim: its integer key, a pre-encoded CBOR value, and
  // whether it is selectively-disclosable (redacted) or clear.
  struct Claim
  {
    int64_t key;
    std::vector<uint8_t> value_cbor;
    bool redact;
  };

  // A generated Salted Disclosed Claim for a redacted map entry.
  struct Disclosure
  {
    int64_t key;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> value_cbor;
    std::vector<uint8_t> encoded; // cbor([salt, value, key])
    std::vector<uint8_t> digest; // sha256(bstr .cbor encoded)
  };

  struct IssuedToken
  {
    std::vector<uint8_t> token; // signed COSE_Sign1, NO disclosures attached
    std::vector<Disclosure> disclosures; // all redacted claims
  };

  // Redacted Claim Hash = sha256 of the CBOR byte-string wrapping the encoded
  // salted disclosure array (draft-08 CDDL `bstr .cbor salted-entry`).
  std::vector<uint8_t> disclosure_digest(std::span<const uint8_t> encoded);

  // Encode the SD-CWT protected header {1: ES256, 170: sd_alg, 16: typ}.
  std::vector<uint8_t> encode_sdcwt_protected_header();

  // Build and sign a redacted SD-CWT over the given top-level claims. Redacted
  // claims are removed from the payload and represented by sorted Redacted
  // Claim Hashes under simple(59); their disclosures are returned separately.
  //
  // Throws std::invalid_argument (non-P-256 key) or std::runtime_error (CBOR
  // failure); a CCF endpoint handler MUST catch these.
  IssuedToken issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    const RandomSource& rng = default_random_source());
}
