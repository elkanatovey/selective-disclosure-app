// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/cbor_value.h"

#include <ccf/crypto/ec_key_pair.h>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace sdcwt
{
  // --- SD-CWT constants (mirror tools/sd_cwt/src/sd_cwt/core.py) ------------
  inline constexpr int64_t SD_ALG_LABEL = 170; // protected: redaction hash alg
  inline constexpr int64_t TYP_LABEL = 16; // protected: typ
  inline constexpr int64_t SD_CLAIMS_LABEL = 17; // unprotected: disclosures
  inline constexpr int64_t SD_CWT_TYP = 293; // application/sd-cwt
  inline constexpr uint8_t REDACTED_CLAIM_KEYS = 59; // CBOR simple(59)
  inline constexpr size_t SALT_LEN = 16; // 128-bit CSPRNG salt

  // Redaction hash algorithm. The enum values are the COSE hash-algorithm
  // identifiers written into the `sd_alg` protected header (and match the
  // Python reference `HashAlg`).
  enum class HashAlg : int64_t
  {
    SHA_256 = -16,
    SHA_384 = -43,
    SHA_512 = -44,
  };

  // Source of salt/garbage bytes; overridable in tests for determinism.
  using RandomSource = std::function<std::vector<uint8_t>(size_t)>;
  RandomSource default_random_source();

  // --- CBOR value constructors ---------------------------------------------
  namespace value
  {
    CborValue text(std::string_view s);
    CborValue integer(int64_t n);
    CborValue bytes(std::span<const uint8_t> b);
    CborValue text_array(const std::vector<std::string>& items);
  }

  // A single top-level claim: its integer key, its value, and whether it is
  // selectively-disclosable (redacted) or clear.
  struct Claim
  {
    int64_t key;
    CborValue value;
    bool redact;
  };

  // A path element: a map key (int or text) or an array index (int).
  using PathElem = std::variant<int64_t, std::string>;
  // A redaction path from the claims-map root, e.g. {1006, 1} redacts element 1
  // of the array claim 1006. A length-1 path redacts a whole top-level claim
  // (equivalent to Claim::redact); longer paths redact nested map/array
  // members.
  using Path = std::vector<PathElem>;

  // A generated Salted Disclosed Claim. `key` is absent for a redacted array
  // element (whose disclosure is `[salt, value]`); present for a map entry
  // (`[salt, value, key]`).
  struct Disclosure
  {
    std::optional<CborKey> key;
    std::vector<uint8_t> salt;
    std::vector<uint8_t>
      encoded; // cbor([salt, value, key]) or cbor([salt, value])
    std::vector<uint8_t> digest; // sd_alg hash of (bstr .cbor encoded)
  };

  struct IssuedToken
  {
    std::vector<uint8_t> token; // signed COSE_Sign1, NO disclosures attached
    std::vector<Disclosure> disclosures; // all redacted claims
  };

  // Redacted Claim Hash = `sd_alg` hash of the CBOR byte-string wrapping the
  // encoded salted disclosure array (draft-08 CDDL `bstr .cbor salted-entry`).
  std::vector<uint8_t> disclosure_digest(
    std::span<const uint8_t> encoded, HashAlg sd_alg = HashAlg::SHA_256);

  // Encode the SD-CWT protected header {1: cose_alg, 170: sd_alg, 16: typ}.
  std::vector<uint8_t> encode_sdcwt_protected_header(
    int64_t cose_alg, HashAlg sd_alg);

  // Build and sign a redacted SD-CWT over the given top-level claims. Each
  // `Claim` with `redact == true` is redacted whole; `redact_paths`
  // additionally redacts nested map entries / array elements at arbitrary depth
  // (the ancestor-disclosure rule applies: a disclosed parent may reveal a
  // still-redacted child). Redacted map entries become sorted Redacted Claim
  // Hashes under simple(59); redacted array elements become tag(60) hashes.
  // Disclosures are returned separately. The COSE signing algorithm is derived
  // from the key's curve; the redaction hash is `sd_alg` (default SHA-256);
  // `salt_len` is the per-disclosure salt length in bytes (default 16).
  //
  // Throws std::invalid_argument (unsupported curve / path into a
  // non-container) or std::runtime_error (CBOR failure).
  IssuedToken issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg = HashAlg::SHA_256,
    const std::vector<Path>& redact_paths = {},
    const RandomSource& rng = default_random_source(),
    size_t salt_len = SALT_LEN);
}
