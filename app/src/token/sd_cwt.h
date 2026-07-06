// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/cbor_value.h"

#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ec_public_key.h>
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
  inline constexpr int64_t CNF_LABEL = 8; // clear: RFC 8747 confirmation claim

  // Key Binding Token constants (draft-08 s8).
  inline constexpr int64_t KCWT_LABEL = 13; // KBT phdr: embedded issued SD-CWT
  inline constexpr int64_t KB_CWT_TYP = 294; // typ: application/kb+cwt
  inline constexpr int64_t CWT_AUD = 3; // audience
  inline constexpr int64_t CWT_EXP = 4; // expiry
  inline constexpr int64_t CWT_NBF = 5; // not-before
  inline constexpr int64_t CWT_IAT = 6; // issued-at
  inline constexpr int64_t CWT_CTI = 7; // token id
  inline constexpr int64_t CWT_CNONCE = 39; // challenge nonce

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
      encoded; // cbor([salt, value, key]), cbor([salt, value]), or cbor([salt])
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
  // `pad_to`, if non-zero, pads the top-level Redacted-Claim-Hash count up to
  // that many entries with indistinguishable salt-only decoy disclosures, so
  // the count does not reveal how many real claims were redacted.
  //
  // `holder`, if non-null, embeds it as the RFC 8747 confirmation claim (`cnf`,
  // claim 8) in the CLEAR payload: `8: {1: COSE_Key}` carrying only the holder
  // public key's EC2 coordinates. This makes the issued token key-binding
  // capable (a holder of the matching private key can later present it with a
  // Key Binding Token); the issuer never sees the private key.
  //
  // Throws std::invalid_argument (unsupported curve, or a redact_path that does
  // not resolve to an existing claim/element / descends into a non-container)
  // or std::runtime_error (CBOR failure).
  IssuedToken issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg = HashAlg::SHA_256,
    const std::vector<Path>& redact_paths = {},
    const RandomSource& rng = default_random_source(),
    size_t salt_len = SALT_LEN,
    size_t pad_to = 0,
    const ccf::crypto::ECPublicKey* holder = nullptr);

  // Attach `selected` disclosures (their encoded `[salt, value, key]` bytes) to
  // an issued SD-CWT's unprotected header (sd_claims, label 17), leaving the
  // protected header, payload and signature untouched (no re-signing). Passing
  // an empty selection omits the sd_claims header entirely. Mirrors the Python
  // reference `present`. Throws std::runtime_error on a malformed token.
  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected);

  // Key Binding Token payload parameters (draft-08 s8.1). `aud` (the intended
  // verifier) is required; at least one of `iat`/`cti` MUST be set. `iss`/`sub`
  // are forbidden by the spec and are never emitted.
  struct KbtParams
  {
    std::string aud;
    std::optional<int64_t> iat;
    std::optional<std::vector<uint8_t>> cti;
    std::optional<std::vector<uint8_t>> cnonce;
    std::optional<int64_t> exp;
    std::optional<int64_t> nbf;
  };

  // Sign a Key Binding Token (draft-08 s8): present `selected` disclosures on
  // the SD-CWT `token`, embed the presented SD-CWT in the KBT `kcwt` (13)
  // protected header, and sign the KBT (typ = application/kb+cwt) with the
  // `holder` private key — which MUST correspond to the SD-CWT `cnf` key for a
  // verifier's proof-of-possession check to pass. The signing algorithm is
  // derived from the holder key's curve.
  //
  // Throws std::invalid_argument (neither iat nor cti set, or an unsupported
  // holder curve) or std::runtime_error (malformed token / CBOR failure).
  std::vector<uint8_t> kbt_sign(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected,
    const ccf::crypto::ECKeyPair& holder,
    const KbtParams& params);
}
