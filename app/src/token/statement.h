// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/sd_cwt.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sdcwt::statement
{
  // --- Clear header claims (standard CWT) ----------------------------------
  inline constexpr int64_t ISS = 1;
  inline constexpr int64_t IAT = 6;

  // --- Content claims (private-use block), all selectively-disclosable -----
  inline constexpr int64_t PARENT = 1000;
  inline constexpr int64_t TITLE = 1001;
  inline constexpr int64_t BODY = 1002;
  inline constexpr int64_t COMPONENT = 1003;
  inline constexpr int64_t SEVERITY = 1004;
  inline constexpr int64_t FINGERPRINT = 1005;
  inline constexpr int64_t REFERENCES = 1006;
  inline constexpr int64_t PATCH = 1007;
  inline constexpr int64_t PATCH_DATE = 1008;

  // Number of content fields carried by every statement (strict uniformity).
  inline constexpr size_t CONTENT_FIELD_COUNT = 9;

  // Schema/profile version this build implements. Bump on any change to the
  // content field set, their IDs, or the redaction/uniformity rules (DESIGN
  // §12.1). Surfaced by GET /version so a client knows which schema a live
  // service speaks; the authoritative binding remains the app code measurement.
  inline constexpr int64_t SCHEMA_VERSION = 1;

  // A statement's content. Absent fields are garbage-padded so every statement
  // has an identical redacted shape (report and note are indistinguishable).
  struct Fields
  {
    std::optional<std::vector<uint8_t>> parent; // parent-statement hash
    std::optional<std::string> title;
    std::optional<std::string> body;
    std::optional<std::string> component;
    std::optional<std::string> severity;
    std::optional<std::vector<uint8_t>> fingerprint;
    std::optional<std::vector<std::string>> references;
    std::optional<std::string> patch;
    std::optional<int64_t> patch_date;
  };

  // Build the strictly-uniform claim set: clear iss/iat + all 9 content fields
  // (real value when set, else a random `pad_len`-byte garbage sentinel), all
  // content redacted.
  std::vector<Claim> build_claims(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    size_t pad_len = SALT_LEN);

  // Build + sign a strictly-uniform statement token. The COSE signing algorithm
  // is derived from the key's curve; the redaction hash is `sd_alg` (default
  // SHA-256); `salt_len` is the per-disclosure salt / padding length (default
  // 16).
  //
  // Throws std::invalid_argument (unsupported curve) or std::runtime_error
  // (CBOR failure).
  IssuedToken issue_statement(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg = HashAlg::SHA_256,
    size_t salt_len = SALT_LEN);
}
