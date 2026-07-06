// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/statement.h"

namespace sdcwt::statement
{
  namespace
  {
    // Encode a content field's value, or a `pad_len`-byte garbage sentinel when
    // absent.
    template <typename T>
    CborValue or_pad(
      const std::optional<T>& field,
      const std::function<CborValue(const T&)>& encode,
      const RandomSource& rng,
      size_t pad_len)
    {
      if (field.has_value())
      {
        return encode(*field);
      }
      return value::bytes(rng(pad_len)); // garbage sentinel (never disclosed)
    }
  }

  std::vector<Claim> build_claims(
    const std::string& iss,
    int64_t iat,
    const Fields& f,
    const RandomSource& rng,
    size_t pad_len)
  {
    const auto enc_text = std::function<CborValue(const std::string&)>(
      [](const std::string& s) { return value::text(s); });
    const auto enc_bytes =
      std::function<CborValue(const std::vector<uint8_t>&)>(
        [](const std::vector<uint8_t>& b) { return value::bytes(b); });
    const auto enc_int = std::function<CborValue(const int64_t&)>(
      [](const int64_t& n) { return value::integer(n); });
    const auto enc_refs =
      std::function<CborValue(const std::vector<std::string>&)>(
        [](const std::vector<std::string>& r) { return value::text_array(r); });

    std::vector<Claim> claims;
    claims.reserve(2 + CONTENT_FIELD_COUNT);

    // Clear claims (service-set).
    claims.push_back({ISS, value::text(iss), false});
    claims.push_back({IAT, value::integer(iat), false});

    // Content claims, in canonical order, all redacted (strict uniformity).
    claims.push_back({PARENT, or_pad(f.parent, enc_bytes, rng, pad_len), true});
    claims.push_back({TITLE, or_pad(f.title, enc_text, rng, pad_len), true});
    claims.push_back({BODY, or_pad(f.body, enc_text, rng, pad_len), true});
    claims.push_back(
      {COMPONENT, or_pad(f.component, enc_text, rng, pad_len), true});
    claims.push_back(
      {SEVERITY, or_pad(f.severity, enc_text, rng, pad_len), true});
    claims.push_back(
      {FINGERPRINT, or_pad(f.fingerprint, enc_bytes, rng, pad_len), true});
    claims.push_back(
      {REFERENCES, or_pad(f.references, enc_refs, rng, pad_len), true});
    claims.push_back({PATCH, or_pad(f.patch, enc_text, rng, pad_len), true});
    claims.push_back(
      {PATCH_DATE, or_pad(f.patch_date, enc_int, rng, pad_len), true});

    return claims;
  }

  IssuedToken issue_statement(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const RandomSource& rng,
    size_t salt_len)
  {
    return issue(
      build_claims(iss, iat, fields, rng, salt_len),
      key,
      sd_alg,
      {},
      rng,
      salt_len);
  }
}
