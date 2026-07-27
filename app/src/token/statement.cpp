// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/statement.h"

#include "token/statement_internal.h"

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

  std::vector<Claim> detail::build_claims(
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
    claims.push_back({ISS, value::text(iss)});
    claims.push_back({IAT, value::integer(iat)});

    // Content claims, in canonical order. Which of these are redacted is
    // expressed by the redaction paths in issue_statement(), not here.
    claims.push_back({PARENT, or_pad(f.parent, enc_bytes, rng, pad_len)});
    claims.push_back({TITLE, or_pad(f.title, enc_text, rng, pad_len)});
    claims.push_back({BODY, or_pad(f.body, enc_text, rng, pad_len)});
    claims.push_back({COMPONENT, or_pad(f.component, enc_text, rng, pad_len)});
    claims.push_back({SEVERITY, or_pad(f.severity, enc_text, rng, pad_len)});
    claims.push_back(
      {FINGERPRINT, or_pad(f.fingerprint, enc_bytes, rng, pad_len)});
    claims.push_back(
      {REFERENCES, or_pad(f.references, enc_refs, rng, pad_len)});
    claims.push_back({PATCH, or_pad(f.patch, enc_text, rng, pad_len)});
    claims.push_back({PATCH_DATE, or_pad(f.patch_date, enc_int, rng, pad_len)});

    return claims;
  }

  IssuedToken detail::issue_statement(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const RandomSource& rng,
    size_t salt_len)
  {
    const auto claims = detail::build_claims(iss, iat, fields, rng, salt_len);

    // Every content claim is redacted whole (strict uniformity); only the
    // service-set clear claims stay visible. Derived from the claim set so the
    // content field list lives in one place (build_claims). Each `references`
    // element is additionally redacted so a single reference can later be
    // disclosed without revealing its siblings; those element hashes live
    // inside the array's own disclosure (ancestor-disclosure rule), so the
    // shape at rest is unchanged. Only when the field is really an array — an
    // absent field is a garbage sentinel with no elements.
    std::vector<Path> redact_paths;
    redact_paths.reserve(CONTENT_FIELD_COUNT);
    for (const auto& c : claims)
    {
      if (c.key != ISS && c.key != IAT)
      {
        redact_paths.push_back(Path{PathElem(c.key)});
      }
    }
    if (fields.references.has_value())
    {
      for (size_t i = 0; i < fields.references->size(); ++i)
      {
        redact_paths.push_back(
          Path{PathElem(REFERENCES), PathElem(static_cast<int64_t>(i))});
      }
    }

    return sdcwt::detail::issue(
      claims, redact_paths, key, sd_alg, rng, salt_len);
  }

  std::vector<Claim> build_claims(
    const std::string& iss, int64_t iat, const Fields& fields, size_t pad_len)
  {
    return detail::build_claims(
      iss, iat, fields, default_random_source(), pad_len);
  }

  IssuedToken issue_statement(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    size_t salt_len)
  {
    return detail::issue_statement(
      iss, iat, fields, key, sd_alg, default_random_source(), salt_len);
  }
}
