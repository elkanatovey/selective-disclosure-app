// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/statement.h"

#include "token/statement_internal.h"
#include "token/text_chunks.h"

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

    CborValue chunk_map(const std::string& text, size_t chunk_chars)
    {
      const auto chunks = text::chunk(text, chunk_chars);
      std::vector<std::pair<CborKey, CborValue>> entries;
      entries.reserve(chunks.size());
      for (size_t i = 0; i < chunks.size(); ++i)
      {
        entries.emplace_back(static_cast<int64_t>(i), value::text(chunks[i]));
      }
      return CborValue::Map(std::move(entries));
    }
  }

  std::vector<Claim> detail::build_claims(
    const std::string& iss,
    int64_t iat,
    const Fields& f,
    const RandomSource& rng,
    size_t pad_len,
    size_t chunk_chars)
  {
    const auto enc_text = std::function<CborValue(const std::string&)>(
      [](const std::string& s) { return value::text(s); });
    const auto enc_body = std::function<CborValue(const std::string&)>(
      [chunk_chars](const std::string& s) { return chunk_map(s, chunk_chars); });
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
    claims.push_back({BODY, or_pad(f.body, enc_body, rng, pad_len)});
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
    size_t pad_len,
    size_t chunk_chars)
  {
    const auto claims =
      detail::build_claims(iss, iat, fields, rng, pad_len, chunk_chars);

    // Every content claim is redacted whole (strict uniformity); only the
    // service-set clear claims stay visible. Derived from the claim set so the
    // content field list lives in one place (build_claims). `body` chunks and
    // `references` elements are additionally redacted one by one, so a single
    // chunk or reference can later be disclosed without revealing its
    // siblings; those hashes live inside the container's own disclosure
    // (ancestor-disclosure rule), so the shape at rest is unchanged. Only when
    // the field is really set — an absent one is a garbage sentinel with no
    // entries.
    std::vector<Path> redact_paths;
    redact_paths.reserve(CONTENT_FIELD_COUNT);
    for (const auto& c : claims)
    {
      if (c.key == ISS || c.key == IAT)
      {
        continue;
      }
      redact_paths.push_back(Path{PathElem(c.key)});
      if (c.key == BODY && c.value.kind == CborValue::Kind::Map)
      {
        for (size_t i = 0; i < c.value.map_keys.size(); ++i)
        {
          redact_paths.push_back(
            Path{PathElem(BODY), PathElem(static_cast<int64_t>(i))});
        }
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

    return sdcwt::detail::issue(claims, redact_paths, key, sd_alg, rng);
  }

  std::vector<Claim> build_claims(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    size_t pad_len,
    size_t chunk_chars)
  {
    return detail::build_claims(
      iss, iat, fields, default_random_source(), pad_len, chunk_chars);
  }

  IssuedToken issue_statement(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    size_t pad_len,
    size_t chunk_chars)
  {
    return detail::issue_statement(
      iss,
      iat,
      fields,
      key,
      sd_alg,
      default_random_source(),
      pad_len,
      chunk_chars);
  }
}
