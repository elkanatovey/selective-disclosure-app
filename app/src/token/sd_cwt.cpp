// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/sd_cwt.h"

#include "token/cbor.h"
#include "token/cose.h"

#include <algorithm>
#include <ccf/crypto/entropy.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/md_type.h>

namespace sdcwt
{
  namespace
  {
    ccf::crypto::MDType md_for_hash_alg(HashAlg sd_alg)
    {
      switch (sd_alg)
      {
        case HashAlg::SHA_256:
          return ccf::crypto::MDType::SHA256;
        case HashAlg::SHA_384:
          return ccf::crypto::MDType::SHA384;
        case HashAlg::SHA_512:
          return ccf::crypto::MDType::SHA512;
        default:
          throw std::invalid_argument("unsupported sd_alg hash");
      }
    }
  }

  RandomSource default_random_source()
  {
    return [](size_t n) { return ccf::crypto::get_entropy()->random(n); };
  }

  namespace value
  {
    CborValue text(std::string_view s)
    {
      return CborValue::Text(std::string(s));
    }

    CborValue integer(int64_t n)
    {
      return CborValue::Int(n);
    }

    CborValue bytes(std::span<const uint8_t> b)
    {
      return CborValue::Bytes(std::vector<uint8_t>(b.begin(), b.end()));
    }

    CborValue text_array(const std::vector<std::string>& items)
    {
      std::vector<CborValue> elems;
      elems.reserve(items.size());
      for (const auto& item : items)
      {
        elems.push_back(CborValue::Text(item));
      }
      return CborValue::Array(std::move(elems));
    }
  }

  std::vector<uint8_t> disclosure_digest(
    std::span<const uint8_t> encoded, HashAlg sd_alg)
  {
    // Wrap the encoded salted array in a CBOR byte string, then hash it.
    const auto wrapped = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_AddBytes(&ctx, to_ubc(encoded));
    });
    return ccf::crypto::make_hash_provider()->hash(
      wrapped.data(), wrapped.size(), md_for_hash_alg(sd_alg));
  }

  std::vector<uint8_t> encode_sdcwt_protected_header(
    int64_t cose_alg, HashAlg sd_alg)
  {
    // Map keys are emitted in CDE (RFC 8949 §4.2) order: 1 (alg) < 16 (typ) <
    // 170 (sd_alg).
    return cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      QCBOREncode_AddInt64ToMapN(&ctx, 1, cose_alg); // alg
      QCBOREncode_AddInt64ToMapN(&ctx, TYP_LABEL, SD_CWT_TYP); // typ (16)
      QCBOREncode_AddInt64ToMapN(
        &ctx, SD_ALG_LABEL, static_cast<int64_t>(sd_alg)); // sd_alg (170)
      QCBOREncode_CloseMap(&ctx);
    });
  }

  namespace
  {
    // cbor([salt, <value>, key]) for a redacted map entry.
    std::vector<uint8_t> encode_map_disclosure(
      std::span<const uint8_t> salt, const CborValue& value, const CborKey& key)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddBytes(&ctx, to_ubc(salt));
        encode_value(ctx, value);
        if (std::holds_alternative<int64_t>(key))
        {
          QCBOREncode_AddInt64(&ctx, std::get<int64_t>(key));
        }
        else
        {
          const auto& s = std::get<std::string>(key);
          QCBOREncode_AddText(&ctx, UsefulBufC{s.data(), s.size()});
        }
        QCBOREncode_CloseArray(&ctx);
      });
    }

    // cbor([salt, <value>]) for a redacted array element.
    std::vector<uint8_t> encode_elem_disclosure(
      std::span<const uint8_t> salt, const CborValue& value)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddBytes(&ctx, to_ubc(salt));
        encode_value(ctx, value);
        QCBOREncode_CloseArray(&ctx);
      });
    }

    bool elem_matches_key(const PathElem& e, const CborKey& key)
    {
      if (
        std::holds_alternative<int64_t>(e) &&
        std::holds_alternative<int64_t>(key))
      {
        return std::get<int64_t>(e) == std::get<int64_t>(key);
      }
      if (
        std::holds_alternative<std::string>(e) &&
        std::holds_alternative<std::string>(key))
      {
        return std::get<std::string>(e) == std::get<std::string>(key);
      }
      return false;
    }

    bool elem_matches_index(const PathElem& e, size_t index)
    {
      return std::holds_alternative<int64_t>(e) && std::get<int64_t>(e) >= 0 &&
        static_cast<size_t>(std::get<int64_t>(e)) == index;
    }

    // Recursively redact `node` at the given relative `paths` (mirrors the
    // Python reference `_redact_node`). A length-1 path redacts that whole
    // entry/element here; longer paths recurse first (ancestor-disclosure
    // rule).
    CborValue redact_node(
      const CborValue& node,
      const std::vector<Path>& paths,
      HashAlg sd_alg,
      const RandomSource& rng,
      size_t salt_len,
      std::vector<Disclosure>& disclosures)
    {
      if (node.kind == CborValue::Kind::Map)
      {
        CborValue out = CborValue::Map({});
        std::vector<std::vector<uint8_t>> digests;
        for (size_t mi = 0; mi < node.map_keys.size(); ++mi)
        {
          const CborKey& key = node.map_keys[mi];
          const CborValue& value = node.map_vals[mi];
          std::vector<Path> deeper;
          bool direct = false;
          for (const auto& p : paths)
          {
            if (p.empty())
            {
              continue;
            }
            if (!elem_matches_key(p.front(), key))
            {
              continue;
            }
            if (p.size() == 1)
            {
              direct = true;
            }
            else
            {
              deeper.emplace_back(p.begin() + 1, p.end());
            }
          }

          const CborValue child = deeper.empty() ?
            value :
            redact_node(value, deeper, sd_alg, rng, salt_len, disclosures);

          if (direct)
          {
            Disclosure d;
            d.key = key;
            d.salt = rng(salt_len);
            d.encoded = encode_map_disclosure(d.salt, child, key);
            d.digest = disclosure_digest(d.encoded, sd_alg);
            digests.push_back(d.digest);
            disclosures.push_back(std::move(d));
          }
          else
          {
            out.map_put(key, child);
          }
        }
        // Hide real-vs-decoy ordering (salts already randomise the hashes).
        std::sort(digests.begin(), digests.end());
        out.redacted_hashes = std::move(digests);
        return out;
      }

      if (node.kind == CborValue::Kind::Array)
      {
        CborValue out = CborValue::Array({});
        for (size_t i = 0; i < node.array_v.size(); ++i)
        {
          std::vector<Path> deeper;
          bool direct = false;
          for (const auto& p : paths)
          {
            if (p.empty())
            {
              continue;
            }
            if (!elem_matches_index(p.front(), i))
            {
              continue;
            }
            if (p.size() == 1)
            {
              direct = true;
            }
            else
            {
              deeper.emplace_back(p.begin() + 1, p.end());
            }
          }

          const CborValue child = deeper.empty() ?
            node.array_v[i] :
            redact_node(
              node.array_v[i], deeper, sd_alg, rng, salt_len, disclosures);

          if (direct)
          {
            Disclosure d;
            d.key = std::nullopt;
            d.salt = rng(salt_len);
            d.encoded = encode_elem_disclosure(d.salt, child);
            d.digest = disclosure_digest(d.encoded, sd_alg);
            out.array_v.push_back(CborValue::RedactedElem(d.digest));
            disclosures.push_back(std::move(d));
          }
          else
          {
            out.array_v.push_back(child);
          }
        }
        return out;
      }

      throw std::invalid_argument(
        "redaction path descends into a non-container value");
    }
  }

  IssuedToken issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const std::vector<Path>& redact_paths,
    const RandomSource& rng,
    size_t salt_len)
  {
    // Derive the COSE signing algorithm from the key's curve (throws early on
    // an unsupported curve, before any redaction work).
    const auto cose_alg = cose_es_alg_for_curve(key.get_curve_id());

    // Assemble the claims map (insertion order preserved; encode_value sorts to
    // CDE order) and the full redaction path list: one length-1 path per whole
    // redacted claim, plus the caller's deeper paths.
    CborValue root = CborValue::Map({});
    std::vector<Path> paths = redact_paths;
    for (const auto& claim : claims)
    {
      root.map_put(CborKey(claim.key), claim.value);
      if (claim.redact)
      {
        paths.push_back(Path{PathElem(claim.key)});
      }
    }

    std::vector<Disclosure> disclosures;
    const CborValue redacted =
      redact_node(root, paths, sd_alg, rng, salt_len, disclosures);
    const auto payload = encode_value(redacted);

    const auto phdr = encode_sdcwt_protected_header(cose_alg, sd_alg);
    IssuedToken out;
    out.token = sign_cose_sign1(key, phdr, payload);
    out.disclosures = std::move(disclosures);
    return out;
  }
}
