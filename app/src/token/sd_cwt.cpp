// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/sd_cwt.h"

#include "token/cbor.h"
#include "token/cose.h"

#include <algorithm>
#include <ccf/crypto/entropy.h>
#include <ccf/crypto/sha256.h>

namespace sdcwt
{
  RandomSource default_random_source()
  {
    return [](size_t n) { return ccf::crypto::get_entropy()->random(n); };
  }

  namespace value
  {
    std::vector<uint8_t> text(std::string_view s)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_AddText(&ctx, UsefulBufC{s.data(), s.size()});
      });
    }

    std::vector<uint8_t> integer(int64_t n)
    {
      return cbor_encode(
        [&](QCBOREncodeContext& ctx) { QCBOREncode_AddInt64(&ctx, n); });
    }

    std::vector<uint8_t> bytes(std::span<const uint8_t> b)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_AddBytes(&ctx, to_ubc(b));
      });
    }

    std::vector<uint8_t> text_array(const std::vector<std::string>& items)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_OpenArray(&ctx);
        for (const auto& item : items)
        {
          QCBOREncode_AddText(&ctx, UsefulBufC{item.data(), item.size()});
        }
        QCBOREncode_CloseArray(&ctx);
      });
    }
  }

  std::vector<uint8_t> disclosure_digest(std::span<const uint8_t> encoded)
  {
    // Wrap the encoded salted array in a CBOR byte string, then hash it.
    const auto wrapped = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_AddBytes(&ctx, to_ubc(encoded));
    });
    return ccf::crypto::sha256(wrapped);
  }

  std::vector<uint8_t> encode_sdcwt_protected_header()
  {
    return cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      QCBOREncode_AddInt64ToMapN(&ctx, 1, COSE_ALG_ES256); // alg
      QCBOREncode_AddInt64ToMapN(&ctx, SD_ALG_LABEL, SD_ALG_SHA_256); // sd_alg
      QCBOREncode_AddInt64ToMapN(&ctx, TYP_LABEL, SD_CWT_TYP); // typ
      QCBOREncode_CloseMap(&ctx);
    });
  }

  namespace
  {
    // cbor([salt, <value>, key]) using the pre-encoded value bytes.
    std::vector<uint8_t> encode_disclosure(
      std::span<const uint8_t> salt,
      std::span<const uint8_t> value_cbor,
      int64_t key)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddBytes(&ctx, to_ubc(salt));
        QCBOREncode_AddEncoded(&ctx, to_ubc(value_cbor));
        QCBOREncode_AddInt64(&ctx, key);
        QCBOREncode_CloseArray(&ctx);
      });
    }
  }

  IssuedToken issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    const RandomSource& rng)
  {
    std::vector<Disclosure> disclosures;
    std::vector<std::vector<uint8_t>> digests;

    for (const auto& claim : claims)
    {
      if (!claim.redact)
      {
        continue;
      }
      Disclosure d;
      d.key = claim.key;
      d.salt = rng(SALT_LEN);
      d.value_cbor = claim.value_cbor;
      d.encoded = encode_disclosure(d.salt, d.value_cbor, d.key);
      d.digest = disclosure_digest(d.encoded);
      digests.push_back(d.digest);
      disclosures.push_back(std::move(d));
    }

    // Hide real-vs-decoy ordering (salts already randomise the hashes).
    std::sort(digests.begin(), digests.end());

    const auto payload = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      for (const auto& claim : claims)
      {
        if (claim.redact)
        {
          continue;
        }
        QCBOREncode_AddInt64(&ctx, claim.key); // clear claim label
        QCBOREncode_AddEncoded(&ctx, to_ubc(claim.value_cbor));
      }
      if (!digests.empty())
      {
        // Redacted Claim Keys live under the CBOR simple(59) label.
        QCBOREncode_AddSimple(&ctx, REDACTED_CLAIM_KEYS);
        QCBOREncode_OpenArray(&ctx);
        for (const auto& dig : digests)
        {
          QCBOREncode_AddBytes(&ctx, to_ubc(dig));
        }
        QCBOREncode_CloseArray(&ctx);
      }
      QCBOREncode_CloseMap(&ctx);
    });

    const auto phdr = encode_sdcwt_protected_header();
    IssuedToken out;
    out.token = sign_cose_sign1_es256(key, phdr, payload);
    out.disclosures = std::move(disclosures);
    return out;
  }
}
