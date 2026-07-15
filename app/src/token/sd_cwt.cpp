// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/sd_cwt.h"

#include "cbor.h"
#include "token/cose.h"
#include "token/sd_cwt_internal.h"

#include <algorithm>
#include <ccf/crypto/entropy.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/md_type.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>

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

    // cbor([salt]) for a salt-only decoy disclosure (pads the redacted-hash
    // count without corresponding to any real claim).
    std::vector<uint8_t> encode_decoy_disclosure(std::span<const uint8_t> salt)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddBytes(&ctx, to_ubc(salt));
        QCBOREncode_CloseArray(&ctx);
      });
    }

    // Re-emit a decoded scalar value without a preceding label, for the split
    // key+value path used when the map label is a uint64 > INT64_MAX.
    void emit_scalar_without_key(QCBOREncodeContext& ctx, const QCBORItem& v)
    {
      switch (v.uDataType)
      {
        case QCBOR_TYPE_INT64:
          QCBOREncode_AddInt64(&ctx, v.val.int64);
          break;
        case QCBOR_TYPE_UINT64:
          QCBOREncode_AddUInt64(&ctx, v.val.uint64);
          break;
        case QCBOR_TYPE_BYTE_STRING:
          QCBOREncode_AddBytes(&ctx, v.val.string);
          break;
        case QCBOR_TYPE_TEXT_STRING:
          QCBOREncode_AddText(&ctx, v.val.string);
          break;
        case QCBOR_TYPE_TRUE:
        case QCBOR_TYPE_FALSE:
          QCBOREncode_AddBool(&ctx, v.uDataType == QCBOR_TYPE_TRUE);
          break;
        case QCBOR_TYPE_NULL:
          QCBOREncode_AddNULL(&ctx);
          break;
        default:
          throw std::runtime_error(
            "present: unsupported unprotected-header value type");
      }
    }

    // Re-emit a decoded unprotected-header scalar value under integer `label`.
    void emit_scalar_to_map(
      QCBOREncodeContext& ctx, int64_t label, const QCBORItem& v)
    {
      switch (v.uDataType)
      {
        case QCBOR_TYPE_INT64:
          QCBOREncode_AddInt64ToMapN(&ctx, label, v.val.int64);
          break;
        case QCBOR_TYPE_UINT64:
          QCBOREncode_AddUInt64ToMapN(&ctx, label, v.val.uint64);
          break;
        case QCBOR_TYPE_BYTE_STRING:
          QCBOREncode_AddBytesToMapN(&ctx, label, v.val.string);
          break;
        case QCBOR_TYPE_TEXT_STRING:
          QCBOREncode_AddTextToMapN(&ctx, label, v.val.string);
          break;
        case QCBOR_TYPE_TRUE:
        case QCBOR_TYPE_FALSE:
          QCBOREncode_AddBoolToMapN(
            &ctx, label, v.uDataType == QCBOR_TYPE_TRUE);
          break;
        case QCBOR_TYPE_NULL:
          QCBOREncode_AddNULLToMapN(&ctx, label);
          break;
        default:
          throw std::runtime_error(
            "present: unsupported unprotected-header value type");
      }
    }

    // Copy an issued token's unprotected-header map into `ctx`, preserving
    // every entry except sd_claims (17), which present() manages itself.
    // Mirrors the Python reference (dict(arr[1]) then override sd_claims), so
    // entries such as kid / x5chain survive a present(). Both definite-length
    // and indefinite-length source maps are supported: the loop terminates on
    // QCBOR_ERR_NO_MORE_ITEMS rather than on a pre-read count, so neither
    // encoding causes a spurious throw. Integer labels in the full uint64 range
    // are supported: labels that fit in int64 use the standard *ToMapN helpers;
    // labels > INT64_MAX use a split QCBOREncode_AddUInt64 key + value emit.
    // Container values (arrays/maps, e.g. an x5chain certificate list) are
    // copied verbatim as raw CBOR. A non-integer label throws.
    void copy_uhdr_except_sd_claims(
      std::span<const uint8_t> uhdr_cbor, QCBOREncodeContext& ctx)
    {
      QCBORDecodeContext dc;
      QCBORDecode_Init(
        &dc,
        UsefulBufC{uhdr_cbor.data(), uhdr_cbor.size()},
        QCBOR_DECODE_MODE_NORMAL);

      QCBORItem map_item;
      QCBORDecode_EnterMap(&dc, &map_item);
      (void)map_item; // uCount not used; loop terminates on NO_MORE_ITEMS

      for (;;)
      {
        QCBORItem peek;
        const QCBORError peek_err = QCBORDecode_PeekNext(&dc, &peek);
        if (peek_err == QCBOR_ERR_NO_MORE_ITEMS)
        {
          break;
        }
        if (peek_err != QCBOR_SUCCESS)
        {
          throw std::runtime_error("present: malformed unprotected header");
        }

        if (
          peek.uLabelType != QCBOR_TYPE_INT64 &&
          peek.uLabelType != QCBOR_TYPE_UINT64)
        {
          throw std::runtime_error(
            "present: unsupported non-integer unprotected-header label");
        }

        // Determine whether the label fits in int64 (all standard COSE labels
        // do). SD_CLAIMS_LABEL (17) is always within int64 range.
        const bool large_uint64 = (peek.uLabelType == QCBOR_TYPE_UINT64) &&
          (peek.label.uint64 > static_cast<uint64_t>(INT64_MAX));
        const int64_t label_i64 = large_uint64 ?
          0 :
          ((peek.uLabelType == QCBOR_TYPE_UINT64) ?
            static_cast<int64_t>(peek.label.uint64) :
            peek.label.int64);
        const bool drop = !large_uint64 && (label_i64 == SD_CLAIMS_LABEL);

        if (peek.uDataType == QCBOR_TYPE_ARRAY)
        {
          QCBORItem it;
          UsefulBufC raw = NULLUsefulBufC;
          QCBORDecode_GetArray(&dc, &it, &raw);
          if (!drop)
          {
            if (!large_uint64)
            {
              QCBOREncode_AddEncodedToMapN(&ctx, label_i64, raw);
            }
            else
            {
              QCBOREncode_AddUInt64(&ctx, peek.label.uint64);
              QCBOREncode_AddEncoded(&ctx, raw);
            }
          }
        }
        else if (peek.uDataType == QCBOR_TYPE_MAP)
        {
          QCBORItem it;
          UsefulBufC raw = NULLUsefulBufC;
          QCBORDecode_GetMap(&dc, &it, &raw);
          if (!drop)
          {
            if (!large_uint64)
            {
              QCBOREncode_AddEncodedToMapN(&ctx, label_i64, raw);
            }
            else
            {
              QCBOREncode_AddUInt64(&ctx, peek.label.uint64);
              QCBOREncode_AddEncoded(&ctx, raw);
            }
          }
        }
        else
        {
          QCBORItem v;
          QCBORDecode_VGetNext(&dc, &v);
          if (!drop)
          {
            if (!large_uint64)
            {
              emit_scalar_to_map(ctx, label_i64, v);
            }
            else
            {
              QCBOREncode_AddUInt64(&ctx, peek.label.uint64);
              emit_scalar_without_key(ctx, v);
            }
          }
        }
      }
      QCBORDecode_ExitMap(&dc);
      if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS)
      {
        throw std::runtime_error("present: malformed unprotected header");
      }
    }

    // Build an RFC 8747 `cnf` claim value `{1: COSE_Key}` holding only the EC2
    // PUBLIC coordinates of `holder` (kty=EC2, crv, x, y). Mirrors the Python
    // reference `_cnf_from_key`.
    CborValue cnf_from_holder(const ccf::crypto::ECPublicKey& holder)
    {
      const auto coords = holder.coordinates();
      CborValue cose_key = CborValue::Map({});
      cose_key.map_put(CborKey(int64_t{1}), value::integer(2)); // kty: EC2
      cose_key.map_put(
        CborKey(int64_t{-1}),
        value::integer(cose_ec_curve_id(holder.get_curve_id()))); // crv
      cose_key.map_put(CborKey(int64_t{-2}), value::bytes(coords.x)); // x
      cose_key.map_put(CborKey(int64_t{-3}), value::bytes(coords.y)); // y

      CborValue cnf = CborValue::Map({});
      cnf.map_put(
        CborKey(int64_t{1}), std::move(cose_key)); // method 1 = COSE_Key
      return cnf;
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

    // Walk `path` through `root` and confirm every element resolves to an
    // existing map entry / in-range array element. A redaction path that
    // matches nothing would otherwise silently produce no redaction, so we
    // reject it here (stricter than the Python reference, which ignores it).
    bool path_resolves(const CborValue& root, const Path& path)
    {
      const CborValue* node = &root;
      for (const auto& elem : path)
      {
        if (node->kind == CborValue::Kind::Map)
        {
          const CborValue* next = nullptr;
          for (size_t i = 0; i < node->map_keys.size(); ++i)
          {
            if (elem_matches_key(elem, node->map_keys[i]))
            {
              next = &node->map_vals[i];
              break;
            }
          }
          if (next == nullptr)
          {
            return false;
          }
          node = next;
        }
        else if (node->kind == CborValue::Kind::Array)
        {
          if (!std::holds_alternative<int64_t>(elem))
          {
            return false;
          }
          const int64_t idx = std::get<int64_t>(elem);
          if (idx < 0 || static_cast<size_t>(idx) >= node->array_v.size())
          {
            return false;
          }
          node = &node->array_v[static_cast<size_t>(idx)];
        }
        else
        {
          return false; // cannot descend into a scalar
        }
      }
      return true;
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
      std::vector<Disclosure>& disclosures,
      const Path& prefix = {})
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
            redact_node(value, deeper, sd_alg, rng, salt_len, disclosures, [&] {
              Path p = prefix;
              p.push_back(key);
              return p;
            }());

          if (direct)
          {
            Disclosure d;
            d.key = key;
            d.path = prefix;
            d.path.push_back(key);
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
              node.array_v[i], deeper, sd_alg, rng, salt_len, disclosures, [&] {
                Path p = prefix;
                p.push_back(static_cast<int64_t>(i));
                return p;
              }());

          if (direct)
          {
            Disclosure d;
            d.key = std::nullopt;
            d.path = prefix;
            d.path.push_back(static_cast<int64_t>(i));
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

  IssuedToken detail::issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const std::vector<Path>& redact_paths,
    const RandomSource& rng,
    size_t salt_len,
    size_t pad_to,
    const ccf::crypto::ECPublicKey* holder)
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

    // Embed the RFC 8747 confirmation claim (clear, never redacted) so the
    // token is key-binding capable.
    if (holder != nullptr)
    {
      root.map_put(CborKey(CNF_LABEL), cnf_from_holder(*holder));
    }

    // Reject caller-supplied paths that resolve to nothing, so a mistyped path
    // can't silently under-redact. (Per-claim paths above always resolve.)
    for (const auto& p : redact_paths)
    {
      if (p.empty() || !path_resolves(root, p))
      {
        throw std::invalid_argument(
          "redact_path does not resolve to an existing claim/element");
      }
    }

    std::vector<Disclosure> disclosures;
    CborValue redacted =
      redact_node(root, paths, sd_alg, rng, salt_len, disclosures);

    // Decoy padding: add salt-only decoy disclosures until the top-level
    // redacted-hash count reaches `pad_to`, so the count leaks nothing about
    // how many real claims were redacted. Decoys are indistinguishable from
    // real hashes and are re-sorted in with them.
    while (redacted.redacted_hashes.size() < pad_to)
    {
      Disclosure d;
      d.key = std::nullopt;
      d.salt = rng(salt_len);
      d.encoded = encode_decoy_disclosure(d.salt);
      d.digest = disclosure_digest(d.encoded, sd_alg);
      redacted.redacted_hashes.push_back(d.digest);
      disclosures.push_back(std::move(d));
    }
    std::sort(redacted.redacted_hashes.begin(), redacted.redacted_hashes.end());

    const auto payload = encode_value(redacted);

    const auto phdr = encode_sdcwt_protected_header(cose_alg, sd_alg);
    IssuedToken out;
    out.token = sign_cose_sign1(key, phdr, payload);
    out.disclosures = std::move(disclosures);
    return out;
  }

  IssuedToken issue(
    const std::vector<Claim>& claims,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const std::vector<Path>& redact_paths,
    size_t salt_len,
    size_t pad_to,
    const ccf::crypto::ECPublicKey* holder)
  {
    return detail::issue(
      claims,
      key,
      sd_alg,
      redact_paths,
      default_random_source(),
      salt_len,
      pad_to,
      holder);
  }

  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected)
  {
    // Decode the tagged COSE_Sign1 [ protected, unprotected, payload, signature
    // ] into its opaque parts. The unprotected header is captured as raw bytes
    // and re-emitted preserving every entry except sd_claims (which present()
    // manages); the protected header, payload and signature are copied verbatim
    // so the signature stays valid.
    QCBORDecodeContext dc;
    QCBORDecode_Init(
      &dc, UsefulBufC{token.data(), token.size()}, QCBOR_DECODE_MODE_NORMAL);

    UsefulBufC phdr = NULLUsefulBufC;
    UsefulBufC uhdr = NULLUsefulBufC;
    UsefulBufC payload = NULLUsefulBufC;
    UsefulBufC sig = NULLUsefulBufC;
    QCBORItem uhdr_item;
    QCBORDecode_EnterArray(&dc, nullptr);
    QCBORDecode_GetByteString(&dc, &phdr);
    QCBORDecode_GetMap(&dc, &uhdr_item, &uhdr); // capture uhdr raw bytes
    QCBORDecode_GetByteString(&dc, &payload);
    QCBORDecode_GetByteString(&dc, &sig);
    QCBORDecode_ExitArray(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }

    const std::span<const uint8_t> uhdr_span{
      static_cast<const uint8_t*>(uhdr.ptr), uhdr.len};
    // Preserve the original map's definite/indefinite-length encoding in the
    // rebuilt unprotected header so round-tripping does not alter the wire
    // format unnecessarily.
    const bool uhdr_indefinite =
      (uhdr_item.val.uCount == QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH);

    return cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_AddTag(&ctx, 18); // COSE_Sign1
      QCBOREncode_OpenArray(&ctx);
      QCBOREncode_AddBytes(&ctx, phdr);
      // Carry through any pre-existing unprotected-header entries (e.g. kid,
      // x5chain) so present() never silently drops them.
      if (uhdr_indefinite)
        QCBOREncode_OpenMapIndefiniteLength(&ctx);
      else
        QCBOREncode_OpenMap(&ctx);
      copy_uhdr_except_sd_claims(uhdr_span, ctx);
      if (!selected.empty())
      {
        QCBOREncode_OpenArrayInMapN(&ctx, SD_CLAIMS_LABEL);
        for (const auto& d : selected)
        {
          QCBOREncode_AddBytes(&ctx, to_ubc(d));
        }
        QCBOREncode_CloseArray(&ctx);
      }
      if (uhdr_indefinite)
        QCBOREncode_CloseMapIndefiniteLength(&ctx);
      else
        QCBOREncode_CloseMap(&ctx);
      QCBOREncode_AddBytes(&ctx, payload);
      QCBOREncode_AddBytes(&ctx, sig);
      QCBOREncode_CloseArray(&ctx);
    });
  }

  std::vector<uint8_t> kbt_sign(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected,
    const ccf::crypto::ECKeyPair& holder,
    const KbtParams& params)
  {
    if (!params.iat.has_value() && !params.cti.has_value())
    {
      throw std::invalid_argument(
        "KBT payload must contain iat or cti (draft-08 s8.1)");
    }

    const auto holder_alg = cose_es_alg_for_curve(holder.get_curve_id());
    const auto presented = present(token, selected);

    // KBT protected header {1: alg, 13: <embedded presented SD-CWT>, 16: typ}.
    // Keys are emitted in CDE order (1, 13, 16).
    const auto phdr = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      QCBOREncode_AddInt64ToMapN(&ctx, 1, holder_alg);
      QCBOREncode_AddEncodedToMapN(&ctx, KCWT_LABEL, to_ubc(presented));
      QCBOREncode_AddInt64ToMapN(&ctx, TYP_LABEL, KB_CWT_TYP);
      QCBOREncode_CloseMap(&ctx);
    });

    // KBT payload: aud plus whichever of exp/nbf/iat/cti/cnonce are set,
    // emitted in ascending (CDE) key order. iss/sub are forbidden and never
    // added.
    const auto payload = cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenMap(&ctx);
      QCBOREncode_AddTextToMapN(
        &ctx, CWT_AUD, UsefulBufC{params.aud.data(), params.aud.size()});
      if (params.exp.has_value())
      {
        QCBOREncode_AddInt64ToMapN(&ctx, CWT_EXP, *params.exp);
      }
      if (params.nbf.has_value())
      {
        QCBOREncode_AddInt64ToMapN(&ctx, CWT_NBF, *params.nbf);
      }
      if (params.iat.has_value())
      {
        QCBOREncode_AddInt64ToMapN(&ctx, CWT_IAT, *params.iat);
      }
      if (params.cti.has_value())
      {
        QCBOREncode_AddBytesToMapN(&ctx, CWT_CTI, to_ubc(*params.cti));
      }
      if (params.cnonce.has_value())
      {
        QCBOREncode_AddBytesToMapN(&ctx, CWT_CNONCE, to_ubc(*params.cnonce));
      }
      QCBOREncode_CloseMap(&ctx);
    });

    return sign_cose_sign1(holder, phdr, payload);
  }
}
