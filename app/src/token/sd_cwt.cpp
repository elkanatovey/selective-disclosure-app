// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/sd_cwt.h"

#include "token/cose.h"
#include "token/sd_cwt_internal.h"

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
    const auto wrapped = ccf::cbor::serialize(bytes_value(encoded));
    return ccf::crypto::make_hash_provider()->hash(
      wrapped.data(), wrapped.size(), md_for_hash_alg(sd_alg));
  }

  std::vector<uint8_t> encode_sdcwt_protected_header(
    int64_t cose_alg, HashAlg sd_alg)
  {
    // Map keys are emitted in CDE (RFC 8949 §4.2) order: 1 (alg) < 16 (typ) <
    // 170 (sd_alg).
    return ccf::cbor::serialize(ccf::cbor::make_map(
      {{ccf::cbor::make_signed(1), ccf::cbor::make_signed(cose_alg)},
       {ccf::cbor::make_signed(TYP_LABEL), ccf::cbor::make_signed(SD_CWT_TYP)},
       {ccf::cbor::make_signed(SD_ALG_LABEL),
        ccf::cbor::make_signed(static_cast<int64_t>(sd_alg))}}));
  }

  namespace
  {
    // cbor([salt, <value>, key]) for a redacted map entry.
    std::vector<uint8_t> encode_map_disclosure(
      std::span<const uint8_t> salt, const CborValue& value, const CborKey& key)
    {
      // Views borrow from salt/value/key, all alive across this call.
      return ccf::cbor::serialize(ccf::cbor::make_array(
        {ccf::cbor::make_bytes(salt), to_ccf_cbor(value), to_ccf_cbor(key)}));
    }

    // cbor([salt, <value>]) for a redacted array element.
    std::vector<uint8_t> encode_elem_disclosure(
      std::span<const uint8_t> salt, const CborValue& value)
    {
      return ccf::cbor::serialize(ccf::cbor::make_array(
        {ccf::cbor::make_bytes(salt), to_ccf_cbor(value)}));
    }

    // cbor([salt]) for a salt-only decoy disclosure (pads the redacted-hash
    // count without corresponding to any real claim).
    std::vector<uint8_t> encode_decoy_disclosure(std::span<const uint8_t> salt)
    {
      return ccf::cbor::serialize(
        ccf::cbor::make_array({ccf::cbor::make_bytes(salt)}));
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
    // reject it here, matching the fail-closed Python reference behavior.
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
    const std::vector<Path>& redact_paths,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const RandomSource& rng,
    size_t salt_len,
    size_t pad_to,
    const ccf::crypto::ECPublicKey* holder)
  {
    // Derive the COSE signing algorithm from the key's curve (throws early on
    // an unsupported curve, before any redaction work).
    const auto cose_alg = cose_es_alg_for_curve(key.get_curve_id());

    // Assemble the claims map (insertion order preserved; encode_value sorts to
    // CDE order).
    CborValue root = CborValue::Map({});
    for (const auto& claim : claims)
    {
      root.map_put(CborKey(claim.key), claim.value);
    }

    // Embed the RFC 8747 confirmation claim (clear, never redacted) so the
    // token is key-binding capable.
    if (holder != nullptr)
    {
      root.map_put(CborKey(CNF_LABEL), cnf_from_holder(*holder));
    }

    // Every redaction path must resolve, so a mistyped path can't silently
    // under-redact. `redact_paths` is the only description of the redaction
    // tree, so this one check covers all of it.
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
      redact_node(root, redact_paths, sd_alg, rng, salt_len, disclosures);

    // Decoy padding: add salt-only decoy disclosures until the top-level
    // redacted-hash count reaches `pad_to`, so the count leaks nothing about
    // how many real claims were redacted. Decoys are indistinguishable from
    // real hashes and are re-sorted in with them.
    while (redacted.redacted_hashes.size() < pad_to)
    {
      Disclosure d;
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
    const std::vector<Path>& redact_paths,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    size_t salt_len,
    size_t pad_to,
    const ccf::crypto::ECPublicKey* holder)
  {
    return detail::issue(
      claims,
      redact_paths,
      key,
      sd_alg,
      default_random_source(),
      salt_len,
      pad_to,
      holder);
  }

  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected)
  {
    namespace cbor = ccf::cbor;

    // Decode the tagged COSE_Sign1 [ protected, unprotected, payload,
    // signature ]. Every entry of the unprotected header is carried through
    // except sd_claims (which present() manages); the protected header,
    // payload and signature are re-emitted unchanged so the signature stays
    // valid.
    //
    // Every node below borrows from `token`, which outlives this call.
    cbor::Value root;
    const cbor::Value* envelope = nullptr;
    try
    {
      root = cbor::parse(token);
      envelope = &root->tag_at(cbor::tag::COSE_SIGN_1);
    }
    catch (const std::exception&)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }

    if (!std::holds_alternative<cbor::Array>((*envelope)->value))
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }
    const auto& parts = std::get<cbor::Array>((*envelope)->value).items;
    if (parts.size() != 4)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }
    if (!std::holds_alternative<cbor::Map>(parts[1]->value))
    {
      throw std::runtime_error("present: malformed unprotected header");
    }

    std::vector<cbor::MapItem> uhdr;
    for (const auto& [label, value] :
         std::get<cbor::Map>(parts[1]->value).items)
    {
      const bool is_sd_claims =
        std::holds_alternative<cbor::Signed>(label->value) &&
        label->as_signed() == SD_CLAIMS_LABEL;
      if (!is_sd_claims)
      {
        uhdr.emplace_back(label, value);
      }
    }
    if (!selected.empty())
    {
      std::vector<cbor::Value> disclosures;
      disclosures.reserve(selected.size());
      for (const auto& d : selected)
      {
        disclosures.push_back(bytes_value(d));
      }
      uhdr.emplace_back(
        cbor::make_signed(SD_CLAIMS_LABEL),
        cbor::make_array(std::move(disclosures)));
    }

    return cbor::serialize(cbor::make_tagged(
      cbor::tag::COSE_SIGN_1,
      cbor::make_array(
        {parts[0], cbor::make_map(std::move(uhdr)), parts[2], parts[3]})));
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
    // Keys are emitted in CDE order (1, 13, 16). The embedded token is parsed
    // rather than spliced; the view borrows from `presented`, alive here.
    const auto phdr = ccf::cbor::serialize(ccf::cbor::make_map(
      {{ccf::cbor::make_signed(1), ccf::cbor::make_signed(holder_alg)},
       {ccf::cbor::make_signed(KCWT_LABEL), ccf::cbor::parse(presented)},
       {ccf::cbor::make_signed(TYP_LABEL),
        ccf::cbor::make_signed(KB_CWT_TYP)}}));

    // KBT payload: aud plus whichever of exp/nbf/iat/cti/cnonce are set,
    // emitted in ascending (CDE) key order. iss/sub are forbidden and never
    // added.
    std::vector<ccf::cbor::MapItem> claims;
    claims.emplace_back(
      ccf::cbor::make_signed(CWT_AUD), ccf::cbor::make_string(params.aud));
    if (params.exp.has_value())
    {
      claims.emplace_back(
        ccf::cbor::make_signed(CWT_EXP), ccf::cbor::make_signed(*params.exp));
    }
    if (params.nbf.has_value())
    {
      claims.emplace_back(
        ccf::cbor::make_signed(CWT_NBF), ccf::cbor::make_signed(*params.nbf));
    }
    if (params.iat.has_value())
    {
      claims.emplace_back(
        ccf::cbor::make_signed(CWT_IAT), ccf::cbor::make_signed(*params.iat));
    }
    if (params.cti.has_value())
    {
      claims.emplace_back(
        ccf::cbor::make_signed(CWT_CTI), bytes_value(*params.cti));
    }
    if (params.cnonce.has_value())
    {
      claims.emplace_back(
        ccf::cbor::make_signed(CWT_CNONCE), bytes_value(*params.cnonce));
    }
    // Borrows from `params`, alive across this call.
    const auto payload =
      ccf::cbor::serialize(ccf::cbor::make_map(std::move(claims)));

    return sign_cose_sign1(holder, phdr, payload);
  }
}
