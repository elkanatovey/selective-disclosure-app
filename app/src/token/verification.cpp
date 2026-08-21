// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/verification.h"

#include "token/cbor.h"
#include "token/cbor_value.h"
#include "token/cose.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace sdcwt
{
  namespace
  {
    constexpr int64_t ALG_LABEL = 1;
    constexpr int64_t SD_CLAIMS_LABEL = 17;
    constexpr int64_t SD_ALG_LABEL = 170;
    constexpr int64_t EXP_LABEL = 4;
    constexpr int64_t NBF_LABEL = 5;
    constexpr int64_t IAT_LABEL = 6;
    constexpr int64_t MAX_DATE = int64_t{1} << 53;
    constexpr int64_t SHA_256 = -16;
    constexpr int64_t SHA_384 = -43;
    constexpr int64_t SHA_512 = -44;
    constexpr size_t SALT_SIZE = 16;
    constexpr uint8_t REDACTED_CLAIM_KEYS = 59;
    constexpr uint64_t REDACTED_ELEMENT_TAG = 60;

    struct ParsedToken
    {
      int64_t cose_algorithm;
      int64_t disclosure_hash_algorithm;
      std::vector<uint8_t> protected_header;
      std::vector<uint8_t> payload;
      std::vector<uint8_t> signature;
      std::vector<std::vector<uint8_t>> disclosures;
      cbor::Value payload_value;
    };

    enum class DisclosureKind
    {
      Map,
      Element,
      Decoy,
    };

    struct PresentedDisclosure
    {
      DisclosureKind kind;
      cbor::Value key;
      cbor::Value value;
    };

    bool key_equal(const cbor::Value& left, const cbor::Value& right)
    {
      return std::visit(
        [](const auto& a, const auto& b) {
          using A = std::decay_t<decltype(a)>;
          using B = std::decay_t<decltype(b)>;
          if constexpr (!std::is_same_v<A, B>)
          {
            return false;
          }
          else if constexpr (
            std::is_same_v<A, cbor::Signed> || std::is_same_v<A, cbor::Simple>)
          {
            return a == b;
          }
          else if constexpr (std::is_same_v<A, cbor::String>)
          {
            return a == b;
          }
          else
          {
            return false;
          }
        },
        left->value,
        right->value);
    }

    bool is_redacted_key(const cbor::Value& key)
    {
      return std::holds_alternative<cbor::Simple>(key->value) &&
        std::get<cbor::Simple>(key->value) == REDACTED_CLAIM_KEYS;
    }

    void validate_key(const cbor::Value& key)
    {
      if (std::holds_alternative<cbor::Signed>(key->value))
      {
        return;
      }
      if (std::holds_alternative<cbor::String>(key->value))
      {
        if (std::get<cbor::String>(key->value).size() <= 255)
        {
          return;
        }
      }
      else if (is_redacted_key(key))
      {
        return;
      }
      throw std::runtime_error("invalid SD-CWT map key type or length");
    }

    void validate_value(const cbor::Value& value)
    {
      if (std::holds_alternative<cbor::Array>(value->value))
      {
        for (const auto& item : std::get<cbor::Array>(value->value).items)
        {
          validate_value(item);
        }
      }
      else if (std::holds_alternative<cbor::Map>(value->value))
      {
        std::vector<cbor::Value> keys;
        for (const auto& [key, item] : std::get<cbor::Map>(value->value).items)
        {
          validate_key(key);
          if (std::any_of(keys.begin(), keys.end(), [&](const auto& seen) {
                return key_equal(seen, key);
              }))
          {
            throw std::runtime_error("duplicate CBOR map key");
          }
          keys.push_back(key);
          validate_value(item);
        }
      }
      else if (std::holds_alternative<cbor::Tagged>(value->value))
      {
        validate_value(std::get<cbor::Tagged>(value->value).item);
      }
    }

    const cbor::Value* find_integer_key(
      const cbor::Value& map, int64_t expected)
    {
      if (!std::holds_alternative<cbor::Map>(map->value))
      {
        throw std::runtime_error("expected CBOR map");
      }
      for (const auto& [key, value] : std::get<cbor::Map>(map->value).items)
      {
        if (
          std::holds_alternative<cbor::Signed>(key->value) &&
          key->as_signed() == expected)
        {
          return &value;
        }
      }
      return nullptr;
    }

    void validate_date_claims(const cbor::Value& claims)
    {
      for (const auto label : {EXP_LABEL, NBF_LABEL, IAT_LABEL})
      {
        const auto* value = find_integer_key(claims, label);
        if (value == nullptr)
        {
          continue;
        }
        if (!std::holds_alternative<cbor::Signed>((*value)->value))
        {
          throw std::runtime_error("exp/nbf/iat must be a finite number");
        }
        const auto date = (*value)->as_signed();
        if (date < -MAX_DATE || date > MAX_DATE)
        {
          throw std::runtime_error("exp/nbf/iat magnitude exceeds 2^53");
        }
      }
    }

    std::vector<uint8_t> copy_bytes(const cbor::Value& value)
    {
      const auto bytes = value->as_bytes();
      return {bytes.begin(), bytes.end()};
    }

    int64_t supported_hash_algorithm(int64_t algorithm)
    {
      switch (algorithm)
      {
        case SHA_256:
        case SHA_384:
        case SHA_512:
          return algorithm;
        default:
          throw std::runtime_error("unsupported SD-CWT disclosure hash");
      }
    }

    int64_t supported_cose_algorithm(int64_t algorithm)
    {
      switch (algorithm)
      {
        case COSE_ALG_ES256:
        case COSE_ALG_ES384:
        case COSE_ALG_ES512:
          return algorithm;
        default:
          throw std::runtime_error("unsupported COSE signing algorithm");
      }
    }

    ParsedToken parse_token(std::span<const uint8_t> token)
    {
      const auto root = cbor::parse(token);
      validate_value(root);
      const auto& envelope = root->tag_at(cbor::COSE_SIGN_1_TAG);
      if (!std::holds_alternative<cbor::Array>(envelope->value))
      {
        throw std::runtime_error("SD-CWT is not a COSE_Sign1 array");
      }
      const auto& parts = std::get<cbor::Array>(envelope->value).items;
      if (parts.size() != 4)
      {
        throw std::runtime_error("malformed COSE_Sign1 array");
      }
      if (!std::holds_alternative<cbor::Map>(parts[1]->value))
      {
        throw std::runtime_error("malformed COSE unprotected header");
      }

      ParsedToken parsed;
      parsed.protected_header = copy_bytes(parts[0]);
      parsed.payload = copy_bytes(parts[2]);
      parsed.signature = copy_bytes(parts[3]);

      const auto protected_headers = cbor::parse(parsed.protected_header);
      validate_value(protected_headers);
      const auto* cose_algorithm =
        find_integer_key(protected_headers, ALG_LABEL);
      if (cose_algorithm == nullptr)
      {
        throw std::runtime_error("COSE protected header has no algorithm");
      }
      parsed.cose_algorithm =
        supported_cose_algorithm((*cose_algorithm)->as_signed());
      const auto* hash_algorithm =
        find_integer_key(protected_headers, SD_ALG_LABEL);
      parsed.disclosure_hash_algorithm = supported_hash_algorithm(
        hash_algorithm == nullptr ? SHA_256 : (*hash_algorithm)->as_signed());

      parsed.payload_value = cbor::parse(parsed.payload);
      validate_value(parsed.payload_value);
      if (!std::holds_alternative<cbor::Map>(parsed.payload_value->value))
      {
        throw std::runtime_error("SD-CWT payload is not a claims map");
      }
      validate_date_claims(parsed.payload_value);

      const auto* sd_claims = find_integer_key(parts[1], SD_CLAIMS_LABEL);
      if (sd_claims != nullptr)
      {
        if (!std::holds_alternative<cbor::Array>((*sd_claims)->value))
        {
          throw std::runtime_error("sd_claims is not an array");
        }
        const auto& items = std::get<cbor::Array>((*sd_claims)->value).items;
        if (items.empty())
        {
          throw std::runtime_error("empty sd_claims is invalid");
        }
        parsed.disclosures.reserve(items.size());
        for (const auto& item : items)
        {
          parsed.disclosures.push_back(copy_bytes(item));
        }
      }
      return parsed;
    }

    void sort_map(std::vector<cbor::MapItem>& items)
    {
      std::sort(
        items.begin(), items.end(), [](const auto& left, const auto& right) {
          return cbor::serialize(left.first) < cbor::serialize(right.first);
        });
    }

    class DisclosureResolver
    {
    private:
      std::map<std::vector<uint8_t>, PresentedDisclosure> presented;
      std::set<std::vector<uint8_t>> consumed;
      std::vector<cbor::Value> top_level_disclosed;

      const PresentedDisclosure* find(
        const std::vector<uint8_t>& digest, DisclosureKind kind) const
      {
        const auto it = presented.find(digest);
        if (it == presented.end() || it->second.kind != kind)
        {
          return nullptr;
        }
        return &it->second;
      }

      bool has_key(
        const std::vector<cbor::MapItem>& items, const cbor::Value& key) const
      {
        return std::any_of(items.begin(), items.end(), [&](const auto& item) {
          return key_equal(item.first, key);
        });
      }

      cbor::Value resolve(const cbor::Value& node, size_t depth)
      {
        if (std::holds_alternative<cbor::Map>(node->value))
        {
          std::vector<cbor::MapItem> output;
          const auto& input = std::get<cbor::Map>(node->value).items;
          for (const auto& [key, value] : input)
          {
            if (!is_redacted_key(key))
            {
              continue;
            }
            if (!std::holds_alternative<cbor::Array>(value->value))
            {
              throw std::runtime_error(
                "redacted claim hashes are not an array");
            }
            for (const auto& hash : std::get<cbor::Array>(value->value).items)
            {
              const auto digest = copy_bytes(hash);
              if (const auto* disclosure = find(digest, DisclosureKind::Map))
              {
                validate_key(disclosure->key);
                if (
                  is_redacted_key(disclosure->key) ||
                  has_key(output, disclosure->key))
                {
                  throw std::runtime_error("duplicate disclosed claim key");
                }
                consumed.insert(digest);
                output.emplace_back(
                  disclosure->key, resolve(disclosure->value, depth + 1));
                if (depth == 0)
                {
                  top_level_disclosed.push_back(disclosure->key);
                }
              }
              else if (find(digest, DisclosureKind::Decoy) != nullptr)
              {
                consumed.insert(digest);
              }
            }
          }
          for (const auto& [key, value] : input)
          {
            if (is_redacted_key(key))
            {
              continue;
            }
            if (has_key(output, key))
            {
              throw std::runtime_error(
                "disclosed claim duplicates a clear claim key");
            }
            output.emplace_back(key, resolve(value, depth + 1));
          }
          sort_map(output);
          return cbor::make_map(std::move(output));
        }

        if (std::holds_alternative<cbor::Array>(node->value))
        {
          std::vector<cbor::Value> output;
          for (const auto& item : std::get<cbor::Array>(node->value).items)
          {
            if (std::holds_alternative<cbor::Tagged>(item->value))
            {
              const auto& tagged = std::get<cbor::Tagged>(item->value);
              if (tagged.tag == REDACTED_ELEMENT_TAG)
              {
                const auto digest = copy_bytes(tagged.item);
                if (
                  const auto* disclosure =
                    find(digest, DisclosureKind::Element))
                {
                  consumed.insert(digest);
                  output.push_back(resolve(disclosure->value, depth + 1));
                }
                else if (find(digest, DisclosureKind::Decoy) != nullptr)
                {
                  consumed.insert(digest);
                }
                continue;
              }
            }
            output.push_back(resolve(item, depth + 1));
          }
          return cbor::make_array(std::move(output));
        }
        return node;
      }

    public:
      DisclosureResolver(
        const std::vector<std::vector<uint8_t>>& encoded,
        const std::vector<std::vector<uint8_t>>& digests)
      {
        if (encoded.size() != digests.size())
        {
          throw std::runtime_error("wrong disclosure digest count");
        }
        for (size_t index = 0; index < encoded.size(); ++index)
        {
          const auto decoded = cbor::parse(encoded[index]);
          validate_value(decoded);
          if (!std::holds_alternative<cbor::Array>(decoded->value))
          {
            throw std::runtime_error("disclosure is not an array");
          }
          const auto& items = std::get<cbor::Array>(decoded->value).items;
          if (
            items.empty() ||
            !std::holds_alternative<cbor::Bytes>(items[0]->value) ||
            items[0]->as_bytes().size() != SALT_SIZE)
          {
            throw std::runtime_error(
              "disclosure salt must be exactly 16 bytes");
          }
          PresentedDisclosure disclosure;
          if (items.size() == 3)
          {
            disclosure = {DisclosureKind::Map, items[2], items[1]};
          }
          else if (items.size() == 2)
          {
            disclosure = {DisclosureKind::Element, nullptr, items[1]};
          }
          else if (items.size() == 1)
          {
            disclosure = {DisclosureKind::Decoy, nullptr, nullptr};
          }
          else
          {
            throw std::runtime_error("malformed disclosure");
          }
          presented.insert_or_assign(digests[index], std::move(disclosure));
        }
      }

      ValidatedClaims run(const cbor::Value& payload)
      {
        const auto claims = resolve(payload, 0);
        for (const auto& [digest, disclosure] : presented)
        {
          (void)disclosure;
          if (!consumed.contains(digest))
          {
            throw std::runtime_error(
              "presented disclosure does not match a redacted hash");
          }
        }

        std::vector<cbor::MapItem> clear;
        std::vector<cbor::MapItem> disclosed;
        for (const auto& item : std::get<cbor::Map>(claims->value).items)
        {
          const bool was_disclosed = std::any_of(
            top_level_disclosed.begin(),
            top_level_disclosed.end(),
            [&](const auto& key) { return key_equal(key, item.first); });
          (was_disclosed ? disclosed : clear).push_back(item);
        }
        return {
          cbor::serialize(claims),
          cbor::serialize(cbor::make_map(std::move(clear))),
          cbor::serialize(cbor::make_map(std::move(disclosed))),
        };
      }
    };
  }

  VerificationPlan prepare_verification(std::span<const uint8_t> token)
  {
    const auto parsed = parse_token(token);
    VerificationPlan plan{
      parsed.cose_algorithm,
      parsed.disclosure_hash_algorithm,
      prepare_cose_sign1_signature(parsed.protected_header, parsed.payload),
      parsed.signature,
      {}};
    plan.disclosure_hash_inputs.reserve(parsed.disclosures.size());
    for (const auto& disclosure : parsed.disclosures)
    {
      plan.disclosure_hash_inputs.push_back(
        cbor::serialize(bytes_value(disclosure)));
    }
    return plan;
  }

  ValidatedClaims finalize_verification(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& disclosure_digests,
    bool signature_valid)
  {
    if (!signature_valid)
    {
      throw std::runtime_error("COSE signature verification failed");
    }
    const auto parsed = parse_token(token);
    DisclosureResolver resolver(parsed.disclosures, disclosure_digests);
    return resolver.run(parsed.payload_value);
  }
}
