// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cbor_value.h"

#include <algorithm>
#include <array>

namespace sdcwt
{
  CborValue CborValue::Int(int64_t v)
  {
    CborValue c;
    c.kind = Kind::Int;
    c.int_v = v;
    return c;
  }

  CborValue CborValue::Bytes(std::vector<uint8_t> v)
  {
    CborValue c;
    c.kind = Kind::Bytes;
    c.bytes_v = std::move(v);
    return c;
  }

  CborValue CborValue::Text(std::string v)
  {
    CborValue c;
    c.kind = Kind::Text;
    c.text_v = std::move(v);
    return c;
  }

  CborValue CborValue::Array(std::vector<CborValue> v)
  {
    CborValue c;
    c.kind = Kind::Array;
    c.array_v = std::move(v);
    return c;
  }

  CborValue CborValue::Map(std::vector<std::pair<CborKey, CborValue>> entries)
  {
    CborValue c;
    c.kind = Kind::Map;
    for (auto& [k, v] : entries)
    {
      c.map_keys.push_back(std::move(k));
      c.map_vals.push_back(std::move(v));
    }
    return c;
  }

  void CborValue::map_put(CborKey key, CborValue value)
  {
    map_keys.push_back(std::move(key));
    map_vals.push_back(std::move(value));
  }

  CborValue CborValue::RedactedElem(std::vector<uint8_t> digest)
  {
    CborValue c;
    c.kind = Kind::RedactedElement;
    c.bytes_v = std::move(digest);
    return c;
  }

  namespace
  {
    // draft-08 wire labels. Kept as literals here rather than pulled from
    // sd_cwt.h, which includes this header.
    constexpr uint8_t REDACTED_CLAIM_KEYS = 59; // simple(59) map key
    constexpr uint64_t REDACTED_ELEMENT_TAG = 60; // tag(60) array element

    std::vector<uint8_t> encoded_key_bytes(const CborKey& key)
    {
      return ccf::cbor::serialize(to_ccf_cbor(key));
    }
  }

  ccf::cbor::Value bytes_value(std::span<const uint8_t> data)
  {
    if (data.empty())
    {
      // Any valid address works: ccf::cbor checks the pointer, not the length.
      static constexpr std::array<uint8_t, 1> anchor{};
      return ccf::cbor::make_bytes(std::span<const uint8_t>{anchor.data(), 0});
    }
    return ccf::cbor::make_bytes(data);
  }

  ccf::cbor::Value to_ccf_cbor(const CborKey& key)
  {
    if (std::holds_alternative<int64_t>(key))
    {
      return ccf::cbor::make_signed(std::get<int64_t>(key));
    }
    return ccf::cbor::make_string(std::get<std::string>(key));
  }

  ccf::cbor::Value to_ccf_cbor(const CborValue& v)
  {
    switch (v.kind)
    {
      case CborValue::Kind::Int:
        return ccf::cbor::make_signed(v.int_v);
      case CborValue::Kind::Bytes:
        return bytes_value(v.bytes_v);
      case CborValue::Kind::Text:
        return ccf::cbor::make_string(v.text_v);
      case CborValue::Kind::RedactedElement:
        // An array element replaced by tag(60) wrapping its Redacted Claim
        // Hash.
        return ccf::cbor::make_tagged(
          REDACTED_ELEMENT_TAG, bytes_value(v.bytes_v));
      case CborValue::Kind::Array:
      {
        std::vector<ccf::cbor::Value> items;
        items.reserve(v.array_v.size());
        for (const auto& elem : v.array_v)
        {
          items.push_back(to_ccf_cbor(elem));
        }
        return ccf::cbor::make_array(std::move(items));
      }
      case CborValue::Kind::Map:
      {
        // CDE (RFC 8949 §4.2): order entries by encoded-key bytes. int and
        // text keys all encode with a first byte < simple(59) (0xf8), so the
        // redacted-keys entry below always sorts last.
        std::vector<std::vector<uint8_t>> keys;
        keys.reserve(v.map_keys.size());
        for (const auto& k : v.map_keys)
        {
          keys.push_back(encoded_key_bytes(k));
        }
        std::vector<size_t> order(v.map_keys.size());
        for (size_t i = 0; i < order.size(); ++i)
        {
          order[i] = i;
        }
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
          return keys[a] < keys[b];
        });

        std::vector<ccf::cbor::MapItem> items;
        items.reserve(v.map_keys.size() + 1);
        for (const size_t idx : order)
        {
          items.emplace_back(
            to_ccf_cbor(v.map_keys[idx]), to_ccf_cbor(v.map_vals[idx]));
        }

        if (!v.redacted_hashes.empty())
        {
          std::vector<ccf::cbor::Value> hashes;
          hashes.reserve(v.redacted_hashes.size());
          for (const auto& dig : v.redacted_hashes)
          {
            hashes.push_back(ccf::cbor::make_bytes(dig));
          }
          items.emplace_back(
            ccf::cbor::make_simple(
              static_cast<ccf::cbor::SimpleValue>(REDACTED_CLAIM_KEYS)),
            ccf::cbor::make_array(std::move(hashes)));
        }
        return ccf::cbor::make_map(std::move(items));
      }
    }
    throw std::runtime_error("unhandled CborValue kind");
  }

  std::vector<uint8_t> encode_value(const CborValue& v)
  {
    // The view is consumed here, while `v` is still alive.
    return ccf::cbor::serialize(to_ccf_cbor(v));
  }
}
