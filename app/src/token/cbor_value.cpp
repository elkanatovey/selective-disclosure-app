// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cbor_value.h"

#include <algorithm>

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
    std::vector<uint8_t> encode_key(const CborKey& key)
    {
      return cbor_encode([&](QCBOREncodeContext& ctx) {
        if (std::holds_alternative<int64_t>(key))
        {
          QCBOREncode_AddInt64(&ctx, std::get<int64_t>(key));
        }
        else
        {
          const auto& s = std::get<std::string>(key);
          QCBOREncode_AddText(&ctx, UsefulBufC{s.data(), s.size()});
        }
      });
    }

    void add_key(QCBOREncodeContext& ctx, const CborKey& key)
    {
      if (std::holds_alternative<int64_t>(key))
      {
        QCBOREncode_AddInt64(&ctx, std::get<int64_t>(key));
      }
      else
      {
        const auto& s = std::get<std::string>(key);
        QCBOREncode_AddText(&ctx, UsefulBufC{s.data(), s.size()});
      }
    }
  }

  void encode_value(QCBOREncodeContext& ctx, const CborValue& v)
  {
    switch (v.kind)
    {
      case CborValue::Kind::Int:
        QCBOREncode_AddInt64(&ctx, v.int_v);
        break;
      case CborValue::Kind::Bytes:
        QCBOREncode_AddBytes(&ctx, to_ubc(v.bytes_v));
        break;
      case CborValue::Kind::Text:
        QCBOREncode_AddText(&ctx, UsefulBufC{v.text_v.data(), v.text_v.size()});
        break;
      case CborValue::Kind::RedactedElement:
        // An array element replaced by tag(60) wrapping its Redacted Claim
        // Hash.
        QCBOREncode_AddTag(&ctx, 60);
        QCBOREncode_AddBytes(&ctx, to_ubc(v.bytes_v));
        break;
      case CborValue::Kind::Array:
        QCBOREncode_OpenArray(&ctx);
        for (const auto& elem : v.array_v)
        {
          encode_value(ctx, elem);
        }
        QCBOREncode_CloseArray(&ctx);
        break;
      case CborValue::Kind::Map:
      {
        // CDE (RFC 8949 §4.2): emit entries sorted by encoded-key bytes. int
        // and text keys all encode with a first byte < simple(59) (0xf8), so
        // the redacted-keys entry is emitted last.
        std::vector<size_t> order(v.map_keys.size());
        for (size_t i = 0; i < order.size(); ++i)
        {
          order[i] = i;
        }
        std::vector<std::vector<uint8_t>> keys;
        keys.reserve(v.map_keys.size());
        for (const auto& k : v.map_keys)
        {
          keys.push_back(encode_key(k));
        }
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
          return keys[a] < keys[b];
        });

        QCBOREncode_OpenMap(&ctx);
        for (const size_t idx : order)
        {
          add_key(ctx, v.map_keys[idx]);
          encode_value(ctx, v.map_vals[idx]);
        }
        if (!v.redacted_hashes.empty())
        {
          QCBOREncode_AddSimple(&ctx, 59); // redacted_claim_keys
          QCBOREncode_OpenArray(&ctx);
          for (const auto& dig : v.redacted_hashes)
          {
            QCBOREncode_AddBytes(&ctx, to_ubc(dig));
          }
          QCBOREncode_CloseArray(&ctx);
        }
        QCBOREncode_CloseMap(&ctx);
        break;
      }
    }
  }

  std::vector<uint8_t> encode_value(const CborValue& v)
  {
    return cbor_encode([&](QCBOREncodeContext& ctx) { encode_value(ctx, v); });
  }
}
