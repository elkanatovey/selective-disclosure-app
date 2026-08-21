// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/cbor.h"

#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace sdcwt
{
  using CborKey = std::variant<int64_t, std::string>;

  // A walkable CBOR tree so redaction can descend
  // into nested maps and arrays.
  struct CborValue
  {
    enum class Kind : uint8_t
    {
      Int,
      Bytes,
      Text,
      Array,
      Map,
      RedactedElement, // an array element replaced by tag(60, digest)
    };

    Kind kind = Kind::Int;
    int64_t int_v = 0;
    std::vector<uint8_t> bytes_v; // Bytes value, or RedactedElement digest
    std::string text_v;
    std::vector<CborValue> array_v;
    // Parallel vectors: a vector of incomplete CborValue is legal here, a
    // vector of std::pair is not.
    std::vector<CborKey> map_keys;
    std::vector<CborValue> map_vals;
    // Map only: sorted Redacted Claim Hashes emitted under simple(59).
    std::vector<std::vector<uint8_t>> redacted_hashes;

    static CborValue Int(int64_t v);
    static CborValue Bytes(std::vector<uint8_t> v);
    static CborValue Text(std::string v);
    static CborValue Array(std::vector<CborValue> v);
    static CborValue Map(std::vector<std::pair<CborKey, CborValue>> entries);
    static CborValue RedactedElem(std::vector<uint8_t> digest);

    void map_put(CborKey key, CborValue value);
  };

  // make_bytes for possibly-empty data: make_bytes rejects a NULL data pointer,
  // so an empty vector/span (data() == nullptr) throws even though an empty
  // byte string is legal CBOR. Passes a non-null zero-length anchor instead.
  cbor::Value bytes_value(std::span<const uint8_t> data);

  // Build a CBOR view of a value/key, sorting map entries into CDE order
  // (RFC 8949 §4.2); the encoder itself preserves insertion order.
  //
  // LIFETIME: the result BORROWS from `v` (Bytes is a span, String a view).
  // Serialize it in the same expression; never let it outlive `v`.
  cbor::Value to_cbor(const CborValue& v);
  cbor::Value to_cbor(const CborKey& k);

  std::vector<uint8_t> encode_value(const CborValue& v);
}
