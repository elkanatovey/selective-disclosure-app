// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "cbor.h"

#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace sdcwt
{
  // A CBOR map key: an integer or text-string label.
  using CborKey = std::variant<int64_t, std::string>;

  // A minimal CBOR value tree covering the types the token layer needs. Unlike
  // opaque pre-encoded bytes, this can be walked for nested/array redaction.
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
    // Map entries as parallel vectors (std::pair<.., CborValue> would require a
    // complete type here; a vector of an incomplete type is allowed).
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

    // Append a key/value entry to a Map value.
    void map_put(CborKey key, CborValue value);
  };

  // Encode a value into an open QCBOR context. Map entries are emitted in CDE
  // (RFC 8949 §4.2) key order; a map's redacted_hashes, if any, are emitted
  // last under the simple(59) label.
  void encode_value(QCBOREncodeContext& ctx, const CborValue& v);

  // Encode a value to standalone CBOR bytes.
  std::vector<uint8_t> encode_value(const CborValue& v);
}
