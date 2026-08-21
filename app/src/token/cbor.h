// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace sdcwt::cbor
{
  inline constexpr uint64_t COSE_SIGN_1_TAG = 18;

  struct ValueImpl;
  using Value = std::shared_ptr<ValueImpl>;
  using Signed = int64_t;
  using Bytes = std::span<const uint8_t>;
  using String = std::string_view;
  using Simple = uint8_t;

  struct Array
  {
    std::vector<Value> items;
  };

  using MapItem = std::pair<Value, Value>;
  struct Map
  {
    std::vector<MapItem> items;
  };

  struct Tagged
  {
    uint64_t tag;
    Value item;
  };

  using Type = std::variant<Signed, Bytes, String, Array, Map, Tagged, Simple>;

  struct ValueImpl
  {
    explicit ValueImpl(Type value_) : value(std::move(value_)) {}

    Type value;

    const Value& array_at(size_t index) const;
    const Value& map_at(const Value& key) const;
    const Value& tag_at(uint64_t tag) const;
    Signed as_signed() const;
    Bytes as_bytes() const;
    size_t size() const;
  };

  Value make_signed(int64_t value);
  Value make_simple(Simple value);
  Value make_string(std::string_view data);
  Value make_bytes(std::span<const uint8_t> data);
  Value make_tagged(uint64_t tag, Value value);
  Value make_array(std::vector<Value> data);
  Value make_map(std::vector<MapItem> data);

  Value parse(std::span<const uint8_t> raw, size_t max_depth = 16);
  std::vector<uint8_t> serialize(const Value& value, size_t max_depth = 16);
}
