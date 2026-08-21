// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cbor.h"

#include <algorithm>
#include <limits>
#include <list>
#include <stdexcept>

extern "C"
{
#include <evercbor/CBORNondet.h>
}

namespace sdcwt::cbor
{
  namespace
  {
    class RawArena
    {
    private:
      std::list<cbor_raw> values;
      std::list<std::vector<cbor_raw>> arrays;
      std::list<std::vector<cbor_map_entry>> maps;

    public:
      cbor_raw* hold(cbor_raw value)
      {
        values.push_back(value);
        return &values.back();
      }

      cbor_raw* hold_array(std::vector<cbor_raw> value)
      {
        arrays.push_back(std::move(value));
        return arrays.back().data();
      }

      cbor_map_entry* hold_map(std::vector<cbor_map_entry> value)
      {
        maps.push_back(std::move(value));
        return maps.back().data();
      }
    };

    void check_depth(size_t depth, size_t max_depth)
    {
      if (depth > max_depth)
      {
        throw std::runtime_error("maximum CBOR nesting depth exceeded");
      }
    }

    Value consume(cbor_nondet_t raw, size_t depth, size_t max_depth)
    {
      check_depth(depth, max_depth);
      switch (cbor_nondet_major_type(raw))
      {
        case CBOR_MAJOR_TYPE_UINT64:
        case CBOR_MAJOR_TYPE_NEG_INT64:
        {
          int64_t value = 0;
          if (!cbor_nondet_read_int64(raw, &value))
          {
            throw std::runtime_error("failed to decode CBOR integer");
          }
          return make_signed(value);
        }
        case CBOR_MAJOR_TYPE_BYTE_STRING:
        {
          uint8_t* data = nullptr;
          uint64_t size = 0;
          if (!cbor_nondet_get_byte_string(raw, &data, &size))
          {
            throw std::runtime_error("failed to decode CBOR byte string");
          }
          return make_bytes({data, static_cast<size_t>(size)});
        }
        case CBOR_MAJOR_TYPE_TEXT_STRING:
        {
          uint8_t* data = nullptr;
          uint64_t size = 0;
          if (!cbor_nondet_get_text_string(raw, &data, &size))
          {
            throw std::runtime_error("failed to decode CBOR text string");
          }
          return make_string(
            {reinterpret_cast<const char*>(data), static_cast<size_t>(size)});
        }
        case CBOR_MAJOR_TYPE_ARRAY:
        {
          cbor_nondet_array_iterator_t iterator;
          if (!cbor_nondet_array_iterator_start(raw, &iterator))
          {
            throw std::runtime_error("failed to decode CBOR array");
          }
          std::vector<Value> items;
          while (!cbor_nondet_array_iterator_is_empty(iterator))
          {
            cbor_nondet_t item;
            if (!cbor_nondet_array_iterator_next(&iterator, &item))
            {
              throw std::runtime_error("failed to decode CBOR array item");
            }
            items.push_back(consume(item, depth + 1, max_depth));
          }
          return make_array(std::move(items));
        }
        case CBOR_MAJOR_TYPE_MAP:
        {
          cbor_nondet_map_iterator_t iterator;
          if (!cbor_nondet_map_iterator_start(raw, &iterator))
          {
            throw std::runtime_error("failed to decode CBOR map");
          }
          std::vector<MapItem> items;
          while (!cbor_nondet_map_iterator_is_empty(iterator))
          {
            cbor_raw key;
            cbor_raw value;
            if (!cbor_nondet_map_iterator_next(&iterator, &key, &value))
            {
              throw std::runtime_error("failed to decode CBOR map item");
            }
            items.emplace_back(
              consume(key, depth + 1, max_depth),
              consume(value, depth + 1, max_depth));
          }
          return make_map(std::move(items));
        }
        case CBOR_MAJOR_TYPE_TAGGED:
        {
          uint64_t tag = 0;
          cbor_nondet_t item;
          if (!cbor_nondet_get_tagged(raw, &item, &tag))
          {
            throw std::runtime_error("failed to decode CBOR tag");
          }
          return make_tagged(tag, consume(item, depth + 1, max_depth));
        }
        case CBOR_MAJOR_TYPE_SIMPLE_VALUE:
        {
          uint8_t value = 0;
          if (!cbor_nondet_read_simple_value(raw, &value))
          {
            throw std::runtime_error("failed to decode CBOR simple value");
          }
          return make_simple(value);
        }
        default:
          throw std::runtime_error("unsupported CBOR major type");
      }
    }

    cbor_raw to_raw(
      const Value& value, RawArena& arena, size_t depth, size_t max_depth)
    {
      check_depth(depth, max_depth);
      return std::visit(
        [&](const auto& item) -> cbor_raw {
          using T = std::decay_t<decltype(item)>;
          if constexpr (std::is_same_v<T, Signed>)
          {
            return cbor_nondet_mk_int64(item);
          }
          else if constexpr (std::is_same_v<T, Bytes>)
          {
            cbor_raw raw;
            if (!cbor_nondet_mk_byte_string(
                  const_cast<uint8_t*>(item.data()), item.size(), &raw))
            {
              throw std::runtime_error("failed to encode CBOR byte string");
            }
            return raw;
          }
          else if constexpr (std::is_same_v<T, String>)
          {
            cbor_raw raw;
            if (!cbor_nondet_mk_text_string(
                  reinterpret_cast<uint8_t*>(const_cast<char*>(item.data())),
                  item.size(),
                  &raw))
            {
              throw std::runtime_error("failed to encode CBOR text string");
            }
            return raw;
          }
          else if constexpr (std::is_same_v<T, Simple>)
          {
            cbor_raw raw;
            if (!cbor_nondet_mk_simple_value(item, &raw))
            {
              throw std::runtime_error("failed to encode CBOR simple value");
            }
            return raw;
          }
          else if constexpr (std::is_same_v<T, Tagged>)
          {
            cbor_raw raw;
            auto* child =
              arena.hold(to_raw(item.item, arena, depth + 1, max_depth));
            if (!cbor_nondet_mk_tagged(item.tag, child, &raw))
            {
              throw std::runtime_error("failed to encode CBOR tag");
            }
            return raw;
          }
          else if constexpr (std::is_same_v<T, Array>)
          {
            std::vector<cbor_raw> items;
            items.reserve(item.items.size());
            for (const auto& child : item.items)
            {
              items.push_back(to_raw(child, arena, depth + 1, max_depth));
            }
            const auto size = items.size();
            if (items.empty())
            {
              items.emplace_back();
            }
            cbor_raw raw;
            if (!cbor_nondet_mk_array(
                  arena.hold_array(std::move(items)), size, &raw))
            {
              throw std::runtime_error("failed to encode CBOR array");
            }
            return raw;
          }
          else
          {
            std::vector<cbor_map_entry> items;
            items.reserve(item.items.size());
            for (const auto& [key, child] : item.items)
            {
              items.push_back(cbor_nondet_mk_map_entry(
                to_raw(key, arena, depth + 1, max_depth),
                to_raw(child, arena, depth + 1, max_depth)));
            }
            const auto size = items.size();
            if (items.empty())
            {
              items.emplace_back();
            }
            cbor_raw raw;
            if (!cbor_nondet_mk_map(
                  arena.hold_map(std::move(items)), size, &raw))
            {
              throw std::runtime_error("failed to encode CBOR map");
            }
            return raw;
          }
        },
        value->value);
    }
  }

  const Value& ValueImpl::array_at(size_t index) const
  {
    if (!std::holds_alternative<Array>(value))
    {
      throw std::runtime_error("CBOR value is not an array");
    }
    const auto& array = std::get<Array>(value).items;
    if (index >= array.size())
    {
      throw std::runtime_error("CBOR array index is out of bounds");
    }
    return array[index];
  }

  const Value& ValueImpl::map_at(const Value& expected) const
  {
    if (!std::holds_alternative<Map>(value))
    {
      throw std::runtime_error("CBOR value is not a map");
    }
    for (const auto& [key, item] : std::get<Map>(value).items)
    {
      const bool matches = std::visit(
        [](const auto& left, const auto& right) {
          using L = std::decay_t<decltype(left)>;
          using R = std::decay_t<decltype(right)>;
          if constexpr (!std::is_same_v<L, R>)
          {
            return false;
          }
          else if constexpr (
            std::is_same_v<L, Signed> || std::is_same_v<L, Simple>)
          {
            return left == right;
          }
          else if constexpr (
            std::is_same_v<L, Bytes> || std::is_same_v<L, String>)
          {
            return std::equal(
              left.begin(), left.end(), right.begin(), right.end());
          }
          else
          {
            return false;
          }
        },
        key->value,
        expected->value);
      if (matches)
      {
        return item;
      }
    }
    throw std::runtime_error("CBOR map key was not found");
  }

  const Value& ValueImpl::tag_at(uint64_t expected) const
  {
    if (!std::holds_alternative<Tagged>(value))
    {
      throw std::runtime_error("CBOR value is not tagged");
    }
    const auto& tagged = std::get<Tagged>(value);
    if (tagged.tag != expected)
    {
      throw std::runtime_error("unexpected CBOR tag");
    }
    return tagged.item;
  }

  Signed ValueImpl::as_signed() const
  {
    if (!std::holds_alternative<Signed>(value))
    {
      throw std::runtime_error("CBOR value is not an integer");
    }
    return std::get<Signed>(value);
  }

  Bytes ValueImpl::as_bytes() const
  {
    if (!std::holds_alternative<Bytes>(value))
    {
      throw std::runtime_error("CBOR value is not a byte string");
    }
    return std::get<Bytes>(value);
  }

  size_t ValueImpl::size() const
  {
    if (std::holds_alternative<Array>(value))
    {
      return std::get<Array>(value).items.size();
    }
    if (std::holds_alternative<Map>(value))
    {
      return std::get<Map>(value).items.size();
    }
    throw std::runtime_error("CBOR value is not a collection");
  }

  Value make_signed(int64_t value)
  {
    return std::make_shared<ValueImpl>(value);
  }

  Value make_simple(Simple value)
  {
    return std::make_shared<ValueImpl>(value);
  }

  Value make_string(std::string_view data)
  {
    return std::make_shared<ValueImpl>(data);
  }

  Value make_bytes(std::span<const uint8_t> data)
  {
    return std::make_shared<ValueImpl>(data);
  }

  Value make_tagged(uint64_t tag, Value value)
  {
    return std::make_shared<ValueImpl>(Tagged{tag, std::move(value)});
  }

  Value make_array(std::vector<Value> data)
  {
    return std::make_shared<ValueImpl>(Array{std::move(data)});
  }

  Value make_map(std::vector<MapItem> data)
  {
    return std::make_shared<ValueImpl>(Map{std::move(data)});
  }

  Value parse(std::span<const uint8_t> input, size_t max_depth)
  {
    cbor_nondet_t raw;
    auto* data = const_cast<uint8_t*>(input.data());
    auto size = input.size();
    if (!cbor_nondet_parse(false, 0, &data, &size, &raw))
    {
      throw std::runtime_error("failed to parse top-level CBOR item");
    }
    if (size != 0)
    {
      throw std::runtime_error("trailing bytes after top-level CBOR item");
    }
    return consume(raw, 0, max_depth);
  }

  std::vector<uint8_t> serialize(const Value& value, size_t max_depth)
  {
    RawArena arena;
    const auto raw = to_raw(value, arena, 0, max_depth);
    const auto size = cbor_nondet_size(raw, std::numeric_limits<size_t>::max());
    std::vector<uint8_t> output(size);
    if (cbor_nondet_serialize(raw, output.data(), output.size()) != size)
    {
      throw std::runtime_error("failed to serialize CBOR item");
    }
    return output;
  }
}
