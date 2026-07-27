// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "report_parse.h"

#include "token/statement.h"

#include <array>
#include <ccf/_private/crypto/cbor.h>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <variant>

namespace selectivedisclosure
{
  namespace
  {
    namespace cbor = ccf::cbor;

    [[noreturn]] void bad(const char* msg)
    {
      throw std::invalid_argument(msg);
    }

    template <typename T>
    bool is(const cbor::Value& v)
    {
      return std::holds_alternative<T>(v->value);
    }

    // The value stored under text key `key`, or nullptr if the map has no such
    // key. Only text-string keys match, so an integer key that happens to share
    // a field's numeric spelling is never mistaken for that field.
    const cbor::Value* find(const cbor::Value& map, std::string_view key)
    {
      for (const auto& [k, v] : std::get<cbor::Map>(map->value).items)
      {
        if (is<cbor::String>(k) && k->as_string() == key)
        {
          return &v;
        }
      }
      return nullptr;
    }

    // Each opt_* returns nullopt for an absent field and throws for a present
    // one of the wrong type. Values are copied out eagerly: cbor::String and
    // cbor::Bytes are views over the caller's buffer, so nothing returned here
    // may alias the parsed input.
    std::optional<std::string> opt_text(const cbor::Value& map, const char* key)
    {
      const auto* v = find(map, key);
      if (v == nullptr)
      {
        return std::nullopt;
      }
      if (!is<cbor::String>(*v))
      {
        bad("string field has the wrong type");
      }
      return std::string((*v)->as_string());
    }

    std::optional<std::vector<uint8_t>> opt_bytes(
      const cbor::Value& map, const char* key)
    {
      const auto* v = find(map, key);
      if (v == nullptr)
      {
        return std::nullopt;
      }
      if (!is<cbor::Bytes>(*v))
      {
        bad("byte-string field has the wrong type");
      }
      const auto b = (*v)->as_bytes();
      return std::vector<uint8_t>(b.begin(), b.end());
    }

    std::optional<int64_t> opt_int(const cbor::Value& map, const char* key)
    {
      const auto* v = find(map, key);
      if (v == nullptr)
      {
        return std::nullopt;
      }
      if (!is<cbor::Signed>(*v))
      {
        bad("integer field has the wrong type");
      }
      return (*v)->as_signed();
    }

    std::optional<std::vector<std::string>> opt_text_array(
      const cbor::Value& map, const char* key)
    {
      const auto* v = find(map, key);
      if (v == nullptr)
      {
        return std::nullopt;
      }
      if (!is<cbor::Array>(*v))
      {
        bad("`references` must be an array");
      }

      std::vector<std::string> out;
      for (const auto& item : std::get<cbor::Array>((*v)->value).items)
      {
        if (!is<cbor::String>(item))
        {
          bad("`references` must contain only strings");
        }
        out.emplace_back(item->as_string());
      }
      return out;
    }

    // Parse a request body as a CBOR map. `ccf::cbor::parse` also enforces the
    // draft-08 encoding MUSTs (definite-length only, no duplicate map keys,
    // nesting bounded by max_depth) and rejects trailing bytes, so a successful
    // return means the body is well-formed, complete, and a map.
    cbor::Value parse_map(std::span<const uint8_t> raw, const char* what)
    {
      cbor::Value v;
      try
      {
        v = cbor::parse(raw);
      }
      catch (const std::exception&)
      {
        bad(what);
      }
      if (!is<cbor::Map>(v))
      {
        bad(what);
      }
      return v;
    }
  }

  sdcwt::statement::Fields parse_report_fields(std::span<const uint8_t> cbor_in)
  {
    const auto map = parse_map(cbor_in, "request body must be a CBOR map");

    sdcwt::statement::Fields f;
    f.title = opt_text(map, "title");
    f.body = opt_text(map, "body");
    f.component = opt_text(map, "component");
    f.severity = opt_text(map, "severity");
    f.patch = opt_text(map, "patch");
    f.fingerprint = opt_bytes(map, "fingerprint");
    f.references = opt_text_array(map, "references");
    f.patch_date = opt_int(map, "patch_date");
    return f;
  }

  std::optional<int64_t> content_field_id(std::string_view name)
  {
    namespace st = sdcwt::statement;
    static const std::array<std::pair<std::string_view, int64_t>, 9> kMap = {{
      {"parent", st::PARENT},
      {"title", st::TITLE},
      {"body", st::BODY},
      {"component", st::COMPONENT},
      {"severity", st::SEVERITY},
      {"fingerprint", st::FINGERPRINT},
      {"references", st::REFERENCES},
      {"patch", st::PATCH},
      {"patch_date", st::PATCH_DATE},
    }};
    for (const auto& [n, id] : kMap)
    {
      if (n == name)
      {
        return id;
      }
    }
    return std::nullopt;
  }

  std::vector<FieldPath> parse_disclosure_selection(
    std::span<const uint8_t> cbor_in)
  {
    const auto map =
      parse_map(cbor_in, "disclosure request must be a CBOR map");

    const auto* fields = find(map, "fields");
    if (fields == nullptr || !is<cbor::Array>(*fields))
    {
      bad("disclosure request must have a `fields` array");
    }

    std::vector<FieldPath> out;
    for (const auto& entry : std::get<cbor::Array>((*fields)->value).items)
    {
      FieldPath fp;
      if (is<cbor::String>(entry))
      {
        // A bare field name: a whole top-level field.
        fp.name = entry->as_string();
      }
      else if (is<cbor::Array>(entry))
      {
        // A path: [name, idx, idx, ...].
        const auto& path = std::get<cbor::Array>(entry->value).items;
        if (path.empty() || !is<cbor::String>(path[0]))
        {
          bad("a `fields` path must start with a field name");
        }
        fp.name = path[0]->as_string();
        for (size_t i = 1; i < path.size(); i++)
        {
          if (!is<cbor::Signed>(path[i]))
          {
            bad("a `fields` path index must be an integer");
          }
          const auto idx = path[i]->as_signed();
          if (idx < 0)
          {
            bad("a `fields` path index must be non-negative");
          }
          fp.indices.push_back(idx);
        }
      }
      else
      {
        bad("a `fields` entry must be a name or a [name, idx, ...] path");
      }
      out.push_back(std::move(fp));
    }
    return out;
  }
}
