// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "disclosure_store.h"

#include "token/cbor_value.h"

#include <algorithm>
#include <ccf/_private/crypto/cbor.h>
#include <stdexcept>
#include <variant>

namespace selectivedisclosure
{
  namespace
  {
    namespace cbor = ccf::cbor;

    template <typename T>
    bool is(const cbor::Value& v)
    {
      return std::holds_alternative<T>(v->value);
    }

    // A path is an array of int (map key / array index) or text (map key).
    // Borrows from `path`, which outlives the enclosing serialize().
    cbor::Value encode_path(const sdcwt::Path& path)
    {
      std::vector<cbor::Value> elems;
      elems.reserve(path.size());
      for (const auto& elem : path)
      {
        if (std::holds_alternative<int64_t>(elem))
        {
          elems.push_back(cbor::make_signed(std::get<int64_t>(elem)));
        }
        else
        {
          elems.push_back(cbor::make_string(std::get<std::string>(elem)));
        }
      }
      return cbor::make_array(std::move(elems));
    }

    sdcwt::Path decode_path(const cbor::Value& v)
    {
      if (!is<cbor::Array>(v))
      {
        throw std::invalid_argument("disclosure store: path must be an array");
      }
      sdcwt::Path path;
      for (const auto& item : std::get<cbor::Array>(v->value).items)
      {
        if (is<cbor::Signed>(item))
        {
          path.emplace_back(item->as_signed());
        }
        else if (is<cbor::String>(item))
        {
          // Copied out: as_string() is a view over the caller's buffer.
          path.emplace_back(std::string(item->as_string()));
        }
        else
        {
          throw std::invalid_argument(
            "disclosure store: path element must be int or text");
        }
      }
      return path;
    }

    // Is `a` a prefix of (or equal to) `b`?
    bool is_prefix(const sdcwt::Path& a, const sdcwt::Path& b)
    {
      if (a.size() > b.size())
      {
        return false;
      }
      return std::equal(a.begin(), a.end(), b.begin());
    }
  }

  std::vector<uint8_t> encode_disclosure_store(
    const std::vector<sdcwt::Disclosure>& disclosures)
  {
    std::vector<cbor::Value> entries;
    entries.reserve(disclosures.size());
    for (const auto& d : disclosures)
    {
      entries.push_back(
        cbor::make_array({encode_path(d.path), sdcwt::bytes_value(d.encoded)}));
    }
    // Borrows from `disclosures`, alive across this call.
    return cbor::serialize(cbor::make_array(std::move(entries)));
  }

  std::vector<StoredDisclosure> decode_disclosure_store(
    std::span<const uint8_t> raw)
  {
    cbor::Value root;
    try
    {
      root = cbor::parse(raw);
    }
    catch (const std::exception&)
    {
      throw std::invalid_argument("malformed disclosure store");
    }
    if (!is<cbor::Array>(root))
    {
      throw std::invalid_argument("disclosure store must be a CBOR array");
    }

    std::vector<StoredDisclosure> out;
    for (const auto& entry : std::get<cbor::Array>(root->value).items)
    {
      // Each entry is a [path, encoded] pair.
      if (!is<cbor::Array>(entry))
      {
        throw std::invalid_argument(
          "disclosure store entry must be a [path, encoded] pair");
      }
      const auto& pair = std::get<cbor::Array>(entry->value).items;
      if (pair.size() != 2)
      {
        throw std::invalid_argument(
          "disclosure store entry must be a [path, encoded] pair");
      }

      StoredDisclosure d;
      d.path = decode_path(pair[0]);
      if (!is<cbor::Bytes>(pair[1]))
      {
        throw std::invalid_argument(
          "disclosure store entry must carry encoded bytes");
      }
      // Copied out: as_bytes() is a view over `raw`.
      const auto b = pair[1]->as_bytes();
      d.encoded.assign(b.begin(), b.end());
      out.push_back(std::move(d));
    }
    return out;
  }

  std::vector<std::vector<uint8_t>> select_disclosures(
    const std::vector<StoredDisclosure>& stored,
    const std::vector<sdcwt::Path>& targets)
  {
    // A target only "resolves" if some stored disclosure is the target itself
    // or a descendant of it. A target that matches nothing (e.g. an
    // out-of-range array index, or a path deeper than anything stored) selects
    // nothing — we must NOT pull an ancestor container for a leaf that does not
    // exist.
    std::vector<const sdcwt::Path*> live;
    for (const auto& t : targets)
    {
      const bool resolves = std::any_of(
        stored.begin(), stored.end(), [&](const StoredDisclosure& d) {
          return is_prefix(t, d.path);
        });
      if (resolves)
      {
        live.push_back(&t);
      }
    }

    // Keep stored order but partition by depth so ancestors precede descendants
    // (resolution is order-independent, but this is deterministic and clear).
    std::vector<const StoredDisclosure*> picked;
    for (const auto& d : stored)
    {
      // Decoy (salt-only padding) disclosures have an empty path. An empty path
      // is a prefix of every target, so without this guard a decoy would be
      // pulled in by ANY resolving target — presenting it to a researcher and
      // revealing which top-level hashes are decoys, defeating decoy padding's
      // purpose. Decoys are never selected by a field/element target; they are
      // only ever presented wholesale in the Operator's own unredacted view.
      if (d.path.empty())
      {
        continue;
      }
      const bool comparable =
        std::any_of(live.begin(), live.end(), [&](const sdcwt::Path* t) {
          return is_prefix(d.path, *t) || is_prefix(*t, d.path);
        });
      if (comparable)
      {
        picked.push_back(&d);
      }
    }
    std::stable_sort(
      picked.begin(), picked.end(), [](const auto* a, const auto* b) {
        return a->path.size() < b->path.size();
      });

    std::vector<std::vector<uint8_t>> out;
    out.reserve(picked.size());
    for (const auto* d : picked)
    {
      out.push_back(d->encoded);
    }
    return out;
  }
}
