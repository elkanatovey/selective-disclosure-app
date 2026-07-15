// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/sd_cwt.h"

#include <cstdint>
#include <span>
#include <vector>

namespace selectivedisclosure
{
  // A disclosure as held in the confidential store: its absolute path from the
  // claims root (map keys / array indices) and its encoded `[salt, value, key]`
  // (or `[salt, value]` / `[salt]`) bytes — the exact form `present()`
  // consumes.
  struct StoredDisclosure
  {
    sdcwt::Path path;
    std::vector<uint8_t> encoded;
  };

  // Serialise a statement's disclosures for the confidential store: a CBOR
  // array of `[path, encoded]` pairs, where `path` is itself a CBOR array of
  // the path's elements (ints and/or text). Keeping each disclosure's path lets
  // the Operator later select an arbitrary subset **at any depth**, pulling in
  // the ancestor disclosures a nested reveal requires (draft-08 ancestor rule).
  //
  // This is what the private DisclosureTable holds — written once on submit and
  // never read on the submit path (the segregation invariant, DESIGN.md s8).
  std::vector<uint8_t> encode_disclosure_store(
    const std::vector<sdcwt::Disclosure>& disclosures);

  // Inverse of `encode_disclosure_store`: recover the ordered list of stored
  // disclosures (path + encoded bytes).
  //
  // Throws std::invalid_argument if the bytes are not a CBOR array of
  // `[path, encoded]` pairs.
  std::vector<StoredDisclosure> decode_disclosure_store(
    std::span<const uint8_t> cbor);

  // Select the disclosures to reveal for the requested target paths, returning
  // their encoded bytes (the form `present()` consumes), ordered shallowest
  // first. A stored disclosure is selected when it is **comparable** to some
  // target — i.e. it is an ancestor-or-self of the target (needed so a nested
  // reveal is resolvable — the ancestor rule) OR a descendant-or-self of it (so
  // disclosing a whole field reveals its nested contents too). Siblings and
  // unrelated branches are never selected.
  std::vector<std::vector<uint8_t>> select_disclosures(
    const std::vector<StoredDisclosure>& stored,
    const std::vector<sdcwt::Path>& targets);
}
