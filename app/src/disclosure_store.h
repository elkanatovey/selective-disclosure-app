// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/sd_cwt.h"

#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace selectivedisclosure
{
  // Serialise a statement's disclosures for the confidential store: a CBOR
  // array of the individual disclosure encodings (each is `cbor([salt, value,
  // key])` for a map entry, or `cbor([salt, value])` / `cbor([salt])`).
  //
  // Storing the encodings is sufficient and minimal: `present()` consumes
  // exactly these bytes, and each disclosure's salt / value / key are
  // recoverable by decoding its entry. This is what the private DisclosureTable
  // holds — written once on submit, never read on the submit path (the
  // segregation invariant, DESIGN.md s8).
  std::vector<uint8_t> encode_disclosure_store(
    const std::vector<sdcwt::Disclosure>& disclosures);

  // Inverse of `encode_disclosure_store`: recover the ordered list of encoded
  // disclosure byte-strings (the exact form `present()` consumes).
  //
  // Throws std::invalid_argument if the bytes are not a CBOR array of
  // byte-strings.
  std::vector<std::vector<uint8_t>> decode_disclosure_store(
    std::span<const uint8_t> cbor);

  // The map-entry key of an encoded disclosure (`cbor([salt, value, key])`),
  // when that key is an integer claim id. Returns nullopt for a salt-only decoy
  // (`[salt]`), a redacted array element (`[salt, value]`), or a non-integer
  // key. Used to select disclosures by statement field id.
  std::optional<int64_t> disclosure_key_id(std::span<const uint8_t> encoded);

  // From the stored encoded disclosures, return (in stored order) those whose
  // map-entry key is one of `field_ids` — the openings the Operator chooses to
  // reveal. Disclosures without a matching integer key are never selected.
  //
  // NOTE: statements currently redact only whole top-level fields, so a field's
  // key uniquely identifies its disclosure. Nested/recursive disclosure would
  // additionally need to pull ancestor disclosures (the ancestor-disclosure
  // rule) — future work when `redact_paths` is used.
  std::vector<std::vector<uint8_t>> select_disclosures(
    const std::vector<std::vector<uint8_t>>& encoded_disclosures,
    const std::set<int64_t>& field_ids);
}
