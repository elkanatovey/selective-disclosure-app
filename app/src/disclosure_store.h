// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "token/sd_cwt.h"

#include <cstdint>
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
}
