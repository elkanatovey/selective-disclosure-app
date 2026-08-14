// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace sdcwt::text
{
  // Split UTF-8 `text` into chunks of `chars` codepoints; the last may be
  // shorter. Concatenating the result reproduces `text` exactly, and a chunk
  // never splits a codepoint, so each is a valid CBOR text string.
  //
  // Throws std::invalid_argument if `chars` is 0.
  std::vector<std::string> chunk(std::string_view text, size_t chars);
}
