// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace sdcwt
{
  // Attach exactly `selected` disclosures to an issued COSE_Sign1 token.
  // Protected header, payload, and signature bytes are preserved.
  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected);
}
