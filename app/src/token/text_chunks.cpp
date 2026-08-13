// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/text_chunks.h"

#include <stdexcept>

namespace sdcwt::text
{
  std::vector<std::string> chunk(std::string_view text, size_t chars)
  {
    if (chars == 0)
    {
      throw std::invalid_argument("chunk size must be positive");
    }

    std::vector<std::string> out;
    out.reserve(text.size() / chars + 1);

    size_t start = 0;
    size_t seen = 0;
    for (size_t i = 0; i < text.size(); ++i)
    {
      // A continuation byte (10xxxxxx) never starts a codepoint.
      if ((static_cast<unsigned char>(text[i]) & 0xC0U) == 0x80U)
      {
        continue;
      }
      if (seen == chars)
      {
        out.emplace_back(text.substr(start, i - start));
        start = i;
        seen = 0;
      }
      ++seen;
    }
    if (start < text.size())
    {
      out.emplace_back(text.substr(start));
    }
    return out;
  }
}
