// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/text_chunks.h"

#include <gtest/gtest.h>
#include <numeric>
#include <stdexcept>

namespace
{
  std::string join(const std::vector<std::string>& parts)
  {
    return std::accumulate(parts.begin(), parts.end(), std::string{});
  }
}

TEST(TextChunks, JoinReproducesInput)
{
  const std::string text =
    "H\u00e9llo w\u00f6rld \u2014 a line.\nAnd another. \U0001F600 done.";
  for (const size_t n : {1U, 2U, 6U, 30U, 1000U})
  {
    EXPECT_EQ(join(sdcwt::text::chunk(text, n)), text) << "chunk size " << n;
  }
}

TEST(TextChunks, AllButTheLastAreFull)
{
  const auto chunks = sdcwt::text::chunk("abcdefghij", 3);
  ASSERT_EQ(chunks.size(), 4U);
  EXPECT_EQ(chunks[0], "abc");
  EXPECT_EQ(chunks[1], "def");
  EXPECT_EQ(chunks[2], "ghi");
  EXPECT_EQ(chunks[3], "j");
}

TEST(TextChunks, CountsCodepointsNotBytes)
{
  const std::string emoji = "\U0001F600\U0001F600\U0001F600"; // 4 bytes each
  const auto chunks = sdcwt::text::chunk(emoji, 1);
  ASSERT_EQ(chunks.size(), 3U);
  for (const auto& c : chunks)
  {
    EXPECT_EQ(c.size(), 4U);
  }
}

TEST(TextChunks, EmptyTextYieldsNoChunks)
{
  EXPECT_TRUE(sdcwt::text::chunk("", 6).empty());
}

TEST(TextChunks, RejectsZeroSize)
{
  EXPECT_THROW(sdcwt::text::chunk("abc", 0), std::invalid_argument);
}
