// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "paging.h"

#include <gtest/gtest.h>
#include <optional>
#include <stdexcept>
#include <vector>

using selectivedisclosure::paging::latest_write;

namespace
{
  // A stand-in for CCF's seqno index. It enforces the same range bound as the
  // real one (throwing when a query spans more than `span`), and records every
  // query so tests can assert the windowing never exceeds the bound.
  struct FakeIndex
  {
    ccf::SeqNo span; // == max_requestable_range()
    ccf::SeqNo watermark;
    std::vector<ccf::SeqNo> writes; // ascending
    std::vector<std::pair<ccf::SeqNo, ccf::SeqNo>> queries;
    // Seqnos for which get_write_txs_in_range should report "not populated".
    std::optional<ccf::SeqNo> unpopulated_from;

    size_t max_requestable_range() const
    {
      return span;
    }

    ccf::TxID get_indexed_watermark()
    {
      return ccf::TxID{2, watermark};
    }

    std::optional<std::vector<ccf::SeqNo>> get_write_txs_in_range(
      ccf::SeqNo from, ccf::SeqNo to)
    {
      queries.emplace_back(from, to);
      // Mirror the real index: an over-wide range is a hard error.
      if (to - from > span)
      {
        throw std::logic_error("range exceeds max_requestable_range");
      }
      if (unpopulated_from.has_value() && from == *unpopulated_from)
      {
        return std::nullopt;
      }
      std::vector<ccf::SeqNo> r;
      for (const auto s : writes)
      {
        if (s >= from && s <= to)
        {
          r.push_back(s);
        }
      }
      return r;
    }

    // Every recorded query stayed within the index's bound.
    [[nodiscard]] bool all_queries_within_bound() const
    {
      for (const auto& [from, to] : queries)
      {
        if (to - from > span)
        {
          return false;
        }
      }
      return true;
    }
  };
}

// latest_write finds the greatest write, walking back through empty windows,
// never exceeding the bound.
TEST(Paging, LatestWriteWalksBack)
{
  FakeIndex idx{.span = 8, .watermark = 40, .writes = {3, 11, 19}};
  const auto latest = latest_write(idx);
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(*latest, 19u);
  EXPECT_TRUE(idx.all_queries_within_bound());
  EXPECT_GT(idx.queries.size(), 1u); // [33,40] empty, then back to find 19
}

// latest_write honours an upper bound (returns the greatest write <= upper).
TEST(Paging, LatestWriteWithUpperBound)
{
  FakeIndex idx{.span = 8, .watermark = 40, .writes = {3, 11, 19, 30}};
  const auto latest = latest_write(idx, 15);
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(*latest, 11u); // 19 and 30 are > 15
  EXPECT_TRUE(idx.all_queries_within_bound());
}

// No writes / empty index -> nullopt.
TEST(Paging, LatestWriteNoneAndEmptyIndex)
{
  FakeIndex none{.span = 8, .watermark = 40, .writes = {}};
  EXPECT_FALSE(latest_write(none).has_value());

  FakeIndex empty{.span = 8, .watermark = 0, .writes = {}};
  EXPECT_FALSE(latest_write(empty).has_value());
}
