// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "paging.h"

#include <gtest/gtest.h>
#include <optional>
#include <stdexcept>
#include <vector>

using selectivedisclosure::paging::latest_write;
using selectivedisclosure::paging::write_txs_in_windows;

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

// A range larger than one window is collected across multiple bounded queries.
TEST(Paging, CollectsAcrossMultipleWindows)
{
  FakeIndex idx{.span = 8, .watermark = 40, .writes = {3, 11, 19, 25, 33}};
  const auto out = write_txs_in_windows(idx, 1, 40, 0);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (std::vector<ccf::SeqNo>{3, 11, 19, 25, 33}));
  EXPECT_GT(idx.queries.size(), 1u); // genuinely windowed
  EXPECT_TRUE(idx.all_queries_within_bound()); // never exceeded the limit
}

// Windows tile the range contiguously without gaps or overlap.
TEST(Paging, WindowsTileContiguously)
{
  FakeIndex idx{.span = 5, .watermark = 20, .writes = {}};
  (void)write_txs_in_windows(idx, 1, 20, 0);
  // [1,5], [6,10], [11,15], [16,20]
  ASSERT_EQ(idx.queries.size(), 4u);
  EXPECT_EQ(idx.queries[0], (std::pair<ccf::SeqNo, ccf::SeqNo>{1, 5}));
  EXPECT_EQ(idx.queries[1], (std::pair<ccf::SeqNo, ccf::SeqNo>{6, 10}));
  EXPECT_EQ(idx.queries[3], (std::pair<ccf::SeqNo, ccf::SeqNo>{16, 20}));
  EXPECT_TRUE(idx.all_queries_within_bound());
}

// `limit` caps the number of collected seqnos (and can stop mid-window).
TEST(Paging, RespectsLimit)
{
  FakeIndex idx{.span = 100, .watermark = 50, .writes = {2, 4, 6, 8, 10}};
  const auto out = write_txs_in_windows(idx, 1, 50, 2);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (std::vector<ccf::SeqNo>{2, 4}));
}

// An empty range yields an empty result with no queries.
TEST(Paging, EmptyRange)
{
  FakeIndex idx{.span = 8, .watermark = 10, .writes = {1, 2}};
  const auto out = write_txs_in_windows(idx, 11, 10, 0); // to < from
  ASSERT_TRUE(out.has_value());
  EXPECT_TRUE(out->empty());
  EXPECT_TRUE(idx.queries.empty());
}

// A not-yet-populated window propagates as nullopt.
TEST(Paging, PropagatesUnpopulated)
{
  FakeIndex idx{
    .span = 8, .watermark = 40, .writes = {3, 20}, .unpopulated_from = 9};
  const auto out = write_txs_in_windows(idx, 1, 40, 0);
  EXPECT_FALSE(out.has_value()); // window [9,16] was not populated
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
