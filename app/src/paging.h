// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <algorithm>
#include <ccf/tx_id.h>
#include <cstddef>
#include <optional>
#include <vector>

namespace selectivedisclosure::paging
{
  // CCF's seqno index (SeqnosForValue_Bucketed) throws if a single
  // get_write_txs_in_range(from, to) query spans more than its
  // max_requestable_range(). These helpers query it in bounded windows so the
  // range stays within that limit no matter how large the ledger grows.
  //
  // `Index` is any type exposing (matching CCF's index):
  //   size_t     max_requestable_range() const
  //   ccf::TxID  get_indexed_watermark()
  //   std::optional<Iterable<ccf::SeqNo>>  // ascending, inclusive [from, to]
  //     get_write_txs_in_range(ccf::SeqNo from, ccf::SeqNo to)

  // The window size to use: at most `max_requestable_range()` seqnos, so a
  // window's inclusive range length (`hi - lo`) is strictly below the limit.
  template <typename Index>
  ccf::SeqNo window_span(Index& index)
  {
    return std::max<ccf::SeqNo>(index.max_requestable_range(), 1);
  }

  // Collect (ascending) the write seqnos in [from, to], querying `index` in
  // windows of at most `window_span` seqnos. Stops once `limit` seqnos are
  // collected (`limit == 0` = no cap). Returns nullopt if a required window is
  // not yet populated (the index returned nullopt).
  template <typename Index>
  std::optional<std::vector<ccf::SeqNo>> write_txs_in_windows(
    Index& index, ccf::SeqNo from, ccf::SeqNo to, size_t limit)
  {
    std::vector<ccf::SeqNo> out;
    if (to < from)
    {
      return out;
    }
    const ccf::SeqNo span = window_span(index);
    for (ccf::SeqNo lo = from; lo <= to;)
    {
      // A window covers at most `span` seqnos, so its range length (hi - lo <=
      // span - 1) stays within the index's max_requestable_range.
      const ccf::SeqNo hi = std::min<ccf::SeqNo>(to, lo + span - 1);
      const auto seqnos = index.get_write_txs_in_range(lo, hi);
      if (!seqnos.has_value())
      {
        return std::nullopt;
      }
      for (const auto s : *seqnos)
      {
        out.push_back(s);
        if (limit != 0 && out.size() >= limit)
        {
          return out;
        }
      }
      lo = hi + 1;
    }
    return out;
  }

  // The highest write seqno at most `upper` (`upper == 0` = up to the index
  // watermark), or nullopt if none. Walks backward in windows of at most
  // `window_span` seqnos.
  template <typename Index>
  std::optional<ccf::SeqNo> latest_write(Index& index, ccf::SeqNo upper = 0)
  {
    const ccf::SeqNo head = index.get_indexed_watermark().seqno;
    if (head == 0)
    {
      return std::nullopt;
    }
    ccf::SeqNo hi = (upper == 0) ? head : std::min<ccf::SeqNo>(upper, head);
    if (hi == 0)
    {
      return std::nullopt;
    }
    const ccf::SeqNo span = window_span(index);
    while (true)
    {
      const ccf::SeqNo lo = (hi >= span) ? (hi - span + 1) : 1;
      const auto seqnos = index.get_write_txs_in_range(lo, hi);
      if (seqnos.has_value() && !seqnos->empty())
      {
        ccf::SeqNo latest = 0; // ascending: the last is the greatest
        for (const auto s : *seqnos)
        {
          latest = s;
        }
        return latest;
      }
      if (lo == 1)
      {
        return std::nullopt;
      }
      hi = lo - 1;
    }
  }
}
