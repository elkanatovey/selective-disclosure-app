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
  // max_requestable_range(). `latest_write` queries it in bounded windows so
  // the range stays within that limit no matter how large the ledger grows.
  //
  // (The Operator statement stream avoids windowing entirely by capping each
  // page's seqno range below the bound -- see kMaxSeqnoPerPage in app.cpp.
  // `latest_write` still needs it because it must walk back an unbounded,
  // sparsely-populated index to find the greatest registration <= a seqno.)
  //
  // `Index` is any type exposing (matching CCF's index):
  //   size_t     max_requestable_range() const
  //   ccf::TxID  get_indexed_watermark()
  //   std::optional<Iterable<ccf::SeqNo>>  // ascending, inclusive [from, to]
  //     get_write_txs_in_range(ccf::SeqNo from, ccf::SeqNo to)

  // The window size to use: `max_requestable_range() - 1`, so a single index
  // query's inclusive range stays strictly below the limit. Falls back to 1
  // when the limit is 0 or 1 (a degenerate index that can only be queried one
  // seqno at a time).
  template <typename Index>
  ccf::SeqNo window_span(Index& index)
  {
    return std::max<ccf::SeqNo>(
      index.max_requestable_range() > 1 ? index.max_requestable_range() - 1 : 1,
      1);
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
