// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "disclosure_store.h"

#include "token/cbor.h"

#include <algorithm>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>
#include <variant>

namespace selectivedisclosure
{
  namespace
  {
    void encode_path(QCBOREncodeContext& ctx, const sdcwt::Path& path)
    {
      QCBOREncode_OpenArray(&ctx);
      for (const auto& elem : path)
      {
        if (std::holds_alternative<int64_t>(elem))
        {
          QCBOREncode_AddInt64(&ctx, std::get<int64_t>(elem));
        }
        else
        {
          QCBOREncode_AddSZString(&ctx, std::get<std::string>(elem).c_str());
        }
      }
      QCBOREncode_CloseArray(&ctx);
    }

    sdcwt::Path decode_path(QCBORDecodeContext& dc)
    {
      QCBORDecode_EnterArray(&dc, nullptr);
      if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
      {
        throw std::invalid_argument("disclosure store: path must be an array");
      }
      sdcwt::Path path;
      while (true)
      {
        QCBORItem item;
        QCBORDecode_VGetNext(&dc, &item);
        const QCBORError e = QCBORDecode_GetError(&dc);
        if (e == QCBOR_ERR_NO_MORE_ITEMS)
        {
          QCBORDecode_GetAndResetError(&dc);
          break;
        }
        if (e != QCBOR_SUCCESS)
        {
          throw std::invalid_argument("disclosure store: malformed path");
        }
        if (item.uDataType == QCBOR_TYPE_INT64)
        {
          path.emplace_back(item.val.int64);
        }
        else if (item.uDataType == QCBOR_TYPE_TEXT_STRING)
        {
          path.emplace_back(std::string(
            static_cast<const char*>(item.val.string.ptr),
            item.val.string.len));
        }
        else
        {
          throw std::invalid_argument(
            "disclosure store: path element must be int or text");
        }
      }
      QCBORDecode_ExitArray(&dc);
      return path;
    }

    // Is `a` a prefix of (or equal to) `b`?
    bool is_prefix(const sdcwt::Path& a, const sdcwt::Path& b)
    {
      if (a.size() > b.size())
      {
        return false;
      }
      return std::equal(a.begin(), a.end(), b.begin());
    }
  }

  std::vector<uint8_t> encode_disclosure_store(
    const std::vector<sdcwt::Disclosure>& disclosures)
  {
    return sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      for (const auto& d : disclosures)
      {
        QCBOREncode_OpenArray(&ctx);
        encode_path(ctx, d.path);
        QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(d.encoded));
        QCBOREncode_CloseArray(&ctx);
      }
      QCBOREncode_CloseArray(&ctx);
    });
  }

  std::vector<StoredDisclosure> decode_disclosure_store(
    std::span<const uint8_t> cbor)
  {
    QCBORDecodeContext dc;
    QCBORDecode_Init(
      &dc, UsefulBufC{cbor.data(), cbor.size()}, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&dc, nullptr);
    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
    {
      throw std::invalid_argument("disclosure store must be a CBOR array");
    }

    std::vector<StoredDisclosure> out;
    while (true)
    {
      QCBORItem peek;
      const QCBORError e = QCBORDecode_PeekNext(&dc, &peek);
      if (e == QCBOR_ERR_NO_MORE_ITEMS)
      {
        QCBORDecode_GetAndResetError(&dc);
        break;
      }
      if (e != QCBOR_SUCCESS)
      {
        throw std::invalid_argument("malformed disclosure store");
      }

      // Each entry is a [path, encoded] pair.
      QCBORDecode_EnterArray(&dc, nullptr);
      if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
      {
        throw std::invalid_argument(
          "disclosure store entry must be a [path, encoded] pair");
      }
      StoredDisclosure d;
      d.path = decode_path(dc);
      UsefulBufC b = NULLUsefulBufC;
      QCBORDecode_GetByteString(&dc, &b);
      if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
      {
        throw std::invalid_argument(
          "disclosure store entry must carry encoded bytes");
      }
      const auto* p = static_cast<const uint8_t*>(b.ptr);
      d.encoded.assign(p, p + b.len);
      QCBORDecode_ExitArray(&dc);
      out.push_back(std::move(d));
    }

    QCBORDecode_ExitArray(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS)
    {
      throw std::invalid_argument("malformed disclosure store");
    }
    return out;
  }

  std::vector<std::vector<uint8_t>> select_disclosures(
    const std::vector<StoredDisclosure>& stored,
    const std::vector<sdcwt::Path>& targets)
  {
    // A target only "resolves" if some stored disclosure is the target itself
    // or a descendant of it. A target that matches nothing (e.g. an
    // out-of-range array index, or a path deeper than anything stored) selects
    // nothing — we must NOT pull an ancestor container for a leaf that does not
    // exist.
    std::vector<const sdcwt::Path*> live;
    for (const auto& t : targets)
    {
      const bool resolves = std::any_of(
        stored.begin(), stored.end(), [&](const StoredDisclosure& d) {
          return is_prefix(t, d.path);
        });
      if (resolves)
      {
        live.push_back(&t);
      }
    }

    // Keep stored order but partition by depth so ancestors precede descendants
    // (resolution is order-independent, but this is deterministic and clear).
    std::vector<const StoredDisclosure*> picked;
    for (const auto& d : stored)
    {
      const bool comparable =
        std::any_of(live.begin(), live.end(), [&](const sdcwt::Path* t) {
          return is_prefix(d.path, *t) || is_prefix(*t, d.path);
        });
      if (comparable)
      {
        picked.push_back(&d);
      }
    }
    std::stable_sort(
      picked.begin(), picked.end(), [](const auto* a, const auto* b) {
        return a->path.size() < b->path.size();
      });

    std::vector<std::vector<uint8_t>> out;
    out.reserve(picked.size());
    for (const auto* d : picked)
    {
      out.push_back(d->encoded);
    }
    return out;
  }
}
