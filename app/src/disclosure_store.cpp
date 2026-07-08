// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "disclosure_store.h"

#include "token/cbor.h"

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>

namespace selectivedisclosure
{
  std::vector<uint8_t> encode_disclosure_store(
    const std::vector<sdcwt::Disclosure>& disclosures)
  {
    return sdcwt::cbor_encode([&](QCBOREncodeContext& ctx) {
      QCBOREncode_OpenArray(&ctx);
      for (const auto& d : disclosures)
      {
        QCBOREncode_AddBytes(&ctx, sdcwt::to_ubc(d.encoded));
      }
      QCBOREncode_CloseArray(&ctx);
    });
  }

  std::vector<std::vector<uint8_t>> decode_disclosure_store(
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

    std::vector<std::vector<uint8_t>> out;
    while (true)
    {
      UsefulBufC b = NULLUsefulBufC;
      QCBORDecode_GetByteString(&dc, &b);
      const QCBORError e = QCBORDecode_GetError(&dc);
      if (e == QCBOR_ERR_NO_MORE_ITEMS)
      {
        QCBORDecode_GetAndResetError(&dc); // normal end of array
        break;
      }
      if (e != QCBOR_SUCCESS)
      {
        throw std::invalid_argument(
          "disclosure store must contain only byte-strings");
      }
      const auto* p = static_cast<const uint8_t*>(b.ptr);
      out.emplace_back(p, p + b.len);
    }

    QCBORDecode_ExitArray(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS)
    {
      throw std::invalid_argument("malformed disclosure store");
    }
    return out;
  }

  std::optional<int64_t> disclosure_key_id(std::span<const uint8_t> encoded)
  {
    QCBORDecodeContext dc;
    QCBORDecode_Init(
      &dc,
      UsefulBufC{encoded.data(), encoded.size()},
      QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&dc, nullptr);
    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
    {
      return std::nullopt; // not a salted-disclosure array
    }

    QCBORItem item;
    QCBORDecode_VGetNextConsume(&dc, &item); // salt (bstr)
    QCBORDecode_VGetNextConsume(&dc, &item); // value (any subtree)
    QCBORDecode_VGetNextConsume(&dc, &item); // key (map entries only)

    std::optional<int64_t> id;
    if (
      QCBORDecode_GetError(&dc) == QCBOR_SUCCESS &&
      item.uDataType == QCBOR_TYPE_INT64)
    {
      id = item.val.int64;
    }

    QCBORDecode_GetAndResetError(&dc); // tolerate short arrays / non-int keys
    QCBORDecode_ExitArray(&dc);
    return id;
  }

  std::vector<std::vector<uint8_t>> select_disclosures(
    const std::vector<std::vector<uint8_t>>& encoded_disclosures,
    const std::set<int64_t>& field_ids)
  {
    std::vector<std::vector<uint8_t>> out;
    for (const auto& enc : encoded_disclosures)
    {
      const auto id = disclosure_key_id(enc);
      if (id.has_value() && field_ids.count(*id) != 0)
      {
        out.push_back(enc);
      }
    }
    return out;
  }
}
