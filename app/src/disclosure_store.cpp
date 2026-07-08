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
}
