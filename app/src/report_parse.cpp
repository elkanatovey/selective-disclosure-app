// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "report_parse.h"

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>

namespace selectivedisclosure
{
  namespace
  {
    [[noreturn]] void bad(const char* msg)
    {
      throw std::invalid_argument(msg);
    }

    std::optional<std::string> opt_text(QCBORDecodeContext& dc, const char* key)
    {
      UsefulBufC s = NULLUsefulBufC;
      QCBORDecode_GetTextStringInMapSZ(&dc, key, &s);
      const QCBORError e = QCBORDecode_GetAndResetError(&dc);
      if (e == QCBOR_ERR_LABEL_NOT_FOUND)
      {
        return std::nullopt;
      }
      if (e != QCBOR_SUCCESS)
      {
        bad("string field has the wrong type");
      }
      return std::string(static_cast<const char*>(s.ptr), s.len);
    }

    std::optional<std::vector<uint8_t>> opt_bytes(
      QCBORDecodeContext& dc, const char* key)
    {
      UsefulBufC b = NULLUsefulBufC;
      QCBORDecode_GetByteStringInMapSZ(&dc, key, &b);
      const QCBORError e = QCBORDecode_GetAndResetError(&dc);
      if (e == QCBOR_ERR_LABEL_NOT_FOUND)
      {
        return std::nullopt;
      }
      if (e != QCBOR_SUCCESS)
      {
        bad("byte-string field has the wrong type");
      }
      const auto* p = static_cast<const uint8_t*>(b.ptr);
      return std::vector<uint8_t>(p, p + b.len);
    }

    std::optional<int64_t> opt_int(QCBORDecodeContext& dc, const char* key)
    {
      int64_t v = 0;
      QCBORDecode_GetInt64InMapSZ(&dc, key, &v);
      const QCBORError e = QCBORDecode_GetAndResetError(&dc);
      if (e == QCBOR_ERR_LABEL_NOT_FOUND)
      {
        return std::nullopt;
      }
      if (e != QCBOR_SUCCESS)
      {
        bad("integer field has the wrong type");
      }
      return v;
    }

    std::optional<std::vector<std::string>> opt_text_array(
      QCBORDecodeContext& dc, const char* key)
    {
      QCBORDecode_EnterArrayFromMapSZ(&dc, key);
      const QCBORError entered = QCBORDecode_GetAndResetError(&dc);
      if (entered == QCBOR_ERR_LABEL_NOT_FOUND)
      {
        return std::nullopt;
      }
      if (entered != QCBOR_SUCCESS)
      {
        bad("`references` must be an array");
      }

      std::vector<std::string> out;
      while (true)
      {
        UsefulBufC s = NULLUsefulBufC;
        QCBORDecode_GetTextString(&dc, &s);
        const QCBORError e = QCBORDecode_GetError(&dc);
        if (e == QCBOR_ERR_NO_MORE_ITEMS)
        {
          QCBORDecode_GetAndResetError(&dc); // normal end of array
          break;
        }
        if (e != QCBOR_SUCCESS)
        {
          bad("`references` must contain only strings");
        }
        out.emplace_back(static_cast<const char*>(s.ptr), s.len);
      }
      QCBORDecode_ExitArray(&dc);
      return out;
    }
  }

  sdcwt::statement::Fields parse_report_fields(std::span<const uint8_t> cbor)
  {
    QCBORDecodeContext dc;
    QCBORDecode_Init(
      &dc, UsefulBufC{cbor.data(), cbor.size()}, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterMap(&dc, nullptr);
    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
    {
      bad("request body must be a CBOR map");
    }

    sdcwt::statement::Fields f;
    f.title = opt_text(dc, "title");
    f.body = opt_text(dc, "body");
    f.component = opt_text(dc, "component");
    f.severity = opt_text(dc, "severity");
    f.patch = opt_text(dc, "patch");
    f.fingerprint = opt_bytes(dc, "fingerprint");
    f.references = opt_text_array(dc, "references");
    f.patch_date = opt_int(dc, "patch_date");

    QCBORDecode_ExitMap(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS)
    {
      bad("malformed CBOR request body");
    }
    return f;
  }
}
