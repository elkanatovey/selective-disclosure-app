// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "report_parse.h"

#include "token/statement.h"

#include <array>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>
#include <utility>

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

  std::optional<int64_t> content_field_id(std::string_view name)
  {
    namespace st = sdcwt::statement;
    static const std::array<std::pair<std::string_view, int64_t>, 9> kMap = {{
      {"parent", st::PARENT},
      {"title", st::TITLE},
      {"body", st::BODY},
      {"component", st::COMPONENT},
      {"severity", st::SEVERITY},
      {"fingerprint", st::FINGERPRINT},
      {"references", st::REFERENCES},
      {"patch", st::PATCH},
      {"patch_date", st::PATCH_DATE},
    }};
    for (const auto& [n, id] : kMap)
    {
      if (n == name)
      {
        return id;
      }
    }
    return std::nullopt;
  }

  std::vector<FieldPath> parse_disclosure_selection(
    std::span<const uint8_t> cbor)
  {
    QCBORDecodeContext dc;
    QCBORDecode_Init(
      &dc, UsefulBufC{cbor.data(), cbor.size()}, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterMap(&dc, nullptr);
    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
    {
      bad("disclosure request must be a CBOR map");
    }

    QCBORDecode_EnterArrayFromMapSZ(&dc, "fields");
    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
    {
      bad("disclosure request must have a `fields` array");
    }

    std::vector<FieldPath> out;
    while (true)
    {
      QCBORItem peek;
      const QCBORError e = QCBORDecode_PeekNext(&dc, &peek);
      if (e == QCBOR_ERR_NO_MORE_ITEMS)
      {
        QCBORDecode_GetAndResetError(&dc); // normal end of array
        break;
      }
      if (e != QCBOR_SUCCESS)
      {
        bad("malformed `fields` entry");
      }

      FieldPath fp;
      if (peek.uDataType == QCBOR_TYPE_TEXT_STRING)
      {
        // A bare field name: a whole top-level field.
        UsefulBufC s = NULLUsefulBufC;
        QCBORDecode_GetTextString(&dc, &s);
        fp.name.assign(static_cast<const char*>(s.ptr), s.len);
      }
      else if (peek.uDataType == QCBOR_TYPE_ARRAY)
      {
        // A path: [name, idx, idx, ...].
        QCBORDecode_EnterArray(&dc, nullptr);
        UsefulBufC s = NULLUsefulBufC;
        QCBORDecode_GetTextString(&dc, &s);
        if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS)
        {
          bad("a `fields` path must start with a field name");
        }
        fp.name.assign(static_cast<const char*>(s.ptr), s.len);
        while (true)
        {
          int64_t idx = 0;
          QCBORDecode_GetInt64(&dc, &idx);
          const QCBORError ie = QCBORDecode_GetError(&dc);
          if (ie == QCBOR_ERR_NO_MORE_ITEMS)
          {
            QCBORDecode_GetAndResetError(&dc);
            break;
          }
          if (ie != QCBOR_SUCCESS)
          {
            bad("a `fields` path index must be an integer");
          }
          if (idx < 0)
          {
            bad("a `fields` path index must be non-negative");
          }
          fp.indices.push_back(idx);
        }
        QCBORDecode_ExitArray(&dc);
      }
      else
      {
        bad("a `fields` entry must be a name or a [name, idx, ...] path");
      }
      out.push_back(std::move(fp));
    }
    QCBORDecode_ExitArray(&dc);

    QCBORDecode_ExitMap(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS)
    {
      bad("malformed disclosure request");
    }
    return out;
  }
}
