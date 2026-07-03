// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstdint>
#include <functional>
#include <qcbor/qcbor_encode.h>
#include <span>
#include <stdexcept>
#include <vector>

namespace sdcwt
{
  // Run a QCBOR encoding closure and return the encoded bytes. Uses QCBOR's
  // size-calculation pass first, then a real pass into an exactly-sized buffer,
  // so callers never guess a capacity.
  inline std::vector<uint8_t> cbor_encode(
    const std::function<void(QCBOREncodeContext&)>& build)
  {
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, SizeCalculateUsefulBuf);
    build(ctx);
    size_t len = 0;
    if (QCBOREncode_FinishGetSize(&ctx, &len) != QCBOR_SUCCESS)
    {
      throw std::runtime_error("cbor: size calculation failed");
    }

    std::vector<uint8_t> out(len);
    QCBOREncode_Init(&ctx, UsefulBuf{out.data(), out.size()});
    build(ctx);
    UsefulBufC encoded{};
    if (QCBOREncode_Finish(&ctx, &encoded) != QCBOR_SUCCESS)
    {
      throw std::runtime_error("cbor: encoding failed");
    }
    out.resize(encoded.len);
    return out;
  }

  // Adapt a byte range to a QCBOR UsefulBufC (const view).
  inline UsefulBufC to_ubc(std::span<const uint8_t> bytes)
  {
    return UsefulBufC{bytes.data(), bytes.size()};
  }
}
