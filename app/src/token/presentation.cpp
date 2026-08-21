// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/presentation.h"

#include "token/cbor.h"
#include "token/cbor_value.h"

#include <stdexcept>

namespace sdcwt
{
  namespace
  {
    constexpr int64_t SD_CLAIMS_LABEL = 17;
  }

  std::vector<uint8_t> present(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& selected)
  {
    cbor::Value root;
    const cbor::Value* envelope = nullptr;
    try
    {
      root = cbor::parse(token);
      envelope = &root->tag_at(cbor::COSE_SIGN_1_TAG);
    }
    catch (const std::exception&)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }

    if (!std::holds_alternative<cbor::Array>((*envelope)->value))
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }
    const auto& parts = std::get<cbor::Array>((*envelope)->value).items;
    if (parts.size() != 4)
    {
      throw std::runtime_error("present: malformed COSE_Sign1 token");
    }
    if (!std::holds_alternative<cbor::Map>(parts[1]->value))
    {
      throw std::runtime_error("present: malformed unprotected header");
    }

    std::vector<cbor::MapItem> unprotected_header;
    for (const auto& [label, value] :
         std::get<cbor::Map>(parts[1]->value).items)
    {
      const bool is_sd_claims =
        std::holds_alternative<cbor::Signed>(label->value) &&
        label->as_signed() == SD_CLAIMS_LABEL;
      if (!is_sd_claims)
      {
        unprotected_header.emplace_back(label, value);
      }
    }
    if (!selected.empty())
    {
      std::vector<cbor::Value> disclosures;
      disclosures.reserve(selected.size());
      for (const auto& disclosure : selected)
      {
        disclosures.push_back(bytes_value(disclosure));
      }
      unprotected_header.emplace_back(
        cbor::make_signed(SD_CLAIMS_LABEL),
        cbor::make_array(std::move(disclosures)));
    }

    return cbor::serialize(cbor::make_tagged(
      cbor::COSE_SIGN_1_TAG,
      cbor::make_array(
        {parts[0],
         cbor::make_map(std::move(unprotected_header)),
         parts[2],
         parts[3]})));
  }
}
