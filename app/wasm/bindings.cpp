// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "token/cose.h"
#include "token/presentation.h"
#include "token/verification.h"

#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace
{
  std::vector<uint8_t> from_uint8_array(const emscripten::val& input)
  {
    if (input.isNull() || input.isUndefined())
    {
      throw std::invalid_argument("expected Uint8Array");
    }
    const auto size = input["length"].as<size_t>();
    std::vector<uint8_t> output(size);
    for (size_t index = 0; index < size; ++index)
    {
      output[index] = input[index].as<uint8_t>();
    }
    return output;
  }

  emscripten::val to_uint8_array(const std::vector<uint8_t>& input)
  {
    auto output = emscripten::val::global("Uint8Array").new_(input.size());
    for (size_t index = 0; index < input.size(); ++index)
    {
      output.set(index, input[index]);
    }
    return output;
  }

  std::vector<std::vector<uint8_t>> from_byte_arrays(
    const emscripten::val& input)
  {
    std::vector<std::vector<uint8_t>> output;
    const auto count = input["length"].as<size_t>();
    output.reserve(count);
    for (size_t index = 0; index < count; ++index)
    {
      output.push_back(from_uint8_array(input[index]));
    }
    return output;
  }

  emscripten::val to_byte_arrays(const std::vector<std::vector<uint8_t>>& input)
  {
    auto output = emscripten::val::array();
    for (size_t index = 0; index < input.size(); ++index)
    {
      output.set(index, to_uint8_array(input[index]));
    }
    return output;
  }

  std::string_view signature_hash_name(int64_t algorithm)
  {
    switch (algorithm)
    {
      case -7:
        return "SHA-256";
      case -35:
        return "SHA-384";
      case -36:
        return "SHA-512";
      default:
        throw std::invalid_argument("unsupported COSE signing algorithm");
    }
  }

  std::string_view disclosure_hash_name(int64_t algorithm)
  {
    switch (algorithm)
    {
      case -16:
        return "SHA-256";
      case -43:
        return "SHA-384";
      case -44:
        return "SHA-512";
      default:
        throw std::invalid_argument("unsupported disclosure hash algorithm");
    }
  }

  emscripten::val present(
    const emscripten::val& token, const emscripten::val& selected)
  {
    return to_uint8_array(
      sdcwt::present(from_uint8_array(token), from_byte_arrays(selected)));
  }

  emscripten::val prepare_signature(
    const emscripten::val& protected_header,
    const emscripten::val& payload,
    const emscripten::val& external_aad)
  {
    return to_uint8_array(sdcwt::prepare_cose_sign1_signature(
      from_uint8_array(protected_header),
      from_uint8_array(payload),
      from_uint8_array(external_aad)));
  }

  emscripten::val finalize_signature(
    const emscripten::val& protected_header,
    const emscripten::val& payload,
    const emscripten::val& signature)
  {
    return to_uint8_array(sdcwt::finalize_cose_sign1_signature(
      from_uint8_array(protected_header),
      from_uint8_array(payload),
      from_uint8_array(signature)));
  }

  emscripten::val prepare_verification(const emscripten::val& token)
  {
    const auto plan = sdcwt::prepare_verification(from_uint8_array(token));
    auto output = emscripten::val::object();
    output.set("coseAlgorithm", plan.cose_algorithm);
    output.set(
      "signatureHash", std::string(signature_hash_name(plan.cose_algorithm)));
    output.set(
      "disclosureHash",
      std::string(disclosure_hash_name(plan.disclosure_hash_algorithm)));
    output.set("toBeSigned", to_uint8_array(plan.to_be_signed));
    output.set("signature", to_uint8_array(plan.signature));
    output.set(
      "disclosureHashInputs", to_byte_arrays(plan.disclosure_hash_inputs));
    return output;
  }

  emscripten::val finalize_verification(
    const emscripten::val& token,
    const emscripten::val& disclosure_digests,
    bool signature_valid)
  {
    const auto result = sdcwt::finalize_verification(
      from_uint8_array(token),
      from_byte_arrays(disclosure_digests),
      signature_valid);
    auto output = emscripten::val::object();
    output.set("claims", to_uint8_array(result.claims));
    output.set("clear", to_uint8_array(result.clear));
    output.set("disclosed", to_uint8_array(result.disclosed));
    return output;
  }
}

EMSCRIPTEN_BINDINGS(sd_cwt)
{
  emscripten::function("present", &present);
  emscripten::function("prepareSignature", &prepare_signature);
  emscripten::function("finalizeSignature", &finalize_signature);
  emscripten::function("prepareVerification", &prepare_verification);
  emscripten::function("finalizeVerification", &finalize_verification);
}
