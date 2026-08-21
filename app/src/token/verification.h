// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace sdcwt
{
  struct VerificationPlan
  {
    int64_t cose_algorithm;
    int64_t disclosure_hash_algorithm;
    std::vector<uint8_t> to_be_signed;
    std::vector<uint8_t> signature;
    std::vector<std::vector<uint8_t>> disclosure_hash_inputs;
  };

  struct ValidatedClaims
  {
    std::vector<uint8_t> claims;
    std::vector<uint8_t> clear;
    std::vector<uint8_t> disclosed;
  };

  // Parse a presented SD-CWT and prepare all asynchronous WebCrypto inputs.
  VerificationPlan prepare_verification(std::span<const uint8_t> token);

  // Reconstruct claims after WebCrypto has verified the issuer signature and
  // hashed each VerificationPlan::disclosure_hash_inputs entry in order.
  ValidatedClaims finalize_verification(
    std::span<const uint8_t> token,
    const std::vector<std::vector<uint8_t>>& disclosure_digests,
    bool signature_valid);
}
