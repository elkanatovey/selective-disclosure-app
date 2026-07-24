// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// INTERNAL header: not part of the public token API. It exposes an injectable
// randomness source for the issuance routines so tests can produce
// deterministic salts. Production code includes only the public headers
// (sd_cwt.h / statement.h), which always draw from the CCF entropy source — a
// deterministic RNG therefore cannot reach a production caller.

#include "token/sd_cwt.h"

#include <functional>

namespace sdcwt
{
  // Source of salt/garbage bytes.
  using RandomSource = std::function<std::vector<uint8_t>(size_t)>;

  // The production randomness source: the CCF entropy CSPRNG.
  RandomSource default_random_source();

  namespace detail
  {
    // issue() with an explicit randomness source. The public sdcwt::issue()
    // forwards here with default_random_source(); tests pass a deterministic
    // source. See sd_cwt.h for parameter semantics.
    IssuedToken issue(
      const std::vector<Claim>& claims,
      const ccf::crypto::ECKeyPair& key,
      HashAlg sd_alg,
      const std::vector<Path>& redact_paths,
      const RandomSource& rng,
      size_t salt_len = SALT_LEN,
      size_t pad_to = 0,
      const ccf::crypto::ECPublicKey* holder = nullptr);
  }
}
