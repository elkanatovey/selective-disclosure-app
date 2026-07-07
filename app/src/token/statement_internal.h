// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// INTERNAL header: not part of the public statement API. Exposes the statement
// issuance routines with an injectable randomness source for deterministic
// tests. Production code includes only statement.h, which draws from the CCF
// entropy source.

#include "token/sd_cwt_internal.h"
#include "token/statement.h"

namespace sdcwt::statement::detail
{
  // build_claims() / issue_statement() with an explicit randomness source (used
  // for both the garbage padding and the disclosure salts). The public
  // overloads in statement.h forward here with default_random_source().
  std::vector<Claim> build_claims(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const RandomSource& rng,
    size_t pad_len = SALT_LEN);

  IssuedToken issue_statement(
    const std::string& iss,
    int64_t iat,
    const Fields& fields,
    const ccf::crypto::ECKeyPair& key,
    HashAlg sd_alg,
    const RandomSource& rng,
    size_t salt_len = SALT_LEN);
}
