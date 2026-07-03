// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ccf/app_interface.h"
#include "ccf/claims_digest.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_consts.h"
#include "ccf/json_handler.h"
#include "ccf/tx_status.h"
#include "reports.h"

#include <ctime>
#include <nlohmann/json.hpp>

namespace selectivedisclosure
{
  namespace statement = ::sdcwt::statement;

  class ReportLedgerHandlers : public ccf::UserEndpointRegistry
  {
  public:
    ReportLedgerHandlers(ccf::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "Selective Disclosure Report Ledger";
      openapi_info.description =
        "Confidential, append-only bug-report transparency ledger built on "
        "SD-CWT: reports are registered as redacted, service-signed tokens.";
      openapi_info.document_version = "0.0.1";
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      // --- submit_report: researchers submit RAW content; the service builds,
      // signs and registers a redacted statement, then returns its txid. -----
      auto submit_report = [this](ccf::endpoints::EndpointContext& ctx) {
        nlohmann::json body;
        try
        {
          body = nlohmann::json::parse(ctx.rpc_ctx->get_request_body());
        }
        catch (const std::exception&)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Request body must be JSON.");
          return;
        }

        statement::Fields fields;
        if (!parse_fields(body, fields, ctx))
        {
          return; // error already set
        }

        int64_t iat = 0;
        ::timespec time{};
        if (get_untrusted_host_time_v1(time) == ccf::ApiResult::OK)
        {
          iat = static_cast<int64_t>(time.tv_sec);
        }

        try
        {
          auto key = get_or_create_signing_key(ctx.tx);
          const auto issued =
            statement::issue_statement(SERVICE_ISS, iat, fields, *key);

          auto* statements =
            ctx.tx.template rw<StatementTable>(STATEMENT_TABLE);
          statements->put(issued.token);

          // Bind the token's digest into the Merkle tree for this transaction,
          // so the receipt attests exactly this redacted statement.
          ctx.rpc_ctx->set_claims_digest(
            ccf::ClaimsDigest::Digest(issued.token));
        }
        catch (const std::exception& e)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Failed to register statement: {}", e.what()));
          return;
        }

        // Respond once the transaction commits, returning its txid.
        ctx.rpc_ctx->set_consensus_committed_function(
          [](ccf::endpoints::CommittedTxInfo& info) {
            if (info.status == ccf::FinalTxStatus::Invalid)
            {
              info.rpc_ctx->set_response_status(
                HTTP_STATUS_SERVICE_UNAVAILABLE);
              info.rpc_ctx->set_response_body(
                std::string("Submission was rolled back; please retry."));
              return;
            }
            nlohmann::json result;
            result["transaction_id"] = info.tx_id.to_str();
            const auto dumped = result.dump();
            info.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            info.rpc_ctx->set_response_header(
              ccf::http::headers::CONTENT_TYPE,
              ccf::http::headervalues::contenttype::JSON);
            info.rpc_ctx->set_response_header(
              ccf::http::headers::CCF_TX_ID, info.tx_id.to_str());
            info.rpc_ctx->set_response_body(
              std::vector<uint8_t>(dumped.begin(), dumped.end()));
          });
      };
      make_endpoint(
        "/reports", HTTP_POST, submit_report, {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      // --- signing key: publish the app's issuer public key (trust anchor). --
      auto get_signing_key = [](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        auto* handle = ctx.tx.template ro<SigningKeyTable>(SIGNING_KEY_TABLE);
        const auto stored = handle->get();
        if (!stored.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "No signing key yet; submit a report to initialise it.");
          return;
        }
        const auto key = load_signing_key(stored.value());
        const auto& pub = key->public_key_pem();
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE, "application/x-pem-file");
        ctx.rpc_ctx->set_response_body(
          std::vector<uint8_t>(pub.str().begin(), pub.str().end()));
      };
      make_read_only_endpoint(
        "/signing-key", HTTP_GET, get_signing_key, {ccf::empty_auth_policy})
        .install();
    }

  private:
    // Read the app signing key, lazily generating (and storing) a P-256 key on
    // first use so any node can sign when it is primary.
    ccf::crypto::ECKeyPairPtr get_or_create_signing_key(ccf::kv::Tx& tx)
    {
      auto* handle = tx.template rw<SigningKeyTable>(SIGNING_KEY_TABLE);
      const auto existing = handle->get();
      if (existing.has_value())
      {
        return load_signing_key(existing.value());
      }
      auto key = ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
      const auto& pem = key->private_key_pem();
      handle->put(std::vector<uint8_t>(pem.str().begin(), pem.str().end()));
      return key;
    }

    // Map the submission JSON onto the statement schema. Returns false and sets
    // an HTTP error when a field has the wrong type.
    bool parse_fields(
      const nlohmann::json& body,
      statement::Fields& fields,
      ccf::endpoints::EndpointContext& ctx)
    {
      const auto bad = [&](std::string msg) {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, std::move(msg));
        return false;
      };

      const auto opt_str = [&](const char* key) -> std::optional<std::string> {
        if (body.contains(key) && body[key].is_string())
        {
          return body[key].get<std::string>();
        }
        return std::nullopt;
      };

      fields.title = opt_str("title");
      fields.body = opt_str("body");
      fields.component = opt_str("component");
      fields.severity = opt_str("severity");
      fields.patch = opt_str("patch");

      // fingerprint: a normalized dedup key, taken as raw string bytes.
      if (const auto fp = opt_str("fingerprint"))
      {
        fields.fingerprint = std::vector<uint8_t>(fp->begin(), fp->end());
      }

      // parent: hex-encoded hash of the parent statement.
      if (body.contains("parent"))
      {
        if (!body["parent"].is_string())
        {
          return bad("`parent` must be a hex string.");
        }
        const auto decoded = from_hex(body["parent"].get<std::string>());
        if (!decoded.has_value())
        {
          return bad("`parent` must be valid hex.");
        }
        fields.parent = decoded;
      }

      if (body.contains("references"))
      {
        if (!body["references"].is_array())
        {
          return bad("`references` must be an array of strings.");
        }
        std::vector<std::string> refs;
        for (const auto& ref : body["references"])
        {
          if (!ref.is_string())
          {
            return bad("`references` must contain only strings.");
          }
          refs.push_back(ref.get<std::string>());
        }
        fields.references = refs;
      }

      if (body.contains("patch_date"))
      {
        if (!body["patch_date"].is_number_integer())
        {
          return bad("`patch_date` must be an integer.");
        }
        fields.patch_date = body["patch_date"].get<int64_t>();
      }

      return true;
    }
  };
}

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<selectivedisclosure::ReportLedgerHandlers>(context);
  }
}
