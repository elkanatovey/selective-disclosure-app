// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ccf/app_interface.h"
#include "ccf/claims_digest.h"
#include "ccf/common_auth_policies.h"
#include "ccf/crypto/cose.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/http_consts.h"
#include "ccf/json_handler.h"
#include "ccf/receipt.h"
#include "ccf/tx_status.h"
#include "report_parse.h"
#include "reports.h"

#include <ctime>
#include <nlohmann/json.hpp>

namespace selectivedisclosure
{
  namespace statement = ::sdcwt::statement;

  // Convert a CCF transaction receipt into a standalone COSE receipt
  // (draft-ietf-cose-merkle-tree-proofs): a COSE_Sign1 over the signed tree
  // root, carrying the Merkle inclusion proof in its unprotected header.
  inline std::vector<uint8_t> make_cose_receipt(
    const ccf::TxReceiptImplPtr& receipt_ptr)
  {
    const auto proof = ccf::describe_merkle_proof_v1(*receipt_ptr);
    if (!proof.has_value())
    {
      throw std::runtime_error("Failed to describe Merkle proof for receipt.");
    }
    const auto signature = ccf::describe_cose_signature_v1(*receipt_ptr);
    if (!signature.has_value())
    {
      throw std::runtime_error(
        "Failed to describe COSE signature for receipt.");
    }

    // vdp (verifiable data proofs) = 396; inclusion proofs live at key -1.
    const int64_t vdp = 396;
    const ccf::cose::edit::desc::Value inclusion_desc{
      ccf::cose::edit::pos::AtKey{-1}, vdp, *proof};
    return ccf::cose::edit::set_unprotected_header(*signature, inclusion_desc);
  }

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

      // --- submit_report: parse raw JSON content, build + sign a redacted
      // statement, store it, and return its transaction id on commit. --------
      auto submit_report = [this](ccf::endpoints::EndpointContext& ctx) {
        statement::Fields fields;
        try
        {
          fields = parse_report_fields(ctx.rpc_ctx->get_request_body());
        }
        catch (const std::exception& e)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, e.what());
          return;
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

      // --- get_statement: retrieve a registered statement + its receipt by
      // transaction id, as a transparent statement (receipt embedded). --------
      auto get_statement = [](
                             ccf::endpoints::ReadOnlyEndpointContext& ctx,
                             ccf::historical::StatePtr state) {
        auto historical_tx = state->store->create_read_only_tx();
        auto* handle =
          historical_tx.template ro<StatementTable>(STATEMENT_TABLE);
        const auto entry = handle->get();
        if (!entry.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "Transaction {} is not a statement submission.",
              state->transaction_id.to_str()));
          return;
        }

        const auto cose_receipt = make_cose_receipt(state->receipt);

        // Embed the receipt into the statement's unprotected header (label
        // 394 = array of receipts) to form a transparent statement.
        const int64_t receipts_label = 394;
        const ccf::cose::edit::desc::Value receipts_desc{
          ccf::cose::edit::pos::InArray{}, receipts_label, cose_receipt};
        const auto transparent =
          ccf::cose::edit::set_unprotected_header(*entry, receipts_desc);

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::COSE);
        ctx.rpc_ctx->set_response_body(transparent);
      };

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, reason);
        };
      auto txid_from_path = [](ccf::endpoints::ReadOnlyEndpointContext& ctx)
        -> std::optional<ccf::TxID> {
        std::string txid_str;
        std::string error;
        if (!ccf::endpoints::get_path_param(
              ctx.rpc_ctx->get_request_path_params(), "txid", txid_str, error))
        {
          return std::nullopt;
        }
        return ccf::TxID::from_str(txid_str);
      };

      make_read_only_endpoint(
        "/statements/{txid}",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_statement, context, is_tx_committed, txid_from_path),
        {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
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
