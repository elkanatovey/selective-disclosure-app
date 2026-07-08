// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ccf/app_interface.h"
#include "ccf/claims_digest.h"
#include "ccf/common_auth_policies.h"
#include "ccf/crypto/cose.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/http_consts.h"
#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"
#include "ccf/json_handler.h"
#include "ccf/receipt.h"
#include "ccf/tx_status.h"
#include "disclosure_store.h"
#include "report_parse.h"
#include "reports.h"
#include "token/cbor.h"

#include <ctime>

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

      // Index the seqnos at which the issuer public key was (re)registered, so
      // GET /signing-key can fetch the registration transaction's receipt.
      signing_key_index = std::make_shared<SigningKeyIndex>(
        SIGNING_KEY_HISTORY, context, 10000, 20);
      context.get_indexing_strategies().install_strategy(signing_key_index);
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
          auto* keys = ctx.tx.template rw<SigningKeyTable>(SIGNING_KEY_TABLE);
          const auto stored = keys->get();
          if (!stored.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_SERVICE_UNAVAILABLE,
              ccf::errors::InternalError,
              "Issuer key not initialised; POST /signing-key first.");
            return;
          }
          auto key = load_signing_key(stored.value());
          const auto issued =
            statement::issue_statement(SERVICE_ISS, iat, fields, *key);

          auto* statements =
            ctx.tx.template rw<StatementTable>(STATEMENT_TABLE);
          statements->put(issued.token);

          // Confidential store: retain the disclosures (the openings for every
          // redacted field) in the PRIVATE table so the Operator can later
          // produce duplicate-proofs. Write-only here (segregation invariant,
          // DESIGN.md s8): the redacted-token build, digest binding and public
          // store above never read it.
          auto* disclosures =
            ctx.tx.template rw<DisclosureTable>(DISCLOSURE_TABLE);
          disclosures->put(encode_disclosure_store(issued.disclosures));

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

        // Respond once the transaction commits. The txid is returned in the
        // standard `x-ms-ccf-transaction-id` header (no JSON body), matching
        // CCF/SCITT convention and the all-CBOR/COSE surface.
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
            info.rpc_ctx->set_response_header(
              ccf::http::headers::CCF_TX_ID, info.tx_id.to_str());
            info.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          });
      };
      make_endpoint(
        "/reports", HTTP_POST, submit_report, {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      // --- register signing key: generate the app issuer key once and endorse
      // it on-ledger. The transaction's claims digest is hash(pubkey), so its
      // receipt endorses the key against the service identity (DESIGN §4/§12).
      // Idempotent: a no-op once initialised. --------------------------------
      auto register_signing_key = [](ccf::endpoints::EndpointContext& ctx) {
        auto* priv = ctx.tx.template rw<SigningKeyTable>(SIGNING_KEY_TABLE);
        if (priv->get().has_value())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
        auto key =
          ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP256R1);
        const auto privpem = key->private_key_pem().str();
        priv->put(std::vector<uint8_t>(privpem.begin(), privpem.end()));

        const auto pubpem = key->public_key_pem().str();
        std::vector<uint8_t> pub(pubpem.begin(), pubpem.end());
        auto* hist = ctx.tx.template rw<SigningKeyHistory>(SIGNING_KEY_HISTORY);
        hist->put(pub);

        // Endorse: bind hash(pubkey) as this transaction's claims digest, so
        // its receipt is a service-identity endorsement of the key.
        ctx.rpc_ctx->set_claims_digest(ccf::ClaimsDigest::Digest(pub));

        ctx.rpc_ctx->set_consensus_committed_function(
          [](ccf::endpoints::CommittedTxInfo& info) {
            info.rpc_ctx->set_response_header(
              ccf::http::headers::CCF_TX_ID, info.tx_id.to_str());
            info.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          });
      };
      make_endpoint(
        "/signing-key",
        HTTP_POST,
        register_signing_key,
        {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      // --- signing key: the issuer public key PLUS its on-ledger endorsement
      // (the registration transaction's receipt, whose claims digest is
      // hash(pubkey)). A verifier checks the receipt against the service
      // identity, then trusts statements signed by this key without their own
      // receipts (DESIGN §4). Returns CBOR { "key": pem, "receipt": cose }.
      // ----
      auto get_signing_key = [](
                               ccf::endpoints::ReadOnlyEndpointContext& ctx,
                               ccf::historical::StatePtr state) {
        auto htx = state->store->create_read_only_tx();
        auto* handle = htx.template ro<SigningKeyHistory>(SIGNING_KEY_HISTORY);
        const auto pubkey = handle->get();
        if (!pubkey.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "No issuer key at the registration seqno.");
          return;
        }
        const auto receipt = make_cose_receipt(state->receipt);
        const auto body = sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
          QCBOREncode_OpenMap(&c);
          QCBOREncode_AddBytesToMap(&c, "key", sdcwt::to_ubc(*pubkey));
          QCBOREncode_AddBytesToMap(&c, "receipt", sdcwt::to_ubc(receipt));
          QCBOREncode_CloseMap(&c);
        });
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::CBOR);
        ctx.rpc_ctx->set_response_body(body);
      };

      auto key_is_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, reason);
        };
      // Resolve the txid of the LATEST issuer-key registration from the index.
      auto key_txid = [this](ccf::endpoints::ReadOnlyEndpointContext&)
        -> std::optional<ccf::TxID> {
        const auto watermark = signing_key_index->get_indexed_watermark();
        if (watermark.seqno == 0)
        {
          return std::nullopt; // not indexed yet
        }
        const auto seqnos =
          signing_key_index->get_write_txs_in_range(1, watermark.seqno);
        if (!seqnos.has_value() || seqnos->empty())
        {
          return std::nullopt;
        }
        ccf::SeqNo reg_seqno = 0; // set is ascending; last is the most recent
        for (const auto s : *seqnos)
        {
          reg_seqno = s;
        }
        ccf::View view = 0;
        if (get_view_for_seqno_v1(reg_seqno, view) != ccf::ApiResult::OK)
        {
          return std::nullopt;
        }
        return ccf::TxID{view, reg_seqno};
      };

      make_read_only_endpoint(
        "/signing-key",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_signing_key, context, key_is_committed, key_txid),
        {ccf::empty_auth_policy})
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

      // --- make_disclosure: the Operator reveals a chosen subset of a
      // statement's fields, returning a presented + transparent statement.
      // Reads the confidential store (private) — the only reader, upholding the
      // segregation invariant — and is gated to the Operator (a CCF user).
      // -----
      auto make_disclosure = [](
                               ccf::endpoints::ReadOnlyEndpointContext& ctx,
                               ccf::historical::StatePtr state) {
        std::vector<sdcwt::Path> targets;
        try
        {
          for (const auto& fp :
               parse_disclosure_selection(ctx.rpc_ctx->get_request_body()))
          {
            const auto id = content_field_id(fp.name);
            if (!id.has_value())
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidInput,
                fmt::format("Unknown disclosure field '{}'.", fp.name));
              return;
            }
            sdcwt::Path p;
            p.emplace_back(*id);
            for (const auto idx : fp.indices)
            {
              p.emplace_back(idx);
            }
            targets.push_back(std::move(p));
          }
        }
        catch (const std::exception& e)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, e.what());
          return;
        }

        auto historical_tx = state->store->create_read_only_tx();
        auto* stmt_handle =
          historical_tx.template ro<StatementTable>(STATEMENT_TABLE);
        const auto token = stmt_handle->get();
        if (!token.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "Transaction {} is not a statement submission.",
              state->transaction_id.to_str()));
          return;
        }

        auto* disc_handle =
          historical_tx.template ro<DisclosureTable>(DISCLOSURE_TABLE);
        const auto stored = disc_handle->get();
        if (!stored.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "No confidential disclosures were retained for this statement.");
          return;
        }

        std::vector<uint8_t> presented;
        try
        {
          const auto selected = select_disclosures(
            decode_disclosure_store(stored.value()), targets);

          // Embed the receipt first (transparent statement; label 394 = array
          // of receipts); present() then adds sd_claims (17) while preserving
          // the receipt — a presented + transparent statement.
          const auto cose_receipt = make_cose_receipt(state->receipt);
          const int64_t receipts_label = 394;
          const ccf::cose::edit::desc::Value receipts_desc{
            ccf::cose::edit::pos::InArray{}, receipts_label, cose_receipt};
          const auto transparent = ccf::cose::edit::set_unprotected_header(
            token.value(), receipts_desc);

          presented = sdcwt::present(transparent, selected);
        }
        catch (const std::exception& e)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Failed to build disclosure: {}", e.what()));
          return;
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::COSE);
        ctx.rpc_ctx->set_response_body(presented);
      };

      make_read_only_endpoint(
        "/operator/statements/{txid}/disclosure",
        HTTP_POST,
        ccf::historical::read_only_adapter_v4(
          make_disclosure, context, is_tx_committed, txid_from_path),
        {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
    }

  private:
    using SigningKeyIndex =
      ccf::indexing::strategies::SeqnosForValue_Bucketed<SigningKeyHistory>;
    std::shared_ptr<SigningKeyIndex> signing_key_index;
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
