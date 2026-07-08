// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ccf/app_interface.h"
#include "ccf/claims_digest.h"
#include "ccf/common_auth_policies.h"
#include "ccf/crypto/cose.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/http_consts.h"
#include "ccf/http_query.h"
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

  // Build a presented + transparent statement: embed the CCF receipt into the
  // token's unprotected header (label 394 = array of receipts) to make it
  // transparent, then attach `selected` disclosures via present() (sd_claims,
  // label 17), which preserves the receipt. An empty `selected` yields the bare
  // redacted transparent statement; the full disclosure set yields a fully
  // unredacted one.
  inline std::vector<uint8_t> present_transparent(
    const std::vector<uint8_t>& token,
    const ccf::TxReceiptImplPtr& receipt,
    const std::vector<std::vector<uint8_t>>& selected)
  {
    const auto cose_receipt = make_cose_receipt(receipt);
    const int64_t receipts_label = 394;
    const ccf::cose::edit::desc::Value receipts_desc{
      ccf::cose::edit::pos::InArray{}, receipts_label, cose_receipt};
    const auto transparent =
      ccf::cose::edit::set_unprotected_header(token, receipts_desc);
    return sdcwt::present(transparent, selected);
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

      // Index the seqnos at which a statement was written (every submit +
      // follow-up writes StatementTable), so the Operator stream can enumerate
      // statements in seqno order.
      statement_index =
        std::make_shared<StatementIndex>(STATEMENT_TABLE, context, 10000, 20);
      context.get_indexing_strategies().install_strategy(statement_index);
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      // --- submit_report: parse the CBOR content body, then build + sign a
      // redacted statement, store it, and return its transaction id on commit.
      // -
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
        issue_and_store(ctx, fields);
      };
      make_endpoint(
        "/reports", HTTP_POST, submit_report, {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      // --- register signing key: generate the app issuer key once and endorse
      // it on-ledger. The transaction's claims digest is hash(pubkey), so its
      // receipt endorses the key against the service identity (DESIGN §4/§12).
      // Idempotent init by default; `?rotate=true` registers a NEW key (old
      // registrations are kept — resolvable via GET /signing-key?at={seqno} —
      // so statements signed under a previous key still verify). Member-gated.
      auto register_signing_key = [](ccf::endpoints::EndpointContext& ctx) {
        const auto pq =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
        std::string err;
        const bool rotate =
          ccf::http::get_query_value_opt<bool>(pq, "rotate", err)
            .value_or(false);

        auto* priv = ctx.tx.template rw<SigningKeyTable>(SIGNING_KEY_TABLE);
        if (priv->get().has_value() && !rotate)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK); // idempotent init
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
        {ccf::member_cert_auth_policy})
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
      // Resolve the txid of the issuer-key registration to return: the LATEST
      // by default, or the one active at `?at={seqno}` (the greatest
      // registration seqno <= at) so a verifier can fetch the key that signed a
      // statement committed before a later rotation.
      auto key_txid = [this](ccf::endpoints::ReadOnlyEndpointContext& ctx)
        -> std::optional<ccf::TxID> {
        const auto pq =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
        std::string err;
        const ccf::SeqNo at =
          ccf::http::get_query_value_opt<uint64_t>(pq, "at", err).value_or(0);
        const auto reg = latest_indexed_write(*signing_key_index, at);
        if (!reg.has_value())
        {
          return std::nullopt; // not indexed yet / no registration
        }
        ccf::View view = 0;
        if (get_view_for_seqno_v1(*reg, view) != ccf::ApiResult::OK)
        {
          return std::nullopt;
        }
        return ccf::TxID{view, *reg};
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
        if (!entry.has_value() || !commits_statement(state, entry.value()))
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
        if (!token.has_value() || !commits_statement(state, token.value()))
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
          presented =
            present_transparent(token.value(), state->receipt, selected);
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

      // --- append_follow_up: the Operator files a child statement linked to an
      // existing one. `parent` = SHA-256 of the parent's token (server-derived,
      // redacted + salted like any field), so the child cryptographically
      // commits to exactly the statement the parent's receipt attests. Uses a
      // read-WRITE historical adapter: it reads the parent's token at
      // {parent_txid} and writes the new statement in the same transaction.
      // ----
      auto append_follow_up = [this](
                                ccf::endpoints::EndpointContext& ctx,
                                ccf::historical::StatePtr state) {
        auto ptx = state->store->create_read_only_tx();
        const auto parent =
          ptx.template ro<StatementTable>(STATEMENT_TABLE)->get();

        // Confirm {parent_txid} genuinely committed this statement (guards the
        // per-tx `Value` staleness trap — see commits_statement).
        if (!parent.has_value() || !commits_statement(state, parent.value()))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "Transaction {} is not a statement submission.",
              state->transaction_id.to_str()));
          return;
        }

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

        // The parent link is the parent's claims digest = SHA-256(its token).
        const auto digest = ccf::ClaimsDigest::Digest(parent.value());
        fields.parent = std::vector<uint8_t>(digest.h.begin(), digest.h.end());

        issue_and_store(ctx, fields);
      };

      auto parent_txid_from_path =
        [](ccf::endpoints::EndpointContext& ctx) -> std::optional<ccf::TxID> {
        std::string txid_str;
        std::string error;
        if (!ccf::endpoints::get_path_param(
              ctx.rpc_ctx->get_request_path_params(),
              "parent_txid",
              txid_str,
              error))
        {
          return std::nullopt;
        }
        return ccf::TxID::from_str(txid_str);
      };

      make_endpoint(
        "/reports/{parent_txid}/follow-ups",
        HTTP_POST,
        ccf::historical::read_write_adapter_v4(
          append_follow_up, context, is_tx_committed, parent_txid_from_path),
        {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      // --- get_operator_statement: a single, FULLY-unredacted transparent
      // statement (every disclosure presented + receipt), for the Operator.
      // Same machinery as make_disclosure, but presents all disclosures.
      // -------
      auto get_operator_statement =
        [](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr state) {
          auto htx = state->store->create_read_only_tx();
          const auto token =
            htx.template ro<StatementTable>(STATEMENT_TABLE)->get();
          if (!token.has_value() || !commits_statement(state, token.value()))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format(
                "Transaction {} is not a statement submission.",
                state->transaction_id.to_str()));
            return;
          }

          std::vector<uint8_t> presented;
          try
          {
            std::vector<std::vector<uint8_t>> all;
            const auto stored =
              htx.template ro<DisclosureTable>(DISCLOSURE_TABLE)->get();
            if (stored.has_value())
            {
              for (auto& d : decode_disclosure_store(stored.value()))
              {
                all.push_back(std::move(d.encoded));
              }
            }
            presented = present_transparent(token.value(), state->receipt, all);
          }
          catch (const std::exception& e)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to build unredacted statement: {}", e.what()));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::COSE);
          ctx.rpc_ctx->set_response_body(presented);
        };

      make_read_only_endpoint(
        "/operator/statements/{txid}",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_operator_statement, context, is_tx_committed, txid_from_path),
        {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      // --- get_statements_since: the Operator stream. Returns the txids of the
      // statements committed after `since` (up to `limit`), in seqno order,
      // plus a `next` cursor. The Operator holds its own high-water cursor and
      // pulls each unredacted statement via GET /operator/statements/{txid}.
      // Uses the statement seqno index (no per-entry historical fetch here).
      // ------------
      auto get_statements_since =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          const auto pq =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
          std::string err;
          const ccf::SeqNo since =
            ccf::http::get_query_value_opt<uint64_t>(pq, "since", err)
              .value_or(0);
          size_t limit =
            ccf::http::get_query_value_opt<uint64_t>(pq, "limit", err)
              .value_or(kDefaultPageLimit);
          limit = std::min<size_t>(std::max<size_t>(limit, 1), kMaxPageLimit);

          std::vector<std::string> txids;
          ccf::SeqNo next = since;
          const auto watermark = statement_index->get_indexed_watermark();
          const auto span =
            std::max<ccf::SeqNo>(statement_index->max_requestable_range(), 1);
          // Walk the seqno range in windows no larger than the index's
          // max_requestable_range (querying an unbounded range throws), until
          // we fill the page or reach the watermark.
          ccf::SeqNo from = since + 1;
          bool stop = false;
          while (!stop && from <= watermark.seqno && txids.size() < limit)
          {
            const ccf::SeqNo to = std::min(watermark.seqno, from + span);
            const auto seqnos =
              statement_index->get_write_txs_in_range(from, to);
            if (!seqnos.has_value())
            {
              break; // window not populated yet
            }
            for (const auto s : *seqnos)
            {
              if (txids.size() >= limit)
              {
                break;
              }
              ccf::View view = 0;
              if (get_view_for_seqno_v1(s, view) != ccf::ApiResult::OK)
              {
                // Don't advance past an unresolved seqno, or it would be
                // permanently skipped; the Operator retries it next poll.
                stop = true;
                break;
              }
              txids.push_back(ccf::TxID{view, s}.to_str());
              next = s;
            }
            from = to + 1;
          }

          const auto body = sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
            QCBOREncode_OpenMap(&c);
            QCBOREncode_OpenArrayInMapSZ(&c, "statements");
            for (const auto& t : txids)
            {
              QCBOREncode_AddSZString(&c, t.c_str());
            }
            QCBOREncode_CloseArray(&c);
            QCBOREncode_AddInt64ToMap(&c, "next", static_cast<int64_t>(next));
            QCBOREncode_CloseMap(&c);
          });

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::CBOR);
          ctx.rpc_ctx->set_response_body(body);
        };

      make_read_only_endpoint(
        "/operator/statements",
        HTTP_GET,
        get_statements_since,
        {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Sometimes)
        .install();
    }

  private:
    // Build + sign a redacted statement from `fields` in this transaction,
    // store the token (public) and its disclosures (confidential), bind the
    // claims digest, and arrange a 204 + txid-header response on commit. Sets
    // an error and returns without a commit callback if the issuer key is
    // missing (503) or issuance fails (500). Shared by submit_report and
    // append_follow_up.
    void issue_and_store(
      ccf::endpoints::EndpointContext& ctx, const statement::Fields& fields)
    {
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

        ctx.tx.template rw<StatementTable>(STATEMENT_TABLE)->put(issued.token);

        // Confidential store: retain the disclosures (the openings for every
        // redacted field) in the PRIVATE table so the Operator can later
        // produce duplicate-proofs. Write-only here (segregation invariant,
        // DESIGN.md s8): the redacted-token build, digest binding and public
        // store never read it.
        ctx.tx.template rw<DisclosureTable>(DISCLOSURE_TABLE)
          ->put(encode_disclosure_store(issued.disclosures));

        // Bind the token's digest into the Merkle tree for this transaction, so
        // the receipt attests exactly this redacted statement.
        ctx.rpc_ctx->set_claims_digest(ccf::ClaimsDigest::Digest(issued.token));
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
            info.rpc_ctx->set_response_status(HTTP_STATUS_SERVICE_UNAVAILABLE);
            info.rpc_ctx->set_response_body(
              std::string("Submission was rolled back; please retry."));
            return;
          }
          info.rpc_ctx->set_response_header(
            ccf::http::headers::CCF_TX_ID, info.tx_id.to_str());
          info.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        });
    }

    using SigningKeyIndex =
      ccf::indexing::strategies::SeqnosForValue_Bucketed<SigningKeyHistory>;
    std::shared_ptr<SigningKeyIndex> signing_key_index;

    using StatementIndex =
      ccf::indexing::strategies::SeqnosForValue_Bucketed<StatementTable>;
    std::shared_ptr<StatementIndex> statement_index;

    // Whether the transaction at `state` genuinely committed `token` as a
    // statement: its receipt's claims digest must equal hash(token). Guards the
    // per-tx `Value` staleness trap — a historical read of StatementTable at an
    // unrelated seqno returns a carried-over token that this rejects.
    static bool commits_statement(
      const ccf::historical::StatePtr& state, const std::vector<uint8_t>& token)
    {
      const auto receipt = ccf::describe_receipt_v2(*state->receipt);
      const auto proof = std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt);
      return proof != nullptr &&
        !proof->leaf_components.claims_digest.empty() &&
        proof->leaf_components.claims_digest.value() ==
        ccf::ClaimsDigest::Digest(token);
    }

    // The highest seqno at most `upper` (or unbounded if `upper == 0`) at which
    // `index` recorded a write, or nullopt if none. Walks the indexed range
    // backward in windows no larger than the index's max_requestable_range,
    // because querying an unbounded range throws once the ledger grows past it.
    template <typename Index>
    static std::optional<ccf::SeqNo> latest_indexed_write(
      Index& index, ccf::SeqNo upper = 0)
    {
      const ccf::SeqNo head = index.get_indexed_watermark().seqno;
      if (head == 0)
      {
        return std::nullopt;
      }
      ccf::SeqNo hi = (upper == 0) ? head : std::min<ccf::SeqNo>(upper, head);
      if (hi == 0)
      {
        return std::nullopt;
      }
      const auto span = std::max<ccf::SeqNo>(index.max_requestable_range(), 1);
      while (true)
      {
        const ccf::SeqNo lo = (hi > span) ? (hi - span) : 1;
        const auto seqnos = index.get_write_txs_in_range(lo, hi);
        if (seqnos.has_value() && !seqnos->empty())
        {
          ccf::SeqNo latest = 0; // the set is ascending
          for (const auto s : *seqnos)
          {
            latest = s;
          }
          return latest;
        }
        if (lo == 1)
        {
          return std::nullopt;
        }
        hi = lo - 1;
      }
    }

    // Operator-stream pagination bounds.
    static constexpr size_t kDefaultPageLimit = 100;
    static constexpr size_t kMaxPageLimit = 1000;
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
