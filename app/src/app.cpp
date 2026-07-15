// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cbor.h"
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
#include "ccf/version.h"
#include "disclosure_store.h"
#include "paging.h"
#include "report_parse.h"
#include "reports.h"

#include <ctime>
#include <fmt/format.h>

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

  // Parse an optional unsigned-integer query parameter. Absent => `dflt`.
  // Present but malformed => sets a 400 on `rpc_ctx` and returns nullopt (the
  // caller must then return). This distinguishes "absent" (use the default)
  // from "present but unparseable" (a client error worth surfacing) --
  // get_query_value_opt alone cannot, as it reports both as nullopt.
  inline std::optional<uint64_t> parse_uint_query_param(
    const ccf::http::ParsedQuery& pq,
    ccf::RpcContext& rpc_ctx,
    const std::string_view& key,
    uint64_t dflt)
  {
    if (pq.find(key) == pq.end())
    {
      return dflt;
    }
    std::string err;
    const auto value = ccf::http::get_query_value_opt<uint64_t>(pq, key, err);
    if (!value.has_value())
    {
      rpc_ctx.set_error(
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidQueryParameterValue,
        fmt::format("Invalid '{}' query parameter: {}", key, err));
    }
    return value;
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
      openapi_info.document_version = kAppVersion;

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

      // --- get_version: public service-discovery metadata. Reports this app's
      // semantic version, the compile-time statement **schema version** (so a
      // client knows which schema a live service speaks, DESIGN §12.1), and the
      // underlying CCF platform version. Unauthenticated on purpose. ----------
      auto get_version = [](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        const auto body = sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
          QCBOREncode_OpenMap(&c);
          QCBOREncode_AddSZStringToMap(&c, "app_version", kAppVersion);
          QCBOREncode_AddInt64ToMap(
            &c,
            "schema_version",
            static_cast<int64_t>(statement::SCHEMA_VERSION));
          QCBOREncode_AddSZStringToMap(&c, "ccf_version", ccf::ccf_version);
          QCBOREncode_CloseMap(&c);
        });
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::CBOR);
        ctx.rpc_ctx->set_response_body(body);
      };
      make_read_only_endpoint(
        "/version", HTTP_GET, get_version, {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

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
        issue_and_store(ctx, fields, wants_wait(ctx));
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

        ctx.rpc_ctx->set_consensus_committed_function(respond_committed_204);
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
        // A malformed ?at= must be a 400, not silently treated as 0 (=latest):
        // returning the current key for a historical query would defeat
        // rotation-safety. Absent ?at= still defaults to 0 (=latest).
        const auto at = parse_uint_query_param(pq, *ctx.rpc_ctx, "at", 0);
        if (!at.has_value())
        {
          return std::nullopt; // malformed ?at= -- 400 already set
        }
        const auto reg = paging::latest_write(*signing_key_index, at.value());
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

      // Reject a present-but-malformed ?at= with a 400 *before* the historical
      // adapter runs: the adapter's txid extractor can only signal failure by
      // returning nullopt, which it renders as a generic 404 -- so pre-validate
      // here to give the same 400 the Operator-stream cursors do.
      auto signing_key_handler = ccf::historical::read_only_adapter_v4(
        get_signing_key, context, key_is_committed, key_txid);
      auto signing_key_guarded =
        [signing_key_handler](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          const auto pq =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
          if (!parse_uint_query_param(pq, *ctx.rpc_ctx, "at", 0).has_value())
          {
            return; // malformed ?at= -- 400 already set
          }
          signing_key_handler(ctx);
        };

      make_read_only_endpoint(
        "/signing-key", HTTP_GET, signing_key_guarded, {ccf::empty_auth_policy})
        .install();

      // --- get_statement: retrieve a registered statement + its receipt by
      // transaction id, as a transparent statement (receipt embedded). --------
      auto get_statement = [](
                             ccf::endpoints::ReadOnlyEndpointContext& ctx,
                             ccf::historical::StatePtr state) {
        const auto entry = committed_statement_token(state, *ctx.rpc_ctx);
        if (!entry.has_value())
        {
          return;
        }

        // The bare redacted statement, made transparent: embed the receipt with
        // no disclosures. present_transparent({}) yields exactly the redacted
        // token + embedded receipt (an empty selection adds no sd_claims).
        const auto transparent =
          present_transparent(entry.value(), state->receipt, {});

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
      auto txid_from_path = [](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        return parse_txid_param(*ctx.rpc_ctx, "txid");
      };

      auto get_statement_adapter = ccf::historical::read_only_adapter_v4(
        get_statement, context, is_tx_committed, txid_from_path);
      make_read_only_endpoint(
        "/statements/{txid}",
        HTTP_GET,
        [get_statement_adapter](
          ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          if (!validate_txid_format(*ctx.rpc_ctx, "txid"))
            return;
          get_statement_adapter(ctx);
        },
        {ccf::empty_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      // --- get_statement_receipt: the CCF receipt alone (COSE), for a verifier
      // that only needs the inclusion/ordering proof without the (redacted)
      // statement bytes. ------------------------------------------------------
      auto get_statement_receipt =
        [](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr state) {
          const auto entry = committed_statement_token(state, *ctx.rpc_ctx);
          if (!entry.has_value())
          {
            return;
          }
          const auto receipt = make_cose_receipt(state->receipt);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::COSE);
          ctx.rpc_ctx->set_response_body(receipt);
        };

      auto get_statement_receipt_adapter = ccf::historical::read_only_adapter_v4(
        get_statement_receipt, context, is_tx_committed, txid_from_path);
      make_read_only_endpoint(
        "/statements/{txid}/receipt",
        HTTP_GET,
        [get_statement_receipt_adapter](
          ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          if (!validate_txid_format(*ctx.rpc_ctx, "txid"))
            return;
          get_statement_receipt_adapter(ctx);
        },
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
        mark_no_store(*ctx.rpc_ctx);
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

        const auto token = committed_statement_token(state, *ctx.rpc_ctx);
        if (!token.has_value())
        {
          return;
        }

        auto historical_tx = state->store->create_read_only_tx();
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

      auto make_disclosure_adapter = ccf::historical::read_only_adapter_v4(
        make_disclosure, context, is_tx_committed, txid_from_path);
      make_read_only_endpoint(
        "/operator/statements/{txid}/disclosure",
        HTTP_POST,
        [make_disclosure_adapter](
          ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          if (!validate_txid_format(*ctx.rpc_ctx, "txid"))
            return;
          make_disclosure_adapter(ctx);
        },
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
        // Confirm {parent_txid} genuinely committed a statement (guards the
        // per-tx `Value` staleness trap — see committed_statement_token).
        const auto parent = committed_statement_token(state, *ctx.rpc_ctx);
        if (!parent.has_value())
        {
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

        issue_and_store(ctx, fields, wants_wait(ctx));
      };

      auto parent_txid_from_path = [](ccf::endpoints::EndpointContext& ctx) {
        return parse_txid_param(*ctx.rpc_ctx, "parent_txid");
      };

      auto append_follow_up_adapter = ccf::historical::read_write_adapter_v4(
        append_follow_up, context, is_tx_committed, parent_txid_from_path);
      make_endpoint(
        "/reports/{parent_txid}/follow-ups",
        HTTP_POST,
        [append_follow_up_adapter](ccf::endpoints::EndpointContext& ctx) {
          if (!validate_txid_format(*ctx.rpc_ctx, "parent_txid"))
            return;
          append_follow_up_adapter(ctx);
        },
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
          mark_no_store(*ctx.rpc_ctx);
          const auto token = committed_statement_token(state, *ctx.rpc_ctx);
          if (!token.has_value())
          {
            return;
          }

          std::vector<uint8_t> presented;
          auto htx = state->store->create_read_only_tx();
          const auto stored =
            htx.template ro<DisclosureTable>(DISCLOSURE_TABLE)->get();
          if (!stored.has_value())
          {
            // No retained confidential store => nothing to unredact. Match
            // make_disclosure's 404 rather than returning an all-redacted 200,
            // so both Operator endpoints report a missing store consistently.
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "No confidential disclosures were retained for this statement.");
            return;
          }
          try
          {
            std::vector<std::vector<uint8_t>> all;
            for (auto& d : decode_disclosure_store(stored.value()))
            {
              all.push_back(std::move(d.encoded));
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

      auto get_operator_statement_adapter =
        ccf::historical::read_only_adapter_v4(
          get_operator_statement, context, is_tx_committed, txid_from_path);
      make_read_only_endpoint(
        "/operator/statements/{txid}",
        HTTP_GET,
        [get_operator_statement_adapter](
          ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          if (!validate_txid_format(*ctx.rpc_ctx, "txid"))
            return;
          get_operator_statement_adapter(ctx);
        },
        {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      // --- get_statements: the Operator stream over a seqno range. Returns the
      // txids of the statements committed in the range [`from`, `to`] (a page
      // at a time), in seqno order, together with the current ledger
      // `watermark` (so the Operator always knows how far the ledger extends --
      // its block count -- and when it has drained the stream) and a `next`
      // cursor when the requested range spans more than one page.
      //
      // Seqno-range pagination: a page covers a bounded seqno
      // *range* (at most `kMaxSeqnoPerPage`), kept strictly below the index's
      // max_requestable_range, so a single index query can never exceed that
      // bound no matter how large the ledger grows -- no server-side windowing
      // is needed. The Operator pulls each unredacted statement via GET
      // /operator/statements/{txid} and follows `next` (or polls `from =
      // to + 1`) until it has caught up with `watermark`.
      // ------------
      auto get_statements =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          mark_no_store(*ctx.rpc_ctx);
          const auto pq =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

          // A malformed cursor must fail loudly (400): silently defaulting a
          // bad `from`/`to` to 1/watermark would mislead an Operator draining
          // the stream into thinking it had caught up.
          const auto from_opt =
            parse_uint_query_param(pq, *ctx.rpc_ctx, "from", 1);
          if (!from_opt.has_value())
          {
            return;
          }
          ccf::SeqNo from = std::max<ccf::SeqNo>(from_opt.value(), 1);

          const ccf::SeqNo watermark =
            statement_index->get_indexed_watermark().seqno;

          // Clamp the (optional) upper bound to what the index can serve, so a
          // page never asks for un-indexed seqnos.
          const auto to_opt =
            parse_uint_query_param(pq, *ctx.rpc_ctx, "to", watermark);
          if (!to_opt.has_value())
          {
            return;
          }
          ccf::SeqNo to = std::min<ccf::SeqNo>(to_opt.value(), watermark);

          // A page covers at most `span` seqnos, kept strictly below the
          // index's max_requestable_range so the single query below can never
          // throw.
          const ccf::SeqNo max_span = statement_index->max_requestable_range();
          const ccf::SeqNo span = std::min<ccf::SeqNo>(
            kMaxSeqnoPerPage, max_span > 1 ? max_span - 1 : kMaxSeqnoPerPage);
          // An empty range (from > to) reports `to = to` (the clamped
          // watermark), never `from - 1`, so a client that polled past the tip
          // still sees `to <= watermark` (and `to == watermark` once drained).
          const ccf::SeqNo page_end = (to >= from) ?
            std::min<ccf::SeqNo>(to, from + span) :
            std::min<ccf::SeqNo>(from - 1, to);

          std::vector<std::string> txids;
          if (to >= from)
          {
            const auto seqnos =
              statement_index->get_write_txs_in_range(from, page_end);
            if (!seqnos.has_value())
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_SERVICE_UNAVAILABLE,
                ccf::errors::InternalError,
                "Statement index is not ready for the requested range; retry.");
              return;
            }
            for (const auto s : *seqnos)
            {
              ccf::View view = 0;
              if (get_view_for_seqno_v1(s, view) != ccf::ApiResult::OK)
              {
                ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Failed to resolve a committed seqno to a transaction id.");
                return;
              }
              txids.push_back(ccf::TxID{view, s}.to_str());
            }
          }
          const bool more = page_end < to;

          const auto body = sdcwt::cbor_encode([&](QCBOREncodeContext& c) {
            QCBOREncode_OpenMap(&c);
            QCBOREncode_OpenArrayInMapSZ(&c, "statements");
            for (const auto& t : txids)
            {
              QCBOREncode_AddSZString(&c, t.c_str());
            }
            QCBOREncode_CloseArray(&c);
            QCBOREncode_AddInt64ToMap(&c, "from", static_cast<int64_t>(from));
            // The highest seqno this page covers; the Operator's next poll
            // starts at `to + 1`.
            QCBOREncode_AddInt64ToMap(&c, "to", static_cast<int64_t>(page_end));
            // The current ledger tip: the Operator's block count and its
            // "caught up" signal (once `to == watermark`, the stream is
            // drained).
            QCBOREncode_AddInt64ToMap(
              &c, "watermark", static_cast<int64_t>(watermark));
            if (more)
            {
              QCBOREncode_AddInt64ToMap(
                &c, "next", static_cast<int64_t>(page_end + 1));
            }
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
        get_statements,
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
      ccf::endpoints::EndpointContext& ctx,
      const statement::Fields& fields,
      bool wait)
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

      if (!wait)
      {
        // Asynchronous: respond as soon as the transaction commits locally. The
        // framework's default locally-committed handler adds the txid header,
        // so the client gets the transaction id without blocking on global
        // commit; it then polls GET /statements/{txid}/receipt until the
        // receipt (which needs global commit) is available.
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        return;
      }

      // Synchronous (default): hold the response until the transaction is
      // globally committed, then return 204 + the txid header (and surface a
      // rollback as 503). The txid is in the standard `x-ms-ccf-transaction-id`
      // header (no JSON body), matching CCF convention.
      ctx.rpc_ctx->set_consensus_committed_function(respond_committed_204);
    }

    using SigningKeyIndex =
      ccf::indexing::strategies::SeqnosForValue_Bucketed<SigningKeyHistory>;
    std::shared_ptr<SigningKeyIndex> signing_key_index;

    using StatementIndex =
      ccf::indexing::strategies::SeqnosForValue_Bucketed<StatementTable>;
    std::shared_ptr<StatementIndex> statement_index;

    // Mark a response as confidential so no cache retains it. `no-store`
    // forbids any storage by client, proxy, or diagnostic caches (it subsumes
    // `private` and `no-cache`). Applied to the Operator confidential-egress
    // responses, which carry unredacted / selectively-disclosed plaintext or
    // the Operator-only statement enumeration. Set at the TOP of each handler
    // so it also covers set_error responses (set_error does not clear headers).
    static void mark_no_store(ccf::RpcContext& rpc)
    {
      rpc.set_response_header(ccf::http::headers::CACHE_CONTROL, "no-store");
    }

    // Consensus-committed callback: on global commit, 204 + the txid header; on
    // a rollback (Invalid), 503 so callers don't mistake a rolled-back
    // submission/registration for success.
    static void respond_committed_204(ccf::endpoints::CommittedTxInfo& info)
    {
      if (info.status == ccf::FinalTxStatus::Invalid)
      {
        info.rpc_ctx->set_error(
          HTTP_STATUS_SERVICE_UNAVAILABLE,
          ccf::errors::TransactionReplicationFailed,
          "The transaction was rolled back before commit; please retry.");
        return;
      }
      info.rpc_ctx->set_response_header(
        ccf::http::headers::CCF_TX_ID, info.tx_id.to_str());
      info.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
    }

    // Whether the submitter wants to block until global commit (default) or get
    // an immediate 202 + txid to poll — `?wait=false` for the async path.
    static bool wants_wait(ccf::endpoints::EndpointContext& ctx)
    {
      const auto pq = ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
      std::string err;
      return ccf::http::get_query_value_opt<bool>(pq, "wait", err)
        .value_or(true);
    }

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

    // Read the statement token committed at this historical `state`, enforcing
    // the claims-digest guard. Returns the token bytes on success; on failure
    // sets a 404 on `rpc` and returns nullopt. EVERY path that serves a
    // statement by txid MUST obtain the token through this, so the guard (the
    // defense against the stale per-tx `Value` trap) can never be omitted by a
    // future endpoint — and so the confidential DisclosureTable is never read
    // for a txid that did not commit a statement. The returned token is copied
    // out, so callers may open their own read tx on `state->store` for the
    // DisclosureTable (same seqno snapshot ⇒ consistent).
    static std::optional<std::vector<uint8_t>> committed_statement_token(
      const ccf::historical::StatePtr& state, ccf::RpcContext& rpc)
    {
      auto htx = state->store->create_read_only_tx();
      const auto token =
        htx.template ro<StatementTable>(STATEMENT_TABLE)->get();
      if (!token.has_value() || !commits_statement(state, token.value()))
      {
        rpc.set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          fmt::format(
            "Transaction {} is not a statement submission.",
            state->transaction_id.to_str()));
        return std::nullopt;
      }
      return token;
    }

    // Extract + parse a transaction-id path parameter (e.g. `txid`,
    // `parent_txid`) for a historical adapter. Returns nullopt if absent or
    // unparseable. Shared by the read-only and read-write path extractors.
    static std::optional<ccf::TxID> parse_txid_param(
      ccf::RpcContext& rpc, const std::string& name)
    {
      std::string txid_str;
      std::string error;
      if (!ccf::endpoints::get_path_param(
            rpc.get_request_path_params(), name, txid_str, error))
      {
        return std::nullopt;
      }
      return ccf::TxID::from_str(txid_str);
    }

    // Pre-validate a transaction-id path parameter format before the historical
    // adapter runs. Returns true (caller should continue) when the parameter is
    // absent (shouldn't happen for a path param) or parses as a valid TxID.
    // Returns false and sets HTTP 400 when the parameter is present but cannot
    // be parsed, matching the scitt-ccf-ledger custom adapter behaviour.
    // A valid-format but unknown TxID passes through so the adapter can return
    // its own 404/503.
    static bool validate_txid_format(
      ccf::RpcContext& rpc, const std::string& name)
    {
      std::string txid_str;
      std::string error;
      if (!ccf::endpoints::get_path_param(
            rpc.get_request_path_params(), name, txid_str, error))
      {
        return true; // absent path param: let the adapter handle
      }
      if (!ccf::TxID::from_str(txid_str).has_value())
      {
        rpc.set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidInput,
          fmt::format("Invalid transaction ID: {}", txid_str));
        return false;
      }
      return true;
    }

    // Semantic version of this ledger application (distinct from the CCF
    // platform version). Bumped on app releases; also used as the OpenAPI
    // document version so the two never drift.
    static constexpr auto kAppVersion = "0.0.1";

    // Operator-stream page size: the maximum seqno *range* a single page
    // covers. Kept well below the statement index's max_requestable_range
    // (== (max_buckets - 1) * seqnos_per_bucket) so one index query per page
    // never exceeds that bound, no matter how large the ledger grows.
    static constexpr ccf::SeqNo kMaxSeqnoPerPage = 10000;
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
