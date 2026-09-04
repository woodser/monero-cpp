/**
 * Copyright (c) everoddandeven
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Parts of this file are originally copyright (c) 2014-2019, The Monero Project
 * Parts of this file are originally copyright (c) 2014-2019, MyMonero.com
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * All rights reserved.
 *
 * 1. Redistributions of source code must retain the above copyright notice, this std::list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this std::list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
 */

#include "monero_wallet_light.h"
#include "utils/gen_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "ringct/rctSigs.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "common/threadpool.h"
#include "net/jsonrpc_structs.h"
#include "serialization/serialization.h"
#include "common/monero_error.h"
#include "device/device.hpp"
#include "device/device_cold.hpp"

#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\004"
#define APPROXIMATE_INPUT_BYTES 80

namespace monero {

  // ------------------------- INITIALIZE CONSTANTS ---------------------------

  static const int BULLETPROOF_VERSION = 4; // default bulletproof version
  static const uint8_t DEFAULT_FEE_PRIORITY = 1;
  static const uint32_t MIXIN_SIZE = 15;
  static const uint64_t DUST_THRESHOLD = 2000000000;

  // --------------------------- LIGHT WALLET CLIENT --------------------------

  class light_wallet_client {
  public:
    light_wallet_client(const std::shared_ptr<monero_rpc_connection>& rpc, const std::string& primary_address, const std::string& private_view_key):
      m_rpc(rpc), m_primary_address(primary_address), m_prv_view_key(private_view_key) {
    }

    std::shared_ptr<monero_rpc_connection> get_rpc_connection() const { return m_rpc; }

    std::shared_ptr<monero_daemon_status> get_daemon_status() const {
      auto result = m_rpc->send_path_request("daemon_status");
      auto response = std::make_shared<monero_daemon_status>();
      monero_daemon_status::from_property_tree(result, response);
      return response;
    }

    bool is_connected() const {
      try {
        auto response = get_daemon_status();
        return response->m_state != boost::none && response->m_state.get() != std::string("unavailable");
      } catch (...) {
        return false;
      }
    }

    std::shared_ptr<monero_login_response> login(bool create_account = true, bool generated_locally = true) const {
      auto params = std::make_shared<monero_login_params>(m_primary_address, m_prv_view_key, create_account, generated_locally);
      auto result = m_rpc->send_path_request("login", params);
      auto response = std::make_shared<monero_login_response>();
      monero_login_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_get_address_info_response> get_address_info() const {
      auto params = std::make_shared<monero_wallet_params>(m_primary_address, m_prv_view_key);
      auto result = m_rpc->send_path_request("get_address_info", params);
      auto response = std::make_shared<monero_get_address_info_response>();
      monero_get_address_info_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_get_address_txs_response> get_address_txs() const {
      auto params = std::make_shared<monero_wallet_params>(m_primary_address, m_prv_view_key);
      auto result = m_rpc->send_path_request("get_address_txs", params);
      auto response = std::make_shared<monero_get_address_txs_response>();
      monero_get_address_txs_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_get_unspent_outs_response> get_unspent_outs(uint64_t amount, uint32_t mixin, bool use_dust = true, uint64_t dust_threshold = 0) const {
      auto params = std::make_shared<monero_get_unspent_outs_params>(m_primary_address, m_prv_view_key, amount, mixin, use_dust, dust_threshold);
      auto result = m_rpc->send_path_request("get_unspent_outs", params);
      auto response = std::make_shared<monero_get_unspent_outs_response>();
      monero_get_unspent_outs_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_get_random_outs_response> get_random_outs(const std::vector<uint64_t>& amounts, uint32_t count) const {
      auto params = std::make_shared<monero_get_random_outs_params>(count, amounts);
      auto result = m_rpc->send_path_request("get_random_outs", params);
      auto response = std::make_shared<monero_get_random_outs_response>();
      monero_get_random_outs_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_subaddrs_response> get_subaddrs() const {
      auto params = std::make_shared<monero_wallet_params>(m_primary_address, m_prv_view_key);
      auto result = m_rpc->send_path_request("get_subaddrs", params);
      auto response = std::make_shared<monero_subaddrs_response>();
      monero_subaddrs_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_subaddrs_response> upsert_subaddrs(const monero_subaddrs& subaddrs, bool get_all = true) const {
      auto params = std::make_shared<monero_upsert_subaddrs_params>(m_primary_address, m_prv_view_key, subaddrs, get_all);
      auto result = m_rpc->send_path_request("upsert_subaddrs", params);
      auto response = std::make_shared<monero_subaddrs_response>();
      monero_subaddrs_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_import_wallet_response> import_request(uint64_t from_height) const {
      auto params = std::make_shared<monero_import_wallet_params>(m_primary_address, m_prv_view_key, from_height);
      auto result = m_rpc->send_path_request("import_wallet_request", params);
      auto response = std::make_shared<monero_import_wallet_response>();
      monero_import_wallet_response::from_property_tree(result, response);
      return response;
    }

    std::shared_ptr<monero_submit_raw_tx_response> submit_raw_tx(const std::string& tx) const {
      auto params = std::make_shared<monero_submit_raw_tx_params>(tx);
      auto result = m_rpc->send_path_request("submit_raw_tx", params);
      auto response = std::make_shared<monero_submit_raw_tx_response>();
      monero_submit_raw_tx_response::from_property_tree(result, response);
      return response;
    }

  private:
    std::shared_ptr<monero_rpc_connection> m_rpc;
    std::string m_primary_address;
    std::string m_prv_view_key;
  };

  // ----------------------- INTERNAL PRIVATE HELPERS -----------------------

  void normalize_unconfirmed_tx(const std::shared_ptr<monero_tx_wallet> &tx) {
    tx->m_outputs.clear();
    tx->m_incoming_transfers.clear();
    tx->m_is_incoming = boost::none;

    tx->m_change_address = boost::none;
    tx->m_change_amount = boost::none;

    for(const auto &input : tx->m_inputs) {
      input->m_amount = boost::none;
    }
  }

  // construct_tx_and_get_tx_key() sorts tx.vin (and construction_data.sources) by key image once
  // the tx is built, so input position no longer matches selection order. Recover the true
  // subaddress per input by matching the spent output's global index against outs.
  void fix_input_subaddress_indices(const std::shared_ptr<monero_tx_wallet>& tx, const tools::wallet2::pending_tx& ptx, const std::vector<std::shared_ptr<monero_output_light>>& outs) {
    const std::set<size_t> used_indexes(ptx.selected_transfers.begin(), ptx.selected_transfers.end());
    std::unordered_map<uint64_t, uint32_t> global_idx_to_subaddr;
    for (const auto& out : outs) {
      if (out->m_cache_index != boost::none && used_indexes.count(*out->m_cache_index)) {
        global_idx_to_subaddr[out->m_global_index.get()] = out->m_recipient->m_min_i;
      }
    }

    const auto& sources = ptx.construction_data.sources;
    for (size_t i = 0; i < sources.size() && i < tx->m_inputs.size(); i++) {
      const auto& src = sources[i];
      if (src.real_output >= src.outputs.size()) continue;
      const auto it = global_idx_to_subaddr.find(src.outputs[src.real_output].first);
      if (it == global_idx_to_subaddr.end()) continue;
      auto input = std::dynamic_pointer_cast<monero_output_wallet>(tx->m_inputs[i]);
      if (input) input->m_subaddress_index = it->second;
    }
  }

  std::shared_ptr<monero_tx_wallet> build_tx_with_vout(const std::shared_ptr<monero_wallet_cache>& cache, const std::shared_ptr<monero_output_light>& out, const std::unordered_set<std::string>& pool_key_images) {

    // construct block
    std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
    block->m_height = out->m_height;

    // construct tx
    std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
    tx->m_block = block;
    block->m_txs.push_back(tx);
    tx->m_hash = out->m_tx_hash;
    tx->m_is_confirmed = true;
    tx->m_is_failed = false;
    tx->m_is_relayed = true;
    tx->m_in_tx_pool = false;
    tx->m_relay = true;
    tx->m_is_double_spend_seen = false;
    tx->m_is_locked = cache->get_num_blocks_to_unlock(out->m_tx_hash.get()) > 0;

    // construct output
    std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
    output->m_tx = tx;
    tx->m_outputs.push_back(output);
    output->m_amount = out->m_amount;
    output->m_index = out->m_global_index;
    output->m_account_index = out->m_recipient->m_maj_i;
    output->m_subaddress_index = out->m_recipient->m_min_i;
    output->m_is_spent = out->is_spent();
    output->m_is_frozen = false;
    output->m_stealth_public_key = out->m_public_key;
    if (out->is_key_image_known()) {
      output->m_key_image = std::make_shared<monero_key_image>();
      output->m_key_image.get()->m_hex = out->m_key_image;
      output->m_is_frozen = out->m_frozen.value_or(false);
      if (!*output->m_is_spent) output->m_is_spent = cache->is_key_image_spent(out->m_key_image.get(), pool_key_images);
    }

    // return pointer to new tx
    return tx;
  }

  bool output_before(const std::shared_ptr<monero_output_light>& ow1, const std::shared_ptr<monero_output_light>& ow2) {
    // compare by account index, subaddress index, output index, then global index
    if (ow1->m_recipient->m_maj_i < ow2->m_recipient->m_maj_i) return true;
    if (ow1->m_recipient->m_maj_i == ow2->m_recipient->m_maj_i) {
      if (ow1->m_recipient->m_min_i < ow2->m_recipient->m_min_i) return true;
      if (ow1->m_recipient->m_min_i == ow2->m_recipient->m_min_i) {
        if (ow1->m_global_index.get() < ow2->m_global_index.get()) return true;
        if (ow1->m_global_index.get() == ow2->m_global_index.get()) throw std::runtime_error("Should never sort outputs with duplicate indices");
      }
    }
    return false;
  }

  /**
   * Builds a tools::wallet2::pending_tx for a light wallet transfer.
   *
   * Implementation based on mymonero-core-cpp's monero_transfer_utils::create_transaction().
   */
  class light_tx_builder {
  public:
    light_tx_builder(cryptonote::network_type nettype, const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& subaddresses, const cryptonote::account_keys& sender_account_keys, bool view_only, light_wallet_client& client, const std::shared_ptr<monero_wallet_cache>& cache): m_nettype(nettype), m_subaddresses(subaddresses), m_sender_account_keys(sender_account_keys), m_view_only(view_only), m_client(client), m_cache(cache) {}

    tools::wallet2::pending_tx build(const uint32_t subaddr_account_idx, const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, bool is_sweeping, uint32_t simple_priority, const std::vector<std::shared_ptr<monero_output_light>>& unspent_outs, uint64_t fee_per_b, uint64_t fee_mask, cryptonote::blobdata& tx_blob, const std::set<uint32_t>& subtract_fee_from = {}) const {
      MTRACE("light_tx_builder::build()");
      if (payment_id_string != boost::none && !payment_id_string->empty()) throw std::runtime_error("Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead");
      boost::optional<uint64_t> prior_fee_attempt;
      boost::optional<monero_output_map> prior_tie_attempt;
      size_t construction_attempt = 0;
      // fee_per_b is already the per-priority rate from get_base_fee(); nothing left to scale
      const uint64_t fee_multiplier = 1;

      // requests decoys and builds the tx, reconstructing with a corrected fee (reusing already-tied decoys)
      // if the actual serialized weight needs more fee than was assumed when selecting inputs.
      // implementation ased mymonero-core-cpp's monero_send_routine.cpp _reenterable_construct_and_send_tx retry loop.
      tools::wallet2::pending_tx ptx;
      while (true) {
        MTRACE("light_tx_builder::build(): attempt " << construction_attempt + 1);
        const auto output_selection = select_outputs(payment_id_string, sending_amounts, is_sweeping, simple_priority, unspent_outs, fee_per_b, fee_mask, prior_fee_attempt, subtract_fee_from, prior_tie_attempt);
        if (output_selection.m_selected_outs.size() == 0) throw std::runtime_error("No output to select");

        const auto decoys = fetch_decoys(output_selection.m_selected_outs, prior_tie_attempt);
        auto tied_outs = monero_outputs_decoys_tie::tie(output_selection.m_selected_outs, decoys, prior_tie_attempt);
        std::vector<size_t> selected_transfers = output_selection.get_output_indexes();
        // re-derived every attempt since output_selection.m_fee can change between retries
        const std::vector<uint64_t> actual_sending_amounts = is_sweeping ? std::vector<uint64_t>{output_selection.m_amount} : get_adjusted_amounts(sending_amounts, subtract_fee_from, output_selection.m_fee);

        ptx = build_pending_tx(subaddr_account_idx, to_address_strings, payment_id_string, actual_sending_amounts, selected_transfers, output_selection.m_change_amount, output_selection.m_fee, output_selection.m_selected_outs, tied_outs.m_decoys);
        tx_blob = cryptonote::tx_to_blob(ptx.tx);
        uint64_t weight = cryptonote::get_transaction_weight(ptx.tx, tx_blob.size());
        uint64_t fee_actually_needed = monero_utils::calculate_fee_from_weight(fee_per_b, weight, fee_multiplier, fee_mask);

        if (fee_actually_needed <= output_selection.m_fee) break;
        if (++construction_attempt > 15) throw std::runtime_error("Unable to construct a transaction with sufficient fee for unknown reason.");

        prior_fee_attempt = fee_actually_needed;
        prior_tie_attempt = tied_outs.m_tie_attempt;
      }

      return ptx;
    }

    // implementation based on monero-project's wallet2::get_tx_proof()
    uint64_t compute_amount_received(const cryptonote::transaction& tx, const crypto::secret_key& tx_key, const std::vector<crypto::secret_key>& additional_tx_keys, const cryptonote::account_public_address& address) const {
      hw::device& hwdev = m_sender_account_keys.get_device();
      const bool is_out = m_subaddresses.find(address.m_spend_public_key) == m_subaddresses.end();

      std::vector<crypto::public_key> shared_secret;
      rct::key aP;
      if (is_out) {
        shared_secret.resize(1 + additional_tx_keys.size());
        hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(tx_key));
        shared_secret[0] = rct::rct2pk(aP);
        for (size_t i = 1; i < shared_secret.size(); ++i) {
          hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
          shared_secret[i] = rct::rct2pk(aP);
        }
      } else {
        crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(tx);
        if (tx_pub_key == crypto::null_pkey) throw std::runtime_error("Tx pubkey was not found");
        std::vector<crypto::public_key> additional_tx_pub_keys = cryptonote::get_additional_tx_pub_keys_from_extra(tx);
        shared_secret.resize(1 + additional_tx_pub_keys.size());
        const crypto::secret_key& a = m_sender_account_keys.m_view_secret_key;
        hwdev.scalarmultKey(aP, rct::pk2rct(tx_pub_key), rct::sk2rct(a));
        shared_secret[0] = rct::rct2pk(aP);
        for (size_t i = 1; i < shared_secret.size(); ++i) {
          hwdev.scalarmultKey(aP, rct::pk2rct(additional_tx_pub_keys[i - 1]), rct::sk2rct(a));
          shared_secret[i] = rct::rct2pk(aP);
        }
      }
      const size_t num_sigs = shared_secret.size();

      crypto::key_derivation derivation;
      if (!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation)) throw std::runtime_error("Failed to generate key derivation");
      std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
      for (size_t i = 1; i < num_sigs; ++i) {
        if (!crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1])) throw std::runtime_error("Failed to generate key derivation");
      }

      uint64_t received = 0;
      for (size_t n = 0; n < tx.vout.size(); ++n) {
        crypto::public_key output_public_key;
        if (!cryptonote::get_output_public_key(tx.vout[n], output_public_key)) continue;

        crypto::key_derivation found_derivation;
        if (is_out_to_acc(address, output_public_key, derivation, additional_derivations, n, cryptonote::get_output_view_tag(tx.vout[n]), found_derivation)) {
          uint64_t amount;
          if (tx.version == 1 || tx.rct_signatures.type == rct::RCTTypeNull) amount = tx.vout[n].amount;
          else {
            // mirrors wallet2.cpp's file-local decodeRct(): derive the per-output scalar first, then
            // decode via decodeRctSimple/decodeRct depending on rct type
            crypto::secret_key scalar1;
            hwdev.derivation_to_scalar(found_derivation, n, scalar1);
            rct::key mask;
            switch (tx.rct_signatures.type) {
              case rct::RCTTypeSimple:
              case rct::RCTTypeBulletproof:
              case rct::RCTTypeBulletproof2:
              case rct::RCTTypeCLSAG:
              case rct::RCTTypeBulletproofPlus:
                amount = rct::decodeRctSimple(tx.rct_signatures, rct::sk2rct(scalar1), n, mask, hwdev);
                break;
              case rct::RCTTypeFull:
                amount = rct::decodeRct(tx.rct_signatures, rct::sk2rct(scalar1), n, mask, hwdev);
                break;
              default:
                amount = 0;
                break;
            }
          }
          received += amount;
        }
      }
      return received;
    }

  private:
    cryptonote::network_type m_nettype;
    const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses;
    const cryptonote::account_keys& m_sender_account_keys;
    bool m_view_only;
    light_wallet_client& m_client;
    std::shared_ptr<monero_wallet_cache> m_cache;

    // validates sender keys
    void validate_keys() const {
      if (m_view_only) {
        if (!m_sender_account_keys.get_device().verify_keys(m_sender_account_keys.m_view_secret_key, m_sender_account_keys.m_account_address.m_view_public_key)) {
          throw std::runtime_error("Invalid view keys");
        }
      }
      else {
        if (!m_sender_account_keys.get_device().verify_keys(m_sender_account_keys.m_spend_secret_key, m_sender_account_keys.m_account_address.m_spend_public_key)
          || !m_sender_account_keys.get_device().verify_keys(m_sender_account_keys.m_view_secret_key, m_sender_account_keys.m_account_address.m_view_public_key)) {
          throw std::runtime_error("Invalid secret keys");
        }
      }
    }

    // validates transfer inputs
    static void validate_transfer(const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, cryptonote::network_type nettype, std::vector<cryptonote::address_parse_info>& infos, std::vector<uint8_t>& extra) {
      if (to_address_strings.empty()) throw std::runtime_error("No destinations for this transfer");
      crypto::hash8 integrated_payment_id = crypto::null_hash8;
      std::string extra_nonce;
      std::vector<cryptonote::address_parse_info> addr_infos(to_address_strings.size());
      size_t to_addr_idx = 0;
      for (const auto& addr : to_address_strings) {
        if (!cryptonote::get_account_address_from_str(addr_infos[to_addr_idx++], nettype, addr)) {
          throw std::runtime_error("Invalid destination address");
        }
      }

      bool payment_id_seen = payment_id_string != boost::none && !payment_id_string->empty();
      for (const auto& info : addr_infos) {
        infos.push_back(info);
        if (!info.has_payment_id) continue;
        if (payment_id_seen || integrated_payment_id != crypto::null_hash8) {
          throw std::runtime_error("A single payment id is allowed per transaction");
        }
        integrated_payment_id = info.payment_id;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, integrated_payment_id);
        if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
          throw std::runtime_error("Something went wrong with integrated payment_id.");
        }
      }

      if (payment_id_seen) throw std::runtime_error("Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead");
    }

    // returns destination amounts adjusted for given fee if subtract_fee_from is enabled
    // implementation based on wallet2's internal TX::get_adjusted_dsts()
    static std::vector<uint64_t> get_adjusted_amounts(const std::vector<uint64_t>& sending_amounts, const std::set<uint32_t>& subtract_fee_from, uint64_t needed_fee) {
      // subtract_fee_from is not enabled or no more remaning needed_fee for this tx
      if (subtract_fee_from.empty() || needed_fee == 0) return sending_amounts;

      uint64_t subtractable_total = 0;
      for (uint32_t idx : subtract_fee_from) {
        if (idx >= sending_amounts.size()) throw std::runtime_error("Invalid destination index to subtract fee from: " + std::to_string(idx));
        subtractable_total += sending_amounts[idx];
      }
      if (subtractable_total < needed_fee) throw std::runtime_error("Destinations selected to subtract fee from are too small to cover the fee");

      std::vector<uint64_t> result = sending_amounts;
      uint64_t remaining = needed_fee;
      auto it = subtract_fee_from.cbegin();
      uint64_t amount_to_subtract = 0;
      while (remaining) {
        // set the amount to subtract iterating at the beginning of the list so equal amounts are
        // subtracted throughout the list of destinations. We use max(x, 1) so that we we still step
        // forwards even when the amount remaining is less than the number of subtractable indices
        if (it == subtract_fee_from.cbegin()) amount_to_subtract = std::max<uint64_t>(remaining / subtract_fee_from.size(), 1);

        uint64_t& amount = result[*it];
        if (amount <= amount_to_subtract) throw std::runtime_error("Subtracting fee from destination would leave it with a zero or negative amount");
        remaining -= amount_to_subtract;
        amount -= amount_to_subtract;
        ++it;

        // wrap around to the first subtractable index once we hit the end of the list
        if (it == subtract_fee_from.cend()) it = subtract_fee_from.cbegin();
      }

      return result;
    }

    // select outputs from get_random_outs request
    // implementation based on mymonero-core-cpp's monero_transfer_utils::send_step1__prepare_params_for_get_decoys()
    static monero_output_selection select_outputs(const boost::optional<std::string>& payment_id, const std::vector<uint64_t>& sending_amounts, bool is_sweeping, uint32_t simple_priority, const std::vector<std::shared_ptr<monero_output_light>> &unspent_outs, uint64_t fee_per_b, uint64_t fee_quantization_mask, boost::optional<uint64_t> prior_fee_attempt, const std::set<uint32_t>& subtract_fee_from, boost::optional<monero_output_map> prior_tie_attempt = boost::none) {
      // validate sending amounts
      if (!is_sweeping) {
        for (uint64_t sending_amount : sending_amounts) {
          if (sending_amount == 0) throw std::runtime_error("entered amount is too low");
        }
      }

      monero_output_selection params;
      params.m_mixin = MIXIN_SIZE;

      std::vector<uint8_t> extra;
      monero_utils::add_pid_to_tx_extra(payment_id, extra);

      const uint64_t base_fee = fee_per_b;
      // fee_per_b is already resolved for this priority tier (see get_base_fee()); no scaling left
      const uint64_t fee_multiplier = 1;

      uint64_t attempt_at_min_fee;
      // use a minimum viable estimate_fee() with 1 input. It would be better to under-shoot this estimate, and then need to use a higher fee  from calculate_fee() because the estimate is too low,
      // versus the worse alternative of over-estimating here and getting stuck using too high of a fee that leads to fingerprinting
      if (prior_fee_attempt == boost::none) attempt_at_min_fee = monero_utils::estimate_fee(1, MIXIN_SIZE, sending_amounts.size() + 1, extra.size(), base_fee, fee_multiplier, fee_quantization_mask);
      else attempt_at_min_fee = *prior_fee_attempt;

      // fee may get changed as follows
      uint64_t sum_sending_amounts;
      uint64_t potential_total; // aka balance_required

      if (is_sweeping) potential_total = sum_sending_amounts = UINT64_MAX; // balance required: all
      else {
        sum_sending_amounts = 0;
        for (uint64_t amount : sending_amounts) sum_sending_amounts += amount;
        // based on wallet2::create_transactions_2(): total_needed_money = needed_money + (subtract_fee_from_outputs.size() ? 0 : min_fee))
        potential_total = sum_sending_amounts + (subtract_fee_from.empty() ? attempt_at_min_fee : 0);
      }

      // Gather outputs and amount to use for getting decoy outputs
      uint64_t selected_outs_amount = 0;
      // take copy so not to modify original
      std::vector<std::shared_ptr<monero_output_light>> remaining_outs = unspent_outs;

      // start by using all the passed in outs that were selected in a prior tx construction attempt
      if (prior_tie_attempt != boost::none) {
        for (size_t i = 0; i < remaining_outs.size(); ) {
          auto &out = remaining_outs[i];
          // search for out by public key to see if it should be re-used in an attempt
          if (prior_tie_attempt->find(out->m_public_key.get()) != prior_tie_attempt->end()) {
            selected_outs_amount += out->m_amount.get();
            // pop_index swaps the last element into index i, so re-check the same index rather than advancing
            params.m_selected_outs.push_back(std::move(gen_utils::pop_index(remaining_outs, i)));
          } else {
            ++i;
          }
        }
      }

      while (selected_outs_amount < potential_total && remaining_outs.size() > 0) {
        if (is_sweeping && !params.m_selected_outs.empty()) {
          const uint64_t estimated_weight = monero_utils::estimate_tx_weight(boost::numeric_cast<int>(params.m_selected_outs.size() + 1), MIXIN_SIZE, 1, extra.size());
          // stop pulling in more outputs once the tx would exceed a safe weight margin
          // based on wallet2.cpp's TX_WEIGHT_TARGET
          if (estimated_weight >= monero_utils::get_tx_weight_limit() * 2 / 3) break;
        }

        auto out = gen_utils::pop_random_value(remaining_outs);
        if (out->m_amount.get() < DUST_THRESHOLD && !out->is_rct()) {
          // unmixable (non-rct) dusty output
          continue;
        }
        selected_outs_amount += out->m_amount.get();
        params.m_selected_outs.push_back(std::move(out));
      }

      //if (/*selected_outs.size() > 1*/) FIXME? see original mymonero core js
      uint64_t needed_fee = monero_utils::estimate_fee(params.m_selected_outs.size(), MIXIN_SIZE, sending_amounts.size() + 1, extra.size(), base_fee, fee_multiplier, fee_quantization_mask);

      // if newNeededFee < neededFee, use neededFee instead (should only happen on the 2nd or later times through (due to estimated fee being too low))
      if (prior_fee_attempt != boost::none && needed_fee < attempt_at_min_fee) needed_fee = attempt_at_min_fee;

      // NOTE: needed_fee may get further modified below when !is_sweeping if selected_outs_amount < total_incl_fees and gets finalized (for this function's scope) as fee
      uint64_t total_wo_fee = is_sweeping ? /*now that we know outsAmount>needed_fee*/(selected_outs_amount - needed_fee) : sum_sending_amounts;
      params.m_amount = total_wo_fee;

      uint64_t total_incl_fees;
      if (is_sweeping) {
        if (selected_outs_amount < needed_fee) {
          // like checking if the result of the following total_wo_fee is < 0
          // sufficiently up-to-date (for this return case) required_balance and selected_outs_amount (spendable balance) will have been stored for return by this point
          throw std::runtime_error("need more money than found; sweeping, selected_outs_amount: " + std::to_string(selected_outs_amount) + ", needed_fee: " + std::to_string(needed_fee));
        }

        total_incl_fees = selected_outs_amount;
      } else {
        // because fee changed because selected_outs.size() was updated
        total_incl_fees = sum_sending_amounts + (subtract_fee_from.empty() ? needed_fee : 0);
        while (selected_outs_amount < total_incl_fees && remaining_outs.size() > 0) {
          // add outputs 1 at a time till we either have them all or can meet the fee
          {
            auto out = gen_utils::pop_random_value(remaining_outs);
            selected_outs_amount += out->m_amount.get();
            params.m_selected_outs.push_back(std::move(out));
          }

          {
            // based on wallet2::create_transactions_2()
            const uint64_t estimated_weight = monero_utils::estimate_tx_weight(boost::numeric_cast<int>(params.m_selected_outs.size()), MIXIN_SIZE, sending_amounts.size() + 1, extra.size());
            if (estimated_weight >= monero_utils::get_tx_weight_limit() * 2 / 3) {
              throw std::runtime_error("Too many small outputs are needed to cover this amount in a single transaction: consolidate the wallet's outputs first.");
            }
          }

          // recalculate fee, total including fees
          needed_fee = monero_utils::estimate_fee(params.m_selected_outs.size(), MIXIN_SIZE, sending_amounts.size() + 1, extra.size(), base_fee, fee_multiplier, fee_quantization_mask);
          // because fee changed
          total_incl_fees = sum_sending_amounts + (subtract_fee_from.empty() ? needed_fee : 0);
        }
      }

      params.m_fee = needed_fee;

      if (selected_outs_amount < total_incl_fees) {
        // sufficiently up-to-date (for this return case) required_balance and selected_outs_amount (spendable balance) will have been stored for return by this point.
        throw std::runtime_error("need more money than found; selected_outs_amount: " + std::to_string(selected_outs_amount) + ", total_incl_fees: " + std::to_string(total_incl_fees) + ", needed_fee: " + std::to_string(needed_fee));
      }

      // change can now be calculated
      uint64_t change_amount = 0; // to initialize
      if (selected_outs_amount > total_incl_fees) {
        if (is_sweeping) throw std::runtime_error("Unexpected total_incl_fees > selected_outs_amount while sweeping");
        change_amount = selected_outs_amount - total_incl_fees;
      }

      params.m_change_amount = change_amount;
      return params;
    }

    // get random outputs
    std::vector<std::shared_ptr<monero_random_outputs>> fetch_decoys(const std::vector<std::shared_ptr<monero_output_light>> &selected_outs, const boost::optional<monero_output_map>& prior_attempt) const {
      // request decoys for any newly selected inputs
      std::vector<std::shared_ptr<monero_output_light>> decoy_requests;
      if (prior_attempt != boost::none) {
        for (size_t i = 0; i < selected_outs.size(); ++i) {
          // only need to request decoys for outs that were not already passed in
          if (prior_attempt->find(*selected_outs[i]->m_public_key) == prior_attempt->end()) {
            decoy_requests.push_back(selected_outs[i]);
          }
        }
      } else decoy_requests = selected_outs;

      std::vector<uint64_t> decoy_amounts;
      for (auto &using_out : decoy_requests) {
        if (using_out->is_rct()) decoy_amounts.push_back(0);
        else {
          MDEBUG("pushing decoy request amount: " << using_out->m_amount.get());
          decoy_amounts.push_back(using_out->m_amount.get());
        }
      }

      return m_client.get_random_outs(decoy_amounts, MIXIN_SIZE + 1)->m_amount_outs;
    }

    // resolves each spendable output (plus its decoys) to a cryptonote::tx_source_entry, and tallies
    // found_money / the spent key images along the way
    std::vector<cryptonote::tx_source_entry> prepare_sources(const std::vector<std::shared_ptr<monero_output_light>> &outputs, std::vector<std::shared_ptr<monero_random_outputs>> &mix_outs, const std::vector<uint8_t>& extra, uint64_t& found_money, std::string& spent_key_images) const {
      std::vector<cryptonote::tx_source_entry> sources;
      LOG_PRINT_L2("preparing outputs");
      for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
        found_money += outputs[out_index]->m_amount.get();
        if (found_money > UINT64_MAX) throw std::runtime_error("input amount overflow");

        auto src = cryptonote::tx_source_entry{};
        src.amount = outputs[out_index]->m_amount.get();
        src.rct = outputs[out_index]->is_rct();

        typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
        if (mix_outs.size() != 0) {
          // sort fake outputs by global index
          std::sort(mix_outs.at(out_index)->m_outputs.begin(), mix_outs.at(out_index)->m_outputs.end(), [] (
            std::shared_ptr<monero_output_light> const& a,
            std::shared_ptr<monero_output_light> const& b
          ) { return a->m_global_index.get() < b->m_global_index.get(); });

          for (size_t j = 0; src.outputs.size() < MIXIN_SIZE && j < mix_outs[out_index]->m_outputs.size(); j++) {
            auto mix_out__output = mix_outs[out_index]->m_outputs[j];
            if (mix_out__output->m_global_index == outputs[out_index]->m_global_index) {
              MDEBUG("got mixin the same as output, skipping");
              continue;
            }
            auto oe = tx_output_entry{};
            oe.first = mix_out__output->m_global_index.get();

            crypto::public_key public_key = AUTO_VAL_INIT(public_key);
            if (!epee::string_tools::hex_to_pod(*mix_out__output->m_public_key, public_key)) throw std::runtime_error("given an invalid public key");
            oe.second.dest = rct::pk2rct(public_key);

            if (mix_out__output->is_rct()) {
              rct::key commit;
              monero_utils::rct_hex_to_rct_commit(mix_out__output->m_rct.get(), commit);
              oe.second.mask = commit;
            } else {
              if (outputs[out_index]->is_rct()) throw std::runtime_error("mix RCT outs missing commit");
              // create identity-masked commitment for non-rct mix input
              oe.second.mask = rct::zeroCommit(src.amount);
            }

            src.outputs.push_back(oe);
          }
        }

        auto real_oe = tx_output_entry{};
        real_oe.first = outputs[out_index]->m_global_index.get();

        crypto::public_key public_key = AUTO_VAL_INIT(public_key);
        if (!epee::string_tools::validate_hex(64, *outputs[out_index]->m_public_key)) throw std::runtime_error("given an invalid public key");
        if (!epee::string_tools::hex_to_pod(*outputs[out_index]->m_public_key, public_key)) throw std::runtime_error("given an invalid public key");
        real_oe.second.dest = rct::pk2rct(public_key);

        if (outputs[out_index]->is_rct() && !outputs[out_index]->is_coinbase()) {
          rct::key commit;
          monero_utils::rct_hex_to_rct_commit(outputs[out_index]->m_rct.get(), commit);
          // add commitment for real input
          real_oe.second.mask = commit;
        } else {
          // create identity-masked commitment for non-rct input
          real_oe.second.mask = rct::zeroCommit(src.amount/*aka outputs[out_index].amount*/);
        }

        // add real_oe to outputs
        uint64_t real_output_index = src.outputs.size();
        for (size_t j = 0; j < src.outputs.size(); j++) {
          if (real_oe.first < src.outputs[j].first) {
            real_output_index = j;
            break;
          }
        }
        src.outputs.insert(src.outputs.begin() + real_output_index, real_oe);
        crypto::public_key tx_pub_key = AUTO_VAL_INIT(tx_pub_key);
        if (!epee::string_tools::validate_hex(64, *outputs[out_index]->m_tx_pub_key)) throw std::runtime_error("given an invalid public key");

        epee::string_tools::hex_to_pod(*outputs[out_index]->m_tx_pub_key, tx_pub_key);
        src.real_out_tx_key = tx_pub_key;
        src.real_out_additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(extra);
        src.real_output = real_output_index;
        uint64_t internal_output_index = *outputs[out_index]->m_index;
        src.real_output_in_tx_index = internal_output_index;

        src.rct = outputs[out_index]->is_rct();
        if (src.rct) {
          rct::key decrypted_mask;
          bool r = monero_utils::rct_hex_to_decrypted_mask(outputs[out_index]->m_rct.get(), m_sender_account_keys.m_view_secret_key, tx_pub_key, internal_output_index, decrypted_mask);
          if (!r) throw std::runtime_error("can't get decrypted mask from RCT hex");
          src.mask = decrypted_mask;

          rct::key calculated_commit = rct::commit(outputs[out_index]->m_amount.get(), decrypted_mask);
          if (!(real_oe.second.mask == calculated_commit)) throw std::runtime_error("rct commit hash mismatch");
        } else {
          // in the original cn_utils impl this was left as null for generate_key_image_helper_rct to fill in with identity I
          rct::identity(src.mask);
        }

        // not doing multisig here yet
        src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
        sources.push_back(src);
        auto& key_image = outputs[out_index]->m_key_image;
        if (key_image != boost::none && !key_image->empty()) spent_key_images += key_image.get() + " ";
      }

      LOG_PRINT_L2("outputs prepared");
      return sources;
    }

    // builds the destination list (recipients + change), matching wallet2's decompose logic for a 0 change amount
    std::vector<cryptonote::tx_destination_entry> prepare_destinations(const std::vector<cryptonote::address_parse_info>& to_addrs, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, cryptonote::tx_destination_entry& change_dst, uint32_t subaddr_account_idx) const {
      // TODO: if this is a multisig wallet, create a list of multisig signers we can use
      std::vector<cryptonote::tx_destination_entry> splitted_dsts;
      if (to_addrs.size() != sending_amounts.size()) throw std::runtime_error("Amounts don't match destinations");
      for (size_t i = 0; i < to_addrs.size(); ++i) {
        cryptonote::tx_destination_entry to_dst = AUTO_VAL_INIT(to_dst);
        to_dst.addr = to_addrs[i].address;
        to_dst.amount = sending_amounts[i];
        to_dst.is_subaddress = to_addrs[i].is_subaddress;
        splitted_dsts.push_back(to_dst);
      }

      change_dst = cryptonote::tx_destination_entry{};
      change_dst.amount = change_amount;
      if (change_dst.amount == 0) {
        if (splitted_dsts.size() == 1) {
          // if the change is 0, send it to a random address, to avoid confusing
          // the sender with a 0 amount output. We send a 0 amount in order to avoid
          // letting the destination be able to work out which of the inputs is the
          // real one in our rings
          LOG_PRINT_L2("generating dummy address for 0 change");
          cryptonote::account_base dummy;
          dummy.generate();
          change_dst.addr = dummy.get_keys().m_account_address;
          LOG_PRINT_L2("generated dummy address for 0 change");
          splitted_dsts.push_back(change_dst);
        }
      } else {
        change_dst.addr = m_sender_account_keys.get_device().get_subaddress(m_sender_account_keys, {subaddr_account_idx, 0});
        splitted_dsts.push_back(change_dst);
      }

      return splitted_dsts;
    }

    // calls into cryptonote to sign the sources/destinations into an actual transaction, and packs
    // the result plus its construction data into a pending_tx
    tools::wallet2::pending_tx construct_pending_tx(std::vector<cryptonote::tx_source_entry>& sources, std::vector<cryptonote::tx_destination_entry>& splitted_dsts, cryptonote::tx_destination_entry& change_dst, std::vector<uint8_t>& extra, uint64_t fee_amount, std::vector<size_t>& selected_transfers, uint32_t subaddr_account_idx, const std::vector<std::shared_ptr<monero_output_light>> &outputs, const std::string& spent_key_images) const {
      cryptonote::transaction tx;
      crypto::secret_key tx_key;
      std::vector<crypto::secret_key> additional_tx_keys;

      // build a subaddress map scoped to just this tx (change address plus each spent output's
      // subaddress) rather than passing the wallet-wide m_subaddresses cache: construct_tx_and_get_tx_key()
      // only looks up the change destination and each real input, so this doesn't depend on
      // process_subaddresses() having already processed these indices
      hw::device& hwdev = m_sender_account_keys.get_device();
      serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index> tx_subaddresses;
      const auto add_subaddress = [&](uint32_t major, uint32_t minor) {
        const crypto::public_key spend_public_key = (major == 0 && minor == 0)
          ? m_sender_account_keys.m_account_address.m_spend_public_key
          : hwdev.get_subaddress_spend_public_key(m_sender_account_keys, {major, minor});
        tx_subaddresses[spend_public_key] = {major, minor};
      };
      add_subaddress(subaddr_account_idx, 0); // change always returns here, even if no selected output uses this index

      std::set<uint32_t> subaddr_indices;
      for (const auto& selected_out : outputs) {
        if (selected_out->m_recipient->m_maj_i != subaddr_account_idx) continue;
        const uint32_t minor = selected_out->m_recipient->m_min_i;
        if (subaddr_indices.insert(minor).second) add_subaddress(subaddr_account_idx, minor); // derive once per distinct minor index
      }

      const rct::RCTConfig rct_config {rct::RangeProofPaddedBulletproof, BULLETPROOF_VERSION};
      LOG_PRINT_L2("constructing tx");
      bool r = cryptonote::construct_tx_and_get_tx_key(m_sender_account_keys, tx_subaddresses, sources, splitted_dsts, change_dst.addr, extra, tx, tx_key, additional_tx_keys, true, rct_config, true);

      LOG_PRINT_L2("constructed tx, r=" << r);
      if (!r) throw std::runtime_error("transaction was not constructed");
      monero_utils::validate_cn_tx(tx);

      tools::wallet2::pending_tx ptx;
      ptx.key_images = spent_key_images;
      ptx.dust = 0;
      ptx.dust_added_to_fee = false;
      ptx.tx = tx;
      ptx.change_dts = change_dst;
      ptx.tx_key = tx_key;
      ptx.additional_tx_keys = additional_tx_keys;
      ptx.fee = fee_amount;
      ptx.dests = splitted_dsts;
      ptx.selected_transfers = selected_transfers;
      ptx.construction_data.sources = sources;
      ptx.construction_data.change_dts = change_dst;
      ptx.construction_data.splitted_dsts = splitted_dsts;
      ptx.construction_data.selected_transfers = selected_transfers;
      ptx.construction_data.extra = tx.extra;
      ptx.construction_data.unlock_time = 0;
      ptx.construction_data.use_rct = true;
      ptx.construction_data.rct_config = rct_config;
      ptx.construction_data.use_view_tags = true;
      ptx.construction_data.dests = splitted_dsts;
      // record which subaddress indices are being used as inputs
      ptx.construction_data.subaddr_account = subaddr_account_idx;
      ptx.construction_data.subaddr_indices = std::move(subaddr_indices);

      LOG_PRINT_L2("transfer_selected_rct done");
      return ptx;
    }

    tools::wallet2::pending_tx build_pending_tx(const uint32_t subaddr_account_idx, const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, std::vector<size_t>& selected_transfers, uint64_t change_amount, uint64_t fee_amount, const std::vector<std::shared_ptr<monero_output_light>> &outputs, std::vector<std::shared_ptr<monero_random_outputs>> &mix_outs) const {
      std::vector<uint8_t> extra;
      std::vector<cryptonote::address_parse_info> to_addrs;
      validate_transfer(to_address_strings, payment_id_string, m_nettype, to_addrs, extra);
      // TODO: do we need to sort destinations by amount, here, according to 'decompose_destinations'?
      if (mix_outs.size() != outputs.size()) throw std::runtime_error("wrong number of mix outs provided: " + std::to_string(mix_outs.size()) + ", outputs: " + std::to_string(outputs.size()));
      for (size_t i = 0; i < mix_outs.size(); i++) {
        if (mix_outs[i]->m_outputs.size() < MIXIN_SIZE) throw std::runtime_error("not enough outputs for mixing");
      }

      validate_keys();

      uint64_t needed_money = fee_amount + change_amount;
      for (uint64_t amount : sending_amounts) {
        needed_money += amount;
        if (needed_money < amount) throw std::runtime_error("transaction sum + fee exceeds " + cryptonote::print_money(std::numeric_limits<uint64_t>::max()));
      }

      uint64_t found_money = 0;
      std::string spent_key_images;
      std::vector<cryptonote::tx_source_entry> sources = prepare_sources(outputs, mix_outs, extra, found_money, spent_key_images);

      cryptonote::tx_destination_entry change_dst = AUTO_VAL_INIT(change_dst);
      std::vector<cryptonote::tx_destination_entry> splitted_dsts = prepare_destinations(to_addrs, sending_amounts, change_amount, change_dst, subaddr_account_idx);

      if (found_money > needed_money) {
        if (change_dst.amount != fee_amount) throw std::runtime_error("result fee not equal to given");
      }
      else if (found_money < needed_money) throw std::runtime_error("need more money than found; found_money: " + std::to_string(found_money) + ", needed_money: " + std::to_string(needed_money));

      if (sources.empty()) throw std::runtime_error("sources is empty");

      tools::wallet2::pending_tx ptx = construct_pending_tx(sources, splitted_dsts, change_dst, extra, fee_amount, selected_transfers, subaddr_account_idx, outputs, spent_key_images);
      sanity_check(ptx, to_addrs, sending_amounts);
      return ptx;
    }

    // checks whether an output at output_index was sent to address.
    // implementation based on monero-project's wallet2::is_out_to_acc().
    static bool is_out_to_acc(const cryptonote::account_public_address& address, const crypto::public_key& out_key, const crypto::key_derivation& derivation, const std::vector<crypto::key_derivation>& additional_derivations, const size_t output_index, const boost::optional<crypto::view_tag>& view_tag_opt, crypto::key_derivation& found_derivation) {
      crypto::public_key derived_out_key;
      bool found = false;

      if (cryptonote::out_can_be_to_acc(view_tag_opt, derivation, output_index)) {
        if (!crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, derived_out_key)) throw std::runtime_error("Failed to derive public key");
        if (out_key == derived_out_key) {
          found = true;
          found_derivation = derivation;
        }
      }

      if (!found && !additional_derivations.empty()) {
        const crypto::key_derivation& additional_derivation = additional_derivations[output_index];
        if (cryptonote::out_can_be_to_acc(view_tag_opt, additional_derivation, output_index)) {
          if (!crypto::derive_public_key(additional_derivation, output_index, address.m_spend_public_key, derived_out_key)) throw std::runtime_error("Failed to derive public key");
          if (out_key == derived_out_key) {
            found = true;
            found_derivation = additional_derivation;
          }
        }
      }

      return found;
    }

    // catches integrated address built from a subaddress (see https://github.com/monero-project/monero/issues/8380).
    // implementation based on wallet2::sanity_check().
    void sanity_check(const tools::wallet2::pending_tx& ptx, const std::vector<cryptonote::address_parse_info>& to_addrs, const std::vector<uint64_t>& sending_amounts) const {
      if (to_addrs.size() != sending_amounts.size()) throw std::runtime_error("Amounts don't match destinations");
      for (size_t i = 0; i < to_addrs.size(); ++i) {
        uint64_t received = compute_amount_received(ptx.tx, ptx.tx_key, ptx.additional_tx_keys, to_addrs[i].address);
        if (received < sending_amounts[i]) {
          throw std::runtime_error("Total received by " + cryptonote::get_account_address_as_str(m_nettype, to_addrs[i].is_subaddress, to_addrs[i].address) +
            ": " + cryptonote::print_money(received) + ", expected " + cryptonote::print_money(sending_amounts[i]));
        }
      }
    }
  };

  // ----------------------------- WALLET LISTENER ----------------------------

  /**
   * Notifies external wallet listeners of monero_wallet_light activity.
   */
  struct light_wallet_listener {

  public:

    /**
     * Constructs the listener.
     *
     * @param wallet provides context to notify external listeners
     */
    light_wallet_listener(monero_wallet_light& wallet) : m_wallet(wallet) {
      this->m_sync_start_height = boost::none;
      this->m_sync_end_height = boost::none;
      m_prev_balance = wallet.get_balance();
      m_prev_unlocked_balance = wallet.get_unlocked_balance();
      m_notification_pool = std::unique_ptr<tools::threadpool>(tools::threadpool::getNewForUnitTests(1));  // TODO (monero-project): utility can be for general use
    }

    ~light_wallet_listener() {
      MTRACE("~light_wallet_listener()");
      m_notification_pool->recycle();
    }

    void on_sync_start(uint64_t start_height) {
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, start_height]() {
        if (m_sync_start_height != boost::none || m_sync_end_height != boost::none) throw std::runtime_error("Sync start or end height should not already be allocated, is previous sync in progress?");
        m_sync_start_height = start_height;
        m_sync_end_height = m_wallet.get_daemon_height();
      });
      waiter.wait(); // TODO: this processes notification on thread, process off thread
    }

    void on_sync_end() {
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this]() {
        check_for_changed_balances();
        check_for_changed_txs();
        m_sync_start_height = boost::none;
        m_sync_end_height = boost::none;
      });
      m_notification_pool->recycle();
      waiter.wait();
    }

    void on_new_block(uint64_t height) {
      if (m_wallet.get_listeners().empty()) return;

      // ignore notifications before sync start height, irrelevant to clients
      if (m_sync_start_height == boost::none || height < *m_sync_start_height) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height]() {

        // notify listeners of new block
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_new_block(height);
        }

        // notify listeners of sync progress
        if (height >= *m_sync_end_height) m_sync_end_height = height + 1; // increase end height if necessary
        double percent_done = (double) (height - *m_sync_start_height + 1) / (double) (*m_sync_end_height - *m_sync_start_height);
        std::string message = std::string("Synchronizing");
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_sync_progress(height, *m_sync_start_height, *m_sync_end_height, percent_done, message);
        }
      });
      waiter.wait();
    }

    void on_spend_tx_hashes(const std::vector<std::string>& tx_hashes) {
      if (m_wallet.get_listeners().empty()) return;
      monero_tx_query tx_query;
      tx_query.m_hashes = tx_hashes;
      tx_query.m_include_outputs = true;
      tx_query.m_is_locked = true;
      on_spend_txs(m_wallet.get_txs(tx_query));
    }

    void on_spend_txs(const std::vector<std::shared_ptr<monero_tx_wallet>>& txs) {
      if (m_wallet.get_listeners().empty()) return;
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, txs]() {
        check_for_changed_balances();
        for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
          notify_outputs(tx);

          // seed tracking state so the next on_sync_end() diff doesn't re-notify this tx as "new"
          if (tx->m_hash != boost::none) {
            m_prev_known_tx_hashes.insert(tx->m_hash.get());
            if (tx->m_is_locked.value_or(true)) m_prev_locked_tx_hashes.insert(tx->m_hash.get());
          }
        }
      });
      waiter.wait();
    }

  private:
    monero_wallet_light& m_wallet; // wallet to provide context for notifications
    boost::optional<uint64_t> m_sync_start_height;
    boost::optional<uint64_t> m_sync_end_height;
    uint64_t m_prev_balance;
    uint64_t m_prev_unlocked_balance;
    std::set<std::string> m_prev_known_tx_hashes;            // txs seen as of the last diff, to detect newly-appeared ones
    std::set<std::string> m_prev_locked_tx_hashes;           // locked txs seen as of the last diff, to detect newly-unlocked ones
    std::unique_ptr<tools::threadpool> m_notification_pool;  // threadpool of size 1 to queue notifications for external announcement

    bool check_for_changed_balances() {
      uint64_t balance = m_wallet.get_balance();
      uint64_t unlocked_balance = m_wallet.get_unlocked_balance();
      if (balance != m_prev_balance || unlocked_balance != m_prev_unlocked_balance) {
        m_prev_balance = balance;
        m_prev_unlocked_balance = unlocked_balance;
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_balances_changed(balance, unlocked_balance);
        }
        return true;
      }
      return false;
    }

    void check_for_changed_txs() {
      if (m_wallet.get_listeners().empty()) return;

      // get recent txs to check for new or newly-unlocked activity
      monero_tx_query query = monero_tx_query();
      query.m_include_outputs = true;
      uint64_t height = m_wallet.get_height();
      query.m_min_height = height >= 70 ? height - 70 : 0; // only monitor recent txs
      std::vector<std::shared_ptr<monero_tx_wallet>> recent_txs = m_wallet.get_txs(query);

      std::set<std::string> current_tx_hashes;
      std::set<std::string> current_locked_tx_hashes;
      std::vector<std::shared_ptr<monero_tx_wallet>> txs_to_notify;

      for (const std::shared_ptr<monero_tx_wallet>& tx : recent_txs) {
        const std::string& hash = tx->m_hash.get();
        bool locked = tx->m_is_locked.value_or(false);
        current_tx_hashes.insert(hash);
        if (locked) current_locked_tx_hashes.insert(hash);

        bool is_new = m_prev_known_tx_hashes.find(hash) == m_prev_known_tx_hashes.end();
        bool newly_unlocked = !locked && m_prev_locked_tx_hashes.find(hash) != m_prev_locked_tx_hashes.end();
        if (is_new || newly_unlocked) txs_to_notify.push_back(tx);
      }

      for (const std::shared_ptr<monero_tx_wallet>& tx : txs_to_notify) notify_outputs(tx);

      m_prev_known_tx_hashes = current_tx_hashes;
      m_prev_locked_tx_hashes = current_locked_tx_hashes;

      // free memory
      monero_utils::free(recent_txs);
    }

    void notify_outputs(const std::shared_ptr<monero_tx_wallet>& tx) {

      // notify spent outputs
      if (tx->m_outgoing_transfer != nullptr) {

        // build dummy input for notification // TODO: this provides one input with outgoing amount like monero-wallet-rpc client, use real inputs instead
        std::shared_ptr<monero_output_wallet> input = std::make_shared<monero_output_wallet>();
        input->m_amount = tx->m_outgoing_transfer->m_amount.get() + tx->m_fee.get();
        input->m_account_index = tx->m_outgoing_transfer->m_account_index;
        if (tx->m_outgoing_transfer->m_subaddress_indices.size() == 1) input->m_subaddress_index = tx->m_outgoing_transfer->m_subaddress_indices[0]; // initialize if transfer sourced from single subaddress
        std::shared_ptr<monero_tx_wallet> tx_notify = std::make_shared<monero_tx_wallet>();
        input->m_tx = tx_notify;
        tx_notify->m_inputs.push_back(input);
        tx_notify->m_hash = tx->m_hash;
        tx_notify->m_is_locked = tx->m_is_locked;
        tx_notify->m_unlock_time = tx->m_unlock_time;
        if (tx->m_block != nullptr) {
          std::shared_ptr<monero_block> block_notify = std::make_shared<monero_block>();
          tx_notify->m_block = block_notify;
          block_notify->m_height = tx->get_height();
          block_notify->m_txs.push_back(tx_notify);
        }

        // notify listeners and free memory
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) listener->on_output_spent(*input);
        monero_utils::free(tx_notify);
      }

      // notify received outputs
      if (!tx->m_incoming_transfers.empty()) {
        for (const std::shared_ptr<monero_output_wallet>& output : tx->get_outputs_wallet()) {
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) listener->on_output_received(*output);
        }
      }
    }
  };

  // ----------------------------- WALLET METHODS -----------------------------

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close(false);
  }

  monero_wallet_light::monero_wallet_light(const std::shared_ptr<monero_rpc_connection>& rpc_connection): m_rpc(rpc_connection) {
    if (rpc_connection == nullptr) throw monero_error("Connection cannot be null");
    if (!rpc_connection->is_online().value_or(false) && rpc_connection->m_uri != boost::none) rpc_connection->check_connection();
  }

  monero_wallet_light::monero_wallet_light(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy_uri, const std::string& zmq_uri, const boost::optional<uint32_t>& timeout): m_rpc(std::make_shared<monero_rpc_connection>(uri, username, password, proxy_uri, zmq_uri, 0, timeout)) {
    if (m_rpc->m_uri != boost::none) m_rpc->check_connection();
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    assert_not_closed();
    try {
      m_is_connected = m_client->is_connected();
    } catch (const std::exception& e) {
      m_is_connected = false;
    }
    return m_is_connected;
  }

  uint64_t monero_wallet_light::get_daemon_height() const {
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    auto status = m_client->get_daemon_status();
    if (status->m_height == boost::none) throw std::runtime_error("Failed to get daemon height");
    return status->m_height.get();
  }

  uint64_t monero_wallet_light::get_daemon_max_peer_height() const {
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    auto status = m_client->get_daemon_status();
    if (status->m_target_height == boost::none) throw std::runtime_error("Failed to get daemon max peer height");
    uint64_t result = status->m_target_height.get();
    if (result == 0) {
      // target height can be 0 when daemon is synced
      if (status->m_height == boost::none) throw std::runtime_error("Failed to get daemon max peer height");
      result = status->m_height.get();
    }
    return result;
  }

  void monero_wallet_light::add_listener(monero_wallet_listener& listener) {
    assert_not_closed();
    m_listeners.insert(&listener);
  }

  void monero_wallet_light::remove_listener(monero_wallet_listener& listener) {
    assert_not_closed();
    m_listeners.erase(&listener);
  }

  std::set<monero_wallet_listener*> monero_wallet_light::get_listeners() {
    assert_not_closed();
    return m_listeners;
  }

  monero_sync_result monero_wallet_light::sync() {
    MTRACE("monero_wallet_light::sync()");
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return lock_and_sync();
  }

  monero_sync_result monero_wallet_light::sync(monero_wallet_listener& listener) {
    MTRACE("monero_wallet_light::sync(listener)");
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // register listener
    add_listener(listener);

    // sync wallet
    monero_sync_result result = lock_and_sync(boost::none);

    // unregister listener
    remove_listener(listener);

    // return sync result
    return result;
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
    MTRACE("monero_wallet_light::sync(" << start_height << ")");
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return lock_and_sync(start_height);
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height, monero_wallet_listener& listener) {
    MTRACE("monero_wallet_light::sync(" << start_height << ", listener)");
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // wrap and register sync listener as wallet listener
    add_listener(listener);

    // sync wallet
    monero_sync_result result = lock_and_sync(start_height);

    // unregister sync listener
    remove_listener(listener);

    // return sync result
    return result;
  }

  void monero_wallet_light::start_syncing(uint64_t sync_period_in_ms) {
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    m_syncing_interval = sync_period_in_ms;
    if (!m_syncing_enabled) {
      m_syncing_enabled = true;
      run_sync_loop(); // sync wallet on loop in background
    }
  }

  void monero_wallet_light::stop_syncing() {
    assert_not_closed();
    m_syncing_enabled = false;
  }

  void monero_wallet_light::scan_txs(const std::vector<std::string>& tx_ids) {
    assert_not_closed();
    sync();
  }

  bool monero_wallet_light::is_daemon_synced() const {
    assert_not_closed();
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return true;
  }

  bool monero_wallet_light::is_daemon_trusted() const {
    assert_not_closed();
    return true;
  }

  bool monero_wallet_light::is_synced() const {
    assert_not_closed();
    if (!is_connected_to_daemon()) return false;
    if (m_cache->get_blockchain_height() <= 1) return false;
    return m_cache->get_scanned_block_height() == m_cache->get_blockchain_height();
  }

  monero_subaddress monero_wallet_light::get_address_index(const std::string& address) const {
    MTRACE("monero_wallet_light::get_address_index(" << address << ")");
    assert_not_closed();
    // validate address
    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, static_cast<cryptonote::network_type>(m_network_type), address)) {
      throw std::runtime_error("Invalid address");
    }

    sync_op_lock op_lock(*this); // do not read m_subaddresses while the sync thread is upserting into it
    // get index of address in wallet
    auto index = m_subaddresses.find(info.address.m_spend_public_key);
    if (index == m_subaddresses.end()) throw std::runtime_error("Address doesn't belong to the wallet");

    // return indices in subaddress
    monero_subaddress subaddress;
    cryptonote::subaddress_index cn_index = index->second;
    subaddress.m_account_index = cn_index.major;
    subaddress.m_index = cn_index.minor;
    return subaddress;
  }

  uint64_t monero_wallet_light::get_height() const {
    assert_not_closed();
    return m_cache->get_scanned_block_height() + 1;
  }

  void monero_wallet_light::set_restore_height(uint64_t restore_height) {
    assert_not_closed();
    auto response = m_client->import_request(restore_height);
    if (response->m_import_fee != boost::none && response->m_import_fee.get() > 0) {
      throw std::runtime_error("Payment is required to rescan blockchain: address " + response->m_payment_address.get() + ", amount " + std::to_string(response->m_import_fee.get()));
    }
    // only update the cache once the server confirms the import took effect; otherwise wait for refresh()
    if (response->m_request_fullfilled != boost::none && response->m_request_fullfilled.get()) {
      m_cache->set_start_height(restore_height);
    }
  }

  uint64_t monero_wallet_light::get_restore_height() const {
    assert_not_closed();
    uint64_t height = m_cache->get_start_height();
    // m_start_height is only known after refresh() processes a get_address_info response, and
    // login()'s response doesn't carry it on monero-lws; fetch it directly the first time instead
    // of reporting an unset cache as height 0
    if (height == 0 && m_is_connected) {
      try {
        auto addr_info = m_client->get_address_info();
        if (addr_info->m_start_height != boost::none) {
          height = addr_info->m_start_height.get();
          m_cache->set_start_height(height);
        }
      } catch (const std::exception&) {
        // fall through with height == 0 (unknown, or genuinely genesis)
      }
    }
    return height == 0 ? 0 : height + 1;
  }

  uint64_t monero_wallet_light::get_balance() const {
    assert_not_closed();
    return m_cache->get_balance();
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_index) const {
    assert_not_closed();
    return m_cache->get_balance(account_index);
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    assert_not_closed();
    return m_cache->get_balance(account_idx, subaddress_idx);
  }

  uint64_t monero_wallet_light::get_unlocked_balance() const {
    assert_not_closed();
    return m_cache->get_unlocked_balance();
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_index) const {
    assert_not_closed();
    return m_cache->get_unlocked_balance(account_index);
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    assert_not_closed();
    return m_cache->get_unlocked_balance(account_idx, subaddress_idx);
  }

  std::vector<monero_account> monero_wallet_light::get_accounts(bool include_subaddresses, const std::string& tag) const {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not read m_subaddrs while the sync thread is reassigning it
    std::vector<monero_account> result;
    bool default_found = false;

    if (m_subaddrs.m_all_subaddrs != nullptr) {
      for (const auto& kv : *m_subaddrs.m_all_subaddrs) {
        if (kv.first == 0) default_found = true;
        monero_account account = get_account(kv.first, include_subaddresses);
        result.push_back(account);
      }
    }

    if (!default_found) {
      monero_account primary_account = get_account(0, include_subaddresses);
      result.push_back(primary_account);
    }

    return result;
  }

  monero_account monero_wallet_light::get_account(const uint32_t account_idx, bool include_subaddresses) const {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not read m_subaddrs while the sync thread is reassigning it
    if (account_idx != 0 && (m_subaddrs.m_all_subaddrs == nullptr || m_subaddrs.m_all_subaddrs->empty())) throw std::runtime_error("Account out of bounds");
    if (m_subaddrs.m_all_subaddrs != nullptr && !m_subaddrs.m_all_subaddrs->is_upsert(account_idx)) throw std::runtime_error("account not upsert: " + std::to_string(account_idx));

    monero_account account = monero_wallet_keys::get_account(account_idx, false);
    account.m_balance = get_balance(account_idx);
    account.m_unlocked_balance = get_unlocked_balance(account_idx);
    if (include_subaddresses) account.m_subaddresses = monero_wallet::get_subaddresses(account_idx);

    return account;
  }

  monero_account monero_wallet_light::create_account(const std::string& label) {
    assert_not_closed();
    if (!label.empty()) throw monero_error("monero_wallet_light doesn't support creating account with label");
    sync_op_lock op_lock(*this); // do not refresh while modifying accounts
    uint32_t last_account_idx = 0;
    if (m_subaddrs.m_all_subaddrs != nullptr) {
      last_account_idx = m_subaddrs.m_all_subaddrs->get_last_account_index();
    }

    uint32_t account_idx = last_account_idx + 1;
    upsert_subaddrs(account_idx, 0);
    monero_account account = monero_wallet_keys::get_account(account_idx, false);
    account.m_balance = 0;
    account.m_unlocked_balance = 0;
    return account;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    assert_not_closed();
    std::vector<monero_subaddress> subaddresses = get_subaddresses_aux(account_idx, subaddress_indices);
    for(monero_subaddress& subaddress : subaddresses) m_cache->init_subaddress(subaddress);
    return subaddresses;
  }

  monero_subaddress monero_wallet_light::create_subaddress(uint32_t account_idx, const std::string& label) {
    assert_not_closed();
    if (!label.empty()) throw monero_error("monero_wallet_light doesn't support creating subaddress with label");
    sync_op_lock op_lock(*this); // do not refresh while modifying subaddresses
    bool account_found = false;
    uint32_t last_subaddress_idx = 0;

    if (m_subaddrs.m_all_subaddrs != nullptr) {
      account_found = m_subaddrs.m_all_subaddrs->contains(account_idx);
      if (account_found) last_subaddress_idx = m_subaddrs.m_all_subaddrs->get_last_subaddress_index(account_idx);
    }

    if (!account_found) throw std::runtime_error("create_subaddress(): account index out of bounds");

    uint32_t subaddress_idx = last_subaddress_idx + 1;

    monero_subaddrs subaddrs;
    subaddrs[account_idx] = std::vector<std::shared_ptr<monero_index_range>>();
    subaddrs[account_idx].push_back(std::make_shared<monero_index_range>(0, subaddress_idx));
    auto response = m_client->upsert_subaddrs(subaddrs, true);
    m_subaddrs.m_all_subaddrs = response->m_all_subaddrs;
    process_subaddresses();

    monero_subaddress subaddress = get_subaddress(account_idx, subaddress_idx);
    subaddress.m_balance = 0;
    subaddress.m_unlocked_balance = 0;
    subaddress.m_num_unspent_outputs = 0;
    subaddress.m_is_used = false;
    subaddress.m_num_blocks_to_unlock = 0;

    return subaddress;
  }

  monero_subaddress monero_wallet_light::get_subaddress(const uint32_t account_idx, const uint32_t subaddress_idx) const {
    assert_not_closed();
    std::vector<uint32_t> indices;
    indices.push_back(subaddress_idx);
    std::vector<monero_subaddress> subaddresses = monero_wallet_keys::get_subaddresses(account_idx, indices);
    monero_subaddress& subaddress = subaddresses[0];
    m_cache->init_subaddress(subaddress);
    return subaddress;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    MTRACE("monero_wallet_light::relay_txs()");
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while relaying txs

    // relay each metadata as a tx
    std::vector<std::string> tx_hashes;
    for (const auto& tx_metadata : tx_metadatas) {

      // parse tx metadata hex
      cryptonote::blobdata blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(tx_metadata, blob)) {
        throw std::runtime_error("Failed to parse hex");
      }

      // deserialize tx
      bool loaded = false;
      tools::wallet2::pending_tx ptx;
      try {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
        if (::serialization::serialize(ar, ptx)) loaded = true;
      } catch (...) {}
      if (!loaded) {
        try {
          std::istringstream iss(blob);
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> ptx;
          loaded = true;
        } catch (...) {}
      }
      if (!loaded) throw std::runtime_error("Failed to parse tx metadata");

      // commit tx
      std::string full_hex = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx));
      try { m_client->submit_raw_tx(full_hex); }
      catch (const std::exception& e) { throw std::runtime_error("Failed to commit tx"); }
      std::string change_pubkey;
      std::shared_ptr<monero_tx_wallet> tx = monero_utils::ptx_to_tx(ptx, static_cast<cryptonote::network_type>(m_network_type), this, &change_pubkey);
      tx->m_full_hex = full_hex;
      m_cache->add_unconfirmed_tx(tx, change_pubkey);
      // collect resulting hash
      std::string pending_tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
      tx_hashes.push_back(pending_tx_hash);
    }

    if (!tx_metadatas.empty()) m_cache->calculate_balance();

    // notify listeners of spent funds
    m_wallet_listener->on_spend_tx_hashes(tx_hashes);

    // return relayed tx hashes
    return tx_hashes;
  }

  monero_tx_set monero_wallet_light::describe_tx_set(const monero_tx_set& tx_set) {
    assert_not_closed();

    // get unsigned and multisig tx sets
    std::string unsigned_tx_hex = tx_set.m_unsigned_tx_hex == boost::none ? "" : tx_set.m_unsigned_tx_hex.get();
    std::string multisig_tx_hex = tx_set.m_multisig_tx_hex == boost::none ? "" : tx_set.m_multisig_tx_hex.get();

    // validate request
    if (m_account.get_device().get_type() != hw::device::device_type::SOFTWARE) throw std::runtime_error("command not supported by HW wallet");
    if (is_view_only()) throw std::runtime_error("command not supported by view-only wallet");
    if (unsigned_tx_hex.empty() && multisig_tx_hex.empty()) throw std::runtime_error("no txset provided");

    std::vector <tools::wallet2::tx_construction_data> tx_constructions;
    if (!unsigned_tx_hex.empty()) {
      try {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");
        tools::wallet2::unsigned_tx_set exported_txs = monero_utils::parse_unsigned_tx(blob, m_account.get_keys().m_view_secret_key);
        tx_constructions = exported_txs.txes;
      }
      catch (const std::exception &e) {
        throw std::runtime_error("failed to parse unsigned transfers: " + std::string(e.what()));
      }
    } else if (!multisig_tx_hex.empty()) {
      throw std::runtime_error("monero_wallet_light::describe_tx_set(): multisign not supported");
    }

    std::vector<tools::wallet2::pending_tx> ptx;  // TODO wallet_rpc_server: unused variable
    try {

      // gather info for each tx
      std::vector<std::shared_ptr<monero_tx_wallet>> txs;
      std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> dests;
      int first_known_non_zero_change_index = -1;
      for (int64_t n = 0; n < tx_constructions.size(); ++n)
      {
        // init tx
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
        tx->m_is_outgoing = true;
        tx->m_input_sum = 0;
        tx->m_output_sum = 0;
        tx->m_change_amount = 0;
        tx->m_num_dummy_outputs = 0;
        tx->m_ring_size = std::numeric_limits<uint32_t>::max(); // smaller ring sizes will overwrite

        const tools::wallet2::tx_construction_data &cd = tx_constructions[n];
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        bool has_encrypted_payment_id = false;
        crypto::hash8 payment_id8 = crypto::null_hash8;
        if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields))
        {
          cryptonote::tx_extra_nonce extra_nonce;
          if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
          {
            crypto::hash payment_id;
            if (cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
            {
              if (payment_id8 != crypto::null_hash8)
              {
                tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id8);
                has_encrypted_payment_id = true;
              }
            }
            else if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
            {
              tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
            }
          }
        }

        for (uint64_t s = 0; s < cd.sources.size(); ++s)
        {
          tx->m_input_sum = tx->m_input_sum.get() + cd.sources[s].amount;
          uint64_t ring_size = cd.sources[s].outputs.size();
          if (ring_size < tx->m_ring_size.get())
            tx->m_ring_size = ring_size;
        }
        for (uint64_t d = 0; d < cd.splitted_dsts.size(); ++d)
        {
          const cryptonote::tx_destination_entry &entry = cd.splitted_dsts[d];
          std::string address = cryptonote::get_account_address_as_str(static_cast<cryptonote::network_type>(m_network_type), entry.is_subaddress, entry.addr);
          if (has_encrypted_payment_id && !entry.is_subaddress && address != entry.original)
            address = cryptonote::get_account_integrated_address_as_str(static_cast<cryptonote::network_type>(m_network_type), entry.addr, payment_id8);
          auto i = dests.find(entry.addr);
          if (i == dests.end())
            dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
          else
            i->second.second += entry.amount;
          tx->m_output_sum = tx->m_output_sum.get() + entry.amount;
        }
        if (cd.change_dts.amount > 0)
        {
          auto it = dests.find(cd.change_dts.addr);
          if (it == dests.end()) throw std::runtime_error("Claimed change does not go to a paid address");
          if (it->second.second < cd.change_dts.amount) throw std::runtime_error("Claimed change is larger than payment to the change address");
          if (cd.change_dts.amount > 0)
          {
            if (first_known_non_zero_change_index == -1)
              first_known_non_zero_change_index = n;
            const tools::wallet2::tx_construction_data &cdn = tx_constructions[first_known_non_zero_change_index];
            if (memcmp(&cd.change_dts.addr, &cdn.change_dts.addr, sizeof(cd.change_dts.addr))) throw std::runtime_error("Change goes to more than one address");
          }
          tx->m_change_amount = tx->m_change_amount.get() + cd.change_dts.amount;
          it->second.second -= cd.change_dts.amount;
          if (it->second.second == 0)
            dests.erase(cd.change_dts.addr);
        }

        tx->m_outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
        uint64_t n_dummy_outputs = 0;
        for (auto i = dests.begin(); i != dests.end(); )
        {
          if (i->second.second > 0)
          {
            std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
            destination->m_address = i->second.first;
            destination->m_amount = i->second.second;
            tx->m_outgoing_transfer.get()->m_destinations.push_back(destination);
          }
          else
            tx->m_num_dummy_outputs = tx->m_num_dummy_outputs.get() + 1;
          ++i;
        }

        if (tx->m_change_amount.get() > 0)
        {
          const tools::wallet2::tx_construction_data &cd0 = tx_constructions[0];
          tx->m_change_address = get_account_address_as_str(static_cast<cryptonote::network_type>(m_network_type), cd0.subaddr_account > 0, cd0.change_dts.addr);
        }

        tx->m_fee = tx->m_input_sum.get() - tx->m_output_sum.get();
        tx->m_unlock_time = cd.unlock_time;
        tx->m_extra_hex = epee::to_hex::string({cd.extra.data(), cd.extra.size()});
        txs.push_back(tx);
      }

      // build and return tx set
      monero_tx_set tx_set;
      tx_set.m_txs = txs;
      return tx_set;
    }
    catch (const std::exception &e)
    {
      throw std::runtime_error("failed to parse unsigned transfers");
    }
  }

  // implementation based on monero-project's wallet_rpc_server.cpp::on_sign_transfer()
  monero_tx_set monero_wallet_light::sign_txs(const std::string& unsigned_tx_hex) {
    assert_not_closed();
    if (m_account.get_device().get_type() != hw::device::device_type::SOFTWARE) throw std::runtime_error("command not supported by HW wallet");
    if (is_view_only()) throw std::runtime_error("command not supported by view-only wallet");

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");

    tools::wallet2::unsigned_tx_set exported_txs = monero_utils::parse_unsigned_tx(blob, m_account.get_keys().m_view_secret_key);

    std::vector<tools::wallet2::pending_tx> ptxs;
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    try {
      tools::wallet2::signed_tx_set signed_txs;
      const auto& outputs = m_cache->m_outputs;
      std::vector<std::string> signed_kis;
      for(const auto& output : outputs) signed_kis.push_back(output->is_key_image_known() ? output->m_key_image.get() : "");
      std::string ciphertext = monero_utils::sign_tx(exported_txs, ptxs, signed_txs, signed_kis, m_account, m_subaddresses);
      if (ciphertext.empty()) throw std::runtime_error("Failed to sign unsigned tx");

      // init tx set
      monero_tx_set tx_set;
      tx_set.m_signed_tx_hex = epee::string_tools::buff_to_hex_nodelimer(ciphertext);
      for (auto &ptx : ptxs) {

        // init tx
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
        tx->m_is_outgoing = true;
        tx->m_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
        tx->m_key = epee::string_tools::pod_to_hex(unwrap(unwrap(ptx.tx_key)));
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys) {
            tx->m_key = tx->m_key.get() += epee::string_tools::pod_to_hex(unwrap(unwrap(additional_tx_key)));
        }
        tx_set.m_txs.push_back(tx);
      }
      return tx_set;
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to sign unsigned tx: ") + e.what());
    }
  }

  std::vector<std::string> monero_wallet_light::submit_txs(const std::string& signed_tx_hex) {
    MTRACE("monero_wallet_light::submit_txs()");
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while relaying txs
    if (m_account.get_device().get_type() != hw::device::device_type::SOFTWARE) throw std::runtime_error("command not supported by HW wallet");

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(signed_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");

    std::vector<tools::wallet2::pending_tx> ptx_vector;
    try { ptx_vector = monero_utils::parse_signed_tx(blob, m_account.get_keys().m_view_secret_key); }
    catch (const std::exception &e) { throw std::runtime_error(std::string("Failed to parse signed tx: ") + e.what()); }

    try {
      std::vector<std::string> tx_hashes;
      for (auto &ptx: ptx_vector) {
        const auto res = m_client->submit_raw_tx(epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(ptx.tx)));
        if (res->m_status == boost::none || res->m_status.get() != std::string("OK")) throw std::runtime_error("Could not relay tx" + signed_tx_hex);
        crypto::hash txid;
        txid = cryptonote::get_transaction_hash(ptx.tx);
        std::string pending_tx_hash = epee::string_tools::pod_to_hex(txid);
        tx_hashes.push_back(pending_tx_hash);
        std::string change_pubkey;
        std::shared_ptr<monero_tx_wallet> tx = monero_utils::ptx_to_tx(ptx, static_cast<cryptonote::network_type>(m_network_type), this, &change_pubkey);
        m_cache->add_unconfirmed_tx(tx, change_pubkey);
      }

      m_wallet_listener->on_spend_tx_hashes(tx_hashes); // notify listeners of spent funds
      return tx_hashes;
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to submit signed tx: ") + e.what());
    }
  }

  // implementation based on monero-project's wallet2::get_tx_key()
  std::string monero_wallet_light::get_tx_key(const std::string& tx_hash) const {
    MTRACE("monero_wallet_light::get_tx_key()");
    assert_not_closed();

    // validate and parse tx hash
    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(tx_hash, txid)) throw std::runtime_error("TX hash has invalid format");

    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;

    // check tx keys stored locally from when this wallet created the tx
    const auto tx_key_it = m_tx_keys.find(txid);
    bool found = tx_key_it != m_tx_keys.end() && tx_key_it->second != crypto::null_skey;
    if (found) {
      tx_key = tx_key_it->second;
      const auto additional_it = m_additional_tx_keys.find(txid);
      if (additional_it != m_additional_tx_keys.end()) additional_tx_keys = additional_it->second;
    } else {
      // fall back to a cold signing device, so far only the cold protocol is supported
      auto& hwdev = m_account.get_device();
      if (hwdev.device_protocol() != hw::device::PROTOCOL_COLD) throw std::runtime_error("No tx secret key is stored for this tx");

      auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
      CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");
      if (!dev_cold->is_get_tx_key_supported()) throw std::runtime_error("No tx secret key is stored for this tx");

      hw::device_cold::tx_key_data_t tx_key_data;
      tx_key_data.tx_prefix_hash = m_cache->get_tx_prefix_hash(tx_hash);
      if (tx_key_data.tx_prefix_hash.empty()) throw std::runtime_error("No tx secret key is stored for this tx");

      std::vector<crypto::secret_key> tx_keys;
      dev_cold->get_tx_key(tx_keys, tx_key_data, m_account.get_keys().m_view_secret_key);
      if (tx_keys.empty() || tx_keys[0] == crypto::null_skey) throw std::runtime_error("No tx secret key is stored for this tx");

      tx_key = tx_keys[0];
      tx_keys.erase(tx_keys.begin());
      additional_tx_keys = tx_keys;
    }

    // build and return tx key with additional keys
    epee::wipeable_string s;
    s += epee::to_hex::wipeable_string(tx_key);
    for (uint64_t i = 0; i < additional_tx_keys.size(); ++i) s += epee::to_hex::wipeable_string(additional_tx_keys[i]);
    return std::string(s.data(), s.size());
  }

  // implementation based on monero-project's wallet2::check_tx_key()
  std::shared_ptr<monero_check_tx> monero_wallet_light::check_tx_key(const std::string& tx_hash, const std::string& tx_key, const std::string& address) const {
    MTRACE("monero_wallet_light::check_tx_key()");
    assert_not_closed();

    // validate and parse tx hash
    crypto::hash _tx_hash;
    if (!epee::string_tools::hex_to_pod(tx_hash, _tx_hash)) throw std::runtime_error("TX hash has invalid format");

    // validate and parse tx key
    epee::wipeable_string tx_key_str = tx_key;
    if (tx_key_str.size() < 64 || tx_key_str.size() % 64) throw std::runtime_error("Tx key has invalid format");
    const char *data = tx_key_str.data();
    crypto::secret_key _tx_key;
    if (!epee::wipeable_string(data, 64).hex_to_pod(unwrap(unwrap(_tx_key)))) throw std::runtime_error("Tx key has invalid format");

    // get additional keys
    uint64_t offset = 64;
    std::vector<crypto::secret_key> additional_tx_keys;
    while (offset < tx_key_str.size()) {
      additional_tx_keys.resize(additional_tx_keys.size() + 1);
      if (!epee::wipeable_string(data + offset, 64).hex_to_pod(unwrap(unwrap(additional_tx_keys.back())))) throw std::runtime_error("Tx key has invalid format");
      offset += 64;
    }

    // validate and parse address
    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, static_cast<cryptonote::network_type>(m_network_type), address)) throw std::runtime_error("Invalid address");

    // this wallet only has raw tx bytes cached for txs it itself built and relayed
    std::shared_ptr<monero_tx_wallet> cached_tx = m_cache->get_self_constructed_tx(tx_hash);
    if (cached_tx == nullptr || cached_tx->m_full_hex == boost::none || cached_tx->m_full_hex->empty()) {
      throw std::runtime_error("No tx secret key is stored for this tx");
    }

    cryptonote::blobdata tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(cached_tx->m_full_hex.get(), tx_blob)) throw std::runtime_error("Failed to parse cached tx");
    cryptonote::transaction tx;
    if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx)) throw std::runtime_error("Failed to parse cached tx");

    uint64_t received_amount;
    {
      sync_op_lock op_lock(*this); // do not read m_subaddresses while the sync thread is upserting into it
      light_tx_builder tx_builder(static_cast<cryptonote::network_type>(m_network_type), m_subaddresses, m_account.get_keys(), is_view_only(), *m_client, m_cache);
      received_amount = tx_builder.compute_amount_received(tx, _tx_key, additional_tx_keys, info.address);
    }

    bool in_tx_pool = cached_tx->m_in_tx_pool != boost::none && cached_tx->m_in_tx_pool.get();
    uint64_t num_confirmations = 0;
    if (!in_tx_pool) {
      uint64_t tx_height = cached_tx->get_height().value_or(0);
      uint64_t chain_height = get_daemon_height();
      if (chain_height > tx_height) num_confirmations = chain_height - tx_height;
    }

    std::shared_ptr<monero_check_tx> check_tx = std::make_shared<monero_check_tx>();
    check_tx->m_is_good = true; // check is good if we get this far
    check_tx->m_received_amount = received_amount;
    check_tx->m_in_tx_pool = in_tx_pool;
    check_tx->m_num_confirmations = num_confirmations;
    return check_tx;
  }

  void monero_wallet_light::freeze_output(const std::string& key_image) {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while modifying outputs
    m_cache->set_key_image_frozen(key_image, true);
  }

  void monero_wallet_light::thaw_output(const std::string& key_image) {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while modifying outputs
    m_cache->set_key_image_frozen(key_image, false);
  }

  bool monero_wallet_light::is_output_frozen(const std::string& key_image) {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while reading outputs
    return m_cache->is_key_image_frozen(key_image);
  }

  monero_tx_priority monero_wallet_light::get_default_fee_priority() const {
    assert_not_closed();
    return static_cast<monero_tx_priority>(DEFAULT_FEE_PRIORITY);
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::create_txs(const monero_tx_config& config) {
    MINFO("monero_wallet_light::create_txs()");
    assert_not_closed();
    if (is_multisig()) throw std::runtime_error("Multisig wallet not supported");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // validate config
    if (config.m_account_index == boost::none) throw std::runtime_error("Must specify account index to send from");

    std::vector<std::shared_ptr<monero_tx_wallet>> result;
    uint32_t subaddr_account_idx = config.m_account_index.get();
    uint64_t amount = 0;
    std::vector<uint64_t> sending_amounts;
    std::vector<std::string> dests;
    std::string multisig_tx_hex;
    std::string unsigned_tx_hex;

    for(const auto &dest : config.get_normalized_destinations()) {
      const auto &dest_address = dest->m_address.get();
      if (!monero_utils::is_valid_address(dest_address, m_network_type)) throw std::runtime_error("Invalid destination address");
      dests.push_back(dest_address);
      sending_amounts.push_back(*dest->m_amount);
      amount += *dest->m_amount;
    }

    const std::set<uint32_t> subtract_fee_from(config.m_subtract_fee_from.begin(), config.m_subtract_fee_from.end());
    for (uint32_t idx : subtract_fee_from) {
      if (idx >= sending_amounts.size()) throw std::runtime_error("Invalid destination index to subtract fee from: " + std::to_string(idx));
    }

    const size_t max_destinations_per_tx = BULLETPROOF_MAX_OUTPUTS - 1;
    if (dests.size() > max_destinations_per_tx && !config.m_can_split.value_or(false)) {
      throw std::runtime_error("Too many destinations for a single transaction (max " + std::to_string(max_destinations_per_tx) + "); enable can_split to send in multiple transactions");
    }

    sync_op_lock op_lock(*this); // do not refresh while creating txs

    auto unspent_outs = m_cache->get_spendable(subaddr_account_idx, config.m_subaddress_indices);
    auto simple_priority = config.m_priority == boost::none ? 0 : config.m_priority.get();
    uint64_t fee_per_b = m_cache->get_base_fee(simple_priority);
    uint64_t fee_mask = m_cache->get_fee_mask();
    if (unspent_outs.empty()) throw std::runtime_error("not enough unlocked money");

    bool relay = config.m_relay == boost::none ? false : config.m_relay.get();

    light_tx_builder tx_builder(static_cast<cryptonote::network_type>(m_network_type), m_subaddresses, m_account.get_keys(), is_view_only(), *m_client, m_cache);

    std::vector<tools::wallet2::tx_construction_data> unsigned_construction_data;
    bool any_relayed = false;

    // one iteration per chunk of up to max_destinations_per_tx destinations
    for (size_t chunk_start = 0; chunk_start < dests.size(); chunk_start += max_destinations_per_tx) {
      const size_t chunk_end = std::min(chunk_start + max_destinations_per_tx, dests.size());
      const std::vector<std::string> chunk_dests(dests.begin() + chunk_start, dests.begin() + chunk_end);
      const std::vector<uint64_t> chunk_amounts(sending_amounts.begin() + chunk_start, sending_amounts.begin() + chunk_end);

      // remap subtract_fee_from indices from global destination indices to this chunk's local ones
      std::set<uint32_t> chunk_subtract_fee_from;
      for (uint32_t idx : subtract_fee_from) {
        if (idx >= chunk_start && idx < chunk_end) chunk_subtract_fee_from.insert(boost::numeric_cast<uint32_t>(idx - chunk_start));
      }

      if (unspent_outs.empty()) throw std::runtime_error("not enough unlocked money");

      cryptonote::blobdata tx_blob;
      tools::wallet2::pending_tx ptx = tx_builder.build(subaddr_account_idx, chunk_dests, config.m_payment_id, chunk_amounts, false, simple_priority, unspent_outs, fee_per_b, fee_mask, tx_blob, chunk_subtract_fee_from);
      std::string full_hex = epee::string_tools::buff_to_hex_nodelimer(tx_blob);

      if (ptx.tx_key != crypto::null_skey) {
        const crypto::hash txid = get_transaction_hash(ptx.tx);
        m_tx_keys[txid] = ptx.tx_key;
        m_additional_tx_keys[txid] = ptx.additional_tx_keys;
      }

      std::string change_pubkey;
      std::shared_ptr<monero_tx_wallet> tx = std::dynamic_pointer_cast<monero_tx_wallet>(monero_utils::ptx_to_tx(ptx, static_cast<cryptonote::network_type>(m_network_type), this, &change_pubkey));
      fix_input_subaddress_indices(tx, ptx, unspent_outs); // unspent_outs is pruned for the next chunk below

      // exclude the outputs this tx just used from the pool available to the next chunk, so two
      // txs in the same batch never try to spend the same output
      if (chunk_end < dests.size()) {
        const std::set<size_t> used_indexes(ptx.selected_transfers.begin(), ptx.selected_transfers.end());
        std::vector<std::shared_ptr<monero_output_light>> remaining_outs;
        remaining_outs.reserve(unspent_outs.size() > used_indexes.size() ? unspent_outs.size() - used_indexes.size() : 0);
        for (const auto& out : unspent_outs) {
          if (out->m_cache_index != boost::none && used_indexes.count(*out->m_cache_index)) continue;
          remaining_outs.push_back(out);
        }
        unspent_outs = std::move(remaining_outs);
      }

      bool relayed = false;
      if (relay) {
        try {
          auto submit_res = m_client->submit_raw_tx(full_hex);
          if (submit_res->m_status != boost::none && submit_res->m_status == std::string("OK")) {
            MINFO("monero_wallet_light::create_txs(): relayed tx");
            relayed = true;
          }
          else MINFO("monero_wallet_light::create_txs(): tx not relayed");
        }
        catch(...) { }
      }

      tx->m_in_tx_pool = relayed;
      tx->m_is_relayed = relayed;
      tx->m_relay = relay;
      tx->m_is_outgoing = true;
      tx->m_is_failed = relay && !relayed;
      tx->m_payment_id = config.m_payment_id;
      tx->m_key = get_tx_key(tx->m_hash.get());
      tx->m_full_hex = full_hex;

      if (!relayed) {
        tx->m_last_relayed_timestamp = boost::none;
        tx->m_is_double_spend_seen = boost::none;
      }

      if (is_view_only()) unsigned_construction_data.push_back(ptx.construction_data);

      std::shared_ptr<monero_tx_wallet> unconfirmed_tx = std::make_shared<monero_tx_wallet>();
      tx->copy(tx, unconfirmed_tx);
      normalize_unconfirmed_tx(unconfirmed_tx);
      result.push_back(unconfirmed_tx);

      MINFO("monero_wallet_light::create_txs(): created unconfirmed tx with " << tx->m_outputs.size() << " outputs and " << tx->m_inputs.size() << " inputs");

      if (!is_view_only() && relayed) m_cache->add_unconfirmed_tx(tx, change_pubkey);
      if (relayed) any_relayed = true;
    }

    if (is_view_only()) {
      unsigned_tx_hex = monero_utils::dump_unsigned_tx(unsigned_construction_data, config.m_payment_id, m_cache->export_outputs(false, 0), m_account.get_keys().m_view_secret_key);
      if (unsigned_tx_hex.empty()) throw std::runtime_error("Failed to save unsigned tx set after creation");
    }

    // build tx set
    std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
    tx_set->m_txs = result;
    for (int i = 0; i < result.size(); i++) result[i]->m_tx_set = tx_set;
    if (!multisig_tx_hex.empty()) tx_set->m_multisig_tx_hex = multisig_tx_hex;
    if (!unsigned_tx_hex.empty()) tx_set->m_unsigned_tx_hex = unsigned_tx_hex;

    m_cache->calculate_balance();

    if (any_relayed) m_wallet_listener->on_spend_txs(result);

    return result;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::sweep_account(const monero_tx_config& config) {
    MINFO("monero_wallet_light::sweep_account()");
    assert_not_closed();
    if (is_multisig()) throw std::runtime_error("Multisig wallet not supported");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (config.m_account_index == boost::none) throw std::runtime_error("Must specify account index to sweep from");
    if (destinations.size() != 1 || destinations[0]->m_address == boost::none || destinations[0]->m_address.get().empty()) throw std::runtime_error("Must provide exactly one destination address to sweep to");
    if (destinations[0]->m_amount != boost::none) throw std::runtime_error("Cannot specify destination amount to sweep");
    if (config.m_key_image != boost::none) throw std::runtime_error("Cannot define key image in sweep_account(); use sweep_output() to sweep an output by its key image");
    if (config.m_sweep_each_subaddress != boost::none && config.m_sweep_each_subaddress.get() == true) throw std::runtime_error("Cannot sweep each subaddress individually with sweep_account");
    if (config.m_subtract_fee_from.size() > 0) throw std::runtime_error("Sweep transactions do not support subtracting fees from destinations");

    const std::string& dest_address = destinations[0]->m_address.get();
    if (!monero_utils::is_valid_address(dest_address, m_network_type)) throw std::runtime_error("Invalid destination address");

    std::vector<std::shared_ptr<monero_tx_wallet>> result;
    uint32_t subaddr_account_idx = config.m_account_index.get();

    sync_op_lock op_lock(*this); // do not refresh while creating txs

    auto unspent_outs = m_cache->get_spendable(subaddr_account_idx, config.m_subaddress_indices);
    if (unspent_outs.empty()) throw std::runtime_error("not enough unlocked money");

    auto simple_priority = config.m_priority == boost::none ? 0 : config.m_priority.get();
    uint64_t fee_per_b = m_cache->get_base_fee(simple_priority);
    uint64_t fee_mask = m_cache->get_fee_mask();
    bool relay = config.m_relay == boost::none ? false : config.m_relay.get();

    light_tx_builder tx_builder(static_cast<cryptonote::network_type>(m_network_type), m_subaddresses, m_account.get_keys(), is_view_only(), *m_client, m_cache);
    std::vector<tools::wallet2::tx_construction_data> unsigned_construction_data;

    while (!unspent_outs.empty()) {
      cryptonote::blobdata tx_blob;
      tools::wallet2::pending_tx ptx = tx_builder.build(subaddr_account_idx, {dest_address}, config.m_payment_id, {}, true, simple_priority, unspent_outs, fee_per_b, fee_mask, tx_blob);
      std::string full_hex = epee::string_tools::buff_to_hex_nodelimer(tx_blob);

      if (ptx.tx_key != crypto::null_skey) {
        const crypto::hash txid = get_transaction_hash(ptx.tx);
        m_tx_keys[txid] = ptx.tx_key;
        m_additional_tx_keys[txid] = ptx.additional_tx_keys;
      }

      std::string change_pubkey;
      std::shared_ptr<monero_tx_wallet> tx = std::dynamic_pointer_cast<monero_tx_wallet>(monero_utils::ptx_to_tx(ptx, static_cast<cryptonote::network_type>(m_network_type), this, &change_pubkey));
      fix_input_subaddress_indices(tx, ptx, unspent_outs); // unspent_outs is pruned for the next iteration below

      // exclude the outputs this tx just used from the pool for the next iteration
      {
        const std::set<size_t> used_indexes(ptx.selected_transfers.begin(), ptx.selected_transfers.end());
        std::vector<std::shared_ptr<monero_output_light>> remaining_outs;
        remaining_outs.reserve(unspent_outs.size() > used_indexes.size() ? unspent_outs.size() - used_indexes.size() : 0);
        for (const auto& out : unspent_outs) {
          if (out->m_cache_index != boost::none && used_indexes.count(*out->m_cache_index)) continue;
          remaining_outs.push_back(out);
        }
        unspent_outs = std::move(remaining_outs);
      }

      bool relayed = false;
      if (relay) {
        try {
          auto submit_res = m_client->submit_raw_tx(full_hex);
          if (submit_res->m_status != boost::none && submit_res->m_status == std::string("OK")) {
            MINFO("monero_wallet_light::sweep_account(): relayed tx");
            relayed = true;
          }
          else MINFO("monero_wallet_light::sweep_account(): tx not relayed");
        }
        catch(...) { }
      }

      tx->m_in_tx_pool = relayed;
      tx->m_is_relayed = relayed;
      tx->m_relay = relay;
      tx->m_is_outgoing = true;
      tx->m_is_failed = relay && !relayed;
      tx->m_payment_id = config.m_payment_id;
      tx->m_key = get_tx_key(tx->m_hash.get());
      tx->m_full_hex = full_hex;

      if (!relayed) {
        tx->m_last_relayed_timestamp = boost::none;
        tx->m_is_double_spend_seen = boost::none;
      }

      if (is_view_only()) unsigned_construction_data.push_back(ptx.construction_data);

      std::shared_ptr<monero_tx_wallet> unconfirmed_tx = std::make_shared<monero_tx_wallet>();
      tx->copy(tx, unconfirmed_tx);
      normalize_unconfirmed_tx(unconfirmed_tx);
      result.push_back(unconfirmed_tx);

      if (!is_view_only() && relayed) m_cache->add_unconfirmed_tx(tx, change_pubkey);
    }

    std::string unsigned_tx_hex;
    if (is_view_only()) {
      unsigned_tx_hex = monero_utils::dump_unsigned_tx(unsigned_construction_data, config.m_payment_id, m_cache->export_outputs(false, 0), m_account.get_keys().m_view_secret_key);
      if (unsigned_tx_hex.empty()) throw std::runtime_error("Failed to save unsigned tx set after creation");
    }

    std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
    tx_set->m_txs = result;
    for (size_t i = 0; i < result.size(); i++) result[i]->m_tx_set = tx_set;
    if (!unsigned_tx_hex.empty()) tx_set->m_unsigned_tx_hex = unsigned_tx_hex;

    m_cache->calculate_balance();

    return result;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::sweep_unlocked(const monero_tx_config& config) {
    MINFO("monero_wallet_light::sweep_unlocked()");
    assert_not_closed();

    // validate config
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (destinations.size() != 1) throw std::runtime_error("Must specify exactly one destination to sweep to");
    if (destinations[0]->m_address == boost::none) throw std::runtime_error("Must specify destination address to sweep to");
    if (destinations[0]->m_amount != boost::none) throw std::runtime_error("Cannot specify amount to sweep");
    if (config.m_account_index == boost::none && config.m_subaddress_indices.size() != 0) throw std::runtime_error("Must specify account index if subaddress indices are specified");

    // determine account and subaddress indices to sweep; default to all with unlocked balance if not specified
    std::map<uint32_t, std::vector<uint32_t>> indices;
    if (config.m_account_index != boost::none) {
      if (config.m_subaddress_indices.size() != 0) {
        indices[config.m_account_index.get()] = config.m_subaddress_indices;
      } else {
        std::vector<uint32_t> subaddress_indices;
        for (const monero_subaddress& subaddress : get_subaddresses(config.m_account_index.get(), std::vector<uint32_t>())) {
          if (subaddress.m_unlocked_balance.get() > 0) subaddress_indices.push_back(subaddress.m_index.get());
        }
        indices[config.m_account_index.get()] = subaddress_indices;
      }
    } else {
      std::vector<monero_account> accounts = get_accounts(true, std::string(""));
      for (const monero_account& account : accounts) {
        if (account.m_unlocked_balance.get() > 0) {
          std::vector<uint32_t> subaddress_indices;
          for (const monero_subaddress& subaddress : account.m_subaddresses) {
            if (subaddress.m_unlocked_balance.get() > 0) subaddress_indices.push_back(subaddress.m_index.get());
          }
          indices[account.m_index.get()] = subaddress_indices;
        }
      }
    }

    // sweep from each account and collect resulting txs
    sync_op_lock op_lock(*this);
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    for (std::pair<uint32_t, std::vector<uint32_t>> subaddress_indices_pair : indices) {
      monero_tx_config copy = config.copy();
      copy.m_account_index = subaddress_indices_pair.first;
      copy.m_sweep_each_subaddress = false;
      copy.m_subaddress_indices = subaddress_indices_pair.second;
      std::vector<std::shared_ptr<monero_tx_wallet>> account_txs = sweep_account(copy);
      txs.insert(std::end(txs), std::begin(account_txs), std::end(account_txs));
    }

    // notify listeners of spent funds
    if (config.m_relay != boost::none && config.m_relay.get()) m_wallet_listener->on_spend_txs(txs);
    return txs;
  }

  std::shared_ptr<monero_tx_wallet> monero_wallet_light::sweep_output(const monero_tx_config& config) {
    MINFO("monero_wallet_light::sweep_output()");
    assert_not_closed();
    if (is_multisig()) throw std::runtime_error("Multisig wallet not supported");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // validate config
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (config.m_key_image == boost::none || config.m_key_image.get().empty()) throw std::runtime_error("Must provide key image of output to sweep");
    if (destinations.size() != 1 || destinations[0]->m_address == boost::none || destinations[0]->m_address.get().empty()) throw std::runtime_error("Must provide exactly one destination address to sweep output to");
    if (destinations[0]->m_amount != boost::none) throw std::runtime_error("Cannot specify amount to sweep");
    if (config.m_subtract_fee_from.size() > 0) throw std::runtime_error("Sweep transactions do not support subtracting fees from destinations");

    const std::string& dest_address = destinations[0]->m_address.get();
    if (!monero_utils::is_valid_address(dest_address, m_network_type)) throw std::runtime_error("Invalid destination address");

    sync_op_lock op_lock(*this); // do not refresh while creating txs

    // locate the requested output and confirm it's actually spendable (unspent, unfrozen, unlocked)
    std::shared_ptr<monero_output_light> output = m_cache->get_output(config.m_key_image.get());
    uint32_t subaddr_account_idx = output->m_recipient->m_maj_i;
    uint32_t subaddress_idx = output->m_recipient->m_min_i;
    const auto candidates = m_cache->get_spendable(subaddr_account_idx, std::vector<uint32_t>{subaddress_idx});
    if (std::find(candidates.begin(), candidates.end(), output) == candidates.end()) throw std::runtime_error("Output is unspendable (already spent, frozen, or still locked)");

    auto simple_priority = config.m_priority == boost::none ? 0 : config.m_priority.get();
    uint64_t fee_per_b = m_cache->get_base_fee(simple_priority);
    uint64_t fee_mask = m_cache->get_fee_mask();
    std::vector<std::shared_ptr<monero_output_light>> unspent_outs{output};

    light_tx_builder tx_builder(static_cast<cryptonote::network_type>(m_network_type), m_subaddresses, m_account.get_keys(), is_view_only(), *m_client, m_cache);

    cryptonote::blobdata tx_blob;
    tools::wallet2::pending_tx ptx = tx_builder.build(subaddr_account_idx, {dest_address}, config.m_payment_id, {}, true, simple_priority, unspent_outs, fee_per_b, fee_mask, tx_blob);
    std::string full_hex = epee::string_tools::buff_to_hex_nodelimer(tx_blob);
    if (ptx.selected_transfers.size() > 1) throw std::runtime_error("The transaction uses multiple inputs, which is not supposed to happen");

    if (ptx.tx_key != crypto::null_skey) {
      const crypto::hash txid = get_transaction_hash(ptx.tx);
      m_tx_keys[txid] = ptx.tx_key;
      m_additional_tx_keys[txid] = ptx.additional_tx_keys;
    }

    std::string change_pubkey;
    std::shared_ptr<monero_tx_wallet> tx = std::dynamic_pointer_cast<monero_tx_wallet>(monero_utils::ptx_to_tx(ptx, static_cast<cryptonote::network_type>(m_network_type), this, &change_pubkey));

    bool relayed = false;
    bool relay = config.m_relay == boost::none ? false : config.m_relay.get();
    if (relay) {
      try {
        auto submit_res = m_client->submit_raw_tx(full_hex);
        if (submit_res->m_status != boost::none && submit_res->m_status == std::string("OK")) {
          MINFO("monero_wallet_light::sweep_output(): relayed tx");
          relayed = true;
        }
        else MINFO("monero_wallet_light::sweep_output(): tx not relayed");
      }
      catch(...) { }
    }

    tx->m_in_tx_pool = relayed;
    tx->m_is_relayed = relayed;
    tx->m_relay = relay;
    tx->m_is_outgoing = true;
    tx->m_is_failed = relay && !relayed;
    tx->m_payment_id = config.m_payment_id;
    tx->m_key = get_tx_key(tx->m_hash.get());
    tx->m_full_hex = full_hex;

    if (!relayed) {
      tx->m_last_relayed_timestamp = boost::none;
      tx->m_is_double_spend_seen = boost::none;
    }

    std::string unsigned_tx_hex;
    if (is_view_only()) {
      std::vector<tools::wallet2::tx_construction_data> unsigned_construction_data{ptx.construction_data};
      unsigned_tx_hex = monero_utils::dump_unsigned_tx(unsigned_construction_data, config.m_payment_id, m_cache->export_outputs(false, 0), m_account.get_keys().m_view_secret_key);
      if (unsigned_tx_hex.empty()) throw std::runtime_error("Failed to save unsigned tx set after creation");
    }

    std::shared_ptr<monero_tx_wallet> unconfirmed_tx = std::make_shared<monero_tx_wallet>();
    tx->copy(tx, unconfirmed_tx);
    normalize_unconfirmed_tx(unconfirmed_tx);

    std::vector<std::shared_ptr<monero_tx_wallet>> result{unconfirmed_tx};
    std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
    tx_set->m_txs = result;
    unconfirmed_tx->m_tx_set = tx_set;
    if (!unsigned_tx_hex.empty()) tx_set->m_unsigned_tx_hex = unsigned_tx_hex;
    if (!is_view_only() && relayed) m_cache->add_unconfirmed_tx(tx, change_pubkey);

    m_cache->calculate_balance();

    if (relayed) m_wallet_listener->on_spend_txs(result);

    return unconfirmed_tx;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs() const {
    assert_not_closed();
    return get_txs(monero_tx_query());
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs(const monero_tx_query& query) const {
    MTRACE("monero_wallet_light::get_txs(query)");
    assert_not_closed();

    // copy query
    std::shared_ptr<monero_tx_query> query_sp = std::make_shared<monero_tx_query>(query); // convert to shared pointer
    std::shared_ptr<monero_tx_query> _query = query_sp->copy(query_sp, std::make_shared<monero_tx_query>()); // deep copy

    // temporarily disable transfer and output queries in order to collect all tx context
    std::shared_ptr<monero_transfer_query> transfer_query = _query->m_transfer_query;
    std::shared_ptr<monero_output_query> input_query = _query->m_input_query;
    std::shared_ptr<monero_output_query> output_query = _query->m_output_query;
    _query->m_transfer_query = nullptr;
    _query->m_input_query = nullptr;
    _query->m_output_query = nullptr;

    // fetch all transfers that meet tx query
    std::shared_ptr<monero_transfer_query> temp_transfer_query = std::make_shared<monero_transfer_query>();
    temp_transfer_query->m_tx_query = monero_tx_query::decontextualize(_query->copy(_query, std::make_shared<monero_tx_query>()));
    temp_transfer_query->m_tx_query->m_transfer_query = temp_transfer_query;
    std::vector<std::shared_ptr<monero_transfer>> transfers = get_transfers_aux(*temp_transfer_query);
    monero_utils::free(temp_transfer_query->m_tx_query);

    // collect unique txs from transfers while retaining order
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();
    std::unordered_set<std::shared_ptr<monero_tx_wallet>> txsSet;
    for (const std::shared_ptr<monero_transfer>& transfer : transfers) {
      if (txsSet.find(transfer->m_tx) == txsSet.end()) {
        txs.push_back(transfer->m_tx);
        txsSet.insert(transfer->m_tx);
      }
    }

    // cache types into maps for merging and lookup
    std::map<std::string, std::shared_ptr<monero_tx_wallet>> tx_map;
    std::map<uint64_t, std::shared_ptr<monero_block>> block_map;
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      monero_utils::merge_tx(tx, tx_map, block_map);
    }

    // fetch and merge outputs if requested
    if ((_query->m_include_outputs != boost::none && *_query->m_include_outputs) || output_query != nullptr) {
      std::shared_ptr<monero_output_query> temp_output_query = std::make_shared<monero_output_query>();
      temp_output_query->m_tx_query = monero_tx_query::decontextualize(_query->copy(_query, std::make_shared<monero_tx_query>()));
      temp_output_query->m_tx_query->m_output_query = temp_output_query;
      std::vector<std::shared_ptr<monero_output_wallet>> outputs = get_outputs_aux(*temp_output_query);
      monero_utils::free(temp_output_query->m_tx_query);

      // merge output txs one time while retaining order
      std::unordered_set<std::shared_ptr<monero_tx_wallet>> output_txs;
      for (const std::shared_ptr<monero_output_wallet>& output : outputs) {
        std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(output->m_tx);
        if (output_txs.find(tx) == output_txs.end()) {
          monero_utils::merge_tx(tx, tx_map, block_map);
          output_txs.insert(tx);
        }
      }
    }

    // restore transfer and output queries
    _query->m_transfer_query = transfer_query;
    _query->m_input_query = input_query;
    _query->m_output_query = output_query;

    // filter txs that don't meet transfer query
    std::vector<std::shared_ptr<monero_tx_wallet>> queried_txs;
    std::vector<std::shared_ptr<monero_tx_wallet>>::iterator tx_iter = txs.begin();
    while (tx_iter != txs.end()) {
      std::shared_ptr<monero_tx_wallet> tx = *tx_iter;
      if (_query->meets_criteria(tx.get())) {
        queried_txs.push_back(tx);
        tx_iter++;
      } else {
        tx_map.erase(tx->m_hash.get());
        tx_iter = txs.erase(tx_iter);
        if (tx->m_block != nullptr) tx->m_block.get()->m_txs.erase(std::remove(tx->m_block.get()->m_txs.begin(), tx->m_block.get()->m_txs.end(), tx), tx->m_block.get()->m_txs.end()); // TODO, no way to use tx_iter?
      }
    }
    txs = queried_txs;

    // special case: re-fetch txs if inconsistency caused by needing to make multiple wallet calls
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      if ((*tx->m_is_confirmed && tx->m_block == nullptr) || (!*tx->m_is_confirmed && tx->m_block != nullptr)) {
        MWARNING("Inconsistency detected building txs from multiple light wallet calls, re-fetching");
        monero_utils::free(txs);
        txs.clear();
        txs = get_txs(*_query);
        monero_utils::free(_query);
        return txs;
      }
    }

    // if tx hashes requested, order txs
    if (!_query->m_hashes.empty()) {
      txs.clear();
      for (const std::string& tx_hash : _query->m_hashes) {
        std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.find(tx_hash);
        if (tx_iter != tx_map.end()) txs.push_back(tx_iter->second);
      }
    }

    // free query and return
    monero_utils::free(_query);
    return txs;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers(const monero_transfer_query& query) const {
    assert_not_closed();
    // get transfers directly if query does not require tx context (e.g. other transfers, outputs)
    if (!monero_transfer_query::is_contextual(query)) return get_transfers_aux(query);

    // otherwise get txs with full models to fulfill query
    std::vector<std::shared_ptr<monero_transfer>> transfers;
    for (const std::shared_ptr<monero_tx_wallet>& tx : get_txs(*query.m_tx_query)) {
      for (const std::shared_ptr<monero_transfer>& transfer : tx->filter_transfers(query)) { // collect queried transfers, erase if excluded
        transfers.push_back(transfer);
      }
    }
    return transfers;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
    assert_not_closed();
    // get outputs directly if query does not require tx context (e.g. other outputs, transfers)
    if (!monero_output_query::is_contextual(query)) return get_outputs_aux(query);

    // otherwise get txs with full models to fulfill query
    std::vector<std::shared_ptr<monero_output_wallet>> outputs;
    for (const std::shared_ptr<monero_tx_wallet>& tx : get_txs(*query.m_tx_query)) {
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(query)) { // collect queried outputs, erase if excluded
        outputs.push_back(output);
      }
    }
    return outputs;
  }

  std::string monero_wallet_light::export_outputs(bool all) const {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while exporting outputs
    uint32_t start = 0;
    uint32_t count = 0xffffffff;
    std::stringstream oss;
    binary_archive<true> ar(oss);

    auto outputs = m_cache->export_outputs(all, start, count);
    if (!serialization::serialize(ar, outputs)) throw std::runtime_error("Failed to serialize output data");

    std::string magic(OUTPUT_EXPORT_FILE_MAGIC, strlen(OUTPUT_EXPORT_FILE_MAGIC));
    const cryptonote::account_public_address &keys = m_account.get_keys().m_account_address;
    std::string header;
    header += std::string((const char *)&keys.m_spend_public_key, sizeof(crypto::public_key));
    header += std::string((const char *)&keys.m_view_public_key, sizeof(crypto::public_key));
    // encrypt with private view key
    std::string ciphertext = monero_utils::encrypt(header + oss.str(), m_account.get_keys().m_view_secret_key);
    std::string outputs_str = magic + ciphertext;
    return epee::string_tools::buff_to_hex_nodelimer(outputs_str);
  }

  std::shared_ptr<monero_key_image_export_result> monero_wallet_light::export_key_images(bool all) const {
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while exporting key images
    std::shared_ptr<monero_key_image_export_result> result = std::make_shared<monero_key_image_export_result>();

    const auto& outputs = m_cache->m_outputs;

    size_t offset = 0;
    if (!all) {
      while (offset < outputs.size() && !m_key_image_cache->request(outputs[offset]->m_tx_pub_key.get(), outputs[offset]->m_index.get(), outputs[offset]->m_recipient->m_maj_i, outputs[offset]->m_recipient->m_min_i))
        ++offset;
    }

    result->m_key_images.reserve(outputs.size() - offset);

    for(size_t n = offset; n < outputs.size(); ++n) {
      const auto& output = outputs[n];
      std::shared_ptr<monero_key_image> key_image = std::make_shared<monero_key_image>();
      uint32_t account_idx = output->m_recipient->m_maj_i;
      uint32_t subaddress_idx = output->m_recipient->m_min_i;

      auto cached_key_image = m_key_image_cache->get(output->m_tx_pub_key.get(), output->m_index.get(), account_idx, subaddress_idx);
      if (cached_key_image != nullptr) key_image = cached_key_image;
      else if (!is_view_only()) key_image = generate_key_image(output->m_tx_pub_key.get(), output->m_index.get(), account_idx, subaddress_idx);
      result->m_key_images.push_back(key_image);
    }

    return result;
  }

  // implementation based on monero-project's wallet2::import_key_images()
  std::shared_ptr<monero_key_image_import_result> monero_wallet_light::import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images, uint64_t offset) {
    MTRACE("monero_wallet_light::import_key_images()");
    assert_not_closed();
    sync_op_lock op_lock(*this); // do not refresh while importing key images
    auto& unspent_outs = m_cache->m_outputs;
    if (offset > unspent_outs.size()) throw monero_error("Offset larger than known outputs");
    if (key_images.size() > unspent_outs.size() - offset) throw monero_error("The blockchain is out of date compared to the signed key images");

    std::shared_ptr<monero_key_image_import_result> result = std::make_shared<monero_key_image_import_result>();
    result->m_height = 0;
    result->m_spent_amount = 0;
    result->m_unspent_amount = 0;

    if (key_images.empty()) return result;

    uint64_t spent_amount = 0;
    uint64_t unspent_amount = 0;

    // validate key images
    std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
    ski.resize(key_images.size());
    for (size_t n = 0; n < ski.size(); ++n) {
      if (!epee::string_tools::hex_to_pod(key_images[n]->m_hex.get(), ski[n].first)) {
        throw std::runtime_error("failed to parse key image");
      }
      if (!epee::string_tools::hex_to_pod(key_images[n]->m_signature.get(), ski[n].second)) {
        throw std::runtime_error("failed to parse signature");
      }
    }

    // verify each key image is signed by the output it claims to spend, as done in wallet2::import_key_images()
    for (size_t n = 0; n < ski.size(); ++n) {
      const auto& unspent_out = unspent_outs[n + offset];
      crypto::public_key pkey;
      if (!epee::string_tools::hex_to_pod(unspent_out->m_public_key.get(), pkey)) throw std::runtime_error("failed to parse output public key");
      std::vector<const crypto::public_key*> pkeys;
      pkeys.push_back(&pkey);
      if (!(rct::scalarmultKey(rct::ki2rct(ski[n].first), rct::curveOrder()) == rct::identity())) {
        throw std::runtime_error("key image out of validity domain: input " + std::to_string(n + offset) + "/" + std::to_string(ski.size()));
      }
      if (!crypto::check_ring_signature((const crypto::hash&)ski[n].first, ski[n].first, pkeys, &ski[n].second)) {
        throw std::runtime_error("signature check failed: input " + std::to_string(n + offset) + "/" + std::to_string(ski.size()));
      }
    }

    bool check_spent = is_connected_to_daemon();
    size_t key_images_size = key_images.size();
    const auto pool_key_images = check_spent ? m_cache->get_pool_key_images() : std::unordered_set<std::string>();

    for (size_t i = 0; i < key_images_size; ++i) {
      auto& unspent_out = unspent_outs[i + offset];
      uint64_t out_index = unspent_out->m_index.get();
      uint32_t account_idx = unspent_out->m_recipient->m_maj_i;
      uint32_t subaddress_idx = unspent_out->m_recipient->m_min_i;
      const std::string& tx_public_key = unspent_out->m_tx_pub_key.get();
      unspent_out->m_key_image = key_images[i]->m_hex;
      m_cache->set_key_image(key_images[i]->m_hex.get(), i + offset);
      m_key_image_cache->set(key_images[i], tx_public_key, out_index, account_idx, subaddress_idx);

      if (!check_spent) continue;
      if (m_cache->is_key_image_spent(key_images[i], pool_key_images)) spent_amount += unspent_outs[i + offset]->m_amount.get();
      else unspent_amount += unspent_outs[i + offset]->m_amount.get();
    }

    result->m_height = unspent_outs[key_images_size - 1 + offset]->m_height;
    result->m_spent_amount = spent_amount;
    result->m_unspent_amount = unspent_amount;

    if (spent_amount > 0 || unspent_amount > 0) {
      uint64_t real_amount = process_outputs(m_cache->m_outputs, m_cache->get_amount());
      m_cache->reindex_outputs(real_amount);
      m_cache->calculate_balance();
    }
    return result;
  }

  uint64_t monero_wallet_light::wait_for_next_block() {
    assert_not_closed();
    // use mutex and condition variable to wait for block
    boost::mutex temp;
    boost::condition_variable cv;

    // create listener which notifies condition variable when block is added
    struct block_notifier : monero_wallet_listener {
      boost::mutex* temp;
      boost::condition_variable* cv;
      uint64_t last_height;
      block_notifier(boost::mutex* temp, boost::condition_variable* cv) { this->temp = temp; this->cv = cv; }
      void on_new_block(uint64_t height) {
        last_height = height;
        cv->notify_one();
      }
    } block_listener(&temp, &cv);

    // register the listener
    add_listener(block_listener);

    // wait until condition variable is notified
    boost::mutex::scoped_lock lock(temp);
    cv.wait(lock);

    // unregister the listener
    remove_listener(block_listener);

    // return last height
    return block_listener.last_height;
  }

  monero_multisig_info monero_wallet_light::get_multisig_info() const {
    assert_not_closed();
    monero_multisig_info info;
    info.m_is_multisig = false;
    return info;
  }

  void monero_wallet_light::close(bool save) {
    MTRACE("monero_wallet_light::close()");
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    if (m_is_closed) return; // closing a closed wallet has not effect
    stop_syncing();
    if (m_sync_loop_running) {
      m_sync_cv.notify_one();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));  // TODO: in emscripten, m_sync_cv.notify_one() returns without waiting, so sleep; bug in emscripten upstream llvm?
      m_syncing_thread.join();
    }

    m_account.deinit();
    m_wallet_listener.reset(); // wait for queued notifications
    m_is_connected = false;
    m_is_closed = true;
  }

  // --------------------------- PRIVATE UTILS --------------------------

  void monero_wallet_light::init_common() {
    monero_wallet_keys::init_common();
    m_cache = std::make_shared<monero_wallet_cache>(m_key_image_cache);
    m_client.reset(new light_wallet_client(m_rpc, get_primary_address(), get_private_view_key()));
    m_rescan_on_sync = false;
    m_syncing_enabled = false;
    m_sync_loop_running = false;
    m_num_sync_pauses = 0;
    m_is_closed = false;
    m_subaddrs.m_all_subaddrs = std::make_shared<monero_subaddrs>();
    process_subaddresses();
    m_wallet_listener = std::unique_ptr<light_wallet_listener>(new light_wallet_listener(*this));
  }

  cryptonote::subaddress_index get_transaction_sender(const std::shared_ptr<monero_tx_light>& tx) {
    cryptonote::subaddress_index si = {0,0};
    for (const auto &output : tx->m_spent_outputs) {
      si.major = output->m_sender->m_maj_i;
      si.minor = output->m_sender->m_min_i;
      break;
    }
    return si;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers_aux(const monero_transfer_query& query) const {

    // copy and normalize query
    std::shared_ptr<monero_transfer_query> _query;
    if (query.m_tx_query == nullptr) {
      std::shared_ptr<monero_transfer_query> query_ptr = std::make_shared<monero_transfer_query>(query); // convert to shared pointer for copy  // TODO: does this copy unecessarily? copy constructor is not defined
      _query = query_ptr->copy(query_ptr, std::make_shared<monero_transfer_query>());
      _query->m_tx_query = std::make_shared<monero_tx_query>();
      _query->m_tx_query->m_transfer_query = _query;
    } else {
      std::shared_ptr<monero_tx_query> tx_query = query.m_tx_query->copy(query.m_tx_query, std::make_shared<monero_tx_query>());
      _query = tx_query->m_transfer_query;
    }
    std::shared_ptr<monero_tx_query> tx_query = _query->m_tx_query;

    std::vector<std::shared_ptr<monero_transfer>> transfers;
    std::unordered_map<uint64_t, std::shared_ptr<monero_block>> blocks;

    const uint64_t current_height = get_height();
    const bool view_only = is_view_only();
    std::unordered_set<std::string> known_hashes; // hashes already represented via m_cache->get_txs(), to avoid duplicate/conflicting tx_wallet objects below

    for (const auto &tx : m_cache->get_txs()) {
      uint64_t total_sent = tx->m_total_sent.get();
      uint64_t total_received = tx->m_total_received.get();
      uint64_t fee = tx->m_fee.get();
      bool is_incoming = total_received > 0;
      bool is_outgoing = total_sent > 0;
      bool is_change = is_incoming && is_outgoing;

      if (is_change && total_sent >= total_received) total_sent -= total_received;
      else if (is_change) total_sent = 0;

      bool is_confirmed = !tx->m_mempool.get();
      // height and timestamp are omitted by the light wallet server for unconfirmed (mempool) txs,
      // since neither exists until the tx is mined into a block
      uint64_t tx_height = is_confirmed ? *tx->m_height : 0;
      bool is_locked = tx->m_unlock_time.get() > current_height || current_height < tx_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
      bool is_miner_tx = *tx->m_coinbase == true;
      bool has_payment_id = tx->m_payment_id != boost::none && !tx->m_payment_id.get().empty() && tx->m_payment_id.get() != monero_tx::DEFAULT_PAYMENT_ID;
      std::string payment_id = has_payment_id ? tx->m_payment_id.get() : "";
      uint64_t timestamp = is_confirmed ? tx->m_timestamp.get() : 0;
      uint64_t num_confirmations = is_confirmed ? current_height - tx_height : 0;
      uint64_t change_amount =  is_change ? total_received : 0;
      uint64_t input_sum = 0;
      uint64_t output_sum = 0;
      std::string tx_hash = tx->m_hash.get();
      known_hashes.insert(tx_hash);
      boost::optional<std::string> known_change_pubkey = m_cache->get_change_pubkey(tx_hash);
      std::shared_ptr<monero_block> block = nullptr;
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
      tx_wallet->m_is_incoming = is_incoming && !is_change;
      tx_wallet->m_is_outgoing = is_outgoing;
      tx_wallet->m_is_locked = is_locked;
      tx_wallet->m_is_relayed = true;
      tx_wallet->m_is_failed = false;
      tx_wallet->m_is_double_spend_seen = false;
      tx_wallet->m_is_confirmed = is_confirmed;
      tx_wallet->m_is_miner_tx = is_miner_tx;
      tx_wallet->m_unlock_time = *tx->m_unlock_time;
      tx_wallet->m_in_tx_pool = !is_confirmed;
      tx_wallet->m_relay = true;
      tx_wallet->m_hash = tx_hash;
      tx_wallet->m_num_confirmations = num_confirmations;
      tx_wallet->m_fee = fee;
      const auto sender = get_transaction_sender(tx);

      if (is_confirmed) {
        auto it = blocks.find(tx_height);
        if (it == blocks.end()) {
          block = std::make_shared<monero_block>();
          block->m_height = tx_height;
          block->m_timestamp = timestamp;
          blocks[tx_height] = block;
        }
        else block = it->second;

        if (is_miner_tx) block->m_miner_tx = tx_wallet;
        block->m_txs.push_back(tx_wallet);
        tx_wallet->m_block = block;
      }
      else tx_wallet->m_received_timestamp = timestamp;

      if (is_incoming) {
        for (const auto &out : m_cache->get_tx_outputs(tx_hash)) {
          uint64_t out_amount = out->m_amount.get();
          uint32_t out_account_idx = out->m_recipient->m_maj_i;
          uint32_t out_subaddress_idx = out->m_recipient->m_min_i;

          bool is_specific_change_output = false;
          bool hide_from_incoming = false;
          if (is_change) {
            hide_from_incoming = sender.major == out_account_idx;
            if (hide_from_incoming) {
              if (known_change_pubkey != boost::none && !known_change_pubkey->empty()) {
                is_specific_change_output = out->m_public_key.value_or("") == *known_change_pubkey;
              } else {
                // fall back to assuming any output returning to the
                // sender's own account is the automatic change
                is_specific_change_output = true;
              }
            }
          }

          if (hide_from_incoming) {
            if (!is_specific_change_output) total_sent += out_amount;
            continue;
          }
          else if (is_change) {
            tx_wallet->m_is_incoming = true;
            total_sent += out_amount;
          }

          std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();

          const auto found = std::find_if(tx_wallet->m_incoming_transfers.begin(), tx_wallet->m_incoming_transfers.end(), [out_account_idx, out_subaddress_idx](const std::shared_ptr<monero_incoming_transfer>& transfer){
            return out_account_idx == transfer->m_account_index.get() && out_subaddress_idx == transfer->m_subaddress_index.get();
          });

          if (found != tx_wallet->m_incoming_transfers.end()) {
            (*found)->m_amount = (*found)->m_amount.get() + out_amount;
          }
          else {
            incoming_transfer->m_tx = tx_wallet;
            incoming_transfer->m_account_index = out_account_idx;
            incoming_transfer->m_subaddress_index = out_subaddress_idx;
            incoming_transfer->m_address = get_address(out_account_idx, out_subaddress_idx);
            incoming_transfer->m_amount = out_amount;

            uint64_t reward = m_cache->get_last_block_reward();
            monero_utils::set_num_suggested_confirmations(incoming_transfer, current_height, reward, *tx->m_unlock_time);

            tx_wallet->m_incoming_transfers.push_back(incoming_transfer);

            std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();

            if (out->m_key_image != boost::none) {
            auto out_key_image = std::make_shared<monero_key_image>();
              out_key_image->m_hex = *out->m_key_image;
              output->m_key_image = out_key_image;
            }

            output->m_tx = tx_wallet;
            output->m_account_index = out_account_idx;
            output->m_subaddress_index = out_subaddress_idx;
            output->m_amount = out_amount;
            output->m_is_spent = out->is_spent();
            output->m_index = out->m_global_index.get();
            output->m_stealth_public_key = out->m_public_key;

            output_sum += out_amount;
          }
        }
      }

      if (has_payment_id) tx_wallet->m_payment_id = payment_id;

      if (is_outgoing && !view_only) {
        std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
        outgoing_transfer->m_tx = tx_wallet;
        outgoing_transfer->m_amount = total_sent >= fee ? total_sent - fee : 0;
        outgoing_transfer->m_account_index = sender.major;
        outgoing_transfer->m_destinations = m_cache->get_tx_destinations(tx_hash);

        // replace transfer amount with destination sum
        // TODO monero_wallet_light: confirmed tx from/to same account has amount 0 but cached transfer destinations
        if (*outgoing_transfer->m_amount == 0 && !outgoing_transfer->m_destinations.empty()) {
          uint64_t amount = 0;
          for (const std::shared_ptr<monero_destination>& destination : outgoing_transfer->m_destinations) amount += *destination->m_amount;
          outgoing_transfer->m_amount = amount;
        }

        for (const auto& spent_output : tx->m_spent_outputs) {
          uint32_t account_idx = spent_output->m_sender->m_maj_i;
          uint32_t subaddress_idx = spent_output->m_sender->m_min_i;
          uint64_t out_amount = spent_output->m_amount.get();

          if (account_idx == sender.major && std::find_if(outgoing_transfer->m_subaddress_indices.begin(), outgoing_transfer->m_subaddress_indices.end(), [subaddress_idx](const uint32_t &idx) { return subaddress_idx == idx; }) == outgoing_transfer->m_subaddress_indices.end()) {
            outgoing_transfer->m_addresses.push_back(get_address(account_idx, subaddress_idx));
            outgoing_transfer->m_subaddress_indices.push_back(subaddress_idx);
          }

          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();

          if (spent_output->m_key_image != boost::none) {
            auto out_key_image = std::make_shared<monero_key_image>();
            out_key_image->m_hex = spent_output->m_key_image;
            output->m_key_image = out_key_image;
          }

          output->m_account_index = account_idx;
          output->m_subaddress_index = subaddress_idx;
          output->m_amount = out_amount;
          output->m_is_spent = true;
          output->m_index = spent_output->m_out_index;
          output->m_tx = tx_wallet;

          input_sum += out_amount;
        }

        sort(outgoing_transfer->m_subaddress_indices.begin(), outgoing_transfer->m_subaddress_indices.end());

        tx_wallet->m_outgoing_transfer = outgoing_transfer;
      }

      sort(tx_wallet->m_incoming_transfers.begin(), tx_wallet->m_incoming_transfers.end(), monero_utils::incoming_transfer_before);

      if (is_confirmed && block != nullptr && !tx_query->meets_criteria(tx_wallet.get())) {
        block->m_txs.erase(std::remove(block->m_txs.begin(), block->m_txs.end(), tx_wallet), block->m_txs.end());
      }

      for (const std::shared_ptr<monero_transfer>& transfer : tx_wallet->filter_transfers(*_query)) transfers.push_back(transfer);
    }

    m_cache->for_each_unconfirmed_tx([&](const std::string& hash, const std::shared_ptr<monero_tx_wallet>& txwallet) {
      if (known_hashes.find(hash) != known_hashes.end()) return;
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
      txwallet->copy(txwallet, tx_wallet);
      tx_wallet->m_weight = boost::none;
      tx_wallet->m_inputs.clear();
      tx_wallet->m_outputs.clear();
      tx_wallet->m_ring_size = boost::none;
      tx_wallet->m_key = boost::none;
      tx_wallet->m_full_hex = boost::none;
      tx_wallet->m_metadata = boost::none;
      tx_wallet->m_last_relayed_timestamp = boost::none;
      for (const std::shared_ptr<monero_transfer>& transfer : tx_wallet->filter_transfers(*_query)) {
        transfers.push_back(transfer);
      }
    });

    return transfers;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs_aux(const monero_output_query& query) const {
    MTRACE("monero_wallet_light::get_outputs_aux(query)");

    // copy and normalize query
    std::shared_ptr<monero_output_query> _query;
    if (query.m_tx_query == nullptr) {
      std::shared_ptr<monero_output_query> query_ptr = std::make_shared<monero_output_query>(query); // convert to shared pointer for copy
      _query = query_ptr->copy(query_ptr, std::make_shared<monero_output_query>());
    } else {
      std::shared_ptr<monero_tx_query> tx_query = query.m_tx_query->copy(query.m_tx_query, std::make_shared<monero_tx_query>());
      if (query.m_tx_query->m_output_query != nullptr && query.m_tx_query->m_output_query.get() == &query) {
        _query = tx_query->m_output_query;
      } else {
        if (query.m_tx_query->m_output_query != nullptr) throw std::runtime_error("Output query's tx query must be a circular reference or null");
        std::shared_ptr<monero_output_query> query_ptr = std::make_shared<monero_output_query>(query);  // convert query to shared pointer for copy
        _query = query_ptr->copy(query_ptr, std::make_shared<monero_output_query>());
        _query->m_tx_query = tx_query;
      }
    }
    if (_query->m_tx_query == nullptr) _query->m_tx_query = std::make_shared<monero_tx_query>();
    std::shared_ptr<monero_tx_query> tx_query = _query->m_tx_query;

    // get light wallet data
    std::vector<std::shared_ptr<monero_output_light>> outs;

    if (query.m_account_index != boost::none) {
      if (query.m_subaddress_index == boost::none) {
        outs = m_cache->get_outputs(query.m_account_index.get());
      }
      else {
        outs = m_cache->get_outputs(query.m_account_index.get(), query.m_subaddress_index.get());
      }
    } else outs = m_cache->m_outputs;

    std::vector<std::shared_ptr<monero_output_wallet>> outputs;

    // cache unique txs and blocks
    std::map<std::string, std::shared_ptr<monero_tx_wallet>> tx_map;
    std::map<uint64_t, std::shared_ptr<monero_block>> block_map;
    const auto pool_key_images = m_cache->get_pool_key_images();
    for (const auto &out : outs) {
      // TODO: skip tx building if output excluded by indices, etc
      std::shared_ptr<monero_tx_wallet> tx = build_tx_with_vout(m_cache, out, pool_key_images);
      monero_utils::merge_tx(tx, tx_map, block_map);
    }

    std::vector<std::shared_ptr<monero_tx_wallet>> txs;

    for (std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.begin(); tx_iter != tx_map.end(); tx_iter++) {
      txs.push_back(tx_iter->second);
    }

    sort(txs.begin(), txs.end(), monero_utils::tx_height_less_than);

    // filter and return outputs
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {

      // sort outputs
      sort(tx->m_outputs.begin(), tx->m_outputs.end(), monero_utils::vout_before);

      // collect queried outputs, erase if excluded
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(*_query)) outputs.push_back(output);

      // remove txs without outputs
      if (tx->m_outputs.empty() && tx->m_block != nullptr) tx->m_block.get()->m_txs.erase(std::remove(tx->m_block.get()->m_txs.begin(), tx->m_block.get()->m_txs.end(), tx), tx->m_block.get()->m_txs.end()); // TODO, no way to use const_iterator?
    }

    // free query and return outputs
    monero_utils::free(tx_query);
    return outputs;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses_aux(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    sync_op_lock op_lock(*this); // do not read m_subaddrs while the sync thread is reassigning it
    // must provide subaddress indices
    std::vector<uint32_t> subaddress_idxs;
    if (subaddress_indices.empty()) {
      if (m_subaddrs.m_all_subaddrs != nullptr)
        subaddress_idxs = m_subaddrs.m_all_subaddrs->get_subaddresses_indices(account_idx);
      if (subaddress_idxs.empty()) subaddress_idxs.push_back(0);
    }
    else subaddress_idxs = subaddress_indices;

    if (subaddress_idxs.empty()) return std::vector<monero_subaddress>();

    // initialize subaddresses at indices
    return monero_wallet_keys::get_subaddresses(account_idx, subaddress_idxs);
  }

  bool monero_wallet_light::is_output_spent(const std::shared_ptr<monero_output_light> &output, const std::unordered_set<std::string>& pool_key_images) const {
    uint32_t account_idx = output->m_recipient->m_maj_i;
    uint32_t subaddress_idx = output->m_recipient->m_min_i;
    const std::string& tx_pub_key = output->m_tx_pub_key.get();
    uint64_t output_idx = output->m_index.get();

    bool spent = false;

    for (auto& key_image : output->m_spend_key_images) {
      if (is_key_image_ours(key_image, tx_pub_key, output_idx, account_idx, subaddress_idx)) {
        output->m_key_image = key_image;
        spent = true;
        break;
      }
    }

    bool checked_unconfirmed = false;

    if (!spent && !output->is_key_image_known()) {
      try {
        output->m_key_image = generate_key_image(tx_pub_key, output_idx, account_idx, subaddress_idx)->m_hex;
        // check key image is spent in unconfirmed transactions
        spent = m_cache->is_key_image_spent(output->m_key_image.get(), pool_key_images);
        checked_unconfirmed = true;
      }
      catch (...) {
        if (is_view_only()) m_key_image_cache->set(nullptr, tx_pub_key, output_idx, account_idx, subaddress_idx, true);
        return false;
      }
    }

    if (!checked_unconfirmed && !spent && output->is_key_image_known()) {
      // check key image is spent in unconfirmed transactions
      spent = m_cache->is_key_image_spent(output->m_key_image.get(), pool_key_images);
    }

    return spent;
  }

  bool monero_wallet_light::is_spend_real(const std::shared_ptr<monero_spend>& spend) const {
    if (spend->m_key_image == boost::none) return false;
    std::string key_image = spend->m_key_image.get();
    return is_key_image_ours(key_image, spend->m_tx_pub_key.get(), spend->m_out_index.get(), spend->m_sender->m_maj_i, spend->m_sender->m_min_i);
  }

  void monero_wallet_light::run_sync_loop() {
    if (m_sync_loop_running) return;  // only run one loop at a time
    m_sync_loop_running = true;

    // start sync loop thread
    // TODO: use global threadpool, background sync wasm wallet in c++ thread
    m_syncing_thread = boost::thread([this]() {

      // sync while enabled and not paused by a wallet operation
      while (m_syncing_enabled) {
        if (m_num_sync_pauses == 0) {
          try { lock_and_sync(); }
          catch (std::exception const& e) { MERROR("monero_wallet_light failed to background synchronize: " << e.what()); }
          catch (...) { MERROR("monero_wallet_light failed to background synchronize: unknown error"); }
        }

        // only wait if syncing still enabled
        if (m_syncing_enabled) {
          boost::mutex::scoped_lock lock(m_syncing_mutex);
          boost::posix_time::milliseconds wait_for_ms(m_syncing_interval.load());
          m_sync_cv.timed_wait(lock, wait_for_ms);
        }
      }

      m_sync_loop_running = false;
    });
  }

  monero_wallet_light::sync_op_lock::sync_op_lock(const monero_wallet_light& wallet) : m_wallet(wallet) {
    wallet.m_num_sync_pauses++; // pause background sync
    wallet.m_sync_data_mutex.lock();
  }

  monero_wallet_light::sync_op_lock::~sync_op_lock() {
    m_wallet.m_sync_data_mutex.unlock();
    m_wallet.m_num_sync_pauses--; // resume background sync
  }

  monero_sync_result monero_wallet_light::lock_and_sync(boost::optional<uint64_t> start_height) {
    bool rescan = m_rescan_on_sync.exchange(false);
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex); // synchronize sync() and syncAsync()
    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    do {
      // skip if daemon is not connected or synced
      if (m_is_connected && is_daemon_synced()) {

        // rescan blockchain if requested
        if (rescan) rescan_blockchain(); // infinite loop?

        // sync wallet
        result = sync_aux(start_height);
      }
    } while (!rescan && (rescan = m_rescan_on_sync.exchange(false))); // repeat if not rescanned and rescan was requested
    return result;
  }

  monero_sync_result monero_wallet_light::sync_aux(boost::optional<uint64_t> start_height) {
    MTRACE("monero_wallet_light::sync_aux()");

    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    // attempt to refresh which may throw exception
    try {
      result = refresh();
    } catch (std::exception& e) {
      m_wallet_listener->on_sync_end(); // signal end of sync to reset listener's start and end heights
      throw;
    }

    // notify listeners of sync end and check for updated funds
    m_wallet_listener->on_sync_end();
    LOG_PRINT_L1("Light wallet refresh done, blocks received: " << result.m_num_blocks_fetched << ", balance (all accounts): " << cryptonote::print_money(get_balance()) << ", unlocked: " << cryptonote::print_money(get_unlocked_balance()));
    return result;
  }

  monero_sync_result monero_wallet_light::refresh() {
    const std::string& address = get_primary_address();
    const std::string& view_key = get_private_view_key();
    // determine sync start height
    uint64_t last_height = get_height();

    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    const uint64_t old_outs_amount = m_cache->get_amount();

    auto addr_info = m_client->get_address_info();
    uint64_t new_height = addr_info->m_scanned_block_height.value_or(0) + 1;
    if (addr_info->m_start_height != boost::none) {
      uint64_t start_height = addr_info->m_start_height.get();
      if (last_height < start_height) last_height = start_height == 0 ? 0 : start_height + 1;
    }

    // notify listeners of sync start
    m_wallet_listener->on_sync_start(last_height);

    if (new_height == last_height) {
      m_cache->set_sync_status(*addr_info);
      return result;
    }

    boost::unique_lock<boost::recursive_mutex> lock(m_sync_data_mutex);

    monero_get_address_txs_response address_txs = *m_client->get_address_txs();
    monero_get_unspent_outs_response unspent_outs = *m_client->get_unspent_outs(0, 0);
    m_subaddrs = *m_client->get_subaddrs();
    process_subaddresses();
    process_txs(address_txs);
    unspent_outs.m_amount = process_outputs(unspent_outs.m_outputs, unspent_outs.m_amount.value_or(0));
    const uint64_t new_outs_amount = unspent_outs.m_amount.get();
    result.m_received_money = new_outs_amount > old_outs_amount;
    m_cache->refresh(unspent_outs, address_txs, *addr_info);

    lock.unlock();

    uint64_t current_height = get_height();
    uint64_t daemon_height = get_daemon_height();
    uint64_t restore_height = get_restore_height();

    if (restore_height < current_height) {
      if (last_height < restore_height) last_height = restore_height;
      uint64_t blocks_fetched = current_height - last_height;
      result.m_num_blocks_fetched = blocks_fetched;

      if (current_height > last_height) {
        // notify blocks processed by lws
        for(uint64_t block_height = last_height; block_height < current_height; block_height++) {
          m_wallet_listener->on_new_block(block_height);
        }
      }
    }

    return result;
  }

  // --------------------------- LWS UTILS --------------------------

  void monero_wallet_light::process_txs(monero_get_address_txs_response& address_txs) {
    std::vector<size_t> txs_to_remove;
    size_t tx_idx = 0;

    for(auto &tx : address_txs.m_transactions) {
      uint64_t tx_total_sent = tx->m_total_sent.get();
      uint64_t tx_total_received = tx->m_total_received.get();
      std::vector<size_t> outs_to_remove;
      size_t out_idx = 0;

      for (auto& spend : tx->m_spent_outputs) {
        if (!is_spend_real(spend)) {
          uint64_t spend_amount = spend->m_amount.get();
          if (spend_amount > tx_total_sent) throw std::runtime_error("tx total sent is negative: " + tx->m_hash.get());
          tx_total_sent -= spend_amount;
          outs_to_remove.push_back(out_idx);
        }
        out_idx++;
      }

      tx->m_total_sent = tx_total_sent;
      tx->m_total_received = tx_total_received;
      if (tx_total_received == 0 && tx_total_sent == 0) {
        txs_to_remove.push_back(tx_idx);
      }
      else for (auto it = outs_to_remove.rbegin(); it != outs_to_remove.rend(); ++it) tx->m_spent_outputs.erase(tx->m_spent_outputs.begin() + *it);

      tx_idx++;
    }

    for (auto it = txs_to_remove.rbegin(); it != txs_to_remove.rend(); ++it) address_txs.m_transactions.erase(address_txs.m_transactions.begin() + *it);
  }

  uint64_t monero_wallet_light::process_outputs(std::vector<std::shared_ptr<monero_output_light>>& outputs, uint64_t total_amount) {
    const auto pool_key_images = m_cache->get_pool_key_images();
    for (auto& output : outputs) {
      if (!is_output_spent(output, pool_key_images)) continue;
      total_amount -= output->m_amount.get();
    }

    sort(outputs.begin(), outputs.end(), output_before);
    return total_amount;
  }

  void monero_wallet_light::process_subaddresses() {
    const cryptonote::account_keys &account_keys = m_account.get_keys();
    hw::device &hwdev = m_account.get_device();
    m_subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};
    if (m_subaddrs.m_all_subaddrs == nullptr) return;
    for (const auto& kv : *m_subaddrs.m_all_subaddrs) {
      const uint32_t account_idx = kv.first;

      // indices up to the watermark already have a cached spend pubkey; skip the EC scalar mult below
      const auto watermark_it = m_processed_subaddr_max_index.find(account_idx);
      const bool has_watermark = watermark_it != m_processed_subaddr_max_index.end();
      const uint32_t watermark = has_watermark ? watermark_it->second : 0;
      uint32_t highest = watermark;

      for (const auto& index_range : kv.second) {
        const uint32_t range_start = index_range->at(0);
        const uint32_t range_end = index_range->at(1);
        for (uint32_t i = range_start; i <= range_end; i++) {
          if (account_idx == 0 && i == 0) continue;
          if (has_watermark && i <= watermark) continue;
          const auto& subaddress_spend_pub_key = hwdev.get_subaddress_spend_public_key(account_keys, {account_idx, i});
          m_subaddresses[subaddress_spend_pub_key] = {account_idx, i};
        }
        if (range_end > highest) highest = range_end;
      }

      m_processed_subaddr_max_index[account_idx] = highest;
    }
  }

  void monero_wallet_light::upsert_subaddrs(uint32_t account_idx, uint32_t subaddress_idx, bool get_all) {
    monero_subaddrs subaddrs;
    auto index_range = std::make_shared<monero_index_range>(0, subaddress_idx == 0 ? 0 : subaddress_idx - 1);

    for(uint32_t i = 0; i <= account_idx; i++) {
      subaddrs[i] = std::vector<std::shared_ptr<monero_index_range>>();
      subaddrs[i].push_back(index_range);
    }

    auto response = m_client->upsert_subaddrs(subaddrs, get_all);

    if (get_all) {
      m_subaddrs.m_all_subaddrs = response->m_all_subaddrs;
      process_subaddresses();
    }
  }

  // --------------------------- STATIC WALLET UTILS --------------------------

  bool monero_wallet_light::wallet_exists(const std::string& primary_address, const std::string& private_view_key, const std::shared_ptr<monero_rpc_connection>& rpc) {
    MTRACE("monero_wallet_light::wallet_exists(" << primary_address << ")");
    try {
      light_wallet_client client(rpc, primary_address, private_view_key);
      client.login(false, false);
      return true;
    }
    catch (const monero_rpc_error& ex) {
      return ex.code == 401;
    }
  }

  bool monero_wallet_light::wallet_exists(const monero_wallet_config& config, const std::shared_ptr<monero_rpc_connection>& rpc) {
    MTRACE("monero_wallet_light::wallet_exists(" << config.serialize() << ")");
    if (rpc == nullptr || rpc->m_uri == boost::none) throw std::runtime_error("Cannot check if wallet exists without a valid RPC connection");

    std::string seed = config.m_seed != boost::none ? config.m_seed.get() : "";
    std::string primary_address = config.m_primary_address != boost::none ? config.m_primary_address.get() : "";
    std::string private_view_key = config.m_private_view_key != boost::none ? config.m_private_view_key.get() : "";

    if (seed.empty() && primary_address.empty() && private_view_key.empty()) return false;
    if (!seed.empty() && (primary_address.empty() || private_view_key.empty())) {
      // derive primary address and private view key from seed
      monero_wallet_keys* wallet_keys = monero_wallet_keys::create_wallet_from_seed(config);
      primary_address = wallet_keys->get_primary_address();
      private_view_key = wallet_keys->get_private_view_key();
      delete wallet_keys;
    } else if ((!primary_address.empty() && private_view_key.empty()) || (primary_address.empty() && !private_view_key.empty())) {
      throw std::runtime_error("Must provide both primary address and private view key to check if wallet exists");
    }
    return wallet_exists(primary_address, private_view_key, rpc);
  }

  monero_wallet_light* monero_wallet_light::open_wallet(const monero_wallet_config& config, const std::shared_ptr<monero_rpc_connection>& rpc) {
    monero_wallet_config _config = config.copy();
    if (config.m_seed != boost::none && !config.m_seed->empty()) return create_wallet_from_seed(_config, rpc);
    return create_wallet_from_keys(_config, rpc);
  }

  monero_wallet_light* monero_wallet_light::create_wallet(const monero_wallet_config& config, const std::shared_ptr<monero_rpc_connection>& rpc) {
    MTRACE("monero_wallet_light::create_wallet(config)");

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config.m_server != nullptr) throw std::runtime_error("Cannot provide server config for light wallet");
    if (config.m_path == boost::none) config_normalized.m_path = std::string("");
    if (config.m_password == boost::none) config_normalized.m_password = std::string("");
    if (config.m_language == boost::none) config_normalized.m_language = std::string("");
    if (config.m_seed == boost::none) config_normalized.m_seed = std::string("");
    if (config.m_primary_address == boost::none) config_normalized.m_primary_address = std::string("");
    if (config.m_private_spend_key == boost::none) config_normalized.m_private_spend_key = std::string("");
    if (config.m_private_view_key == boost::none) config_normalized.m_private_view_key = std::string("");
    if (config.m_seed_offset == boost::none) config_normalized.m_seed_offset = std::string("");
    if (config.m_is_multisig == boost::none) config_normalized.m_is_multisig = false;
    if (config.m_account_lookahead != boost::none && config.m_subaddress_lookahead == boost::none) throw std::runtime_error("No subaddress lookahead provided with account lookahead");
    if (config.m_account_lookahead == boost::none && config.m_subaddress_lookahead != boost::none) throw std::runtime_error("No account lookahead provided with subaddress lookahead");
    if (config_normalized.m_language.get().empty()) config_normalized.m_language = std::string("English");
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    // create wallet

    if (!config_normalized.m_seed.get().empty()) {
      if (rpc != nullptr && rpc->m_uri != boost::none && wallet_exists(config, rpc)) throw std::runtime_error("Wallet already exists");
      return create_wallet_from_seed(config_normalized, rpc);
    }
    else if (!config_normalized.m_primary_address.get().empty() || !config_normalized.m_private_spend_key.get().empty() || !config_normalized.m_private_view_key.get().empty()) {
      if (rpc != nullptr && rpc->m_uri != boost::none && wallet_exists(config_normalized, rpc)) throw std::runtime_error("Wallet already exists");
      return create_wallet_from_keys(config_normalized, rpc);
    } else {
      return create_wallet_random(config_normalized, rpc);
    }
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_seed(monero_wallet_config& config, const std::shared_ptr<monero_rpc_connection>& rpc) {
    MTRACE("monero_wallet_light::create_wallet_from_seed(...)");

    // validate config
    if (config.m_is_multisig != boost::none && config.m_is_multisig.get()) throw std::runtime_error("Restoring from multisig seed not supported");
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config.m_seed == boost::none || config.m_seed.get().empty()) throw std::runtime_error("Must provide wallet seed");

    // validate mnemonic and get recovery key and language
    crypto::secret_key spend_key_sk;
    std::string language = config.m_language != boost::none ? config.m_language.get() : "";
    bool is_valid = crypto::ElectrumWords::words_to_bytes(config.m_seed.get(), spend_key_sk, language);
    if (!is_valid) throw std::runtime_error("Invalid mnemonic");
    if (language == crypto::ElectrumWords::old_language_name) language = Language::English().get_language_name();

    // validate language
    if (!crypto::ElectrumWords::is_valid_language(language)) throw std::runtime_error("Invalid language: " + language);

    // apply offset if given
    bool offset_set = config.m_seed_offset != boost::none && !config.m_seed_offset.get().empty();
    if (offset_set) spend_key_sk = cryptonote::decrypt_key(spend_key_sk, config.m_seed_offset.get());

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light(rpc);
    wallet->m_account = cryptonote::account_base{};
    crypto::secret_key spend_key_val = wallet->m_account.generate(spend_key_sk, true, false);

    // initialize remaining wallet
    wallet->m_network_type = config.m_network_type.get();
    wallet->m_language = language;
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_val, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    if (offset_set && wallet->m_seed == config.m_seed) throw std::runtime_error("Expected different seed");
    wallet->init_common();
    wallet->m_is_view_only = false;

    if (wallet->is_connected_to_daemon()) {
      auto login_response = wallet->m_client->login(true, true);
      // seed m_start_height from login(), in case it's set, so get_restore_height() works before the first refresh()
      if (login_response->m_start_height != boost::none) wallet->m_cache->set_start_height(login_response->m_start_height.get());
      if (config.m_account_lookahead != boost::none) wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      if (config.m_restore_height != boost::none) wallet->set_restore_height(config.m_restore_height.get());
    }
    else if (config.m_restore_height != boost::none) throw std::runtime_error("Cannote restore wallet from height: wallet is not connected to lws");

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(monero_wallet_config& config, const std::shared_ptr<monero_rpc_connection>& rpc) {
    MTRACE("monero_wallet_light::create_wallet_from_keys(...)");

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
    if (config.m_private_spend_key == boost::none) config_normalized.m_private_spend_key = std::string("");
    if (config.m_private_view_key == boost::none) config_normalized.m_private_view_key = std::string("");
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

    // parse and validate private spend key
    crypto::secret_key spend_key_sk;
    bool has_spend_key = false;
    if (!config_normalized.m_private_spend_key.get().empty()) {
      cryptonote::blobdata spend_key_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(config.m_private_spend_key.get(), spend_key_data) || spend_key_data.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("failed to parse secret spend key");
      }
      has_spend_key = true;
      spend_key_sk = *reinterpret_cast<const crypto::secret_key*>(spend_key_data.data());
    }

    // parse and validate private view key
    bool has_view_key = true;
    crypto::secret_key view_key_sk;
    if (config_normalized.m_private_view_key.get().empty()) {
      if (has_spend_key) has_view_key = false;
      else throw std::runtime_error("Neither spend key nor view key supplied");
    }
    if (has_view_key) {
      cryptonote::blobdata view_key_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(config_normalized.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("failed to parse secret view key");
      }
      view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());
    }

    // parse and validate address
    cryptonote::address_parse_info address_info;
    if (config_normalized.m_primary_address == boost:: none || config_normalized.m_primary_address.get().empty()) {
      if (has_view_key) throw std::runtime_error("must provide address if providing private view key");
    } else {
      if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config_normalized.m_network_type.get()), config_normalized.m_primary_address.get())) throw std::runtime_error("failed to parse address");

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (has_spend_key) {
        if (!crypto::secret_key_to_public_key(spend_key_sk, pkey)) throw std::runtime_error("failed to verify secret spend key");
        if (address_info.address.m_spend_public_key != pkey) throw std::runtime_error("spend key does not match address");
      }
      if (has_view_key) {
        if (!crypto::secret_key_to_public_key(view_key_sk, pkey)) throw std::runtime_error("failed to verify secret view key");
        if (address_info.address.m_view_public_key != pkey) throw std::runtime_error("view key does not match address");
      }
    }

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light(rpc);
    if (has_spend_key && has_view_key) wallet->m_account.create_from_keys(address_info.address, spend_key_sk, view_key_sk);
    else if (has_spend_key) wallet->m_account.generate(spend_key_sk, true, false);
    else wallet->m_account.create_from_viewkey(address_info.address, view_key_sk);

    // initialize remaining wallet
    wallet->m_is_view_only = !has_spend_key;
    wallet->m_network_type = config_normalized.m_network_type.get();
    if (!config_normalized.m_private_spend_key.get().empty()) {
      wallet->m_language = config_normalized.m_language.get();
      epee::wipeable_string wipeable_mnemonic;
      if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
      wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    }

    wallet->init_common();
    if (wallet->is_connected_to_daemon()) {
      auto login_response = wallet->m_client->login(true, false);
      // seed m_start_height from login(), in case it's set, so get_restore_height() works before the first refresh()
      if (login_response->m_start_height != boost::none) wallet->m_cache->set_start_height(login_response->m_start_height.get());
      if (config.m_account_lookahead != boost::none) wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      if (config.m_restore_height != boost::none) wallet->set_restore_height(config.m_restore_height.get());
    }
    else if (config.m_restore_height != boost::none) throw std::runtime_error("Cannote restore wallet from height: wallet is not connected to lws");

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_random(monero_wallet_config& config, const std::shared_ptr<monero_rpc_connection>& rpc) {
    MTRACE("monero_wallet_light::create_wallet_random(...)");

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config_normalized.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config_normalized.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

    // initialize random wallet account
    monero_wallet_light* wallet = new monero_wallet_light(rpc);
    crypto::secret_key spend_key_sk = wallet->m_account.generate();

    // initialize remaining wallet
    wallet->m_network_type = config_normalized.m_network_type.get();
    wallet->m_language = config_normalized.m_language.get();
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    wallet->init_common();
    wallet->m_is_view_only = false;

    if (wallet->is_connected_to_daemon()) {
      auto login_response = wallet->m_client->login(true, true);
      // seed m_start_height from login(), in case it's set, so get_restore_height() works before the first refresh()
      if (login_response->m_start_height != boost::none) wallet->m_cache->set_start_height(login_response->m_start_height.get());
      if (config.m_account_lookahead != boost::none) {
        wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      }
    }

    return wallet;
  }

}
