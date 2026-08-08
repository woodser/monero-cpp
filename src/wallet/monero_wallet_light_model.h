/**
 * Copyright (c) everoddaneven
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
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * All rights reserved.
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
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

#pragma once

#include "wallet/monero_wallet_model.h"
#include "wallet/monero_wallet_keys.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "utils/monero_utils.h"
#include <map>

/**
 * Internal data model for monero_wallet_light.
 */
namespace monero {

  // ------------------------------- LWS DATA MODEL -------------------------------

  struct monero_daemon_status {
    boost::optional<std::string> m_state;
    boost::optional<uint64_t> m_outgoing_connections_count;
    boost::optional<uint64_t> m_incoming_connections_count;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_target_height;
    boost::optional<monero_network_type> m_network_type;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_status>& version);
  };

  struct monero_server_version {
    boost::optional<std::string> m_server_type;
    boost::optional<std::string> m_server_version;
    boost::optional<std::string> m_last_git_commit_hash;
    boost::optional<std::string> m_last_git_commit_date;
    boost::optional<std::string> m_git_branch_name;
    boost::optional<std::string> m_monero_version_full;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<uint32_t> m_api;
    boost::optional<uint32_t> m_max_subaddresses;
    boost::optional<bool> m_testnet;
    boost::optional<monero_network_type> m_network_type;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_server_version>& version);
  };

  struct monero_address_meta {
    uint32_t m_maj_i = 0;
    uint32_t m_min_i = 0;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_address_meta>& address_meta);
  };

  struct monero_output_light {
    boost::optional<std::string> m_rct;
    boost::optional<std::string> m_tx_hash;
    boost::optional<std::string> m_tx_prefix_hash;
    boost::optional<std::string> m_public_key;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<std::string> m_key_image;
    boost::optional<uint64_t> m_tx_id;
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_index;
    boost::optional<uint64_t> m_global_index;
    boost::optional<uint64_t> m_timestamp;
    boost::optional<uint64_t> m_height;
    boost::optional<size_t> m_cache_index;
    boost::optional<bool> m_frozen;
    std::shared_ptr<monero_address_meta> m_recipient;
    std::vector<std::string> m_spend_key_images;

    bool is_key_image_known() const;
    bool is_rct() const;
    bool is_coinbase() const;
    bool is_spent() const;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_light>& output);
  };

  struct monero_spend {
    boost::optional<std::string> m_key_image;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_out_index;
    boost::optional<uint32_t> m_mixin;
    std::shared_ptr<monero_address_meta> m_sender;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_spend>& spend);
    std::shared_ptr<monero_spend> copy(const std::shared_ptr<monero_spend>& src, const std::shared_ptr<monero_spend>& tgt) const;
  };

  struct monero_tx_light {
    boost::optional<std::string> m_hash;
    boost::optional<std::string> m_payment_id;
    boost::optional<uint64_t> m_id;
    boost::optional<uint64_t> m_timestamp;
    boost::optional<uint64_t> m_total_received;
    boost::optional<uint64_t> m_total_sent;
    boost::optional<uint64_t> m_fee;
    boost::optional<uint64_t> m_unlock_time;
    boost::optional<uint64_t> m_height;
    boost::optional<uint32_t> m_mixin;
    boost::optional<bool> m_coinbase;
    boost::optional<bool> m_mempool;
    std::shared_ptr<monero_address_meta> m_recipient;
    std::vector<std::shared_ptr<monero_spend>> m_spent_outputs;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_light>& transaction);
    std::shared_ptr<monero_tx_light> copy(const std::shared_ptr<monero_tx_light>& src, const std::shared_ptr<monero_tx_light>& tgt, bool exclude_spend = false) const;
  };

  struct monero_random_outputs {
    boost::optional<uint64_t> m_amount;
    std::vector<std::shared_ptr<monero_output_light>> m_outputs;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_random_outputs>& random_outputs);
  };

  class monero_index_range : public std::vector<uint32_t> {
  public:
    monero_index_range() = default;
    monero_index_range(const uint32_t min_i, const uint32_t maj_i);

    std::vector<uint32_t> to_subaddress_indices() const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_index_range>& index_range);
  };

  class monero_subaddrs : public std::map<uint32_t, std::vector<std::shared_ptr<monero_index_range>>>, public serializable_struct {
  public:
    bool contains(const uint32_t account_idx) const { return find(account_idx) != end(); }
    bool is_upsert(const uint32_t account_idx) const { return account_idx == 0 || contains(account_idx); }
    uint32_t get_last_account_index() const;
    uint32_t get_last_subaddress_index(const uint32_t account_idx) const;
    std::vector<uint32_t> get_subaddresses_indices(const uint32_t account_idx) const;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_subaddrs>& subaddrs);
  };

  typedef std::unordered_map<std::string/*public_key*/, std::vector<std::shared_ptr<monero_output_light>>> monero_output_map;

  struct monero_outputs_decoys_tie {
    std::vector<std::shared_ptr<monero_random_outputs>> m_decoys;
    monero_output_map m_tie_attempt;

    static monero_outputs_decoys_tie tie(const std::vector<std::shared_ptr<monero_output_light>>& outputs, std::vector<std::shared_ptr<monero_random_outputs>> decoys, const boost::optional<monero_output_map>& prior_tie_attempt);
  };

  struct monero_output_selection {
    uint32_t m_mixin;
    uint64_t m_fee;
    uint64_t m_amount;
    uint64_t m_change_amount;
    std::vector<std::shared_ptr<monero_output_light>> m_selected_outs;

    std::vector<size_t> get_output_indexes() const {
      std::vector<size_t> indexes;
      indexes.reserve(m_selected_outs.size());
      for (const auto &output : m_selected_outs) {
        if (output->m_cache_index == boost::none) throw std::runtime_error("output doesn't belong to the wallet");
        indexes.push_back(output->m_cache_index.get());
      }
      return indexes;
    }

  };

  // ------------------------------ RPC Params ---------------------------------

  struct monero_wallet_params : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;

    monero_wallet_params(const std::string& address, const std::string& view_key): m_address(address), m_view_key(view_key) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_random_outs_params : public serializable_struct {
    boost::optional<uint32_t> m_count;
    std::vector<uint64_t> m_amounts;

    monero_get_random_outs_params(uint32_t count, const std::vector<uint64_t>& amounts): m_count(count), m_amounts(amounts) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_unspent_outs_params : public monero_wallet_params {
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_dust_threshold;
    boost::optional<uint32_t> m_mixin;
    boost::optional<bool> m_use_dust;

    monero_get_unspent_outs_params(const std::string& address, const std::string& view_key, uint64_t amount, uint32_t mixin, bool use_dust, uint64_t dust_threshold): monero_wallet_params(address, view_key), m_amount(amount), m_mixin(mixin), m_use_dust(use_dust), m_dust_threshold(dust_threshold) {}
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_import_wallet_params : public monero_wallet_params {
    boost::optional<uint64_t> m_from_height;

    monero_import_wallet_params(const std::string& address, const std::string& view_key, uint64_t from_height): monero_wallet_params(address, view_key), m_from_height(from_height) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_login_params : public monero_wallet_params {
    boost::optional<bool> m_create_account;
    boost::optional<bool> m_generated_locally;

    monero_login_params(const std::string& address, const std::string& view_key, bool create_account, bool generated_locally): monero_wallet_params(address, view_key), m_create_account(create_account), m_generated_locally(generated_locally) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_submit_raw_tx_params : public serializable_struct {
    boost::optional<std::string> m_tx;

    monero_submit_raw_tx_params(const std::string& tx): m_tx(tx) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_upsert_subaddrs_params : public monero_wallet_params {
    boost::optional<bool> m_get_all;
    boost::optional<monero_subaddrs> m_subaddrs;

    monero_upsert_subaddrs_params(const std::string& address, const std::string& view_key, const monero_subaddrs& subaddrs, bool get_all): monero_wallet_params(address, view_key), m_subaddrs(subaddrs), m_get_all(get_all) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  // ------------------------------ RPC Response ---------------------------------

  struct monero_get_address_info_response {
    boost::optional<uint64_t> m_locked_funds;
    boost::optional<uint64_t> m_total_received;
    boost::optional<uint64_t> m_total_sent;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_transaction_height;
    boost::optional<uint64_t> m_blockchain_height;
    std::vector<std::shared_ptr<monero_spend>> m_spent_outputs;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_address_info_response>& response);
  };

  struct monero_get_address_txs_response {
    boost::optional<uint64_t> m_total_received;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_blockchain_height;
    std::vector<std::shared_ptr<monero_tx_light>> m_transactions;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_address_txs_response>& response);
  };

  struct monero_get_random_outs_response {
    std::vector<std::shared_ptr<monero_random_outputs>> m_amount_outs;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_random_outs_response>& response);
  };

  struct monero_get_unspent_outs_response {
    boost::optional<uint64_t> m_per_byte_fee;
    boost::optional<uint64_t> m_fee_mask;
    boost::optional<uint64_t> m_amount;
    std::vector<std::shared_ptr<monero_output_light>> m_outputs;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_unspent_outs_response>& response);
  };

  struct monero_import_wallet_response {
    boost::optional<std::string> m_payment_address;
    boost::optional<std::string> m_payment_id;
    boost::optional<std::string> m_status;
    boost::optional<uint64_t> m_import_fee;
    boost::optional<bool> m_new_request;
    boost::optional<bool> m_request_fullfilled;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_import_wallet_response>& response);
  };

  struct monero_login_response {
    boost::optional<uint64_t> m_start_height;
    boost::optional<bool> m_new_address;
    boost::optional<bool> m_generated_locally;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_login_response>& response);
  };

  struct monero_submit_raw_tx_response {
    boost::optional<std::string> m_status;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_submit_raw_tx_response>& response);
  };

  struct monero_subaddrs_response {
    std::shared_ptr<monero_subaddrs> m_new_subaddrs;
    std::shared_ptr<monero_subaddrs> m_all_subaddrs;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_subaddrs_response>& response);
  };

  // ------------------------------- MONERO WALLET CACHE -------------------------------

  struct monero_output_wallet_light : public monero_output_wallet {
    boost::optional<bool> m_is_change;
  };

  class monero_wallet_cache {
  public:
    std::vector<std::shared_ptr<monero_output_light>> m_outputs;

    monero_wallet_cache(const std::shared_ptr<monero_key_image_cache>& key_image_cache) : m_key_image_cache(key_image_cache) { }

    uint64_t get_blockchain_height() const { return m_blockchain_height; }
    uint64_t get_last_block_reward() const { return m_block_reward > 1 ? m_block_reward - 2 : m_block_reward; } // TODO why wallet full gives to 2 piconero less ?
    uint64_t get_scanned_block_height() const { return m_scanned_block_height; }
    uint64_t get_start_height() const { return m_start_height; }
    void set_sync_status(const monero_get_address_info_response& address_info);

    std::vector<std::shared_ptr<monero_tx_light>> get_txs() const { return m_tx_list; }
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_wallet>> get_unconfirmed_txs() const;
    std::string get_tx_prefix_hash(const std::string& tx_hash) const;
    void refresh(const monero_get_unspent_outs_response& unspent_outs, const monero_get_address_txs_response& address_txs, const monero_get_address_info_response& address_info);
    void add_unconfirmed_tx(const std::shared_ptr<monero_tx_wallet>& tx, const std::string& change_pubkey = "");

    boost::optional<std::string> get_change_pubkey(const std::string& tx_hash) const {
      auto it = m_self_constructed_txs.find(tx_hash);
      if (it == m_self_constructed_txs.end() || it->second == nullptr) return boost::none;
      for (const auto& out : it->second->m_outputs) {
        auto change_out = std::dynamic_pointer_cast<monero_output_wallet_light>(out);
        if (change_out != nullptr && change_out->m_is_change.value_or(false)) return change_out->m_stealth_public_key.value_or("");
      }
      return std::string("");
    }

    std::vector<std::shared_ptr<monero_destination>> get_tx_destinations(const std::string& tx_hash) const {
      auto it = m_self_constructed_txs.find(tx_hash);
      if (it == m_self_constructed_txs.end() || it->second == nullptr || it->second->m_outgoing_transfer == nullptr) return std::vector<std::shared_ptr<monero_destination>>();
      std::vector<std::shared_ptr<monero_destination>> destinations;
      for (const auto& destination : it->second->m_outgoing_transfer->m_destinations) {
        destinations.push_back(destination->copy(destination, std::make_shared<monero_destination>()));
      }
      return destinations;
    }

    bool is_key_image_spent(const std::string& key_image) const;
    bool is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image) const;
    bool is_key_image_frozen(const std::string& key_image) const;
    void set_key_image_frozen(const std::string& key_image, bool frozen);
    std::shared_ptr<monero_output_light> get_output(const std::string& key_image) const;

    std::vector<std::shared_ptr<monero_output_light>> get_outputs(uint32_t account_idx) const;
    std::vector<std::shared_ptr<monero_output_light>> get_outputs(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<std::shared_ptr<monero_output_light>> get_spendable(const uint32_t account_idx, const std::vector<uint32_t> &subaddresses_indices) const;
    std::vector<std::shared_ptr<monero_output_light>> get_tx_outputs(const std::string& tx_hash, bool filter_spent = false) const;
    monero_utils::wallet2_exported_outputs export_outputs(bool all, uint32_t start, uint32_t count = 0xffffffff) const;
    uint64_t get_num_blocks_to_unlock(const std::vector<std::shared_ptr<monero_output_light>>& outputs) const;
    uint64_t get_num_blocks_to_unlock(const std::string& hash) const;
    uint64_t get_num_blocks_to_unlock(uint32_t account_idx, uint32_t subaddress_idx) const;
    void reindex_outputs(uint64_t amount);
    uint64_t get_per_byte_fee() const { return m_per_byte_fee; }
    uint64_t get_fee_mask() const { return m_fee_mask; }
    uint64_t get_amount() const { return m_amount; }
    void set_key_image(const std::string& key_image, size_t index);
    bool is_subaddress_used(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_num_unspent(uint32_t account_idx, uint32_t subaddress_idx) const;

    uint64_t get_balance() const { return m_balance; }
    uint64_t get_balance(uint32_t account_idx) const;
    uint64_t get_balance(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_unlocked_balance() const { return m_unlocked_balance; }
    uint64_t get_unlocked_balance(uint32_t account_idx) const;
    uint64_t get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const;
    void calculate_balance();

    void init_subaddress(monero_subaddress& subaddress) const;

  private:
    mutable boost::recursive_mutex m_mutex;
    std::shared_ptr<monero_key_image_cache> m_key_image_cache;

    // transactions
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_light>> m_txs;
    std::vector<std::shared_ptr<monero_tx_light>> m_tx_list;
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_wallet>> m_self_constructed_txs;
    serializable_unordered_map<std::string, bool> m_spent_key_images;

    std::shared_ptr<monero_tx_light> get_tx(const std::string& hash) const;
    void set_txs(const monero_get_address_txs_response& response, const monero_get_address_info_response& addr_info_response);

    // blockchain
    uint64_t m_block_reward = 0;
    uint64_t m_blockchain_height = 0;
    uint64_t m_scanned_block_height = 0;
    uint64_t m_start_height = 0;

    // key images
    bool is_key_image_in_pool(const std::string& key_image) const;

    // outputs
    uint64_t m_per_byte_fee = 0;
    uint64_t m_fee_mask = 0;
    uint64_t m_amount = 0;
    mutable serializable_unordered_map<std::string, std::vector<std::shared_ptr<monero_output_light>>> m_tx_hash_index;
    mutable serializable_unordered_map<std::string, size_t> m_key_image_index;
    mutable serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::vector<std::shared_ptr<monero_output_light>>>> m_spent;
    mutable serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::vector<std::shared_ptr<monero_output_light>>>> m_unspent;

    void reindex();
    void set_outputs(const monero_get_unspent_outs_response& response);
    std::vector<std::shared_ptr<monero_output_light>> get_spent(uint32_t account_idx) const;
    std::vector<std::shared_ptr<monero_output_light>> get_spent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<std::shared_ptr<monero_output_light>> get_unspent(uint32_t account_idx) const;
    std::vector<std::shared_ptr<monero_output_light>> get_unspent(uint32_t account_idx, uint32_t subaddress_idx) const;

    // balance info
    uint64_t m_balance = 0;
    uint64_t m_unlocked_balance = 0;
    serializable_unordered_map<uint32_t, uint64_t> m_account_balance;
    serializable_unordered_map<uint32_t, uint64_t> m_account_unlocked_balance;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>> m_subaddress_balance;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>> m_subaddress_unlocked_balance;

    void clear_balance();
  };

}