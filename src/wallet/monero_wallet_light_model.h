/**
 * Copyright (c) woodser
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
#include <map>

using namespace monero;

namespace monero {

  // ------------------------------- LIGHT WALLET DATA STRUCTURES -------------------------------

  struct monero_light_version {
    boost::optional<std::string> m_server_type;
    boost::optional<std::string> m_server_version;
    boost::optional<std::string> m_last_git_commit_hash;
    boost::optional<std::string> m_last_git_commit_date;
    boost::optional<std::string> m_git_branch_name;
    boost::optional<std::string> m_monero_version_full;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<uint32_t> m_api;
    boost::optional<uint32_t> m_max_subaddresses;
    boost::optional<monero_network_type> m_network_type;
    boost::optional<bool> m_testnet;

    static std::shared_ptr<monero_light_version> deserialize(const std::string& version_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_version>& version);
  };

  struct monero_light_address_meta {
    uint32_t m_maj_i = 0;
    uint32_t m_min_i = 0;

    static std::shared_ptr<monero_light_address_meta> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta);
  };

  struct monero_light_output {
    boost::optional<uint64_t> m_tx_id;
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_index;
    boost::optional<uint64_t> m_global_index;
    boost::optional<std::string> m_rct;
    boost::optional<std::string> m_tx_hash;
    boost::optional<std::string> m_tx_prefix_hash;
    boost::optional<std::string> m_public_key;
    boost::optional<std::string> m_tx_pub_key;
    std::vector<std::string> m_spend_key_images;
    boost::optional<uint64_t> m_timestamp;
    boost::optional<uint64_t> m_height;
    monero_light_address_meta m_recipient;

    // custom members
    boost::optional<std::string> m_key_image;
    boost::optional<bool> m_frozen;

    bool key_image_is_known() const { return m_key_image != boost::none && !m_key_image->empty(); };

    bool is_rct() const { return m_rct != boost::none && !m_rct->empty(); };
    bool is_mined() const { return is_rct() && m_rct.get() == "coinbase"; };

    bool is_spent() const {
      if (!key_image_is_known() || m_spend_key_images.empty()) return false;
      for(const auto& spend_key_image : m_spend_key_images) {
        if (spend_key_image == m_key_image.get()) return true;
      }
      return false;
    };

    static std::shared_ptr<monero_light_output> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output);
  };

  struct monero_light_spend {
    boost::optional<uint64_t> m_amount;
    boost::optional<std::string> m_key_image;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<uint64_t> m_out_index;
    boost::optional<uint32_t> m_mixin;
    monero_light_address_meta m_sender;

    static std::shared_ptr<monero_light_spend> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend);
    std::shared_ptr<monero_light_spend> copy(const std::shared_ptr<monero_light_spend>& src, const std::shared_ptr<monero_light_spend>& tgt) const;
  };

  struct monero_light_tx {
    boost::optional<uint64_t> m_id;
    boost::optional<std::string> m_hash;
    boost::optional<uint64_t> m_timestamp;
    boost::optional<uint64_t> m_total_received;
    boost::optional<uint64_t> m_total_sent;
    boost::optional<uint64_t> m_fee;
    boost::optional<uint64_t> m_unlock_time;
    boost::optional<uint64_t> m_height;
    std::vector<monero_light_spend> m_spent_outputs;
    boost::optional<std::string> m_payment_id;
    boost::optional<bool> m_coinbase;
    boost::optional<bool> m_mempool;
    boost::optional<uint32_t> m_mixin;
    monero_light_address_meta m_recipient;

    static std::shared_ptr<monero_light_tx> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_tx>& transaction);
    std::shared_ptr<monero_light_tx> copy(const std::shared_ptr<monero_light_tx>& src, const std::shared_ptr<monero_light_tx>& tgt, bool exclude_spend = false) const;
  };

  struct monero_light_random_outputs {
    boost::optional<uint64_t> m_amount;
    std::vector<monero_light_output> m_outputs;

    static std::shared_ptr<monero_light_random_outputs> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_outputs>& random_outputs);
  };

  typedef std::unordered_map<std::string/*public_key*/, std::vector<monero_light_output>> monero_light_spendable_random_outputs;

  struct tied_spendable_to_random_outs {
    std::vector<monero_light_random_outputs> m_mix_outs;
    monero_light_spendable_random_outputs m_prior_attempt_unspent_outs_to_mix_outs_new;
  };

  struct monero_light_get_random_outs_params {
    uint32_t m_mixin;
    std::vector<monero_light_output> m_using_outs;
    uint64_t m_using_fee;
    uint64_t m_final_total_wo_fee;
    uint64_t m_change_amount;
  };

  // ------------------------------- REQUEST/RESPONSE DATA STRUCTURES -------------------------------

  struct monero_light_wallet_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_address_info_response {
    boost::optional<uint64_t> m_locked_funds;
    boost::optional<uint64_t> m_total_received;
    boost::optional<uint64_t> m_total_sent;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_transaction_height;
    boost::optional<uint64_t> m_blockchain_height;
    std::vector<monero_light_spend> m_spent_outputs;
    
    static std::shared_ptr<monero_light_get_address_info_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_address_txs_response {
    boost::optional<uint64_t> m_total_received;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_blockchain_height;
    std::vector<monero_light_tx> m_transactions;

    static std::shared_ptr<monero_light_get_address_txs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_random_outs_request : public serializable_struct {
    boost::optional<uint32_t> m_count;
    std::vector<uint64_t> m_amounts;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_random_outs_response {
    std::vector<monero_light_random_outputs> m_amount_outs;
    
    static std::shared_ptr<monero_light_get_random_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_unspent_outs_request : public monero_light_wallet_request {
    boost::optional<uint64_t> m_amount;
    boost::optional<uint32_t> m_mixin;
    boost::optional<bool> m_use_dust;
    boost::optional<uint64_t> m_dust_threshold;
    
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_unspent_outs_response {
    boost::optional<uint64_t> m_per_byte_fee;
    boost::optional<uint64_t> m_fee_mask;
    boost::optional<uint64_t> m_amount;
    std::vector<monero_light_output> m_outputs;
    
    static std::shared_ptr<monero_light_get_unspent_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_import_wallet_request : public monero_light_wallet_request {
    boost::optional<uint64_t> m_from_height;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_import_wallet_response {
    boost::optional<std::string> m_payment_address;
    boost::optional<std::string> m_payment_id;
    boost::optional<uint64_t> m_import_fee;
    boost::optional<bool> m_new_request;
    boost::optional<bool> m_request_fullfilled;
    boost::optional<std::string> m_status;
    
    static std::shared_ptr<monero_light_import_wallet_response> deserialize(const std::string& config_json);
  };

  struct monero_light_login_request : public monero_light_wallet_request {
    boost::optional<bool> m_create_account;
    boost::optional<bool> m_generated_locally;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_login_response {
    boost::optional<bool> m_new_address;
    boost::optional<bool> m_generated_locally;
    boost::optional<uint64_t> m_start_height;
      
    static std::shared_ptr<monero_light_login_response> deserialize(const std::string& config_json);
  };

  struct monero_light_submit_raw_tx_request : public serializable_struct {
    boost::optional<std::string> m_tx;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_submit_raw_tx_response {
    boost::optional<std::string> m_status;
    
    static std::shared_ptr<monero_light_submit_raw_tx_response> deserialize(const std::string& config_json);
  };

  class monero_light_index_range : public std::vector<uint32_t> {
  public:
    monero_light_index_range() { 
      std::vector<uint32_t>();
    };

    monero_light_index_range(const uint32_t min_i, const uint32_t maj_i) {
      push_back(min_i);
      push_back(maj_i);
    };

    bool in_range(uint32_t subaddress_idx) const {
      if (empty() || size() != 2) return false;
      return at(0) <= subaddress_idx && subaddress_idx <= at(1);
    };

    std::vector<uint32_t> to_subaddress_indices() const {
      std::vector<uint32_t> indices;

      if (size() != 2) {
        return indices;
      }

      uint32_t min_i = at(0);
      uint32_t maj_i = at(1);

      for(uint32_t i = min_i; i <= maj_i; i++) {
        indices.push_back(i);
      }

      return indices;
    }
    
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_index_range>& index_range);
  };

  class monero_light_subaddrs : public std::map<uint32_t, std::vector<monero_light_index_range>>, public serializable_struct {
  public:

    bool contains(const uint32_t account_index) const {
      auto it = find(account_index);
      return it != end();
    }

    bool contains(const uint32_t account_index, const uint32_t subaddress_index) const {
      auto it = find(account_index);
      if (it == end()) return false;
      for(const auto& index_range : it->second) {
        if (index_range.in_range(subaddress_index)) return true;
      }
      return false;
    }

    bool is_upsert(const uint32_t account_idx) const {
      if (account_idx == 0) return true;
      auto it = find(account_idx);
      return it != end();
    }

    std::vector<uint32_t> get_subaddresses_indices(const uint32_t account_idx) const {
      std::vector<uint32_t> subaddress_idxs;
      auto it = find(account_idx);
      if (it != end()) {
        for (const auto& index_range : it->second) {
          const auto& idxs = index_range.to_subaddress_indices();
          subaddress_idxs.insert(subaddress_idxs.begin(), idxs.begin(), idxs.end());
        }
      }
      return subaddress_idxs;
    }

    uint32_t get_last_account_index() const {
      uint32_t last_account_idx = 0;
      for(const auto &kv : *this) {
        if (kv.first > last_account_idx) last_account_idx = kv.first;
      }
      return last_account_idx;
    }

    uint32_t get_last_subaddress_index(const uint32_t account_idx) const {
      uint32_t last_subaddress_idx = 0;
      auto it = find(account_idx);
      if (it == end()) throw std::runtime_error("account not found");
      for(const auto& index_range : it->second) {
        last_subaddress_idx = index_range.at(1);
      }
      return last_subaddress_idx;
    }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_subaddrs>& subaddrs);
  };

  struct monero_light_upsert_subaddrs_request : public monero_light_wallet_request {
    boost::optional<monero_light_subaddrs> m_subaddrs;
    boost::optional<bool> m_get_all;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_upsert_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_new_subaddrs;
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_upsert_subaddrs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_get_subaddrs_response> deserialize(const std::string& config_json);
  };

  // ------------------------------- UTILS -------------------------------

  class monero_light_client {
  public:

    monero_light_client(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);
    ~monero_light_client();
    bool is_connected() const { return m_connected; };
    void disconnect();
    void set_connection(const boost::optional<monero_rpc_connection>& connection);
    void set_connection(const std::string& uri, const std::string& username = "", const std::string& password = "", const std::string& proxy = "");
    boost::optional<monero_rpc_connection> get_connection() const;

    monero_light_get_address_info_response get_address_info(const std::string &address, const std::string &view_key) const;
    monero_light_get_address_txs_response get_address_txs(const std::string &address, const std::string &view_key) const;
    monero_light_get_unspent_outs_response get_unspent_outs(const std::string &address, const std::string &view_key, uint64_t amount, uint32_t mixin, bool use_dust = true, const uint64_t dust_threshold = 0) const;
    monero_light_get_random_outs_response get_random_outs(uint32_t count, const std::vector<uint64_t> &amounts) const;
    monero_light_get_subaddrs_response get_subaddrs(const std::string &address, const std::string &view_key) const;
    monero_light_upsert_subaddrs_response upsert_subaddrs(const std::string &address, const std::string &view_key, const monero_light_subaddrs &subaddrs, bool get_all = true) const;
    monero_light_login_response login(const std::string &address, const std::string &view_key, bool create_account = true, bool generated_locally = true) const;
    monero_light_import_wallet_response import_request(const std::string &address, const std::string &view_key, uint64_t from_height) const;
    monero_light_submit_raw_tx_response submit_raw_tx(const std::string& tx) const;
    monero_light_version get_version() const;
    
  protected:
    mutable boost::recursive_mutex m_mutex;
    std::string m_server;
    std::string m_proxy;
    epee::net_utils::http::login m_credentials;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    bool m_connected = false;

    template<class t_request, class t_response>
    inline int invoke_post(const boost::string_ref uri, const t_request& request, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15)) const {
      if (!m_http_client) throw std::runtime_error("http client not set");

      rapidjson::Document document(rapidjson::Type::kObjectType);
      rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
      rapidjson::StringBuffer sb;
      rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
      req.Accept(writer);
      std::string body = sb.GetString();

      std::shared_ptr<epee::net_utils::http::http_response_info> _res = std::make_shared<epee::net_utils::http::http_response_info>();
      const epee::net_utils::http::http_response_info* response = _res.get();
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

      if (!m_http_client->invoke_post(uri, body, timeout, &response)) {
        throw std::runtime_error("Network error");
      }

      int status_code = response->m_response_code;

      if (status_code == 200) {
        res = *t_response::deserialize(response->m_body);
      }

      return status_code;
    }
  };

  class monero_light_tx_store {
  public:
    monero_light_tx get(const std::string& hash) const;
    monero_light_tx get(const monero_light_output& output) const;
    uint64_t get_unlock_time(const std::string& hash) const;
    void set(const monero_light_get_address_txs_response& response, const monero_light_get_address_info_response& addr_info_response);
    void set(const monero_light_tx& tx);
    void set_unconfirmed(const std::shared_ptr<monero_tx_wallet>& tx);
    void remove_unconfirmed(const std::string& hash);
    void set_relayed(const std::string& hash);
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_wallet>> get_unconfirmed_txs() const { return m_unconfirmed_txs; };
    bool is_key_image_in_pool(const std::string& key_image) const;
    bool is_key_image_spent(const std::string& key_image) const;
    bool is_key_image_spent(const crypto::key_image& key_image) const;
    bool is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image) const;
    bool is_key_image_spent(const monero_key_image& key_image) const;
    void set(const std::vector<monero_light_tx>& txs, bool clear_txs = false);
    uint64_t calculate_num_blocks_to_unlock(const monero_light_output& output, uint64_t current_height) const;
    uint64_t calculate_num_blocks_to_unlock(const std::vector<monero_light_output>& outputs, uint64_t current_height) const;
    uint64_t calculate_num_blocks_to_unlock(const std::vector<std::string>& hashes, uint64_t current_height) const;
    uint64_t calculate_num_blocks_to_unlock(const std::string& hash, uint64_t current_height) const;
    bool is_locked(const std::string& hash, uint64_t current_height) const;
    bool is_locked(const monero_light_output& output, uint64_t current_height) const;
    bool is_confirmed(const std::string& hash) const;
    void clear();
    void clear_unconfirmed();
    uint64_t get_last_block_reward() const { return m_block_reward > 1 ? m_block_reward - 2 : m_block_reward; } // TODO why wallet full gives to 2 piconero less ?
  private:
    mutable boost::recursive_mutex m_mutex;
    serializable_unordered_map<std::string, monero_light_tx> m_txs;
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_wallet>> m_unconfirmed_txs;
    serializable_unordered_map<std::string, bool> m_spent_key_images;
    serializable_unordered_map<std::string, std::vector<std::string>> m_pool_key_images;
    uint64_t m_block_reward = 0;

    void add_key_images_to_pool(const std::shared_ptr<monero_tx_wallet>& tx);
  };

  class monero_light_output_store {
  public:
    std::vector<monero_light_output> m_all;

    std::vector<monero_light_output> get(uint32_t account_idx) const;
    std::vector<monero_light_output> get(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<monero_light_output> get_spent(uint32_t account_idx) const;
    std::vector<monero_light_output> get_spent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<monero_light_output> get_unspent(uint32_t account_idx) const;
    std::vector<monero_light_output> get_unspent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<monero_light_output> get_spendable(const uint32_t account_idx, const std::vector<uint32_t> &subaddresses_indices, const monero_light_tx_store& tx_store, uint64_t height) const;
    std::vector<monero_light_output> get_by_tx_hash(const std::string& tx_hash, bool filter_spent = false) const;
    std::string get_tx_prefix_hash(const std::string& tx_hash) const;
    void set(const monero_light_tx_store& tx_store, const monero_light_get_unspent_outs_response& response);
    void set(const std::vector<monero_light_output>& spent, const std::vector<monero_light_output>& unspent);
    void set_spent(const std::vector<monero_light_output>& outputs);
    void set_unspent(const std::vector<monero_light_output>& outputs);
    void set_key_image(const std::string& key_image, size_t index);
    bool is_used(uint32_t account_idx, uint32_t subaddress_idx) const;
    size_t get_num() const { return m_num_spent + m_num_unspent; }
    size_t get_num_spent() const { return m_num_spent; }
    size_t get_num_unspent() const { return m_num_unspent; }
    uint64_t get_num_unspent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<size_t> get_indexes(const std::vector<monero_light_output>& outputs) const;
    void calculate_balance(const monero_light_tx_store& tx_store, uint64_t current_height);
    uint64_t get_balance() const { return m_balance; };
    uint64_t get_balance(uint32_t account_idx) const;
    uint64_t get_balance(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_unlocked_balance() const { return m_unlocked_balance; };
    uint64_t get_unlocked_balance(uint32_t account_idx) const;
    uint64_t get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const;
    bool is_frozen(const std::string& key_image) const;
    bool is_frozen(const monero_light_output& output) const;
    void freeze(const std::string& key_image);
    void thaw(const std::string& key_image);
    void clear();
    void clear_frozen();
    void set_key_image_spent(const std::string& key_image, bool spent = true);
    bool is_key_image_spent(const std::string& key_image) const;
    wallet2_exported_outputs export_outputs(const monero_light_tx_store& tx_store, monero_key_image_cache& key_image_cache, bool all, uint32_t start, uint32_t count = 0xffffffff) const;

  private:
    mutable boost::recursive_mutex m_mutex;
    // cache
    mutable serializable_unordered_map<std::string, size_t> m_index;
    mutable serializable_unordered_map<std::string, std::vector<monero_light_output>> m_tx_hash_index;
    mutable serializable_unordered_map<std::string, size_t> m_key_image_index;
    mutable serializable_unordered_map<std::string, bool> m_key_image_status_index;

    mutable serializable_unordered_map<size_t, bool> m_frozen_key_image_index;
    mutable serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::vector<monero_light_output>>> m_spent;
    mutable serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::vector<monero_light_output>>> m_unspent;
    size_t m_num_spent = 0;
    size_t m_num_unspent = 0;
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