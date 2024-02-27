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

#include <vector>
#include "daemon/monero_daemon_model.h"
#include "utils/monero_utils.h"
#include "monero_wallet.h"
#include "wallet/wallet2.h"
#include "cryptonote_basic/account.h"

using namespace monero;

/**
 * Public library interface.
 */
namespace monero {

  /**
   * Models a connection to a light wallet server.
   */
  struct monero_lws_connection : public serializable_struct {
      boost::optional<std::string> m_uri;
      boost::optional<std::string> m_port;

      monero_lws_connection(const std::string& uri = "", const std::string& port = "") : m_uri(uri), m_port(port) {}
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
      static monero_lws_connection from_property_tree(const boost::property_tree::ptree& node);
  };

  /**
   * Models a connection to a light wallet administration server.
   */
  struct monero_lws_admin_connection : public monero_lws_connection {
      boost::optional<std::string> m_uri;
      boost::optional<std::string> m_port;
      boost::optional<std::string> m_admin_uri;
      boost::optional<std::string> m_admin_port;
      boost::optional<std::string> m_token;

      monero_lws_admin_connection(
          const std::string& uri = "", const std::string& port = "",
          const std::string& admin_uri = "", const std::string& admin_port = "",
          const std::string& token = "") : m_uri(uri), m_port(port), m_admin_uri(admin_uri), m_admin_port(admin_port), m_token(token) {}

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
      static monero_lws_admin_connection from_property_tree(const boost::property_tree::ptree& node);
  };

  struct monero_light_output {
      boost::optional<uint64_t> m_tx_id;
      boost::optional<std::string> m_amount;
      boost::optional<uint16_t> m_index;
      boost::optional<std::string> m_global_index;
      boost::optional<std::string> m_rct;
      boost::optional<std::string> m_tx_hash;
      boost::optional<std::string> m_tx_prefix_hash;
      boost::optional<std::string> m_public_key;
      boost::optional<std::string> m_tx_pub_key;
      boost::optional<std::vector<std::string>> m_spend_key_images;
      boost::optional<std::string> m_timestamp;
      boost::optional<uint64_t> m_height;

      static std::shared_ptr<monero_light_output> deserialize(const std::string& config_json);
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output);
  };

  struct monero_light_rates {
      boost::optional<float> m_aud;
      boost::optional<float> m_brl;
      boost::optional<float> m_btc;
      boost::optional<float> m_cad;
      boost::optional<float> m_chf;
      boost::optional<float> m_cny;
      boost::optional<float> m_eur;
      boost::optional<float> m_gbp;
      boost::optional<float> m_hkd;
      boost::optional<float> m_inr;
      boost::optional<float> m_jpy;
      boost::optional<float> m_krw;
      boost::optional<float> m_mxn;
      boost::optional<float> m_nok;
      boost::optional<float> m_nzd;
      boost::optional<float> m_sek;
      boost::optional<float> m_sgd;
      boost::optional<float> m_try;
      boost::optional<float> m_usd;
      boost::optional<float> m_rub;
      boost::optional<float> m_zar;

      static std::shared_ptr<monero_light_rates> deserialize(const std::string& config_json);
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_rates>& rates);
  };

  struct monero_light_spend {
      boost::optional<std::string> m_amount;
      boost::optional<std::string> m_key_image;
      boost::optional<std::string> m_tx_pub_key;
      boost::optional<uint16_t> m_out_index;
      boost::optional<uint32_t> m_mixin;

      static std::shared_ptr<monero_light_spend> deserialize(const std::string& config_json);
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend);
  };

  struct monero_light_transaction {
      boost::optional<uint64_t> m_id;
      boost::optional<std::string> m_hash;
      boost::optional<std::string> m_timestamp;
      boost::optional<std::string> m_total_received;
      boost::optional<std::string> m_total_sent;
      boost::optional<uint64_t> m_unlock_time;
      boost::optional<uint64_t> m_height;
      boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
      boost::optional<std::string> m_payment_id;
      boost::optional<bool> m_coinbase;
      boost::optional<bool> m_mempool;
      boost::optional<uint32_t> m_mixin;

      static std::shared_ptr<monero_light_transaction> deserialize(const std::string& config_json);
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_transaction>& transaction);
  };

  struct monero_light_random_output {
      boost::optional<std::string> m_global_index;
      boost::optional<std::string> m_public_key;
      boost::optional<std::string> m_rct;

      static std::shared_ptr<monero_light_random_output> deserialize(const std::string& config_json);
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output);
  };

  struct monero_light_random_outputs {
      boost::optional<std::string> m_amount;
      boost::optional<std::vector<monero_light_random_output>> m_outputs;

      static std::shared_ptr<monero_light_random_outputs> deserialize(const std::string& config_json);
      
  };

  struct monero_light_get_address_info_request {
      boost::optional<std::string> m_address;
      boost::optional<std::string> m_view_key;

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_address_info_response {
      boost::optional<std::string> m_locked_funds;
      boost::optional<std::string> m_total_received;
      boost::optional<std::string> m_total_sent;
      boost::optional<uint64_t> m_scanned_height;
      boost::optional<uint64_t> m_scanned_block_height;
      boost::optional<uint64_t> m_start_height;
      boost::optional<uint64_t> m_transaction_height;
      boost::optional<uint64_t> m_blockchain_height;
      boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
      boost::optional<monero_light_rates> m_rates;
      
      static std::shared_ptr<monero_light_get_address_info_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_address_txs_request : public serializable_struct {
      boost::optional<std::string> m_address;
      boost::optional<std::string> m_view_key;

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_address_txs_response {
      boost::optional<std::string> m_total_received;
      boost::optional<uint64_t> m_scanned_height;
      boost::optional<uint64_t> m_scanned_block_height;
      boost::optional<uint64_t> m_start_height;
      boost::optional<uint64_t> m_blockchain_height;
      boost::optional<std::vector<monero_light_transaction>> m_transactions;

      static std::shared_ptr<monero_light_get_address_txs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_random_outs_request : public serializable_struct {
      boost::optional<uint32_t> m_count;
      boost::optional<std::vector<std::string>> m_amounts;
      
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_random_outs_response {
      boost::optional<std::vector<monero_light_random_output>> m_amount_outs;
      
      static std::shared_ptr<monero_light_get_random_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_unspent_outs_request : public serializable_struct {
      boost::optional<std::string> m_address;
      boost::optional<std::string> m_view_key;
      boost::optional<std::string> m_amount;
      boost::optional<uint32_t> m_mixin;
      boost::optional<bool> m_use_dust;
      boost::optional<std::string> m_dust_threshold;
      
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_unspent_outs_response {
      boost::optional<std::string> m_per_byte_fee;
      boost::optional<std::string> m_fee_mask;
      boost::optional<std::string> m_amount;
      boost::optional<std::vector<monero_light_output>> m_outputs;
      
      static std::shared_ptr<monero_light_get_unspent_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_import_request_request : public serializable_struct {
      boost::optional<std::string> m_address;
      boost::optional<std::string> m_view_key;
      
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_import_request_response {
      boost::optional<std::string> m_payment_address;
      boost::optional<std::string> m_payment_id;
      boost::optional<std::string> m_import_fee;
      boost::optional<bool> m_new_request;
      boost::optional<bool> m_request_fullfilled;
      boost::optional<std::string> m_status;
      
      static std::shared_ptr<monero_light_import_request_response> deserialize(const std::string& config_json);
  };

  struct monero_light_login_request : public serializable_struct {
      boost::optional<std::string> m_address;
      boost::optional<std::string> m_view_key;
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

  struct monero_light_accept_requests_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<std::string> m_type;
      boost::optional<std::vector<std::string>> m_addresses;

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_add_account_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<std::string> m_address;
      boost::optional<std::string> m_key;

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_list_accounts_request : public serializable_struct {
      boost::optional<std::string> m_token;
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_account {
      boost::optional<std::string> m_address;
      boost::optional<uint64_t> m_scan_height;
      boost::optional<uint64_t> m_access_time;

      static std::shared_ptr<monero_light_account> deserialize(const std::string& config_json);
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_account>& account);
  };

  struct monero_light_list_accounts_response {
      boost::optional<std::vector<monero_light_account>> m_active;
      boost::optional<std::vector<monero_light_account>> m_inactive;
      boost::optional<std::vector<monero_light_account>> m_hidden;

      static std::shared_ptr<monero_light_list_accounts_response> deserialize(const std::string& config_json);
  };

  struct monero_light_list_requests_request : public serializable_struct {
      boost::optional<std::string> m_token;
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_list_requests_response {
      static std::shared_ptr<monero_light_list_requests_response> deserialize(const std::string& config_json);
  };

  struct monero_light_modify_account_status_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<std::string> m_status;
      boost::optional<std::vector<std::string>> m_addresses;

      monero_light_modify_account_status_request(std::string status, std::vector<std::string> addresses): m_status(status), m_addresses(addresses) {}
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_reject_requests_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<std::string> m_type;
      boost::optional<std::vector<std::string>> m_addresses;

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_rescan_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<uint64_t> m_height;
      boost::optional<std::vector<std::string>> m_addresses;

      monero_light_rescan_request(uint64_t &height, std::vector<std::string> addresses): m_height(height), m_addresses(addresses) {}
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Implements a Monero wallet to provide basic lws management.
   */
  class monero_wallet_light : public monero_wallet {

  public:

    // --------------------------- STATIC WALLET UTILS --------------------------

    /**
     * Create a wallet from an address, view key, and private view key.
     * 
     * @param config is the wallet configuration (network type, address, view key, private view key)
     */
    static monero_wallet_light* create_wallet_from_keys(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);

    // ----------------------------- WALLET METHODS -----------------------------

    /**
     * Destruct the wallet.
     */
    ~monero_wallet_light();

    /**
     * Supported wallet methods.
     */
    bool is_view_only() const override { return true; }
    void set_daemon_connection(const boost::optional<monero_lws_connection>& connection);
    void set_daemon_connection(const boost::optional<monero_lws_admin_connection>& connection);
    void set_daemon_connection(std::string host, std::string port = "", std::string admin_uri = "", std::string admin_port = "", std::string token = "");
    bool is_connected_to_daemon() const override;
    bool is_daemon_synced() const override;
    bool is_synced() const override;

    monero_version get_version() const override;
    monero_network_type get_network_type() const override { return m_network_type; }
    std::string get_private_view_key() const override { return m_prv_view_key; }
    std::string get_primary_address() const override { return m_primary_address; }
    uint64_t get_height() const override;
    uint64_t get_restore_height() const override;
    void set_restore_height(uint64_t restore_height) override;
    uint64_t get_daemon_height() const override;
    monero_sync_result sync() override;
    monero_sync_result sync(uint64_t start_height) override;
    void start_syncing(uint64_t sync_period_in_ms = 10000) override { rescan(); }
    void stop_syncing() override { deactive_account(); };
    void rescan_blockchain() override { rescan(); };
    uint64_t get_balance() const override;
    uint64_t get_unlocked_balance() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs() const override;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs(const monero_output_query& query) const override;
    std::vector<std::string> relay_txs(const std::vector<std::string>& tx_metadatas) override;
    uint64_t wait_for_next_block() override;
    bool is_multisig_import_needed() const override { return false; }
    bool is_multisig() const override { return false; }

    void close(bool save = false) override;

    monero_light_get_address_info_response get_address_info() const {
      return get_address_info(m_primary_address, m_prv_view_key);
    };

    monero_light_get_address_txs_response get_address_txs() const {
      return get_address_txs(m_primary_address, m_prv_view_key);
    }

    monero_light_get_unspent_outs_response get_unspent_outs(std::string amount, uint32_t mixin, bool use_dust, std::string dust_threshold) const {
      return get_unspent_outs(m_primary_address, m_prv_view_key, amount, mixin, use_dust, dust_threshold);
    }

    monero_light_get_unspent_outs_response get_unspent_outs(uint32_t mixin, bool use_dust = true, std::string dust_threshold = "0") const {
      uint64_t balance = get_balance();
      std::ostringstream o;
      o << balance;
      std::string amount = o.str();

      return get_unspent_outs(amount, mixin, use_dust, dust_threshold);
    }

    monero_light_get_unspent_outs_response get_unspent_outs() const {
      return get_unspent_outs(m_mixin);
    }

    monero_light_import_request_response import_request() const {
      return import_request(m_primary_address, m_prv_view_key);
    }

    monero_light_login_response login() const {
      return login(false);
    }

    monero_light_login_response login(bool create_account) const {
      return login(create_account, false);
    }

    monero_light_login_response login(bool create_account, bool generated_locally) const {
      return login(m_primary_address, m_prv_view_key, create_account, generated_locally);
    }

    // --------------------------------- PROTECTED ------------------------------------------

  protected:
    cryptonote::account_base m_account;
    monero_network_type m_network_type;
    std::string m_prv_view_key;
    std::string m_primary_address;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_admin_client;
    std::chrono::milliseconds m_timeout = std::chrono::milliseconds(120000);
    std::string m_host;
    std::string m_port;
    std::string m_admin_uri;
    std::string m_admin_port;
    std::string m_token;
    uint64_t m_mixin = 4;

    void init_common();
    
    // --------------------------------- LIGHT WALLET METHODS ------------------------------------------

    monero_light_get_address_info_response get_address_info(std::string address, std::string view_key) const { 
      monero_light_get_address_info_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return get_address_info(request);
    };

    monero_light_get_address_txs_response get_address_txs(std::string address, std::string view_key) const {
      monero_light_get_address_txs_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return get_address_txs(request);
    }

    monero_light_get_random_outs_response get_random_outs(uint32_t count, std::vector<std::string> amounts) const {
      monero_light_get_random_outs_request request;
      request.m_count = count;
      request.m_amounts = amounts;

      return get_random_outs(request);
    };

    monero_light_get_unspent_outs_response get_unspent_outs(std::string address, std::string view_key, std::string amount, uint32_t mixin, bool use_dust, std::string dust_threshold) const {
      monero_light_get_unspent_outs_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_amount = amount;
      request.m_mixin = mixin;
      request.m_use_dust = use_dust;
      request.m_dust_threshold = dust_threshold;

      return get_unspent_outs(request);
    };

    monero_light_submit_raw_tx_response submit_raw_tx(std::string tx) const {
      monero_light_submit_raw_tx_request request;
      request.m_tx = tx;
      return submit_raw_tx(request);
    }

    monero_light_import_request_response import_request(std::string address, std::string view_key) const {
      monero_light_import_request_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return import_request(request);
    };

    monero_light_login_response login(std::string address, std::string view_key, bool create_account, bool generated_locally) const {
      monero_light_login_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_create_account = create_account;
      request.m_generated_locally = generated_locally;
      
      return login(request);
    };

    void accept_requests() { 
      monero_light_accept_requests_request request; 
      return accept_requests(request); 
    }

    void add_account(std::string address, std::string view_key) const {
      monero_light_add_account_request request;
      request.m_address = address;
      request.m_key = view_key;

      add_account(request);
    }

    void active_account() {
      modify_account_status("active");
    }

    void deactive_account() {
      modify_account_status("deactive");
    }

    void hide_account() {
      modify_account_status("hidden");
    }

    void modify_account_status(std::string type) {
      modify_account_status(type, m_primary_address);
    }

    void modify_account_status(std::string type, std::string address) {
      std::vector<std::string> addresses = std::vector<std::string>();
      addresses.push_back(address);

      modify_account_status(type, addresses);
    }

    void modify_account_status(std::string type, std::vector<std::string> addresses) {
      monero_light_modify_account_status_request request(type, addresses);

      modify_account_status(request);
    }

    void rescan() const {
      rescan(m_primary_address);
    }

    void rescan(uint64_t start_height) {
      rescan(start_height, m_primary_address);
    }

    void rescan(std::string address) const {
      rescan(0, address);
    }

    void rescan(uint64_t height, std::string address) const {
      std::vector<std::string> addresses = std::vector<std::string>();
      addresses.push_back(address);

      rescan(height, addresses);
    }

    void rescan(uint64_t height, std::vector<std::string> addresses) const {
      monero_light_rescan_request request(height, addresses);

      rescan(request);
    }

    monero_light_get_address_info_response get_address_info(monero_light_get_address_info_request request) const;
    monero_light_get_address_txs_response get_address_txs(monero_light_get_address_txs_request request) const;
    monero_light_get_random_outs_response get_random_outs(monero_light_get_random_outs_request request) const;
    monero_light_get_unspent_outs_response get_unspent_outs(monero_light_get_unspent_outs_request request) const;
    monero_light_submit_raw_tx_response submit_raw_tx(monero_light_submit_raw_tx_request request) const;
    monero_light_import_request_response import_request(monero_light_import_request_request request) const;
    monero_light_login_response login(monero_light_login_request request) const;

    // --------------------------------- LIGHT WALLET ADMIN METHODS ------------------------------------------

    void accept_requests(monero_light_accept_requests_request request) const;
    void reject_requests(monero_light_reject_requests_request request) const;
    void add_account(monero_light_add_account_request request) const;
    monero_light_list_accounts_response list_accounts(monero_light_list_accounts_request request) const;
    monero_light_list_requests_response list_requests(monero_light_list_requests_request request) const;
    void modify_account_status(monero_light_modify_account_status_request request) const;
    void rescan(monero_light_rescan_request request) const;

    epee::net_utils::http::http_response_info* post(std::string method, std::string &body, bool admin = false) const;

  };
}
