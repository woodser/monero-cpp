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

#include "monero_wallet_full.h"

#include "wallet/wallet2.h"
#include "cryptonote_basic/account.h"

using namespace monero;

/**
 * Public library interface.
 */
namespace monero {

  /**
   * Implements a Monero wallet to provide basic light wallet management.
   */
  class monero_wallet_light : public monero_wallet_full {

  public:

    // --------------------------- STATIC WALLET UTILS --------------------------
    
    static monero_wallet_light* open_wallet(const std::string& path, const std::string& password, const monero_network_type network_type);

    static monero_wallet_light* open_wallet_data(const std::string& password, const monero_network_type, const std::string& keys_data, const std::string& cache_data, const monero_rpc_connection& daemon_connection = monero_rpc_connection(), std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    static monero_wallet_light* create_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    static monero_wallet_light* create_wallet_from_seed(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
   
    static monero_wallet_light* create_wallet_from_keys(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
    
    static monero_wallet_light* create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
    

    // ----------------------------- WALLET METHODS -----------------------------

    /**
     * Destruct the wallet.
     */
    ~monero_wallet_light();

    /**
     * Supported wallet methods.
     */
    void set_daemon_connection(const std::string& uri, const std::string& username = "", const std::string& password = "") override;
    void set_daemon_connection(const boost::optional<monero_rpc_connection>& connection) override;
    void set_daemon_proxy(const std::string& uri = "") override;
    boost::optional<monero_rpc_connection> get_daemon_connection() const override;
    bool is_connected_to_daemon() const override;
    bool is_connected_to_admin_daemon() const;
    bool is_daemon_synced() const override;
    bool is_daemon_trusted() const override { return false; };
    bool is_synced() const override;
    
    uint64_t get_height() const override { return m_scanned_block_height + 1; };
    uint64_t get_restore_height() const override { return m_start_height; };
    void set_restore_height(uint64_t restore_height) override;
    uint64_t get_daemon_height() const override;
    uint64_t get_daemon_max_peer_height() const override { return m_blockchain_height == 0 ? 0 : m_blockchain_height + 1; };
    
    uint64_t get_height_by_date(uint16_t year, uint8_t month, uint8_t day) const override;

    void scan_txs(const std::vector<std::string>& tx_hashes) override;
    void rescan_blockchain() override;

    std::vector<monero_account> get_accounts(bool include_subaddresses, const std::string& tag) const override;
    monero_account create_account(const std::string& label) override;
    monero_subaddress create_subaddress(const uint32_t account_idx, const std::string& label) override;

    std::string export_outputs(bool all) const override;

    std::shared_ptr<monero_key_image_import_result> import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) override;

    std::vector<std::shared_ptr<monero_tx_wallet>> create_txs(const monero_tx_config& config) override;

    void start_mining(boost::optional<uint64_t> num_threads, boost::optional<bool> background_mining, boost::optional<bool> ignore_battery) override {
      throw std::runtime_error("start_mining() not supported by light wallet");
    }

    void stop_mining() override {
      throw std::runtime_error("stop_mining() not supported by light wallet");
    }

    uint64_t wait_for_next_block() override;
    bool is_multisig_import_needed() const override { return false; }
    bool is_multisig() const override { return false; }

    monero_multisig_info get_multisig_info() const override {
      throw std::runtime_error("get_multisig_info() not supported");
    }

    std::string prepare_multisig() override {
      throw std::runtime_error("prepare_multisig() not supported by light wallet");
    }

    std::string make_multisig(const std::vector<std::string>& multisig_hexes, int threshold, const std::string& password) override {
      throw std::runtime_error("make_multisig() not supported by light wallet");
    }

    monero_multisig_init_result exchange_multisig_keys(const std::vector<std::string>& mutisig_hexes, const std::string& password) override {
      throw std::runtime_error("exchange_multisig_keys() not supported by light wallet");
    }

    std::string export_multisig_hex() override {
      throw std::runtime_error("export_multisig_hex() not supported by light wallet");
    }

    int import_multisig_hex(const std::vector<std::string>& multisig_hexes) override {
      throw std::runtime_error("import_multisig_hex() not supported by light wallet");
    }

    monero_multisig_sign_result sign_multisig_tx_hex(const std::string& multisig_tx_hex) override {
      throw std::runtime_error("monero_multisig_sign_result() not supported by light wallet");
    }

    std::vector<std::string> submit_multisig_tx_hex(const std::string& signed_multisig_tx_hex) override {
      throw std::runtime_error("submit_multisig_tx_hex() not supported by light wallet");
    }

    void close(bool save = false) override;

  private:
    void connect_to_lws();

  // --------------------------------- PROTECTED ------------------------------------------

  protected:

    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_admin_client;
    std::chrono::milliseconds m_timeout = std::chrono::milliseconds(3000);
    std::string m_host;
    std::string m_port;
    std::string m_lws_uri;
    std::string m_admin_uri;
    std::string m_admin_port;
    std::string m_lws_admin_uri;
    std::string m_token;

    bool m_request_pending;
    bool m_request_accepted;

    bool m_daemon_supports_subaddresses = false;

    uint64_t m_mixin = 15;
    uint64_t m_start_height = 0;
    uint64_t m_scanned_block_height = 0;
    uint64_t m_blockchain_height = 0;

    uint64_t m_per_byte_fee = 0;
    uint64_t m_fee_mask = 0;

    monero_light_subaddrs m_subaddrs;
    uint32_t m_account_lookahead = 0;
    uint32_t m_subaddress_lookahead = 0;

    mutable boost::recursive_mutex m_daemon_mutex;

    void init_common() override;

    bool daemon_supports_subaddresses() { return m_daemon_supports_subaddresses; };

    std::vector<monero_subaddress> get_subaddresses_aux(uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices, const std::vector<tools::wallet2::transfer_details>& transfers) const override;

    monero_sync_result sync_aux(boost::optional<uint64_t> start_height = boost::none) override;
    monero_sync_result lock_and_sync(boost::optional<uint64_t> start_height = boost::none) override;  // internal function to synchronize request to sync and rescan

    // --------------------------------- LIGHT WALLET METHODS ------------------------------------------
    // --------------------------------- LIGHT WALLET CLIENT METHODS ------------------------------------------

    monero_light_get_address_info_response get_address_info() const {
      return get_address_info(get_primary_address(), get_private_view_key());
    };

    monero_light_get_address_txs_response get_address_txs() const {
      return get_address_txs(get_primary_address(), get_private_view_key());
    }

    monero_light_get_unspent_outs_response get_unspent_outs(std::string amount = "0", boost::optional<uint32_t> mixin = boost::none, bool use_dust = false, std::string dust_threshold = "0") const {
      return get_unspent_outs(get_primary_address(), get_private_view_key(), amount, (mixin == boost::none) ? m_mixin : mixin.get(), use_dust, dust_threshold);
    }

    monero_light_import_request_response import_request() const {
      return import_request(get_primary_address(), get_private_view_key());
    }

    monero_light_login_response login(bool create_account = true, bool generated_locally = true) {
      return login(get_primary_address(), get_private_view_key(), create_account, generated_locally);
    }

    monero_light_provision_subaddrs_response provision_subaddrs(uint32_t maj_i, uint32_t min_i, uint32_t n_maj, uint32_t n_min, bool get_all) const {
      return provision_subaddrs(get_primary_address(), get_private_view_key(), maj_i, min_i, n_maj, n_min, get_all);
    }

    monero_light_get_subaddrs_response get_subaddrs() {
      return get_subaddrs(get_primary_address(), get_private_view_key());
    };

    bool upsert_subaddr(const cryptonote::subaddress_index subaddress_index) {
      return upsert_subaddr(subaddress_index.major, subaddress_index.minor);
    }

    bool upsert_subaddr(const uint32_t account_index, const uint32_t subaddress_index) {
      monero_light_subaddrs subaddrs;
      std::vector<monero_light_index_range> ranges;
      monero_light_index_range index_range(subaddress_index, subaddress_index);
      ranges.push_back(index_range);
      subaddrs.emplace(account_index, ranges);

      monero_light_upsert_subaddrs_response response = upsert_subaddrs(subaddrs, true);

      if (response.m_all_subaddrs == boost::none) return false;

      return response.m_all_subaddrs.get().contains(account_index, subaddress_index);
    };

    monero_light_upsert_subaddrs_response upsert_subaddrs(monero_light_subaddrs subaddrs, bool get_all = true) {
      return upsert_subaddrs(get_primary_address(), get_private_view_key(), subaddrs, get_all);
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

    monero_light_login_response login(std::string address, std::string view_key, bool create_account, bool generated_locally) {
      monero_light_login_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_create_account = create_account;
      request.m_generated_locally = generated_locally;
      
      return login(request);
    };

    monero_light_get_address_info_response get_address_info(std::string address, std::string view_key) const { 
      monero_light_get_address_info_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return get_address_info(request);
    };
    
    monero_light_provision_subaddrs_response provision_subaddrs(std::string address, std::string view_key, uint32_t maj_i, uint32_t min_i, uint32_t n_maj, uint32_t n_min, bool get_all) const {
      monero_light_provision_subaddrs_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_maj_i = maj_i;
      request.m_min_i = min_i;
      request.m_n_maj = n_maj;
      request.m_n_min = n_min;
      request.m_get_all = get_all;
      return provision_subaddrs(request);
    };

    monero_light_upsert_subaddrs_response upsert_subaddrs(std::string address, std::string view_key, monero_light_subaddrs subaddrs, bool get_all) {
      monero_light_upsert_subaddrs_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_subaddrs = subaddrs;
      request.m_get_all = get_all;

      return upsert_subaddrs(request);
    };

    monero_light_get_subaddrs_response get_subaddrs(std::string address, std::string view_key) {
      monero_light_get_subaddrs_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return get_subaddrs(request);
    };

    /**
     * Returns the minimal set of information needed to calculate a wallet balance. 
     * The server cannot calculate when a spend occurs without the spend key, so a list of candidate spends is returned.
     * 
     * @param request 
    */
    monero_light_get_address_info_response get_address_info(monero_light_get_address_info_request request) const;
    
    /**
     * Returns information needed to show transaction history. 
     * The server cannot calculate when a spend occurs without the spend key, so a list of candidate spends is returned.
     * 
     * @param request
    */
    monero_light_get_address_txs_response get_address_txs(monero_light_get_address_txs_request request) const;
    
    /**
     * Selects random outputs to use in a ring signature of a new transaction.
     * 
     * @param request
    */
    monero_light_get_random_outs_response get_random_outs(monero_light_get_random_outs_request request) const;
    
    /**
     * Returns a list of received outputs. The client must determine when the output was actually spent.
     * 
     * @param request
    */
    monero_light_get_unspent_outs_response get_unspent_outs(monero_light_get_unspent_outs_request request) const;

    /**
     * Submit raw transaction to be relayed to monero network.
     * 
     * @param request
    */
    monero_light_submit_raw_tx_response submit_raw_tx(monero_light_submit_raw_tx_request request) const;
    
    /**
     * Request an account scan from the genesis block.
     * 
     * @param request
    */
    monero_light_import_request_response import_request(monero_light_import_request_request request) const;

    /**
     * Check for the existence of an account or create a new one.
     * 
     * @param request
    */
    monero_light_login_response login(monero_light_login_request request);

    monero_light_provision_subaddrs_response provision_subaddrs(monero_light_provision_subaddrs_request request) const;

    monero_light_upsert_subaddrs_response upsert_subaddrs(monero_light_upsert_subaddrs_request request);

    monero_light_get_subaddrs_response get_subaddrs(monero_light_get_subaddrs_request request);

    bool is_address_upsert(const uint32_t account_index, const uint32_t subaddress_index = 0) const;

    // --------------------------------- LIGHT WALLET ADMIN METHODS ------------------------------------------

    void accept_requests() { 
      monero_light_accept_requests_request request; 
      return accept_requests(request); 
    }

    void add_account() const {
      add_account(get_primary_address(), get_private_view_key());
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
      modify_account_status(type, get_primary_address());
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
      rescan(get_primary_address());
    }

    void rescan(uint64_t start_height) {
      rescan(start_height, get_primary_address());
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

    void accept_requests(monero_light_accept_requests_request request) const;
    void reject_requests(monero_light_reject_requests_request request) const;
    void add_account(monero_light_add_account_request request) const;
    monero_light_list_accounts_response list_accounts(monero_light_list_accounts_request request) const;
    monero_light_list_requests_response list_requests(monero_light_list_requests_request request) const;
    void modify_account_status(monero_light_modify_account_status_request request) const;
    void rescan(monero_light_rescan_request request) const;

    const epee::net_utils::http::http_response_info* post(std::string method, std::string &body, bool admin = false) const;

  };
}