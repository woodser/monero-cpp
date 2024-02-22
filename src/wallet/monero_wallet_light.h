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

#include "utils/monero_utils.h"
#include "monero_wallet.h"
#include "monero_wallet_light_model.h"
#include "cryptonote_basic/account.h"

using namespace monero;

/**
 * Public library interface.
 */
namespace monero {

  class monero_lws_connection {
   public:
    std::string uri;
    std::string token;
  }

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
    void set_daemon_connection(std::string host, std::string port);
    void set_daemon_connection(std::string uri, std::string port, std::string adminUri, std::string adminPort, std::string token);
    void set_daemon_connection(std::string uri, std::string port, std::string token) { set_daemon_connection(uri, port, "admin", port, token); };
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
    void start_syncing(uint64_t sync_period_in_ms = 10000) override { sync(); }
    void stop_syncing() override;
    void rescan_blockchain() override;
    uint64_t get_balance() const override;
    uint64_t get_unlocked_balance() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs() const override;
    std::vector<std::string> relay_txs(const std::vector<std::string>& tx_metadatas) override;
    bool is_multisig_import_needed() const override { return false; }
    bool is_multisig() const override { return false; }

    void close(bool save = false) override;

    monero_light_get_address_info_response get_address_info get_address_info() {
      return get_address_info(m_primary_address, m_prv_view_key);
    };

    monero_light_get_address_txs_response get_address_txs() {
      return get_address_txs(m_primary_address, m_prv_view_key);
    }

    monero_light_get_unspent_outs_response get_unspent_outs(std::string amount, uint32_t mixin, bool use_dust, std::string dust_threshold) {
      return get_unspent_outs(m_primary_address, m_prv_view_key, amount, mixin, use_dust, dust_threshold);
    }

    monero_light_import_request_response import_request() {
      return import_request(m_primary_address, m_prv_view_key);
    }

    monero_light_login_response login() {
      return login(false);
    }

    monero_light_login_response login(bool create_account) {
      return login(create_account, false);
    }

    monero_light_login_response login(bool create_account, bool generated_locally) {
      return login(m_primary_address, m_prv_view_key, create_account, generated_locally);
    }

    // --------------------------------- PRIVATE --------------------------------

  private:
    cryptonote::account_base m_account;
    monero_network_type m_network_type;
    std::string m_prv_view_key;
    std::string m_primary_address;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    
    void init_common();

    monero_light_get_address_info_response get_address_info(std::string address, std::string view_key) { 
      monero_light_get_address_info_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return get_address_info(request);
    };

    monero_light_get_address_txs_response get_address_txs(std::string address, std::string view_key) {
      monero_light_get_address_txs_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return get_address_txs(request);
    }

    monero_light_get_random_outs_response get_random_outs(uint32_t count, std::string amounts) {
      monero_light_get_random_outs_request request;
      request.m_count = count;
      request.m_amounts = amounts;

      return get_random_outs(request);
    };

    monero_light_get_unspent_outs_response get_unspent_outs(
      std::string address, std::string view_key, std::string amount, uint32_t mixin,
      bool use_dust, std::string dust_threshold
    ){
      monero_light_get_unspent_outs_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_amount = amount;
      request.m_mixin = mixin;
      request.m_use_dust = use_dust;
      request.m_dust_threshold = dust_threshold;

      return get_unspent_outs(request);
    };

    monero_light_import_request_response import_request(std::string address, std::string view_key) {
      monero_light_import_request_request request;
      request.m_address = address;
      request.m_view_key = view_key;

      return import_request(request);
    };

    monero_light_login_response login(
      std::string address, std::string view_key,
      bool create_account, bool generated_locally
    ){
      monero_light_login_request request;
      request.m_address = address;
      request.m_view_key = view_key;
      request.m_create_account = create_account;
      request.m_generated_locally = generated_locally;
      
      return login(request);
    };

    monero_light_get_address_info_response get_address_info(monero_light_get_address_info_request request);
    monero_light_get_address_txs_response get_address_txs(monero_light_get_address_txs_request request);
    monero_light_get_random_outs_response get_random_outs(monero_light_get_random_outs_request request);
    monero_light_get_unspent_outs_response get_unspent_outs(monero_light_get_unspent_outs_request request);
    monero_light_import_request_response import_request(monero_light_import_request_request request);
    monero_light_login_response login(monero_light_login_request request);
  };
}
