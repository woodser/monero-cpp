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

#include "monero_wallet_light.h"

#include "utils/monero_utils.h"
#include <thread>
#include <chrono>
#include <iostream>
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "string_tools.h"
#include "device/device.hpp"

using namespace epee;
using namespace tools;
using namespace crypto;

/**
 * Public library interface.
 */
namespace monero {

  // ---------------------------- WALLET MANAGEMENT ---------------------------

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    if (http_client_factory == nullptr) throw std::runtime_error("Must provide a http client factory");
    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");

    // parse and validate private view key
    crypto::secret_key view_key_sk;
    if (config_normalized.m_private_view_key.get().empty()) {
      throw std::runtime_error("Must provide view key");
    }

    cryptonote::blobdata view_key_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(config_normalized.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("failed to parse secret view key");
    }
    view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());

    // parse and validate address
    cryptonote::address_parse_info address_info;
    if (config_normalized.m_primary_address.get().empty()) {
      throw std::runtime_error("must provide primary address");
    } else {
      if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config_normalized.m_network_type.get()), config_normalized.m_primary_address.get())) throw std::runtime_error("failed to parse address");

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(view_key_sk, pkey)) throw std::runtime_error("failed to verify secret view key");
      if (address_info.address.m_view_public_key != pkey) throw std::runtime_error("view key does not match address");
    }

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light();
    wallet->m_account.create_from_viewkey(address_info.address, view_key_sk);

    // initialize remaining wallet
    wallet->m_network_type = config_normalized.m_network_type.get();
    wallet->m_http_client = http_client_factory->create();
    wallet->m_http_admin_client = http_client_factory->create();
    wallet->init_common();

    return wallet;
  }

  // ----------------------------- WALLET METHODS -----------------------------

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close();
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_lws_connection>& connection) {
    if (connection == boost::none) set_daemon_connection("", "");
    else set_daemon_connection(connection->m_uri == boost::none ? "" : connection->m_uri.get(), connection->m_port == boost::none ? "" : connection->m_port.get());
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_lws_admin_connection>& connection) {
    if (connection == boost::none) set_daemon_connection("", "");
    else set_daemon_connection(
      connection->m_uri == boost::none ? "" : connection->m_uri.get(), connection->m_port == boost::none ? "" : connection->m_port.get(), 
      connection->m_admin_uri == boost::none ? "" : connection->m_admin_uri.get(), connection->m_admin_port == boost::none ? "" : connection->m_admin_port.get(), 
      connection->m_token == boost::none ? "" : connection->m_token.get()
      );
  }

  void monero_wallet_light::set_daemon_connection(std::string host, std::string port = "", std::string admin_uri = "", std::string admin_port = "", std::string token = "") {
    m_host = host;
    m_port = port;
    m_admin_uri = admin_uri;
    m_admin_port = admin_port;
    m_token = token;
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    return m_http_client->is_connected();
  }

  bool monero_wallet_light::is_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_scanned_block_height.get() == address_info.m_scanned_height.get();
  }

  bool monero_wallet_light::is_daemon_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_blockchain_height.get() == address_info.m_scanned_height.get();
  }

  monero_version monero_wallet_light::get_version() const {
    monero_version version;
    version.m_number = 65552; // same as monero-wallet-rpc v0.15.0.1 release
    version.m_is_release = false; // TODO: could pull from MONERO_VERSION_IS_RELEASE in version.cpp
    return version;
  }

  uint64_t monero_wallet_light::get_height() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_scanned_height.get();
  }

  uint64_t monero_wallet_light::get_restore_height() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_start_height.get();
  }

  void monero_wallet_light::set_restore_height(uint64_t restore_height) {
    rescan(restore_height);
  }

  uint64_t monero_wallet_light::get_daemon_height() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_blockchain_height.get();
  }

  monero_sync_result monero_wallet_light::sync() {
    rescan(0, m_primary_address);

    while(!is_synced()) {
      std::this_thread::sleep_for(std::chrono::seconds(120));
    }
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
    rescan(start_height, m_primary_address);

    while(!is_synced()) {
      std::this_thread::sleep_for(std::chrono::seconds(120));
    }
  }

  uint64_t monero_wallet_light::get_balance() const {
    monero_light_get_address_info_response address_info = get_address_info();
    uint64_t total_received;
    uint64_t total_sent;
    
    std::istringstream itr(address_info.m_total_received.get());
    std::istringstream its(address_info.m_total_sent.get());

    itr >> total_received;
    its >> total_sent;

    if (total_sent > total_received) return 0;

    return total_received - total_sent;
  }

  uint64_t monero_wallet_light::get_unlocked_balance() const {
    monero_light_get_address_info_response address_info = get_address_info();
    uint64_t total_received;
    uint64_t total_sent;
    uint64_t locked_funds;

    std::istringstream itr(address_info.m_total_received.get());
    std::istringstream its(address_info.m_total_sent.get());
    std::istringstream itl(address_info.m_locked_funds.get());

    itr >> total_received;
    its >> total_sent;
    itl >> locked_funds;

    if (total_sent > total_received) return 0;

    return total_received - total_sent - locked_funds;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs() const {
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();
    monero_light_get_address_txs_response response = get_address_txs();

    std::vector<monero_light_transaction> light_txs = response.m_transactions.get();

    for (monero_light_transaction light_tx : light_txs) {
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::shared_ptr<monero_tx_wallet>();

      tx_wallet->m_block.get()->m_height = light_tx.m_height;
      tx_wallet->m_hash = light_tx.m_hash;
      tx_wallet->m_is_relayed = true;
      
      uint64_t total_sent;
      uint64_t total_received;

      std::istringstream tss(light_tx.m_total_sent.get());
      std::istringstream trs(light_tx.m_total_received.get());

      tss >> total_sent;
      trs >> total_received;

      if (total_sent == 0 && total_received > 0) {
        tx_wallet->m_is_incoming = true;
        tx_wallet->m_is_outgoing = false;
        tx_wallet->m_change_amount = total_received;
      } else if (total_received == 0 && total_sent > 0) {
        tx_wallet->m_is_outgoing = true;
        tx_wallet->m_is_incoming = false;
        tx_wallet->m_change_amount = total_sent;
      } else if (light_tx.m_coinbase.get() == true) {
        tx_wallet->m_is_incoming = true;
        tx_wallet->m_is_outgoing = false;
        tx_wallet->m_change_amount = total_received;
      }

      if (light_tx.m_unlock_time.get() == 0) {
        tx_wallet->m_is_confirmed = true;
      } else {
        tx_wallet->m_is_confirmed = false;
      }

      tx_wallet->m_unlock_time = light_tx.m_unlock_time;
      tx_wallet->m_payment_id = light_tx.m_payment_id;
      tx_wallet->m_in_tx_pool = light_tx.m_mempool;
      tx_wallet->m_is_miner_tx = light_tx.m_coinbase;

      txs.push_back(tx_wallet);
    }

    return txs;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
    monero_light_get_unspent_outs_response response = get_unspent_outs();

    std::vector<std::shared_ptr<monero_output_wallet>> outputs;

    for(monero_light_output light_output : response.m_outputs.get()) {
      std::shared_ptr<monero_output_wallet> output = std::shared_ptr<monero_output_wallet>();
      output->m_account_index = 0;
      output->m_amount = light_output.m_amount;
      output->m_index = light_output.m_index;
      output->m_amount = light_output.m_amount;
      output->m_stealth_public_key = light_output.m_public_key;

      output->m_tx = std::make_shared<monero_tx>();
      output->m_tx->m_hash = light_output.m_tx_hash;
      output->m_tx->m_key = light_output.m_tx_pub_key;
      output->m_tx->m_rct_signatures = light_output.m_rct;

      outputs.push_back(output);
    }

    return outputs;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    for (std::string tx_metadata : tx_metadatas) {
      submit_raw_tx(tx_metadata);
    }
  }

  uint64_t monero_wallet_light::wait_for_next_block() {
    uint64_t last_block = get_daemon_height();
        
    while(true) {
      uint64_t current_block = get_daemon_height();

      if (current_block > last_block) {
        last_block = current_block;
        break;
      }

      std::this_thread::sleep_for(std::chrono::seconds(120));
    }

    return last_block;
  }

  void monero_wallet_light::close(bool save) {
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    m_http_client->disconnect();
    // no pointers to destroy
  }

  // ------------------------------- PROTECTED HELPERS ----------------------------

  void monero_wallet_light::init_common() {
    m_primary_address = m_account.get_public_address_str(static_cast<cryptonote::network_type>(m_network_type));
    const cryptonote::account_keys& keys = m_account.get_keys();
    m_prv_view_key = epee::string_tools::pod_to_hex(keys.m_view_secret_key);

    if (m_host != "") {
      std::string address = m_host;

      if (m_port != "") {
        address = address + ":" + m_port;
      }

      m_http_client->set_server(address, boost::none);
      m_http_client->connect(m_timeout);
    }

    if (m_admin_uri != "") {
      std::string address = m_admin_uri;

      if (m_admin_port != "") {
        address = address + ":" + m_admin_port;
      }

      m_http_admin_client->set_server(address, boost::none);
      m_http_client->connect(m_timeout);
    }

  }

  // ------------------------------- PROTECTED LWS HELPERS ----------------------------

  epee::net_utils::http::http_response_info* monero_wallet_light::post(std::string method, std::string &body, bool admin = false) const {
    epee::net_utils::http::http_response_info *response = nullptr;
    
    if (admin) {
      if (!m_http_admin_client->invoke_post(method, body, m_timeout, &response)) {
        throw std::runtime_error("Network error");
      }    
    }
    else {
      if (!m_http_client->invoke_post(method, body, m_timeout, &response)) {
        throw std::runtime_error("Network error");
      }
    }

    return response;
  }

  monero_light_get_address_info_response monero_wallet_light::get_address_info(monero_light_get_address_info_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);

    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/get_address_info", body);

    return *monero_light_get_address_info_response::deserialize(response->m_body);
  }

  monero_light_get_address_txs_response monero_wallet_light::get_address_txs(monero_light_get_address_txs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/get_address_txs", body);

    return *monero_light_get_address_txs_response::deserialize(response->m_body);
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(monero_light_get_random_outs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/get_random_outs", body);

    return *monero_light_get_random_outs_response::deserialize(response->m_body);
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(monero_light_get_unspent_outs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/get_unspent_outs", body);

    return *monero_light_get_unspent_outs_response::deserialize(response->m_body);
  }

  monero_light_import_request_response monero_wallet_light::import_request(monero_light_import_request_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/import_request", body);

    return *monero_light_import_request_response::deserialize(response->m_body);
  }

  monero_light_submit_raw_tx_response monero_wallet_light::submit_raw_tx(monero_light_submit_raw_tx_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/submit_raw_tx", body);

    return *monero_light_submit_raw_tx_response::deserialize(response->m_body);
  }

  monero_light_login_response monero_wallet_light::login(monero_light_login_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/login", body);

    return *monero_light_login_response::deserialize(response->m_body);
  }

  // ------------------------------- PROTECTED LWS ADMIN HELPERS ----------------------------

  void monero_wallet_light::accept_requests(monero_light_accept_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/accept_requests", body, true);
  }

  void monero_wallet_light::reject_requests(monero_light_reject_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/reject_requests", body, true);
  }
  
  void monero_wallet_light::add_account(monero_light_add_account_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/add_account", body, true);
  }
  
  monero_light_list_accounts_response monero_wallet_light::list_accounts(monero_light_list_accounts_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/list_accounts", body, true);

    return *monero_light_list_accounts_response::deserialize(response->m_body);
  }
  
  monero_light_list_requests_response monero_wallet_light::list_requests(monero_light_list_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/list_requests", body, true);

    return *monero_light_list_requests_response::deserialize(response->m_body);
  }
  
  void monero_wallet_light::modify_account_status(monero_light_modify_account_status_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/modify_account_status", body, true);
  }
  
  void monero_wallet_light::rescan(monero_light_rescan_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    epee::net_utils::http::http_response_info *response = post("/rescan", body, true);
  }

}