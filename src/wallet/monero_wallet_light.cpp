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
    wallet->init_common();

    return wallet;
  }

  // ----------------------------- WALLET METHODS -----------------------------

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close();
  }

  void monero_wallet_light::set_daemon_connection(std::string host, std::string port) {

  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    return m_http_client->is_connected();
  }

  bool monero_wallet_light::is_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();
    
    return address_info.blockchain_height == address_info.scanned_height;
  }

  monero_version monero_wallet_light::get_version() const {
    monero_version version;
    version.m_number = 65552; // same as monero-wallet-rpc v0.15.0.1 release
    version.m_is_release = false; // TODO: could pull from MONERO_VERSION_IS_RELEASE in version.cpp
    return version;
  }

  uint64_t monero_wallet_light::get_height() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.scanned_height;
  }

  uint64_t monero_wallet_light::get_restore_height() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.start_height;
  }

  void monero_wallet_light::set_restore_height(uint64_t restore_height) {
    throw std::runtime_error("not supported yet");
  }

  uint64_t monero_wallet_light::get_daemon_height() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.blockchain_height;
  }

  uint64_t monero_wallet_light::get_balance() const {
    monero_light_get_address_info_response address_info = get_address_info();
    uint65_t total_received;
    uint64_t total_sent;
    
    std::istringstream itr(address_info.total_received);
    std::istringstream its(address_info.total_sent);

    itr >> total_received;
    its >> total_sent;

    if (total_sent > total_received) return 0;

    return total_received - total_sent;
  }

  uint64_t monero_wallet_light::get_unlocked_balance() const {
    monero_light_get_address_info_response address_info = get_address_info();
    uint65_t total_received;
    uint64_t total_sent;
    uint64_t locked_funds;

    std::istringstream itr(address_info.total_received);
    std::istringstream its(address_info.total_sent);
    std::istringstream itl(address_info.locked_funds);

    itr >> total_received;
    its >> total_sent;
    itl >> locked_funds;

    if (total_sent > total_received) return 0;

    return total_received - total_sent - locked_funds;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> get_txs() const {
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();
    monero_light_get_address_txs_response response = get_address_txs();
    response
    return txs;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {

  }

  void monero_wallet_light::close(bool save) {
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    m_http_client->disconnect();
    // no pointers to destroy
  }

  // ------------------------------- PRIVATE HELPERS ----------------------------

  void monero_wallet_light::init_common() {
    m_primary_address = m_account.get_public_address_str(static_cast<cryptonote::network_type>(m_network_type));
    const cryptonote::account_keys& keys = m_account.get_keys();
    m_prv_view_key = epee::string_tools::pod_to_hex(keys.m_view_secret_key);
  }

  monero_light_get_address_info_response monero_wallet_light::get_address_info(monero_light_get_address_info_request request) {

  }

}
