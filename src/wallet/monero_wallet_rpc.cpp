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
 * Parts of this file are originally copyright (c) 2025-2026 woodser
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
#include "monero_wallet_rpc.h"
#include "monero_wallet_rpc_model.h"
#include "common/monero_error.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
#include <atomic>

namespace monero {

  namespace {
    // RAII guard for monero_tx_query trees copied for get_txs()/get_transfers_aux()/
    // get_outputs_aux(): they hold circular shared_ptr references (m_tx_query <->
    // m_transfer_query/m_output_query) that plain refcounting can't break, so
    // monero_utils::free() must run on every exit path or the copies leak. Swallow: free()
    // can throw (e.g. allocation failure), and a throwing destructor during unwind is
    // std::terminate.
    struct query_free_guard {
      std::shared_ptr<monero_tx_query> tx_query;
      ~query_free_guard() { try { monero_utils::free(tx_query); } catch (...) {} }
    };
  }

  /**
  * Polls wallet and sends notifications in order to notify external wallet listeners.
  */
  class monero_wallet_poller: public gen_utils::thread_poller {
  public:

    explicit monero_wallet_poller(monero_wallet_rpc *wallet): m_num_polling(0) {
      m_wallet = wallet;
      init_common("monero_wallet_rpc");
    };

    ~monero_wallet_poller() override {
      set_is_polling(false);
    }

    void poll() override {
      // skip if next poll is queued
      if (m_num_polling.fetch_add(1) > 1) {
        m_num_polling--;
        return;
      }

      struct decrement_guard {
        std::atomic<int>& counter;
        ~decrement_guard() { counter--; }
      } num_polling_guard{m_num_polling};

      // synchronize polls
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      gen_utils::thread_poller::announce_scope announce_guard(*this); // see wait_for_callbacks_idle()
      try {
        // skip if wallet is closed
        if (m_wallet->is_closed()) {
          return;
        }

        // take initial snapshot
        if (m_prev_balances == nullptr) {
          m_prev_height = m_wallet->get_height();
          monero_tx_query tx_query;
          tx_query.m_is_locked = true;
          m_prev_locked_txs = m_wallet->get_txs(tx_query);
          m_prev_balances = m_wallet->get_balances(boost::none, boost::none);
          return;
        }

        // announce height changes
        uint64_t height = m_wallet->get_height();
        if (m_prev_height.get() != height) {
          for (uint64_t i = m_prev_height.get(); i < height; i++) {
            on_new_block(i);
          }

          m_prev_height = height;
        }

        // get locked txs for comparison to previous
        uint64_t min_height = 0; // only monitor recent txs
        if (height > 70) min_height = height - 70;
        monero_tx_query tx_query;
        tx_query.m_is_locked = true;
        tx_query.m_min_height = min_height;
        tx_query.m_include_outputs = true;

        auto locked_txs = m_wallet->get_txs(tx_query);

        // collect hashes of txs no longer locked
        std::vector<std::string> no_longer_locked_hashes;
        for (const auto &prev_locked_tx : m_prev_locked_txs) {
          if (get_tx(locked_txs, prev_locked_tx->m_hash.get()) == nullptr) {
            no_longer_locked_hashes.push_back(prev_locked_tx->m_hash.get());
          }
        }

        // save locked txs for next comparison
        m_prev_locked_txs = locked_txs;
        std::vector<std::shared_ptr<monero_tx_wallet>> unlocked_txs;

        if (!no_longer_locked_hashes.empty()) {
          // fetch txs which are no longer locked
          monero_tx_query tx_query;
          tx_query.m_is_locked = false;
          tx_query.m_min_height = min_height;
          tx_query.m_hashes = no_longer_locked_hashes;
          tx_query.m_include_outputs = true;
          unlocked_txs = m_wallet->get_txs(tx_query);
        }

        // announce new unconfirmed and confirmed txs
        for (const auto &locked_tx : locked_txs) {
          bool announced = false;
          const std::string& tx_hash = locked_tx->m_hash.get();
          if (gen_utils::bool_equals(true, locked_tx->m_is_confirmed)) {
            if (std::find(m_prev_confirmed_notifications.begin(), m_prev_confirmed_notifications.end(), tx_hash) == m_prev_confirmed_notifications.end()) {
              m_prev_confirmed_notifications.push_back(tx_hash);
              announced = true;
            }
          }
          else {
            if (std::find(m_prev_unconfirmed_notifications.begin(), m_prev_unconfirmed_notifications.end(), tx_hash) == m_prev_unconfirmed_notifications.end()) {
              m_prev_unconfirmed_notifications.push_back(tx_hash);
              announced = true;
            }
          }

          if (announced) notify_outputs(locked_tx);
        }

        // announce new unlocked outputs
        for (const auto &unlocked_tx : unlocked_txs) {
          std::string tx_hash = unlocked_tx->m_hash.get();
          // stop tracking tx notifications
          m_prev_confirmed_notifications.erase(std::remove_if(m_prev_confirmed_notifications.begin(), m_prev_confirmed_notifications.end(), [&tx_hash](const std::string& iter){ return iter == tx_hash; }), m_prev_confirmed_notifications.end());
          m_prev_unconfirmed_notifications.erase(std::remove_if(m_prev_unconfirmed_notifications.begin(), m_prev_unconfirmed_notifications.end(), [&tx_hash](const std::string& iter){ return iter == tx_hash; }), m_prev_unconfirmed_notifications.end());
          notify_outputs(unlocked_tx);
        }

        // announce balance changes
        check_for_changed_balances();
      }
      catch (const std::exception &e) {
        if (m_is_polling) {
          MERROR("Failed to background poll wallet " << m_wallet->get_path() << ": " << e.what());
        }
      }
      catch (...) {
        if (m_is_polling) {
          MERROR("Failed to background poll wallet " << m_wallet->get_path());
        }
      }
    }

  private:
    monero_wallet_rpc *m_wallet;
    std::atomic<int> m_num_polling;

    std::vector<std::string> m_prev_unconfirmed_notifications;
    std::vector<std::string> m_prev_confirmed_notifications;
    std::shared_ptr<monero_subaddress> m_prev_balances;
    boost::optional<uint64_t> m_prev_height;
    std::vector<std::shared_ptr<monero_tx_wallet>> m_prev_locked_txs;

    std::shared_ptr<monero_tx_wallet> get_tx(const std::vector<std::shared_ptr<monero_tx_wallet>>& txs, const std::string& tx_hash){
      for (const auto& tx : txs) {
        if (tx->m_hash == tx_hash) return tx;
      }

      return nullptr;
    }

    void on_new_block(uint64_t height) {
      announce_new_block(height);
    }

    void notify_outputs(const std::shared_ptr<monero_tx_wallet> &tx) {
      // notify spent outputs
      // TODO (monero-project): monero-wallet-rpc does not allow scrape of tx inputs so providing one input with outgoing amount
      if (tx->m_outgoing_transfer != nullptr) {
        auto outgoing_transfer = tx->m_outgoing_transfer;
        if (!tx->m_inputs.empty()) throw monero_error("Tx inputs should be empty");
        auto output = std::make_shared<monero_output_wallet>();
        output->m_amount = outgoing_transfer->m_amount.get() + tx->m_fee.get();
        output->m_account_index = outgoing_transfer->m_account_index;
        output->m_tx = tx;
        // initialize if transfer sourced from single subaddress
        if (outgoing_transfer->m_subaddress_indices.size() == 1) {
          output->m_subaddress_index = outgoing_transfer->m_subaddress_indices[0];
        }
        tx->m_inputs.clear();
        tx->m_inputs.push_back(output);
        announce_output_spent(output);
      }

      // notify received outputs
      if (tx->m_incoming_transfers.size() > 0) {
        if (!tx->m_outputs.empty()) {
          // TODO (monero-project): outputs only returned for confirmed txs
          for(const auto &output : tx->get_outputs_wallet()) {
            announce_output_received(output);
          }
        }
        else {
          // TODO (monero-project): monero-wallet-rpc does not allow scrape of unconfirmed received outputs so using incoming transfer values
          tx->m_outputs.clear();
          for (const auto &transfer : tx->m_incoming_transfers) {
            auto output = std::make_shared<monero_output_wallet>();
            output->m_account_index = transfer->m_account_index;
            output->m_subaddress_index = transfer->m_subaddress_index;
            output->m_amount = transfer->m_amount.get();
            output->m_tx = tx;
            tx->m_outputs.push_back(output);
          }

          for (const auto &output : tx->get_outputs_wallet()) {
            announce_output_received(output);
          }
        }
      }
    }

    bool check_for_changed_balances() {
      std::shared_ptr<monero_subaddress> balances = m_wallet->get_balances(boost::none, boost::none);
      if (balances->m_balance != m_prev_balances->m_balance || balances->m_unlocked_balance != m_prev_balances->m_unlocked_balance) {
        m_prev_balances = balances;
        announce_balances_changed(balances->m_balance.get(), balances->m_unlocked_balance.get());
        return true;
      }
      return false;
    }

    // mirrors monero_daemon_poller
    void announce_new_block(uint64_t height) {
      for (const auto &listener : m_wallet->get_listeners()) {
        try {
          listener->on_new_block(height);
        } catch (const std::exception &e) {
          MERROR(e.what());
        }
      }
    }

    void announce_balances_changed(uint64_t balance, uint64_t unlocked_balance) {
      for (const auto &listener : m_wallet->get_listeners()) {
        try {
          listener->on_balances_changed(balance, unlocked_balance);
        } catch (const std::exception &e) {
          MERROR(e.what());
        }
      }
    }

    void announce_output_spent(const std::shared_ptr<monero_output_wallet> &output) {
      for (const auto &listener : m_wallet->get_listeners()) {
        try {
          listener->on_output_spent(*output);
        } catch (const std::exception &e) {
          MERROR(e.what());
        }
      }
    }

    void announce_output_received(const std::shared_ptr<monero_output_wallet> &output) {
      for (const auto &listener : m_wallet->get_listeners()) {
        try {
          listener->on_output_received(*output);
        } catch (const std::exception &e) {
          MERROR(e.what());
        }
      }
    }
  };

  monero_wallet_rpc::monero_wallet_rpc(const std::shared_ptr<monero_rpc_connection>& rpc_connection): m_rpc(rpc_connection) {
    if (rpc_connection == nullptr) throw monero_error("Connection cannot be null");
    if (!rpc_connection->is_online().value_or(false) && rpc_connection->m_uri != boost::none) rpc_connection->check_connection();
  }

  monero_wallet_rpc::monero_wallet_rpc(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy_uri, const std::string& zmq_uri, const boost::optional<uint32_t>& timeout): m_rpc(std::make_shared<monero_rpc_connection>(uri, username, password, proxy_uri, zmq_uri, 0, timeout)) {
    if (m_rpc->m_uri != boost::none) m_rpc->check_connection();
  }

  monero_wallet_rpc::~monero_wallet_rpc() {
    MTRACE("~monero_wallet_rpc()");
    clear();
  }

  void monero_wallet_rpc::set_poll_period_in_ms(uint64_t period_ms) {
    boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);
    if (!m_poller) m_poller = std::make_unique<monero_wallet_poller>(this);
    m_poller->set_period_in_ms(period_ms);
  }

  std::set<monero_wallet_listener*> monero_wallet_rpc::get_listeners() {
    boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
    return m_listeners;
  }

  void monero_wallet_rpc::add_listener(monero_wallet_listener& listener) {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      m_listeners.insert(&listener);
    }
    refresh_listening();
  }

  void monero_wallet_rpc::remove_listener(monero_wallet_listener& listener) {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      m_listeners.erase(&listener);
    }
    refresh_listening();
    wait_for_listener_callbacks_idle();
  }

  void monero_wallet_rpc::wait_for_listener_callbacks_idle() {
    // ensures no in-flight callback dispatch can still reference a removed listener
    monero_wallet_poller* poller;
    {
      boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);
      poller = m_poller.get();
    }
    if (poller != nullptr) poller->wait_for_callbacks_idle();
  }

  monero_wallet_rpc* monero_wallet_rpc::open_wallet(const std::shared_ptr<monero_wallet_config> &config) {
    MTRACE("monero_wallet_rpc::open_wallet(...)");
    if (config == nullptr) throw monero_error("Must provide configuration of wallet to open");
    if (config->m_path == boost::none || config->m_path->empty()) throw monero_error("Filename is not initialized");
    std::string path = config->m_path.get();
    std::string password = std::string("");
    if (config->m_password != boost::none) password = config->m_password.get();

    auto params = std::make_shared<monero_create_open_wallet_params>(path, password);
    m_rpc->send_json_request("open_wallet", params);
    clear();

    if (config->m_server != nullptr) {
      set_daemon_connection(config->m_server, config->m_is_trusted_daemon);
    }

    m_path = path;

    return this;
  }

  monero_wallet_rpc* monero_wallet_rpc::open_wallet(const std::string& name, const std::string& password) {
    MTRACE("monero_wallet_rpc::open_wallet(" << name << ", ***");
    auto config = std::make_shared<monero_wallet_config>();
    config->m_path = name;
    config->m_password = password;
    return open_wallet(config);
  }

  void handle_create_wallet_error(const monero_rpc_error& ex, const std::string& path) {
    std::string msg = ex.what();
    std::transform(msg.begin(), msg.end(), msg.begin(), [](unsigned char c){ return std::tolower(c); });
    if (msg.find("already exists") != std::string::npos) throw monero_rpc_error(ex.code, std::string("Wallet already exists: ") + path);
    if (msg == std::string("electrum-style word list failed verification")) throw monero_rpc_error(ex.code, std::string("Invalid mnemonic"));
    throw ex;
  }

  monero_wallet_rpc* monero_wallet_rpc::create_wallet(const std::shared_ptr<monero_wallet_config> &config) {
    MTRACE("monero_wallet_rpc::create_wallet(...)");

    if (config == nullptr) throw monero_error("Must specify config to create wallet");
    if (config->m_network_type != boost::none) throw monero_error("Cannot specify network type when creating RPC wallet");
    if (config->m_seed != boost::none && (config->m_primary_address != boost::none || config->m_private_view_key != boost::none || config->m_private_spend_key != boost::none)) {
      throw monero_error("Wallet can be initialized with a seed or keys but not both");
    }
    if (config->m_account_lookahead != boost::none || config->m_subaddress_lookahead != boost::none) throw monero_error("monero-wallet-rpc does not support creating wallets with subaddress lookahead over rpc");

    if (config->m_seed != boost::none) create_wallet_from_seed(config);
    else if (config->m_private_spend_key != boost::none || config->m_primary_address != boost::none) create_wallet_from_keys(config);
    else create_wallet_random(config);

    if (config->m_server != nullptr) {
      set_daemon_connection(config->m_server, config->m_is_trusted_daemon);
    }

    return this;
  }

  std::vector<std::string> monero_wallet_rpc::get_seed_languages() const {
    auto result = m_rpc->send_json_request("get_languages");
    std::vector<std::string> languages;
    deserialize_seed_languages(result, languages);
    return languages;
  }

  void monero_wallet_rpc::stop() {
    MTRACE("monero_wallet_rpc::stop()");
    clear();
    m_rpc->send_json_request("stop_wallet");
  }

  bool monero_wallet_rpc::is_view_only() const {
    try {
      std::string key = "mnemonic";
      query_key(key);
      return false;
    }
    catch (const monero_rpc_error& e) {
      if (e.code == -29) return true;
      if (e.code == -1) return false;
      throw;
    }
  }

  std::shared_ptr<monero_rpc_connection> monero_wallet_rpc::get_daemon_connection() const {
    MTRACE("monero_wallet_rpc::get_daemon_connection()");
    return m_daemon_connection;
  }

  void monero_wallet_rpc::set_daemon_connection(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy_uri, const boost::optional<bool>& is_trusted) {
    MTRACE("monero_wallet_rpc::set_daemon_connection(" << uri << ", " << username << ", " << "***" << ", " << proxy_uri << ")");

    if (uri.empty()) {
      set_daemon_connection(std::shared_ptr<monero_rpc_connection>());
      return;
    }
    std::shared_ptr<monero_rpc_connection> rpc = std::make_shared<monero_rpc_connection>(uri, username, password, proxy_uri);
    set_daemon_connection(rpc, is_trusted);
  }

  void monero_wallet_rpc::set_daemon_connection(const std::shared_ptr<monero_rpc_connection>& connection, bool is_trusted, const boost::optional<ssl_options>& ssl_options) {
    auto params = std::make_shared<monero_set_daemon_params>();
    if (connection == nullptr) {
      params->m_address = "placeholder";
      params->m_username = "";
      params->m_password = "";
      params->m_proxy = "";
    }
    else {
      params->m_address = connection->m_uri;
      params->m_username = connection->m_username;
      params->m_password = connection->m_password;
      params->m_proxy = connection->m_proxy_uri.value_or("");
    }

    params->m_trusted = is_trusted;
    params->m_ssl_support = "autodetect";
    params->m_ssl_options = ssl_options;

    m_rpc->send_json_request("set_daemon", params);

    if (connection == nullptr || connection->m_uri == boost::none || connection->m_uri->empty()) {
      m_daemon_connection = nullptr;
    }
    else {
      m_daemon_connection = connection;
    }
  }

  void monero_wallet_rpc::set_daemon_connection(const std::shared_ptr<monero_rpc_connection>& connection, const boost::optional<bool>& is_trusted) {
    set_daemon_connection(connection, is_trusted.value_or(false), boost::none);
  }

  bool monero_wallet_rpc::is_connected_to_daemon() const {
    try {
      check_reserve_proof(get_primary_address(), "", "");
      return false;
    }
    catch (const monero_rpc_error& e) {
      if (e.code == -13) throw; // no wallet file
      return e.message.find("Failed to connect to daemon") == std::string::npos;
    }
  }

  monero_version monero_wallet_rpc::get_version() const {
    auto result = m_rpc->send_json_request("get_version");
    monero_version version;
    deserialize_version(result, version);
    return version;
  }

  std::string monero_wallet_rpc::get_path() const {
    return m_path;
  }

  std::string monero_wallet_rpc::get_seed() const {
    std::string key = "mnemonic";
    return query_key(key);
  }

  std::string monero_wallet_rpc::get_seed_language() const {
    throw monero_error("MoneroWalletRpc::get_seed_language() not supported");
  }

  std::string monero_wallet_rpc::get_public_view_key() const {
    MTRACE("monero_wallet_rpc::get_public_view_key()");
    std::string key = "public_view_key";
    return query_key(key);
  }

  std::string monero_wallet_rpc::get_private_view_key() const {
    MTRACE("monero_wallet_rpc::get_private_view_key()");
    std::string key = "view_key";
    return query_key(key);
  }

  std::string monero_wallet_rpc::get_public_spend_key() const {
    MTRACE("monero_wallet_rpc::get_public_spend_key()");
    std::string key = "public_spend_key";
    return query_key(key);
  }

  std::string monero_wallet_rpc::get_private_spend_key() const {
    MTRACE("monero_wallet_rpc::get_private_spend_key()");
    std::string key = "spend_key";
    return query_key(key);
  }

  std::string monero_wallet_rpc::get_address(const uint32_t account_idx, const uint32_t subaddress_idx) const {
    boost::unique_lock<boost::mutex> lock(m_address_cache_mutex);
    auto it = m_address_cache.find(account_idx);
    if (it == m_address_cache.end()) {
      // cache's all addresses at this account
      lock.unlock();
      std::vector<uint32_t> empty_indices;
      get_subaddresses(account_idx, empty_indices, true);
      // uses cache
      return get_address(account_idx, subaddress_idx);
    }

    auto subaddress_map = it->second;
    auto it2 = subaddress_map.find(subaddress_idx);

    if (it2 == subaddress_map.end()) {
      // cache's all addresses at this account
      lock.unlock();
      std::vector<uint32_t> empty_indices;
      get_subaddresses(account_idx, empty_indices, true);
      lock.lock();
      auto it3 = m_address_cache.find(account_idx);
      if (it3 == m_address_cache.end()) return std::string("");
      auto it4 = it3->second.find(subaddress_idx);
      if (it4 == it3->second.end()) return std::string("");
      return it4->second;
    }

    return it2->second;
  }

  monero_subaddress monero_wallet_rpc::get_address_index(const std::string& address) const {
    MTRACE("monero_wallet_rpc:.get_address_index(" << address << ")");

    auto params = std::make_shared<monero_get_address_params>(address);
    auto result = m_rpc->send_json_request("get_address_index", params);
    auto subaddress = std::make_shared<monero_subaddress>();
    deserialize_subaddress(result, subaddress);
    return *subaddress;
  }

  monero_integrated_address monero_wallet_rpc::get_integrated_address(const std::string& standard_address, const std::string& payment_id) const {
    MTRACE("monero_wallet_rpc::get_integrated_address(" << standard_address << ", " << payment_id << ")");
    try {
      auto params = std::make_shared<monero_integrated_address_params>(standard_address, payment_id);
      auto result = m_rpc->send_json_request("make_integrated_address", params);
      monero_integrated_address integrated_address;
      deserialize_integrated_address(result, integrated_address);
      return decode_integrated_address(integrated_address.m_integrated_address);
    } catch (const monero_rpc_error& ex) {
      if (ex.code == -5 && std::string(ex.what()).find("Invalid payment ID") != std::string::npos) {
        throw monero_rpc_error(-5, "Invalid payment ID: " + payment_id);
      }
      throw;
    }
  }

  monero_integrated_address monero_wallet_rpc::decode_integrated_address(const std::string& integrated_address) const {
    MTRACE("monero_wallet_rpc::decode_integrated_address(" << integrated_address << ")");
    auto params = std::make_shared<monero_integrated_address_params>(integrated_address);
    auto result = m_rpc->send_json_request("split_integrated_address", params);
    monero_integrated_address integrated_addr;
    deserialize_integrated_address(result, integrated_addr);
    integrated_addr.m_integrated_address = integrated_address;
    return integrated_addr;
  }

  uint64_t monero_wallet_rpc::get_height() const {
    auto result = m_rpc->send_json_request("get_height");
    return deserialize_block_height(result);
  }

  uint64_t monero_wallet_rpc::get_daemon_height() const {
    throw monero_error("monero-wallet-rpc does not support getting the chain height");
  }

  uint64_t monero_wallet_rpc::get_height_by_date(uint16_t year, uint8_t month, uint8_t day) const {
    throw monero_error("monero-wallet-rpc does not support getting a height by date");
  }

  monero_sync_result monero_wallet_rpc::refresh(const std::shared_ptr<serializable_struct>& params) {
    monero_sync_result sync_result(0, false);
    {
      // released before poll() since poll() takes the poller's own m_mutex, and a listener
      // callback dispatched from the poll thread may call back into sync()/refresh(), which
      // needs m_sync_mutex. Holding both at once (in opposite order on each thread) is an ABBA deadlock
      boost::lock_guard<boost::recursive_mutex> lock(m_sync_mutex);
      try {
        auto result = m_rpc->send_json_request("refresh", params);
        deserialize_sync_result(result, sync_result);
      } catch (const monero_rpc_error& ex) {
        if (ex.message == std::string("no connection to daemon")) throw monero_error("Wallet is not connected to daemon");
        throw;
      }
    }
    poll();
    return sync_result;
  }

  monero_sync_result monero_wallet_rpc::sync() {
    MTRACE("monero_wallet_rpc::sync()");
    auto params = std::make_shared<monero_wallet_refresh_params>();
    return refresh(params);
  }

  monero_sync_result monero_wallet_rpc::sync(monero_wallet_listener& listener) {
    throw monero_error("Monero Wallet RPC does not support reporting sync progress");
  }

  monero_sync_result monero_wallet_rpc::sync(uint64_t start_height, monero_wallet_listener& listener) {
    throw monero_error("Monero Wallet RPC does not support reporting sync progress");
  }

  monero_sync_result monero_wallet_rpc::sync(uint64_t start_height) {
    MTRACE("monero_wallet_rpc::sync(" << start_height << ")");
    auto params = std::make_shared<monero_wallet_refresh_params>(start_height);
    return refresh(params);
  }

  void monero_wallet_rpc::start_syncing(uint64_t sync_period_in_ms) {
    // convert ms to seconds for rpc parameter
    uint64_t sync_period_in_seconds = sync_period_in_ms / 1000;

    // send rpc request
    auto params = std::make_shared<monero_wallet_refresh_params>(true, sync_period_in_seconds);
    m_rpc->send_json_request("auto_refresh", params);

    // update sync period for poller
    {
      boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);
      m_sync_period_in_ms = sync_period_in_ms;
      if (m_poller != nullptr) m_poller->set_period_in_ms(m_sync_period_in_ms.get());
    }

    // poll if listening
    poll();
  }

  void monero_wallet_rpc::stop_syncing() {
    auto params = std::make_shared<monero_wallet_refresh_params>(false);
    m_rpc->send_json_request("auto_refresh", params);
  }

  void monero_wallet_rpc::scan_txs(const std::vector<std::string>& tx_hashes) {
    MTRACE("monero_wallet_rpc::scan_txs()");
    if (tx_hashes.empty()) throw monero_error("No tx hashes given to scan");
    auto params = std::make_shared<monero_submit_tx_params>(tx_hashes);
    m_rpc->send_json_request("scan_tx", params);
    poll();
  }

  void monero_wallet_rpc::rescan_spent() {
    MTRACE("monero_wallet_rpc::rescan_spent()");
    m_rpc->send_json_request("rescan_spent");
  }

  void monero_wallet_rpc::rescan_blockchain() {
    MTRACE("monero_wallet_rpc::rescan_blockchain()");
    m_rpc->send_json_request("rescan_blockchain");
  }

  uint64_t monero_wallet_rpc::get_balance() const {
    auto wallet_balance = get_balances(boost::none, boost::none);
    return wallet_balance->m_balance.get();
  }

  uint64_t monero_wallet_rpc::get_balance(uint32_t account_index) const {
    auto wallet_balance = get_balances(account_index, boost::none);
    return wallet_balance->m_balance.get();
  }

  uint64_t monero_wallet_rpc::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto wallet_balance = get_balances(account_idx, subaddress_idx);
    return wallet_balance->m_balance.get();
  }

  uint64_t monero_wallet_rpc::get_unlocked_balance() const {
    auto wallet_balance = get_balances(boost::none, boost::none);
    return wallet_balance->m_unlocked_balance.get();
  }

  uint64_t monero_wallet_rpc::get_unlocked_balance(uint32_t account_index) const {
    auto wallet_balance = get_balances(account_index, boost::none);
    return wallet_balance->m_unlocked_balance.get();
  }

  uint64_t monero_wallet_rpc::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto wallet_balance = get_balances(account_idx, subaddress_idx);
    return wallet_balance->m_unlocked_balance.get();
  }

  monero_account monero_wallet_rpc::get_account(const uint32_t account_idx, bool include_subaddresses) const {
    return get_account(account_idx, include_subaddresses, false);
  }

  monero_account monero_wallet_rpc::get_account(const uint32_t account_idx, bool include_subaddresses, bool skip_balances) const {
    MTRACE("monero_wallet_rpc::get_account(" << account_idx << ", " << include_subaddresses << ")");

    for(auto& account : monero_wallet::get_accounts()) {
      if (account.m_index.get() == account_idx) {
        if (include_subaddresses) {
          std::vector<uint32_t> empty_indices;
          account.m_subaddresses = get_subaddresses(account_idx, empty_indices, skip_balances);
        }
        return account;
      }
    }
    throw monero_error("Account with index " + std::to_string(account_idx) + " does not exist");
  }

  std::vector<monero_account> monero_wallet_rpc::get_accounts(bool include_subaddresses, const std::string& tag) const {
    return get_accounts(include_subaddresses, tag, false);
  }

  std::vector<monero_account> monero_wallet_rpc::get_accounts(bool include_subaddresses, const std::string& tag, bool skip_balances) const {
    MTRACE("monero_wallet_rpc::get_accounts(" << include_subaddresses << ", " << tag << ")");

    auto params = std::make_shared<monero_account_tag_params>(tag);
    auto accounts_result = m_rpc->send_json_request("get_accounts", params);
    std::vector<monero_account> accounts;
    deserialize_accounts(accounts_result, accounts);
    if (include_subaddresses) {

      for (auto &account : accounts) {
        std::vector<uint32_t> empty_indices;
        account.m_subaddresses = get_subaddresses(account.m_index.get(), empty_indices, true);

        if (!skip_balances) {
          for (auto &subaddress : account.m_subaddresses) {
            subaddress.m_balance = 0;
            subaddress.m_unlocked_balance = 0;
            subaddress.m_num_unspent_outputs = 0;
            subaddress.m_num_blocks_to_unlock = 0;
          }
        }
      }

      if (!skip_balances) {
        auto balance_params = std::make_shared<monero_get_balance_params>(true);
        auto balance_result = m_rpc->send_json_request("get_balance", balance_params);
        auto balance_response = std::make_shared<monero_get_balance_response>();
        monero_get_balance_response::from_property_tree(balance_result, balance_response);
        for (const auto &subaddress : balance_response->m_per_subaddress) {
          // merge info
          auto account = &accounts.at(subaddress->m_account_index.get());
          if (account->m_index != subaddress->m_account_index) throw monero_error("RPC accounts are out of order");
          auto tgt_subaddress = &account->m_subaddresses.at(subaddress->m_index.get());
          if (tgt_subaddress->m_index != subaddress->m_index) throw monero_error("RPC subaddresses are out of order");

          if (subaddress->m_balance != boost::none) tgt_subaddress->m_balance = subaddress->m_balance;
          if (subaddress->m_unlocked_balance != boost::none) tgt_subaddress->m_unlocked_balance = subaddress->m_unlocked_balance;
          if (subaddress->m_num_unspent_outputs != boost::none) tgt_subaddress->m_num_unspent_outputs = subaddress->m_num_unspent_outputs;
          if (subaddress->m_num_blocks_to_unlock != boost::none) tgt_subaddress->m_num_blocks_to_unlock = subaddress->m_num_blocks_to_unlock;
        }
      }
    }

    return accounts;
  }

  monero_account monero_wallet_rpc::create_account(const std::string& label) {
    MTRACE("monero_wallet_rpc::create_account(" << label << ")");
    auto params = std::make_shared<monero_account_tag_params>();
    params->m_label = label;
    auto result = m_rpc->send_json_request("create_account", params);
    monero_account account;
    deserialize_account(result, account);
    account.m_balance = 0;
    account.m_unlocked_balance = 0;
    if (account.m_index == boost::none || account.m_primary_address == boost::none) throw monero_error("Could not create account");
    return account;
  }

  std::vector<monero_subaddress> monero_wallet_rpc::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices, bool skip_balances) const {
    MTRACE("monero_wallet_rpc::get_subaddresses(" << account_idx << ", ...)");
    MTRACE("monero_wallet_rpc::get_subaddresses(): Subaddress indices size: " << subaddress_indices.size());

    // fetch subaddresses
    auto params = std::make_shared<monero_get_address_params>(account_idx, subaddress_indices);
    auto subaddress_result = m_rpc->send_json_request("get_address", params);
    std::vector<monero_subaddress> subaddresses;
    std::vector<std::shared_ptr<monero_subaddress>> subaddresses_ptr;
    deserialize_subaddresses(subaddress_result, subaddresses_ptr);

    for(const auto& subaddress_ptr : subaddresses_ptr) {
      subaddress_ptr->m_account_index = account_idx;
      subaddresses.push_back(*subaddress_ptr);
    }

    // initialize subaddresses

    // fetch and initialize subaddress balances
    if (!skip_balances) {
      // these fields are not initialized if subaddress is unused and therefore not returned from `get_balance`
      for (auto &subaddress : subaddresses) {
        subaddress.m_balance = 0;
        subaddress.m_unlocked_balance = 0;
        subaddress.m_num_unspent_outputs = 0;
        subaddress.m_num_blocks_to_unlock = 0;
      }

      // fetch and initialize balances
      auto balance_result = m_rpc->send_json_request("get_balance", params);
      std::vector<std::shared_ptr<monero_subaddress>> subaddresses2;
      deserialize_subaddresses(balance_result, subaddresses2);

      for (auto &tgt_subaddress: subaddresses) {
        for (const auto &rpc_subaddress : subaddresses2) {
          if (rpc_subaddress->m_index != tgt_subaddress.m_index) continue; // skip to subaddress with same index
          if (rpc_subaddress->m_balance != boost::none) tgt_subaddress.m_balance = rpc_subaddress->m_balance;
          if (rpc_subaddress->m_unlocked_balance != boost::none) tgt_subaddress.m_unlocked_balance = rpc_subaddress->m_unlocked_balance;
          if (rpc_subaddress->m_num_unspent_outputs != boost::none) tgt_subaddress.m_num_unspent_outputs = rpc_subaddress->m_num_unspent_outputs;
          if (rpc_subaddress->m_num_blocks_to_unlock != boost::none) tgt_subaddress.m_num_blocks_to_unlock = rpc_subaddress->m_num_blocks_to_unlock;
        }
      }
    }

    // cache addresses
    {
      boost::lock_guard<boost::mutex> lock(m_address_cache_mutex);
      auto it = m_address_cache.find(account_idx);
      if (it == m_address_cache.end()) {
        m_address_cache[account_idx] = std::unordered_map<uint32_t, std::string>();
      }

      for (const auto& subaddress : subaddresses) {
        m_address_cache[account_idx][subaddress.m_index.get()] = subaddress.m_address.get();
      }
    }

    // return results
    return subaddresses;
  }

  std::vector<monero_subaddress> monero_wallet_rpc::get_subaddresses(uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    return get_subaddresses(account_idx, subaddress_indices, false);
  }

  std::vector<monero_subaddress> monero_wallet_rpc::get_subaddresses(const uint32_t account_idx) const {
    std::vector<uint32_t> empty_indices;
    return get_subaddresses(account_idx, empty_indices);
  }

  monero_subaddress monero_wallet_rpc::get_subaddress(const uint32_t account_idx, const uint32_t subaddress_idx) const {
    std::vector<uint32_t> subaddress_indices;
    subaddress_indices.push_back(subaddress_idx);
    auto subaddresses = get_subaddresses(account_idx, subaddress_indices);
    if (subaddresses.empty()) throw monero_error("Subaddress is not initialized");
    if (subaddresses.size() != 1) throw monero_error("Only 1 subaddress should be returned");
    return subaddresses[0];
  }

  monero_subaddress monero_wallet_rpc::create_subaddress(uint32_t account_idx, const std::string& label) {
    MTRACE("monero_wallet_rpc::create_subaddress(" << account_idx << ", " << label << ")");
    auto params = std::make_shared<monero_create_edit_subaddress_params>(account_idx, label);
    auto result = m_rpc->send_json_request("create_address", params);
    auto subaddress = std::make_shared<monero_subaddress>();
    deserialize_subaddress(result, subaddress);
    subaddress->m_account_index = account_idx;
    subaddress->m_balance = 0;
    subaddress->m_unlocked_balance = 0;
    subaddress->m_num_unspent_outputs = 0;
    subaddress->m_is_used = false;
    subaddress->m_num_blocks_to_unlock = 0;
    if (!label.empty()) subaddress->m_label = label;
    return *subaddress;
  }

  void monero_wallet_rpc::set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label) {
    MTRACE("monero_wallet_rpc::set_subaddress_label(" << account_idx << ", " << subaddress_idx << ", " << label << ")");
    auto params = std::make_shared<monero_create_edit_subaddress_params>(account_idx, subaddress_idx, label);
    m_rpc->send_json_request("label_address", params);
  }

  std::string monero_wallet_rpc::export_outputs(bool all) const {
    auto params = std::make_shared<monero_wallet_data_params>(all);
    auto result = m_rpc->send_json_request("export_outputs", params);
    return deserialize_exported_outputs(result);
  }

  int monero_wallet_rpc::import_outputs(const std::string& outputs_hex) {
    auto params = std::make_shared<monero_wallet_data_params>(outputs_hex);
    auto result = m_rpc->send_json_request("import_outputs", params);
    return deserialize_num_imported_outputs(result);
  }

  std::vector<std::shared_ptr<monero_key_image>> monero_wallet_rpc::export_key_images(bool all) const {
    MTRACE("monero_wallet_rpc::export_key_images()");
    auto params = std::make_shared<monero_wallet_data_params>(all);
    auto result = m_rpc->send_json_request("export_key_images", params);
    std::vector<std::shared_ptr<monero_key_image>> key_images;
    deserialize_key_images(result, key_images);
    return key_images;
  }

  std::shared_ptr<monero_key_image_import_result> monero_wallet_rpc::import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) {
    MTRACE("monero_wallet_rpc::import_key_images()");
    auto params = std::make_shared<monero_wallet_data_params>(key_images);
    auto result = m_rpc->send_json_request("import_key_images", params);
    auto import_result = std::make_shared<monero_key_image_import_result>();
    deserialize_key_image_import_result(result, import_result);
    return import_result;
  }

  void monero_wallet_rpc::freeze_output(const std::string& key_image) {
    auto params = std::make_shared<monero_query_output_params>(key_image);
    m_rpc->send_json_request("freeze", params);
  }

  void monero_wallet_rpc::thaw_output(const std::string& key_image) {
    auto params = std::make_shared<monero_query_output_params>(key_image);
    m_rpc->send_json_request("thaw", params);
  }

  bool monero_wallet_rpc::is_output_frozen(const std::string& key_image) {
    auto params = std::make_shared<monero_query_output_params>(key_image);
    auto result = m_rpc->send_json_request("frozen", params);
    return deserialize_frozen_output_info(result);
  }

  monero_tx_priority monero_wallet_rpc::get_default_fee_priority() const {
    auto result = m_rpc->send_json_request("get_default_fee_priority");
    return deserialize_tx_priority(result);
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_rpc::create_txs(const monero_tx_config& conf) {
    MTRACE("monero_wallet_rpc::create_txs");

    // validate, copy, and normalize request
    monero_tx_config config = conf;
    if (config.m_address == boost::none && config.m_destinations.empty()) throw monero_error("Destinations cannot be empty");
    if (config.m_sweep_each_subaddress != boost::none) throw monero_error("Sweep each subaddress not supported");
    if (config.m_below_amount != boost::none) throw monero_error("Below amount not supported");

    if (config.m_can_split == boost::none) {
      config = config.copy();
      config.m_can_split = true;
    }
    if (gen_utils::bool_equals(true, config.m_relay) && is_multisig()) throw monero_error("Cannot relay multisig transaction until co-signed");

    // determine account and subaddresses to send from
    if (config.m_account_index == boost::none) throw monero_error("Must specify the account index to send from");
    auto account_idx = config.m_account_index.get();

    // cannot apply subtractFeeFrom with `transfer_split` call
    if (gen_utils::bool_equals(true, config.m_can_split) && config.m_subtract_fee_from.size() > 0) {
      throw monero_error("subtractfeefrom transfers cannot be split over multiple transactions yet");
    }

    // build request parameters
    auto params = std::make_shared<monero_transfer_params>(config);
    std::string request_path = "transfer";
    if (gen_utils::bool_equals(true, config.m_can_split)) request_path = "transfer_split";

    boost::property_tree::ptree result;
    try {
      result = m_rpc->send_json_request(request_path, params);
    } catch (const monero_rpc_error& ex) {
      std::string message = ex.what();
      if (message.find("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS") != std::string::npos) throw monero_error("Invalid destination address");
      throw;
    }

    // pre-initialize txs iff present. multisig and view-only wallets will have tx set without transactions
    bool can_split = gen_utils::bool_equals(true, config.m_can_split);
    int num_txs = deserialize_num_created_txs(result, can_split);
    bool copy_destinations = num_txs == 1;

    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    for (int i = 0; i < num_txs; i++) {
      auto tx = std::make_shared<monero_tx_wallet>();
      init_sent_tx(config, tx, copy_destinations);
      tx->m_outgoing_transfer->m_account_index = account_idx;

      if (config.m_subaddress_indices.size() == 1) {
        tx->m_outgoing_transfer->m_subaddress_indices = config.m_subaddress_indices;
      }

      txs.push_back(tx);
    }

    // notify of changes
    if (gen_utils::bool_equals(true, config.m_relay)) poll();

    // initialize tx set from rpc response with pre-initialized txs
    auto tx_set = std::make_shared<monero_tx_set>();
    if (can_split) {
      deserialize_sent_tx_set(result, tx_set, txs, config);
    }
    else if (txs.empty()) {
      auto __tx = std::make_shared<monero_tx_wallet>();
      deserialize_tx_set(result, tx_set, __tx, true, config);
    }
    else {
      deserialize_tx_set(result, tx_set, txs[0], true, config);
    }

    return tx_set->m_txs;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_rpc::sweep_unlocked(const monero_tx_config& config) {
    // validate config
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (destinations.size() != 1) throw monero_error("Must specify exactly one destination to sweep to");
    if (destinations[0]->m_address == boost::none) throw monero_error("Must specify destination address to sweep to");
    if (destinations[0]->m_amount != boost::none) throw monero_error("Cannot specify amount to sweep");
    if (config.m_account_index == boost::none && config.m_subaddress_indices.size() != 0) throw monero_error("Must specify account index if subaddress indices are specified");

    // determine account and subaddress indices to sweep; default to all with unlocked balance if not specified
    std::map<uint32_t, std::vector<uint32_t>> indices;
    if (config.m_account_index != boost::none) {
      if (config.m_subaddress_indices.size() != 0) {
        indices[config.m_account_index.get()] = config.m_subaddress_indices;
      } else {
        std::vector<uint32_t> subaddress_indices;
        for (const monero_subaddress& subaddress : monero_wallet::get_subaddresses(config.m_account_index.get())) {
          // TODO wallet rpc sweep_all now supports req.subaddr_indices_all
          if (subaddress.m_unlocked_balance.get() > 0) subaddress_indices.push_back(subaddress.m_index.get());
        }
        indices[config.m_account_index.get()] = subaddress_indices;
      }
    } else {
      std::vector<monero_account> accounts = monero_wallet::get_accounts(true);
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
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    for (std::pair<uint32_t, std::vector<uint32_t>> subaddress_indices_pair : indices) {

      // copy and modify the original config
      monero_tx_config copy = config.copy();
      copy.m_account_index = subaddress_indices_pair.first;
      copy.m_sweep_each_subaddress = false;

      // sweep all subaddresses together  // TODO monero-project: can this reveal outputs belong to the same wallet?
      if (copy.m_sweep_each_subaddress == boost::none || copy.m_sweep_each_subaddress.get() != true) {
        copy.m_subaddress_indices = subaddress_indices_pair.second;
        std::vector<std::shared_ptr<monero_tx_wallet>> account_txs = sweep_account(copy);
        txs.insert(std::end(txs), std::begin(account_txs), std::end(account_txs));
      }

      // otherwise sweep each subaddress individually
      else {
        for (uint32_t subaddress_index : subaddress_indices_pair.second) {
          std::vector<uint32_t> subaddress_indices;
          subaddress_indices.push_back(subaddress_index);
          copy.m_subaddress_indices = subaddress_indices;
          std::vector<std::shared_ptr<monero_tx_wallet>> account_txs = sweep_account(copy);
          txs.insert(std::end(txs), std::begin(account_txs), std::end(account_txs));
        }
      }
    }

    // notify listeners of spent funds
    if (config.m_relay != boost::none && config.m_relay.get()) poll();
    return txs;
  }

  std::shared_ptr<monero_tx_wallet> monero_wallet_rpc::sweep_output(const monero_tx_config& config) {
    MTRACE("monero_wallet_rpc::sweep_output()");

    // validate request
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (config.m_sweep_each_subaddress != boost::none) throw monero_error("Cannot sweep each subaddress when sweeping single output");
    if (config.m_below_amount != boost::none) throw monero_error("Cannot specifiy below_amount when sweeping single output");
    if (config.m_can_split != boost::none) throw monero_error("Splitting is not applicable when sweeping output");
    if (destinations.size() != 1) throw monero_error("Must provide exactly one destination address to sweep output to");
    if (destinations[0]->m_address == boost::none) throw monero_error("Must specify destination address to sweep to");
    if (destinations[0]->m_amount != boost::none) throw monero_error("Cannot specify amount to sweep");
    if (config.m_subtract_fee_from.size() > 0) throw monero_error("Sweep transactions do not support subtracting fees from destinations");

    auto params = std::make_shared<monero_sweep_params>(config);
    auto result = m_rpc->send_json_request("sweep_single", params);
    if (gen_utils::bool_equals(true, config.m_relay)) poll();
    auto set = std::make_shared<monero_tx_set>();
    auto tx = std::make_shared<monero_tx_wallet>();
    init_sent_tx(config, tx, true);
    deserialize_tx_set(result, set, tx, true, config);
    // initialize destination amount
    tx->m_outgoing_transfer->m_destinations[0]->m_amount = tx->m_outgoing_transfer->m_amount;
    return tx;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_rpc::sweep_dust(bool relay) {
    MTRACE("monero_wallet_rpc::sweep_dust()");
    auto params = std::make_shared<monero_sweep_params>(relay);
    auto result = m_rpc->send_json_request("sweep_dust", params);
    if (relay) poll();
    auto set = std::make_shared<monero_tx_set>();
    deserialize_sent_tx_set(result, set);

    for(const std::shared_ptr<monero_tx_wallet>& tx : set->m_txs) {
      tx->m_is_relayed = relay;
      tx->m_in_tx_pool = relay;
    }

    return set->m_txs;
  }

  std::vector<std::string> monero_wallet_rpc::relay_txs(const std::vector<std::string>& tx_metadatas) {
    MTRACE("monero_wallet_rpc::relay_txs()");

    if (tx_metadatas.empty()) throw monero_error("Must provide an array of tx metadata to relay");

    std::vector<std::string> tx_hashes;

    for (const auto &tx_metadata : tx_metadatas) {
      auto params = std::make_shared<monero_wallet_relay_tx_params>(tx_metadata);
      auto result = m_rpc->send_json_request("relay_tx", params);
      deserialize_relayed_tx_hash(result, tx_hashes);
    }

    // notify of changes
    poll();

    return tx_hashes;
  }

  monero_tx_set monero_wallet_rpc::describe_tx_set(const monero_tx_set& tx_set) {
    auto params = std::make_shared<monero_sign_describe_transfer_params>();
    params->m_multisig_txset = tx_set.m_multisig_tx_hex;
    params->m_unsigned_txset = tx_set.m_unsigned_tx_hex;
    auto result = m_rpc->send_json_request("describe_transfer", params);
    auto set = std::make_shared<monero_tx_set>();
    deserialize_described_tx_set(result, set);
    return *set;
  }

  monero_tx_set monero_wallet_rpc::sign_txs(const std::string& unsigned_tx_hex) {
    auto params = std::make_shared<monero_sign_describe_transfer_params>(unsigned_tx_hex);
    auto result = m_rpc->send_json_request("sign_transfer", params);
    auto set = std::make_shared<monero_tx_set>();
    deserialize_sent_tx_set(result, set);
    return *set;
  }

  std::vector<std::string> monero_wallet_rpc::submit_txs(const std::string& signed_tx_hex) {
    auto params = std::make_shared<monero_wallet_relay_tx_params>();
    params->m_signed_tx_hex = signed_tx_hex;
    auto result = m_rpc->send_json_request("submit_transfer", params);
    poll();
    std::vector<std::string> tx_hashes;
    deserialize_submitted_tx_hashes(result, tx_hashes);
    return tx_hashes;
  }

  std::string monero_wallet_rpc::sign_message(const std::string& msg, monero_message_signature_type signature_type, uint32_t account_idx, uint32_t subaddress_idx) const {
    auto params = std::make_shared<monero_verify_sign_message_params>(msg, signature_type, account_idx, subaddress_idx);
    auto result = m_rpc->send_json_request("sign", params);
    return deserialize_signature(result);
  }

  monero_message_signature_result monero_wallet_rpc::verify_message(const std::string& msg, const std::string& address, const std::string& signature) const {
    auto params = std::make_shared<monero_verify_sign_message_params>(msg, address, signature);
    monero_message_signature_result sig_result;
    sig_result.m_is_good = false;
    try {
      auto result = m_rpc->send_json_request("verify", params);
      deserialize_message_signature_result(result, sig_result);
    } catch (const monero_rpc_error& ex) {
      if (ex.code != -2) throw;
    }

    return sig_result;
  }

  void normalize_wallet_error(const monero_rpc_error& ex) {
    // normalize error message
    if (ex.code == -1 && std::string(ex.what()).find("basic_string") != std::string::npos) {
      throw monero_rpc_error(-1, "Must provide signature to check tx proof");
    } else if (ex.code == -8 && ex.what() == std::string("TX ID has invalid format")) {
      throw monero_rpc_error(-8, "TX hash has invalid format");
    }
    throw;
  }

  std::string monero_wallet_rpc::get_tx_key(const std::string& tx_hash) const {
    MTRACE("monero_wallet_rpc::get_tx_key()");
    std::string tx_key;

    try {
      auto params = std::make_shared<monero_check_tx_key_params>(tx_hash);
      auto result = m_rpc->send_json_request("get_tx_key", params);
      tx_key = deserialize_tx_key(result);
    } catch (const monero_rpc_error& ex) {
      normalize_wallet_error(ex);
    }

    return tx_key;
  }

  std::shared_ptr<monero_check_tx> monero_wallet_rpc::check_tx_key(const std::string& tx_hash, const std::string& tx_key, const std::string& address) const {
    MTRACE("monero_wallet_rpc::check_tx_key()");
    auto check = std::make_shared<monero_check_tx>();

    try {
      auto params = std::make_shared<monero_check_tx_key_params>(tx_hash, tx_key, address);
      auto result = m_rpc->send_json_request("check_tx_key", params);
      check->m_is_good = true;
      deserialize_check_tx(result, check);
    } catch (const monero_rpc_error& ex) {
      normalize_wallet_error(ex);
    }

    return check;
  }

  std::string monero_wallet_rpc::get_tx_proof(const std::string& tx_hash, const std::string& address, const std::string& message) const {
    std::string tx_proof;
    try {
      auto params = std::make_shared<monero_reserve_proof_params>(tx_hash, message);
      params->m_address = address;
      auto result = m_rpc->send_json_request("get_tx_proof", params);
      tx_proof = deserialize_signature(result);
    } catch (const monero_rpc_error& ex) {
      normalize_wallet_error(ex);
    }

    return tx_proof;
  }

  std::shared_ptr<monero_check_tx> monero_wallet_rpc::check_tx_proof(const std::string& tx_hash, const std::string& address, const std::string& message, const std::string& signature) const {
    MTRACE("monero_wallet_rpc::check_tx_proof()");

    auto check = std::make_shared<monero_check_tx>();
    try {
      auto params = std::make_shared<monero_reserve_proof_params>(tx_hash, address, message, signature);
      auto result = m_rpc->send_json_request("check_tx_proof", params);
      deserialize_check_tx(result, check);
    } catch (const monero_rpc_error& ex) {
      normalize_wallet_error(ex);
    }

    return check;
  }

  std::string monero_wallet_rpc::get_spend_proof(const std::string& tx_hash, const std::string& message) const {
    MTRACE("monero_wallet_rpc::get_spend_proof()");

    std::string spend_proof;
    try {
      auto params = std::make_shared<monero_reserve_proof_params>(tx_hash, message);
      auto result = m_rpc->send_json_request("get_spend_proof", params);
      spend_proof = deserialize_signature(result);
    } catch (const monero_rpc_error& ex) {
      normalize_wallet_error(ex);
    }

    return spend_proof;
  }

  bool monero_wallet_rpc::check_spend_proof(const std::string& tx_hash, const std::string& message, const std::string& signature) const {
    MTRACE("monero_wallet_rpc::check_spend_proof()");

    auto proof = std::make_shared<monero_check_reserve>();
    try {
      auto params = std::make_shared<monero_reserve_proof_params>(tx_hash, message);
      params->m_signature = signature;
      auto result = m_rpc->send_json_request("check_spend_proof", params);
      deserialize_check_reserve(result, proof);
    } catch (const monero_rpc_error& ex) {
      normalize_wallet_error(ex);
    }

    return proof->m_is_good;
  }

  std::string monero_wallet_rpc::get_reserve_proof_wallet(const std::string& message) const {
    MTRACE("monero_wallet_rpc::get_reserve_proof_wallet()");
    auto params = std::make_shared<monero_reserve_proof_params>(message);
    auto result = m_rpc->send_json_request("get_reserve_proof", params);
    return deserialize_signature(result);
  }

  std::string monero_wallet_rpc::get_reserve_proof_account(uint32_t account_idx, uint64_t amount, const std::string& message) const {
    MTRACE("monero_wallet_rpc::get_reserve_proof_account()");
    auto params = std::make_shared<monero_reserve_proof_params>(account_idx, amount, message);
    auto result = m_rpc->send_json_request("get_reserve_proof", params);
    return deserialize_signature(result);
  }

  std::shared_ptr<monero_check_reserve> monero_wallet_rpc::check_reserve_proof(const std::string& address, const std::string& message, const std::string& signature) const {
    MTRACE("monero_wallet_rpc::check_reserve_proof()");
    auto params = std::make_shared<monero_reserve_proof_params>(address, message, signature);
    auto result = m_rpc->send_json_request("check_reserve_proof", params);
    auto proof = std::make_shared<monero_check_reserve>();
    deserialize_check_reserve(result, proof);
    return proof;
  }

  std::string monero_wallet_rpc::get_tx_note(const std::string& tx_hash) const {
    MTRACE("monero_wallet_rpc::get_tx_note()");
    std::vector<std::string> tx_hashes;
    tx_hashes.push_back(tx_hash);
    auto notes = get_tx_notes(tx_hashes);
    if (notes.size() != 1) throw monero_error("Expected one tx note");
    return notes[0];
  }

  std::vector<std::string> monero_wallet_rpc::get_tx_notes(const std::vector<std::string>& tx_hashes) const {
    MTRACE("monero_wallet_rpc::get_tx_notes()");
    auto params = std::make_shared<monero_tx_notes_params>(tx_hashes);
    auto result = m_rpc->send_json_request("get_tx_notes", params);
    std::vector<std::string> tx_notes;
    deserialize_tx_notes(result, tx_notes);
    return tx_notes;
  }

  void monero_wallet_rpc::set_tx_note(const std::string& tx_hash, const std::string& note) {
    MTRACE("monero_wallet_rpc::set_tx_note()");
    std::vector<std::string> tx_hashes;
    std::vector<std::string> notes;
    tx_hashes.push_back(tx_hash);
    notes.push_back(note);
    set_tx_notes(tx_hashes, notes);
  }

  void monero_wallet_rpc::set_tx_notes(const std::vector<std::string>& tx_hashes, const std::vector<std::string>& notes) {
    MTRACE("monero_wallet_rpc::set_tx_notes()");
    auto params = std::make_shared<monero_tx_notes_params>(tx_hashes, notes);
    m_rpc->send_json_request("set_tx_notes", params);
  }

  std::vector<monero_address_book_entry> monero_wallet_rpc::get_address_book_entries(const std::vector<uint64_t>& indices) const {
    MTRACE("monero_wallet_rpc::get_address_book_entries()");
    auto params = std::make_shared<monero_address_book_entry_params>(indices);
    auto result = m_rpc->send_json_request("get_address_book", params);
    std::vector<monero_address_book_entry> entries;
    deserialize_address_book_entries(result, entries);
    return entries;
  }

  uint64_t monero_wallet_rpc::add_address_book_entry(const std::string& address, const std::string& description) {
    MTRACE("monero_wallet_rpc::add_address_book_entry()");
    auto params = std::make_shared<monero_address_book_entry_params>(address, description);
    auto result = m_rpc->send_json_request("add_address_book", params);
    return deserialize_address_book_index(result);
  }

  void monero_wallet_rpc::edit_address_book_entry(uint64_t index, bool set_address, const std::string& address, bool set_description, const std::string& description) {
    MTRACE("monero_wallet_rpc::edit_address_book_entry()");
    auto params = std::make_shared<monero_address_book_entry_params>(index, set_address, address, set_description, description);
    m_rpc->send_json_request("edit_address_book", params);
  }

  void monero_wallet_rpc::delete_address_book_entry(uint64_t index) {
    auto params = std::make_shared<monero_address_book_entry_params>(index);
    m_rpc->send_json_request("delete_address_book", params);
  }

  void monero_wallet_rpc::tag_accounts(const std::string& tag, const std::vector<uint32_t>& account_indices) {
    auto params = std::make_shared<monero_account_tag_params>(tag, account_indices);
    m_rpc->send_json_request("tag_accounts", params);
  }

  void monero_wallet_rpc::untag_accounts(const std::vector<uint32_t>& account_indices) {
    auto params = std::make_shared<monero_account_tag_params>(account_indices);
    m_rpc->send_json_request("untag_accounts", params);
  }

  std::vector<std::shared_ptr<monero_account_tag>> monero_wallet_rpc::get_account_tags() const {
    auto result = m_rpc->send_json_request("get_account_tags");
    std::vector<std::shared_ptr<monero_account_tag>> account_tags;
    deserialize_account_tags(result, account_tags);
    return account_tags;
  }

  void monero_wallet_rpc::set_account_tag_label(const std::string& tag, const std::string& label) {
    auto params = std::make_shared<monero_account_tag_params>(tag, label);
    m_rpc->send_json_request("set_account_tag_description", params);
  }

  std::string monero_wallet_rpc::get_payment_uri(const monero_tx_config& config) const {
    MTRACE("monero_wallet_rpc::get_payment_uri()");
    auto params = std::make_shared<monero_payment_uri_params>(config);
    auto result = m_rpc->send_json_request("make_uri", params);
    return deserialize_payment_uri(result);
  }

  std::shared_ptr<monero_tx_config> monero_wallet_rpc::parse_payment_uri(const std::string& uri) const {
    MTRACE("monero_wallet_rpc::parse_payment_uri(" << uri << ")");
    auto params = std::make_shared<monero_payment_uri_params>(uri);
    auto result = m_rpc->send_json_request("parse_uri", params);
    auto tx_config = std::make_shared<monero_tx_config>();
    deserialize_payment_uri(result, tx_config);
    return tx_config;
  }

  void monero_wallet_rpc::set_attribute(const std::string& key, const std::string& val) {
    auto params = std::make_shared<key_value>(key, val);
    m_rpc->send_json_request("set_attribute", params);
  }

  bool monero_wallet_rpc::get_attribute(const std::string& key, std::string& value) const {
    try {
      auto params = std::make_shared<key_value>(key);
      auto result = m_rpc->send_json_request("get_attribute", params);
      key_value::from_property_tree(result, params);
      if (params->m_value == boost::none) return false;
      value = params->m_value.get();
      return true;
    }
    catch (const monero_rpc_error& ex) {
      if (ex.code == -45) {
        // attribute not found
        value = std::string("");
        return false;
      }
      throw;
    }

    return false;
  }

  void monero_wallet_rpc::start_mining(boost::optional<uint64_t> num_threads, boost::optional<bool> background_mining, boost::optional<bool> ignore_battery) {
    MTRACE("monero_wallet_rpc::start_mining()");
    auto params = std::make_shared<monero_start_mining_params>(num_threads, background_mining, ignore_battery);
    m_rpc->send_json_request("start_mining", params);
  }

  void monero_wallet_rpc::stop_mining() {
    MTRACE("monero_wallet_rpc::stop_mining()");
    m_rpc->send_json_request("stop_mining");
  }

  bool monero_wallet_rpc::is_multisig_import_needed() const {
    auto result = m_rpc->send_json_request("get_balance");
    auto balance = std::make_shared<monero_get_balance_response>();
    monero_get_balance_response::from_property_tree(result, balance);
    return gen_utils::bool_equals(true, balance->m_multisig_import_needed);
  }

  monero_multisig_info monero_wallet_rpc::get_multisig_info() const {
    auto result = m_rpc->send_json_request("is_multisig");
    monero_multisig_info info;
    deserialize_multisig_info(result, info);
    return info;
  }

  std::string monero_wallet_rpc::prepare_multisig() {
    auto params = std::make_shared<monero_multisig_params>();
    auto result = m_rpc->send_json_request("prepare_multisig", params);
    clear_address_cache();
    auto response = std::make_shared<monero_multisig_response>();
    monero_multisig_response::from_property_tree(result, response);
    if (response->m_multisig_info == boost::none) throw monero_error("Failed to prepare multisig");
    return response->m_multisig_info.get();
  }

  std::string monero_wallet_rpc::make_multisig(const std::vector<std::string>& multisig_hexes, int threshold, const std::string& password) {
    auto params = std::make_shared<monero_multisig_params>(multisig_hexes, threshold, password);
    auto result = m_rpc->send_json_request("make_multisig", params);
    clear_address_cache();
    auto response = std::make_shared<monero_multisig_response>();
    monero_multisig_response::from_property_tree(result, response);
    if (response->m_multisig_info == boost::none) throw monero_error("Failed to make multisig");
    return response->m_multisig_info.get();
  }

  monero_multisig_init_result monero_wallet_rpc::exchange_multisig_keys(const std::vector<std::string>& multisig_hexes, const std::string& password) {
    auto params = std::make_shared<monero_multisig_params>(multisig_hexes, password);
    auto result = m_rpc->send_json_request("exchange_multisig_keys", params);
    clear_address_cache();
    monero_multisig_init_result multisig_init;
    deserialize_multisig_init_result(result, multisig_init);
    return multisig_init;
  }

  std::string monero_wallet_rpc::export_multisig_hex() {
    auto result = m_rpc->send_json_request("export_multisig_info");
    auto response = std::make_shared<monero_multisig_response>();
    monero_multisig_response::from_property_tree(result, response);
    if (response->m_multisig_info == boost::none) throw monero_error("Failed to export multisig");
    return response->m_multisig_info.get();
  }

  int monero_wallet_rpc::import_multisig_hex(const std::vector<std::string>& multisig_hexes, const bool refresh_after_import) {
    auto params = std::make_shared<monero_multisig_params>(multisig_hexes, refresh_after_import);
    auto result = m_rpc->send_json_request("import_multisig_info", params);
    auto response = std::make_shared<monero_multisig_response>();
    monero_multisig_response::from_property_tree(result, response);
    if (response->m_num_outputs == boost::none) throw monero_error("Failed to import multisig");
    return response->m_num_outputs.get();
  }

  monero_multisig_sign_result monero_wallet_rpc::sign_multisig_tx_hex(const std::string& multisig_tx_hex) {
    auto params = std::make_shared<monero_multisig_params>(multisig_tx_hex);
    auto result = m_rpc->send_json_request("sign_multisig", params);
    monero_multisig_sign_result multisig_result;
    deserialize_multisig_sign_result(result, multisig_result);
    return multisig_result;
  }

  std::vector<std::string> monero_wallet_rpc::submit_multisig_tx_hex(const std::string& signed_multisig_tx_hex) {
    auto params = std::make_shared<monero_multisig_params>(signed_multisig_tx_hex);
    auto result = m_rpc->send_json_request("submit_multisig", params);
    auto response = std::make_shared<monero_multisig_response>();
    monero_multisig_response::from_property_tree(result, response);
    return response->m_tx_hashes;
  }

  void monero_wallet_rpc::change_password(const std::string& old_password, const std::string& new_password) {
    MTRACE("monero_wallet_rpc::change_password(" << "***" << ", ***)");
    auto params = std::make_shared<monero_change_wallet_password_params>(old_password, new_password);
    m_rpc->send_json_request("change_wallet_password", params);
  }

  void monero_wallet_rpc::save() {
    MTRACE("monero_wallet_rpc::save()");
    m_rpc->send_json_request("store");
  }

  bool monero_wallet_rpc::is_closed() const {
    try {
      get_primary_address();
    } catch (const monero_rpc_error& ex) {
      return ex.code == -8 && std::string(ex.what()).find("No wallet file") != std::string::npos;
    } catch (const monero_error&) {
      return false;
    }

    return false;
  }

  void monero_wallet_rpc::close(bool save) {
    MTRACE("monero_wallet_rpc::close()");
    clear();
    auto params = std::make_shared<monero_close_wallet_params>(save);
    m_rpc->send_json_request("close_wallet", params);
  }

  std::shared_ptr<monero_subaddress> monero_wallet_rpc::get_balances(const boost::optional<uint32_t>& account_idx, const boost::optional<uint32_t>& subaddress_idx) const {
    auto balance = std::make_shared<monero_subaddress>();
    balance->m_balance = 0;
    balance->m_unlocked_balance = 0;

    if (account_idx == boost::none) {
      if (subaddress_idx != boost::none) throw monero_error("Must provide account index with subaddress index");

      auto accounts = monero_wallet::get_accounts();

      for(const auto &account : accounts) {
        balance->m_balance = balance->m_balance.get() + account.m_balance.get();
        balance->m_unlocked_balance = balance->m_unlocked_balance.get() + account.m_unlocked_balance.get();
      }

      return balance;
    }
    else {
      auto params = std::make_shared<monero_get_balance_params>(account_idx.get(), subaddress_idx);
      auto result = m_rpc->send_json_request("get_balance", params);
      auto balance_response = std::make_shared<monero_get_balance_response>();
      monero_get_balance_response::from_property_tree(result, balance_response);

      if (subaddress_idx == boost::none) {
        balance->m_balance = balance_response->m_balance.get();
        balance->m_unlocked_balance = balance_response->m_unlocked_balance.get();
        return balance;
      }
      else if (balance_response->m_per_subaddress.size() > 0) {
        auto sub = balance_response->m_per_subaddress[0];
        balance->m_balance = sub->m_balance.get();
        balance->m_unlocked_balance = sub->m_unlocked_balance.get();
      }
    }

    return balance;
  }

  monero_wallet_rpc* monero_wallet_rpc::create_wallet_random(const std::shared_ptr<monero_wallet_config> &conf) {
    // validate and normalize config
    auto config = conf->copy();
    if (config.m_seed_offset != boost::none) throw monero_error("Cannot specify seed offset when creating random wallet");
    if (config.m_restore_height != boost::none) throw monero_error("Cannot specify restore height when creating random wallet");
    if (config.m_save_current != boost::none && config.m_save_current == false) throw monero_error("Current wallet is saved automatically when creating random wallet");
    if (config.m_path == boost::none || config.m_path->empty()) throw monero_error("Wallet name is not initialized");
    if (config.m_language == boost::none || config.m_language->empty()) config.m_language = "English";

    // send request
    std::string filename = config.m_path.get();
    std::string password = config.m_password.value_or("");
    std::string language = config.m_language.get();

    auto params = std::make_shared<monero_create_open_wallet_params>(filename, password, language);
    try { m_rpc->send_json_request("create_wallet", params); }
    catch (const monero_rpc_error& ex) { handle_create_wallet_error(ex, filename); }
    clear();
    m_path = filename;
    return this;
  }

  monero_wallet_rpc* monero_wallet_rpc::create_wallet_from_seed(const std::shared_ptr<monero_wallet_config> &conf) {
    auto config = conf->copy();
    if (config.m_seed == boost::none || config.m_seed->empty()) throw monero_error("Must specify a valid mnemonic when creating wallet from seed");
    if (config.m_path == boost::none || config.m_path->empty()) throw monero_error("Wallet name is not initialized");
    if (config.m_language == boost::none || config.m_language->empty()) config.m_language = "English";

    // send request
    bool autosave_current = config.m_save_current.value_or(false);
    bool enable_multisig_experimental = config.m_is_multisig.value_or(false);
    auto params = std::make_shared<monero_create_open_wallet_params>(config.m_path, config.m_password, config.m_seed, config.m_seed_offset, config.m_restore_height, config.m_language, autosave_current, enable_multisig_experimental);
    try { m_rpc->send_json_request("restore_deterministic_wallet", params); }
    catch (const monero_rpc_error& ex) { handle_create_wallet_error(ex, config.m_path.get()); }
    clear();
    m_path = config.m_path.get();
    return this;
  }

  monero_wallet_rpc* monero_wallet_rpc::create_wallet_from_keys(const std::shared_ptr<monero_wallet_config> &conf) {
    auto config = conf->copy();
    if (config.m_seed_offset != boost::none) throw monero_error("Cannot specify seed offset when creating wallet from keys");
    if (config.m_path == boost::none || config.m_path->empty()) throw monero_error("Wallet name is not initialized");

    std::string filename = config.m_path.get();
    std::string password = config.m_password.value_or("");
    std::string address = config.m_primary_address.value_or("");
    std::string view_key = config.m_private_view_key.value_or("");
    std::string spend_key = config.m_private_spend_key.value_or("");
    uint64_t restore_height = config.m_restore_height.value_or(0);
    bool autosave_current = config.m_save_current.value_or(false);
    auto params = std::make_shared<monero_create_open_wallet_params>(filename, password, address, view_key, spend_key, restore_height, autosave_current);
    try { m_rpc->send_json_request("generate_from_keys", params); }
    catch (const monero_rpc_error& ex) { handle_create_wallet_error(ex, filename); }
    clear();
    m_path = config.m_path.get();
    return this;
  }

  std::string monero_wallet_rpc::query_key(const std::string& key_type) const {
    auto params = std::make_shared<monero_query_key_params>(key_type);
    auto result = m_rpc->send_json_request("query_key", params);
    auto kv = std::make_shared<key_value>();
    key_value::from_property_tree(result, kv);
    if (kv->m_key == boost::none) throw monero_error(std::string("Could not query key: ") + key_type);
    return *kv->m_key;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_rpc::sweep_account(const monero_tx_config &conf) {
    auto config = conf.copy();
    // validate config
    if (config.m_account_index == boost::none) throw monero_error("Must specify an account index to sweep from");
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (destinations.size() != 1) throw monero_error("Must provide exactly one destination address to sweep output to");
    if (destinations[0]->m_address == boost::none || destinations[0]->m_address->empty()) throw monero_error("Must specify destination address to sweep to");
    if (destinations[0]->m_amount != boost::none) throw monero_error("Cannot specify destination amount to sweep");
    if (config.m_key_image != boost::none) throw monero_error("Cannot define key image in sweep_account(); use sweep_output() to sweep an output by its key image");
    if (gen_utils::bool_equals(true, config.m_sweep_each_subaddress)) throw monero_error("Cannot sweep each subaddress with RPC `sweep_all`");
    if (config.m_subtract_fee_from.size() > 0) throw monero_error("Sweep transactions do not support subtracting fees from destinations");

    // sweep from all subaddresses if not otherwise defined
    if (config.m_subaddress_indices.empty()) {
      uint32_t account_idx = config.m_account_index.get();
      auto subaddresses = get_subaddresses(account_idx);
      for (const auto &subaddress : subaddresses) {
        config.m_subaddress_indices.push_back(subaddress.m_index.get());
      }
    }
    if (config.m_subaddress_indices.size() == 0) throw monero_error("No subaddresses to sweep from");
    bool relay = config.m_relay == true;
    auto params = std::make_shared<monero_sweep_params>(config);
    params->m_get_tx_key = boost::none;
    params->m_get_tx_keys = true;
    auto result = m_rpc->send_json_request("sweep_all", params);
    if (gen_utils::bool_equals(true, config.m_relay)) poll();
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    auto set = std::make_shared<monero_tx_set>();
    deserialize_sent_tx_set(result, set, txs, config);

    for (auto &tx : set->m_txs) {
      tx->m_is_locked = true;
      tx->m_is_confirmed = false;
      tx->m_num_confirmations = 0;
      tx->m_relay = relay;
      tx->m_in_tx_pool = relay;
      tx->m_is_relayed = relay;
      tx->m_is_miner_tx = false;
      tx->m_is_failed = false;
      tx->m_ring_size = monero_utils::RING_SIZE;
      if (tx->m_outgoing_transfer == nullptr) throw monero_error("Tx outgoing transfer is none");
      auto transfer = tx->m_outgoing_transfer;
      transfer->m_account_index = config.m_account_index;
      if (config.m_subaddress_indices.size() == 1) {
        transfer->m_subaddress_indices = config.m_subaddress_indices;
      }
      auto destination = std::make_shared<monero_destination>();
      destination->m_address = destinations[0]->m_address;
      destination->m_amount = transfer->m_amount;
      transfer->m_destinations.clear();
      transfer->m_destinations.push_back(destination);
      tx->m_payment_id = config.m_payment_id;
      if (tx->m_unlock_time == boost::none) tx->m_unlock_time = 0;
      if (relay) {
        if (tx->m_last_relayed_timestamp == boost::none) {
          // TODO (monero-wallet-rpc): provide timestamp on response; unconfirmed timestamps vary
          tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
        }
        if (tx->m_is_double_spend_seen == boost::none) tx->m_is_double_spend_seen = false;
      }
    }

    return set->m_txs;
  }

  void monero_wallet_rpc::clear_address_cache() {
    boost::lock_guard<boost::mutex> lock(m_address_cache_mutex);
    m_address_cache.clear();
  }

  void monero_wallet_rpc::refresh_listening() {
    boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);

    bool should_poll;
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      should_poll = !m_listeners.empty();
    }

    if (m_poller == nullptr && should_poll) {
      m_poller = std::make_unique<monero_wallet_poller>(this);
      if (m_sync_period_in_ms != boost::none) m_poller->set_period_in_ms(m_sync_period_in_ms.get());
    }
    if (m_poller != nullptr) m_poller->request_is_polling(should_poll);
  }

  void monero_wallet_rpc::poll() {
    monero_wallet_poller* poller;
    {
      boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);
      poller = m_poller.get();
    }
    if (poller != nullptr && poller->is_polling()) {
      poller->poll();
    }
  }

  void monero_wallet_rpc::clear() {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      m_listeners.clear();
    }
    refresh_listening();
    wait_for_listener_callbacks_idle();
    clear_address_cache();
    m_path = "";
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_rpc::get_txs() const {
    return get_txs(monero_tx_query());
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_rpc::get_txs(const monero_tx_query& query) const {
    MTRACE("monero_wallet_rpc::get_txs(query)");

    // copy query
    std::shared_ptr<monero_tx_query> query_sp = std::make_shared<monero_tx_query>(query); // convert to shared pointer
    std::shared_ptr<monero_tx_query> _query = query_sp->copy(query_sp, std::make_shared<monero_tx_query>()); // deep copy

    // covers the special-case re-fetch below throwing on a recursive call, too
    query_free_guard free_guard{_query};

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
    std::vector<std::shared_ptr<monero_transfer>> transfers;
    {
      // free unconditionally, even if get_transfers_aux() throws an error
      // otherwise this circularly-referenced copy leaks
      query_free_guard free_guard{temp_transfer_query->m_tx_query};
      transfers = get_transfers_aux(*temp_transfer_query);
    }

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
      // start from the caller's own output_query (if any) rather than a blank default, so
      // the outputs merged into the returned txs actually honor the caller's output filter
      std::shared_ptr<monero_output_query> temp_output_query = output_query != nullptr
        ? output_query->copy(output_query, std::make_shared<monero_output_query>())
        : std::make_shared<monero_output_query>();
      temp_output_query->m_tx_query = monero_tx_query::decontextualize(_query->copy(_query, std::make_shared<monero_tx_query>()));
      temp_output_query->m_tx_query->m_output_query = temp_output_query;
      std::vector<std::shared_ptr<monero_output_wallet>> outputs;
      {
        // free unconditionally, even if get_outputs_aux() throws an error
        // otherwise this circularly-referenced copy leaks
        query_free_guard free_guard{temp_output_query->m_tx_query};
        outputs = get_outputs_aux(*temp_output_query);
      }

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
        ++tx_iter;
      } else {
        tx_map.erase(tx->m_hash.get());
        tx_iter = txs.erase(tx_iter);
        if (tx->m_block != nullptr) tx->m_block->m_txs.erase(std::remove(tx->m_block->m_txs.begin(), tx->m_block->m_txs.end(), tx), tx->m_block->m_txs.end()); // TODO, no way to use tx_iter?
      }
    }
    txs = queried_txs;

    // special case: re-fetch txs if inconsistency caused by needing to make multiple wallet calls
    // TODO monero-project: offer wallet.get_txs(...)
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      if ((*tx->m_is_confirmed && tx->m_block == nullptr) || (!*tx->m_is_confirmed && tx->m_block != nullptr)) {
        MWARNING("Inconsistency detected building txs from multiple wallet2 calls, re-fetching");
        monero_utils::free(txs);
        txs.clear();
        txs = get_txs(*_query);
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

    return txs;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_rpc::get_transfers(const monero_transfer_query& query) const {
    // get transfers directly if query does not require tx context (e.g. other transfers, outputs)
    if (!monero_transfer_query::is_contextual(query)) return get_transfers_aux(query);

    // otherwise get txs with full models to fulfill query
    std::vector<std::shared_ptr<monero_transfer>> transfers;
    for (const std::shared_ptr<monero_tx_wallet>& tx : get_txs(*(query.m_tx_query))) {
      for (const std::shared_ptr<monero_transfer>& transfer : tx->filter_transfers(query)) { // collect queried transfers, erase if excluded
        transfers.push_back(transfer);
      }
    }
    return transfers;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_rpc::get_outputs(const monero_output_query& query) const {
    // get outputs directly if query does not require tx context (e.g. other outputs, transfers)
    if (!monero_output_query::is_contextual(query)) return get_outputs_aux(query);

    // otherwise get txs with full models to fulfill query
    std::vector<std::shared_ptr<monero_output_wallet>> outputs;
    for (const std::shared_ptr<monero_tx_wallet>& tx : get_txs(*(query.m_tx_query))) {
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(query)) { // collect queried outputs, erase if excluded
        outputs.push_back(output);
      }
    }
    return outputs;
  }

  std::map<uint32_t, std::vector<uint32_t>> monero_wallet_rpc::get_account_indices(bool get_subaddr_indices) const {
    std::map<uint32_t, std::vector<uint32_t>> indices;
    for (const auto& account : monero_wallet::get_accounts()) {
      uint32_t account_idx = account.m_index.get();
      if (get_subaddr_indices) {
        indices[account_idx] = get_subaddress_indices(account_idx);
      }
      else indices[account_idx] = std::vector<uint32_t>();
    }
    return indices;
  }

  std::vector<uint32_t> monero_wallet_rpc::get_subaddress_indices(uint32_t account_idx) const {
    // fetch subaddresses
    auto params = std::make_shared<monero_get_address_params>(account_idx);
    auto result = m_rpc->send_json_request("get_address", params);
    std::vector<uint32_t> subadress_indices;
    std::vector<std::shared_ptr<monero_subaddress>> subaddresses;
    deserialize_subaddresses(result, subaddresses);
    for (const auto& subaddress : subaddresses) {
      subadress_indices.push_back(subaddress->m_index.get());
    }
    return subadress_indices;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_rpc::get_transfers_aux(const monero_transfer_query& query) const {
    MTRACE("monero_wallet_rpc::get_transfers_aux(query)");

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

    // _query/tx_query hold circular shared_ptr references (m_tx_query <-> m_transfer_query)
    // that plain refcounting can't break; monero_utils::free() breaks the cycle manually and
    // must run on every exit path, or the copies leak
    query_free_guard free_guard{tx_query};

    // translate from monero_tx_query to in, out, pending, pool, failed terminology used by monero-wallet-rpc
    bool can_be_confirmed = !gen_utils::bool_equals(false, tx_query->m_is_confirmed) && !gen_utils::bool_equals(true, tx_query->m_in_tx_pool) && !gen_utils::bool_equals(true, tx_query->m_is_failed) && !gen_utils::bool_equals(false, tx_query->m_is_relayed);
    bool can_be_in_tx_pool = !gen_utils::bool_equals(true, tx_query->m_is_confirmed) && !gen_utils::bool_equals(false, tx_query->m_in_tx_pool) && !gen_utils::bool_equals(true, tx_query->m_is_failed) && tx_query->get_height() == boost::none && tx_query->m_max_height == boost::none && !gen_utils::bool_equals(false, tx_query->m_is_locked);
    bool can_be_incoming = !gen_utils::bool_equals(false, _query->m_is_incoming) && !gen_utils::bool_equals(true, _query->is_outgoing()) && !gen_utils::bool_equals(true, _query->m_has_destinations);
    bool can_be_outgoing = !gen_utils::bool_equals(false, _query->is_outgoing()) && !gen_utils::bool_equals(true, _query->m_is_incoming);
    bool is_in = can_be_incoming && can_be_confirmed;
    bool is_out = can_be_outgoing && can_be_confirmed;
    bool is_pending = can_be_outgoing && can_be_in_tx_pool;
    bool is_pool = can_be_incoming && can_be_in_tx_pool;
    bool is_failed = !gen_utils::bool_equals(false, tx_query->m_is_failed) && !gen_utils::bool_equals(true, tx_query->m_is_confirmed) && !gen_utils::bool_equals(true, tx_query->m_in_tx_pool);

    // check if fetching pool txs contradicted by configuration
    if (tx_query->m_in_tx_pool != boost::none && tx_query->m_in_tx_pool.get() && !can_be_in_tx_pool) {
      throw monero_error("Cannot fetch pool transactions because it contradicts configuration");
    }

    // cache unique txs and blocks
    std::map<std::string, std::shared_ptr<monero_tx_wallet>> tx_map;
    std::map<uint64_t, std::shared_ptr<monero_block>> block_map;

    auto params = std::make_shared<monero_get_transfers_params>();
    params->m_in = is_in;
    params->m_out = is_out;
    params->m_pool = is_pool;
    params->m_pending = is_pending;
    params->m_failed = is_failed;
    params->m_max_height = tx_query->m_max_height;

    if (tx_query->m_min_height != boost::none) {
      uint64_t min_height = tx_query->m_min_height.get();
      // TODO monero-project: wallet2::get_payments() min_height is exclusive, so manually offset to match intended range (issues #5751, #5598)
      if (min_height > 0) params->m_min_height = min_height - 1;
      else params->m_min_height = min_height;
    }

    if (_query->m_account_index == boost::none) {
      if (_query->m_subaddress_index != boost::none || !_query->m_subaddress_indices.empty()) throw monero_error("Filter specifies a subaddress index but not an account index");
      params->m_all_accounts = true;
    } else {
      params->m_account_index = _query->m_account_index;

      // set subaddress indices param
      if (_query->m_subaddress_index != boost::none) {
        params->m_subaddr_indices.push_back(_query->m_subaddress_index.get());
      }
      for (const uint32_t& subaddress_idx : _query->m_subaddress_indices) {
        params->m_subaddr_indices.push_back(subaddress_idx);
      }
    }

    // build txs using `get_transfers`
    auto result = m_rpc->send_json_request("get_transfers", params);

    deserialize_tx_with_transfer_and_merge(result, tx_map, block_map);

    // sort txs by block height
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    for (std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.begin(); tx_iter != tx_map.end(); ++tx_iter) {
      txs.push_back(tx_iter->second);
    }
    sort(txs.begin(), txs.end(), monero_utils::tx_height_less_than);

    // filter transfers
    std::vector<std::shared_ptr<monero_transfer>> transfers;
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {

      // tx is not incoming/outgoing unless already set
      if (tx->m_is_incoming == boost::none) tx->m_is_incoming = false;
      if (tx->m_is_outgoing == boost::none) tx->m_is_outgoing = false;

      // sort incoming transfers
      sort(tx->m_incoming_transfers.begin(), tx->m_incoming_transfers.end(), monero_utils::incoming_transfer_before);

      // collect queried transfers, erase if excluded
      for (const std::shared_ptr<monero_transfer>& transfer : tx->filter_transfers(*_query)) transfers.push_back(transfer);

      // remove excluded txs from block
      if (tx->m_block != nullptr && tx->m_outgoing_transfer == nullptr && tx->m_incoming_transfers.empty()) {
        tx->m_block->m_txs.erase(std::remove(tx->m_block->m_txs.begin(), tx->m_block->m_txs.end(), tx), tx->m_block->m_txs.end()); // TODO, no way to use const_iterator?
      }
    }
    MTRACE("monero_wallet_rpc::get_transfers() returning " << transfers.size() << " transfers");

    return transfers;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_rpc::get_outputs_aux(const monero_output_query& query) const {
    MTRACE("monero_wallet_rpc::get_outputs_aux(query)");

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
        if (query.m_tx_query->m_output_query != nullptr) throw monero_error("Output query's tx query must be a circular reference or null");
        std::shared_ptr<monero_output_query> query_ptr = std::make_shared<monero_output_query>(query);  // convert query to shared pointer for copy
        _query = query_ptr->copy(query_ptr, std::make_shared<monero_output_query>());
        _query->m_tx_query = tx_query;
      }
    }
    if (_query->m_tx_query == nullptr) _query->m_tx_query = std::make_shared<monero_tx_query>();
    std::shared_ptr<monero_tx_query> tx_query = _query->m_tx_query;

    // _query/tx_query hold circular shared_ptr references (m_tx_query <-> m_transfer_query)
    // that plain refcounting can't break; monero_utils::free() breaks the cycle manually and
    // must run on every exit path, or the copies leak
    query_free_guard free_guard{tx_query};

    // determine account and subaddress indices to be queried
    std::map<uint32_t, std::vector<uint32_t>> indices;
    if (_query->m_account_index != boost::none) {
      std::vector<uint32_t> subaddress_indices;
      if (_query->m_subaddress_index != boost::none) {
        subaddress_indices.push_back(_query->m_subaddress_index.get());
      }
      for (const auto& subaddress_idx : _query->m_subaddress_indices) {
        subaddress_indices.push_back(subaddress_idx);
      }
      // null will fetch from all subaddresses
      indices[_query->m_account_index.get()] = subaddress_indices;
    }
    else {
      if (_query->m_subaddress_index != boost::none) throw monero_error("Request specifies a subaddress index but not an account index");
      if (!_query->m_subaddress_indices.empty()) throw monero_error("Request specifies subaddress indices but not an account index");
      // fetch all account indices without subaddresses
      indices = get_account_indices(false);
    }

    // cache unique txs and blocks
    std::map<std::string, std::shared_ptr<monero_tx_wallet>> tx_map;
    std::map<uint64_t, std::shared_ptr<monero_block>> block_map;

    // collect txs with outputs for each indicated account using `incoming_transfers` rpc call
    std::string transfer_type = "all";
    if (_query->m_is_spent != boost::none) {
      if (_query->m_is_spent.value() == true) transfer_type = "unavailable";
      else transfer_type = "available";
    }

    auto params = std::make_shared<monero_get_incoming_transfers_params>(transfer_type);

    for(const auto& kv : indices) {
      uint32_t account_idx = kv.first;
      params->m_account_index = account_idx;
      params->m_subaddr_indices = kv.second;
      // send request
      auto result = m_rpc->send_json_request("incoming_transfers", params);

      // convert response to txs with outputs and merge
      deserialize_tx_with_output_and_merge(result, tx_map, block_map);
    }

    // sort txs by block height
    std::vector<std::shared_ptr<monero_tx_wallet>> txs ;
    for (std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.begin(); tx_iter != tx_map.end(); ++tx_iter) {
      txs.push_back(tx_iter->second);
    }
    sort(txs.begin(), txs.end(), monero_utils::tx_height_less_than);

    // filter and return outputs
    std::vector<std::shared_ptr<monero_output_wallet>> outputs;
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {

      // sort outputs
      sort(tx->m_outputs.begin(), tx->m_outputs.end(), monero_utils::vout_before);

      // collect queried outputs, erase if excluded
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(*_query)) outputs.push_back(output);

      // remove txs without outputs
      if (tx->m_outputs.empty() && tx->m_block != nullptr) tx->m_block->m_txs.erase(std::remove(tx->m_block->m_txs.begin(), tx->m_block->m_txs.end(), tx), tx->m_block->m_txs.end()); // TODO, no way to use const_iterator?
    }

    return outputs;
  }

}