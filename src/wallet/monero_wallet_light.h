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

#include "monero_wallet_keys.h"
#include "monero_wallet_light_model.h"
#include "monero_wallet_utils.h"
#include "utils/monero_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/condition_variable.hpp>

/**
 * Implements a monero_wallet.h light wallet.
 */
namespace monero {

  // --------------------------- STATIC WALLET UTILS --------------------------

  // there is a light that never goes out
  class monero_wallet_light : public monero_wallet_keys {
  
  public:

    /**
      * Indicates if a wallet exists at the light wallet server.
      *
      * @param primary_address wallet standard address
      * @param private_view_key wallet private view key
      * @param server_uri light wallet server uri
      * @param http_client_factory allows use of custom http clients
      * @return true if a wallet exists at the light wallet server, false otherwise
      */
    static bool wallet_exists(const std::string& primary_address, const std::string& private_view_key, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
      * Indicates if a wallet exists at the light wallet server.
      *
      * @param config wallet configuration
      * @param server_uri light wallet server uri
      * @param http_client_factory allows use of custom http clients
      * @return true if a wallet exists at the light wallet server, false otherwise
      */
    static bool wallet_exists(const monero_wallet_config& config, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
      * Open an existing wallet from a light wallet server.
      *
      * @param primary_address wallet standard address
      * @param private_view_key wallet private view key
      * @param server_uri light wallet server uri
      * @param network_type is the wallet's network type
      * @param http_client_factory allows use of custom http clients
      * @return a pointer to the wallet instance
      */
    static monero_wallet_light* open_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
      * Create a new wallet with the given configuration.
      *
      * @param config is the wallet configuration
      * @param http_client_factory allows use of custom http clients
      * @return a pointer to the wallet instance
      */
    static monero_wallet_light* create_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);
    
    monero_wallet_light(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);
    ~monero_wallet_light();

    void set_daemon_connection(const std::string& uri, const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "") override;
    void set_daemon_connection(const boost::optional<monero_rpc_connection>& connection) override;
    boost::optional<monero_rpc_connection> get_daemon_connection() const override;
    bool is_connected_to_daemon() const override;
    bool is_daemon_synced() const override;
    bool is_daemon_trusted() const override;
    bool is_synced() const override;
    std::string get_seed() const override;
    std::string get_seed_language() const override;
    std::string get_private_spend_key() const override;
    monero_subaddress get_address_index(const std::string& address) const override;
    uint64_t get_height() const override;
    void set_restore_height(uint64_t restore_height) override;
    uint64_t get_restore_height() const override;
    uint64_t get_daemon_height() const override;
    uint64_t get_daemon_max_peer_height() const override;
    void add_listener(monero_wallet_listener& listener) override;
    void remove_listener(monero_wallet_listener& listener) override;
    std::set<monero_wallet_listener*> get_listeners() override;
    monero_sync_result sync() override;
    monero_sync_result sync(monero_wallet_listener& listener) override;
    monero_sync_result sync(uint64_t start_height) override;
    monero_sync_result sync(uint64_t start_height, monero_wallet_listener& listener) override;
    void start_syncing(uint64_t sync_period_in_ms) override;
    void stop_syncing() override;
    void scan_txs(const std::vector<std::string>& tx_ids) override;
    void rescan_spent() override;
    void rescan_blockchain() override;
    uint64_t get_balance() const override;
    uint64_t get_balance(uint32_t account_idx) const override;
    uint64_t get_balance(uint32_t account_idx, uint32_t subaddress_idx) const override;
    uint64_t get_unlocked_balance() const override;
    uint64_t get_unlocked_balance(uint32_t account_idx) const override;
    uint64_t get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const override;
    std::vector<monero_account> get_accounts(bool include_subaddresses, const std::string& tag) const override;
    monero_account get_account(const uint32_t account_idx, bool include_subaddresses) const override;
    monero_account create_account(const std::string& label = "") override;
    monero_subaddress get_subaddress(const uint32_t account_idx, const uint32_t subaddress_idx) const override;
    std::vector<monero_subaddress> get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const override;
    monero_subaddress create_subaddress(uint32_t account_idx, const std::string& label = "") override;
    void set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label = "") override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs(const monero_tx_query& query) const override;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers(const monero_transfer_query& query) const override;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs(const monero_output_query& query) const override;
    std::string export_outputs(bool all = false) const override;
    int import_outputs(const std::string& outputs_hex) override;
    std::vector<std::shared_ptr<monero_key_image>> export_key_images(bool all = true) const override;
    std::shared_ptr<monero_key_image_import_result> import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) override;
    void freeze_output(const std::string& key_image) override;
    void thaw_output(const std::string& key_image) override;
    bool is_output_frozen(const std::string& key_image) override;
    monero_tx_priority get_default_fee_priority() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> create_txs(const monero_tx_config& config) override;
    std::vector<std::string> relay_txs(const std::vector<std::string>& tx_metadatas) override;
    monero_tx_set describe_tx_set(const monero_tx_set& tx_set) override;
    monero_tx_set sign_txs(const std::string& unsigned_tx_hex) override;
    std::vector<std::string> submit_txs(const std::string& signed_tx_hex) override;
    std::string get_tx_note(const std::string& tx_hash) const override;
    std::vector<std::string> get_tx_notes(const std::vector<std::string>& tx_hashes) const override;
    void set_tx_note(const std::string& tx_hash, const std::string& note) override;
    void set_tx_notes(const std::vector<std::string>& tx_hashes, const std::vector<std::string>& notes) override;
    std::vector<monero_address_book_entry> get_address_book_entries(const std::vector<uint64_t>& indices) const override;
    uint64_t add_address_book_entry(const std::string& address, const std::string& description) override;
    void edit_address_book_entry(uint64_t index, bool set_address, const std::string& address, bool set_description, const std::string& description) override;
    void delete_address_book_entry(uint64_t index) override;
    bool get_attribute(const std::string& key, std::string& value) const override;
    void set_attribute(const std::string& key, const std::string& val) override;
    uint64_t wait_for_next_block() override;
    bool is_multisig_import_needed() const override { return false; };
    monero_multisig_info get_multisig_info() const override;
    void close(bool save) override;

  // ---------------------------------- PRIVATE ---------------------------------

  protected:
    void init_common() override;
    wallet2_exported_outputs export_outputs(bool all, uint32_t start, uint32_t count = 0xffffffff) const override;
    std::string get_tx_prefix_hash(const std::string& tx_hash) const override { return m_output_store.get_tx_prefix_hash(tx_hash); };

    std::unique_ptr<monero_wallet_utils::wallet2_listener> m_wallet_listener; // internal wallet implementation listener
    std::set<monero_wallet_listener*> m_listeners;                            // external wallet listeners

    static monero_wallet_light* create_wallet_from_seed(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
    static monero_wallet_light* create_wallet_from_keys(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
    static monero_wallet_light* create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);

    void init_subaddress(monero_subaddress& subaddress) const;
    boost::optional<std::string> get_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_subaddress_num_blocks_to_unlock(uint32_t account_idx, uint32_t subaddress_idx) const; 
    std::vector<monero_subaddress> get_subaddresses_aux(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers_aux(const monero_transfer_query& query) const;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs_aux(const monero_output_query& query) const;

    // blockchain sync management
    mutable std::atomic<bool> m_is_synced;       // whether or not wallet is synced
    mutable std::atomic<bool> m_is_connected;    // cache connection status to avoid unecessary RPC calls
    boost::condition_variable m_sync_cv;         // to make sync threads woke
    boost::recursive_mutex m_sync_mutex;         // synchronize sync() and syncAsync() requests
    std::atomic<bool> m_rescan_on_sync;          // whether or not to rescan on sync
    std::atomic<bool> m_syncing_enabled;         // whether or not auto sync is enabled
    std::atomic<bool> m_sync_loop_running;       // whether or not the syncing thread is shut down
    std::atomic<int> m_syncing_interval;         // auto sync loop interval in milliseconds
    boost::thread m_syncing_thread;              // thread for auto sync loop
    boost::mutex m_syncing_mutex;                // synchronize auto sync loop
    void run_sync_loop();                        // run the sync loop in a thread
    monero_sync_result lock_and_sync(boost::optional<uint64_t> start_height = boost::none);  // internal function to synchronize request to sync and rescan
    monero_sync_result sync_aux(boost::optional<uint64_t> start_height = boost::none);       // internal function to immediately block, sync, and report progress

    // wallet data
    std::vector<monero_address_book_entry> m_address_book;
    serializable_unordered_map<crypto::hash, std::string> m_tx_notes;
    serializable_unordered_map<std::string, std::string> m_attributes;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::string>> m_subaddress_labels;

    mutable boost::recursive_mutex m_sync_data_mutex;
    std::unique_ptr<monero_light_client> m_client;
    monero_light_get_address_info_response m_address_info;
    monero_light_get_address_txs_response m_address_txs;
    monero_light_get_unspent_outs_response m_unspent_outs;
    monero_light_get_subaddrs_response m_subaddrs;
    monero_light_output_store m_output_store;
    monero_light_tx_store m_tx_store;
    boost::optional<uint64_t> m_prior_attempt_size_calcd_fee;
    boost::optional<monero_light_spendable_random_outputs> m_prior_attempt_unspent_outs_to_mix_outs;
    size_t m_construction_attempt;

    bool output_is_spent(monero_light_output &output) const;
    bool spend_is_real(monero_light_spend &spend) const;   
    void process_txs();
    void process_outputs();
    void process_subaddresses();
    void calculate_balance();
    void upsert_subaddrs(const monero_light_subaddrs &subaddrs, bool get_all = true);
    void upsert_subaddrs(uint32_t account_idx, uint32_t subaddress_idx, bool get_all = true);
    void login(bool create_account = true, bool generated_locally = true) const;
    monero_sync_result refresh();
  };

}