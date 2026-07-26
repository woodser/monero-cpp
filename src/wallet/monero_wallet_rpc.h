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
#pragma once

#include "monero_wallet.h"

/**
 * Implements a monero_wallet.h by wrapping monero-project's monero-wallet-rpc.
 */
namespace monero {

  // forward declaration of internal wallet poller
  class monero_wallet_poller;

  /**
   * Implements a Monero wallet using monero-wallet-rpc.
   */
  class monero_wallet_rpc : public monero_wallet {
  public:

    /**
     * Destruct the wallet.
     */
    ~monero_wallet_rpc();
    monero_wallet_rpc(const std::shared_ptr<monero_rpc_connection>& rpc_connection);
    monero_wallet_rpc(const std::string& uri = "", const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "", const std::string& zmq_uri = "", const boost::optional<uint32_t>& timeout = boost::none);

    /**
     * Set the wallet poll period.
     *
     * @param period_ms poll period in milliseconds.
     */
    void set_poll_period_in_ms(uint64_t period_ms);

    /**
     * Open an existing wallet from rpc server.
     *
     * @param config is the wallet configuration
     * @return a pointer to the wallet instance
     */
    monero_wallet_rpc* open_wallet(const std::shared_ptr<monero_wallet_config> &config);

    /**
     * Open an existing wallet from rpc server.
     *
     * @param name is the wallet's name to open
     * @param password is the password of the wallet file to open
     * @return a pointer to the wallet instance
     */
    monero_wallet_rpc* open_wallet(const std::string& name, const std::string& password);

    /**
     * Create a new wallet with the given configuration.
     *
     * @param config is the wallet configuration
     * @return a pointer to the wallet instance
     */
    monero_wallet_rpc* create_wallet(const std::shared_ptr<monero_wallet_config> &config);

    /**
     * Get the wallet's RPC connection.
     *
     * @return the wallet's rpc connection
     */
    std::shared_ptr<monero_rpc_connection> get_rpc_connection() const { return m_rpc; }

    /**
     * Get a list of available languages for the wallet's seed.
     *
     * @return the available languages for the wallet's seed
     */
    std::vector<std::string> get_seed_languages() const;

    /**
     * Save and close the current wallet and stop the RPC server.
     */
    void stop();

    /**
     * Supported wallet methods.
     */
    void add_listener(monero_wallet_listener& listener) override;
    void remove_listener(monero_wallet_listener& listener) override;
    std::set<monero_wallet_listener*> get_listeners() override;
    bool is_view_only() const override;
    std::shared_ptr<monero_rpc_connection> get_daemon_connection() const override;
    void set_daemon_connection(const std::shared_ptr<monero_rpc_connection>& connection, bool is_trusted, const boost::optional<ssl_options>& ssl_options);
    void set_daemon_connection(const std::shared_ptr<monero_rpc_connection>& connection, const boost::optional<bool>& is_trusted = boost::none) override;
    void set_daemon_connection(const std::string& uri, const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "", const boost::optional<bool>& is_trusted = boost::none) override;
    bool is_connected_to_daemon() const override;
    monero_version get_version() const override;
    std::string get_path() const override;
    std::string get_seed() const override;
    std::string get_seed_language() const override;
    std::string get_public_view_key() const override;
    std::string get_private_view_key() const override;
    std::string get_public_spend_key() const override;
    std::string get_private_spend_key() const override;
    std::string get_address(const uint32_t account_idx, const uint32_t subaddress_idx) const override;
    monero_subaddress get_address_index(const std::string& address) const override;
    monero_integrated_address get_integrated_address(const std::string& standard_address = "", const std::string& payment_id = "") const override;
    monero_integrated_address decode_integrated_address(const std::string& integrated_address) const override;
    uint64_t get_height() const override;
    uint64_t get_daemon_height() const override;
    uint64_t get_height_by_date(uint16_t year, uint8_t month, uint8_t day) const override;
    monero_sync_result sync() override;
    monero_sync_result sync(monero_wallet_listener& listener) override;
    monero_sync_result sync(uint64_t start_height, monero_wallet_listener& listener) override;
    monero_sync_result sync(uint64_t start_height) override;
    void start_syncing(uint64_t sync_period_in_ms = 10000) override;
    void stop_syncing() override;
    void scan_txs(const std::vector<std::string>& tx_hashes) override;
    void rescan_spent() override;
    void rescan_blockchain() override;
    uint64_t get_balance() const override;
    uint64_t get_balance(uint32_t account_index) const override;
    uint64_t get_balance(uint32_t account_idx, uint32_t subaddress_idx) const override;
    uint64_t get_unlocked_balance() const override;
    uint64_t get_unlocked_balance(uint32_t account_index) const override;
    uint64_t get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const override;
    monero_account get_account(const uint32_t account_idx, bool include_subaddresses) const override;
    monero_account get_account(const uint32_t account_idx, bool include_subaddresses, bool skip_balances) const;
    std::vector<monero_account> get_accounts(bool include_subaddresses, const std::string& tag) const override;
    std::vector<monero_account> get_accounts(bool include_subaddresses, const std::string& tag, bool skip_balances) const;
    monero_account create_account(const std::string& label = "") override;
    std::vector<monero_subaddress> get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices, bool skip_balances) const;
    std::vector<monero_subaddress> get_subaddresses(uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const override;
    std::vector<monero_subaddress> get_subaddresses(const uint32_t account_idx) const override;
    monero_subaddress get_subaddress(const uint32_t account_idx, const uint32_t subaddress_idx) const override;
    monero_subaddress create_subaddress(uint32_t account_idx, const std::string& label = "") override;
    void set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label = "") override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs(const monero_tx_query& query) const override;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers(const monero_transfer_query& query) const override;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs(const monero_output_query& query) const override;
    std::string export_outputs(bool all = false) const override;
    int import_outputs(const std::string& outputs_hex) override;
    std::shared_ptr<monero_key_image_export_result> export_key_images(bool all = false) const override;
    std::shared_ptr<monero_key_image_import_result> import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images, uint64_t offset = 0) override;
    void freeze_output(const std::string& key_image) override;
    void thaw_output(const std::string& key_image) override;
    bool is_output_frozen(const std::string& key_image) override;
    monero_tx_priority get_default_fee_priority() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> create_txs(const monero_tx_config& conf) override;
    std::shared_ptr<monero_tx_wallet> sweep_output(const monero_tx_config& config) override;
    std::vector<std::shared_ptr<monero_tx_wallet>> sweep_dust(bool relay = false) override;
    std::vector<std::shared_ptr<monero_tx_wallet>> sweep_unlocked(const monero_tx_config& config) override;
    std::vector<std::string> relay_txs(const std::vector<std::string>& tx_metadatas) override;
    monero_tx_set describe_tx_set(const monero_tx_set& tx_set) override;
    monero_tx_set sign_txs(const std::string& unsigned_tx_hex) override;
    std::vector<std::string> submit_txs(const std::string& signed_tx_hex) override;
    std::string sign_message(const std::string& msg, monero_message_signature_type signature_type, uint32_t account_idx = 0, uint32_t subaddress_idx = 0) const override;
    monero_message_signature_result verify_message(const std::string& msg, const std::string& address, const std::string& signature) const override;
    std::string get_tx_key(const std::string& tx_hash) const override;
    std::shared_ptr<monero_check_tx> check_tx_key(const std::string& tx_hash, const std::string& tx_key, const std::string& address) const override;
    std::string get_tx_proof(const std::string& tx_hash, const std::string& address, const std::string& message) const override;
    std::shared_ptr<monero_check_tx> check_tx_proof(const std::string& tx_hash, const std::string& address, const std::string& message, const std::string& signature) const override;
    std::string get_spend_proof(const std::string& tx_hash, const std::string& message) const override;
    bool check_spend_proof(const std::string& tx_hash, const std::string& message, const std::string& signature) const override;
    std::string get_reserve_proof_wallet(const std::string& message) const override;
    std::string get_reserve_proof_account(uint32_t account_idx, uint64_t amount, const std::string& message) const override;
    std::shared_ptr<monero_check_reserve> check_reserve_proof(const std::string& address, const std::string& message, const std::string& signature) const override;
    std::string get_tx_note(const std::string& tx_hash) const override;
    std::vector<std::string> get_tx_notes(const std::vector<std::string>& tx_hashes) const override;
    void set_tx_note(const std::string& tx_hashes, const std::string& notes) override;
    void set_tx_notes(const std::vector<std::string>& tx_hashes, const std::vector<std::string>& notes) override;
    std::vector<monero_address_book_entry> get_address_book_entries(const std::vector<uint64_t>& indices) const override;
    uint64_t add_address_book_entry(const std::string& address, const std::string& description) override;
    void edit_address_book_entry(uint64_t index, bool set_address, const std::string& address, bool set_description, const std::string& description) override;
    void delete_address_book_entry(uint64_t index) override;
    void tag_accounts(const std::string& tag, const std::vector<uint32_t>& account_indices) override;
    void untag_accounts(const std::vector<uint32_t>& account_indices) override;
    std::vector<std::shared_ptr<monero_account_tag>> get_account_tags() const override;
    void set_account_tag_label(const std::string& tag, const std::string& label) override;
    std::string get_payment_uri(const monero_tx_config& config) const override;
    std::shared_ptr<monero_tx_config> parse_payment_uri(const std::string& uri) const override;
    void set_attribute(const std::string& key, const std::string& val) override;
    bool get_attribute(const std::string& key, std::string& value) const override;
    void start_mining(boost::optional<uint64_t> num_threads, boost::optional<bool> background_mining, boost::optional<bool> ignore_battery) override;
    void stop_mining() override;
    bool is_multisig_import_needed() const override;
    monero_multisig_info get_multisig_info() const override;
    std::string prepare_multisig() override;
    std::string make_multisig(const std::vector<std::string>& multisig_hexes, int threshold, const std::string& password) override;
    monero_multisig_init_result exchange_multisig_keys(const std::vector<std::string>& multisig_hexes, const std::string& password) override;
    std::string export_multisig_hex() override;
    int import_multisig_hex(const std::vector<std::string>& multisig_hexes, const bool refresh_after_import = true) override;
    monero_multisig_sign_result sign_multisig_tx_hex(const std::string& multisig_tx_hex) override;
    std::vector<std::string> submit_multisig_tx_hex(const std::string& signed_multisig_tx_hex) override;
    void change_password(const std::string& old_password, const std::string& new_password) override;
    void save() override;
    bool is_closed() const override;
    void close(bool save = false) override;
    std::shared_ptr<monero_subaddress> get_balances(const boost::optional<uint32_t>& account_idx, const boost::optional<uint32_t>& subaddress_idx) const;

  // --------------------------------- PRIVATE --------------------------------

  private:
    friend class monero_wallet_poller;
    boost::optional<uint64_t> m_sync_period_in_ms;
    std::string m_path = "";
    std::shared_ptr<monero_rpc_connection> m_rpc;
    std::shared_ptr<monero_rpc_connection> m_daemon_connection;
    mutable boost::recursive_mutex m_listeners_mutex;
    std::set<monero_wallet_listener*> m_listeners;

    mutable boost::recursive_mutex m_sync_mutex;
    mutable boost::mutex m_address_cache_mutex;
    mutable std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::string>> m_address_cache;
    boost::mutex m_poller_mutex;
    std::unique_ptr<monero_wallet_poller> m_poller;

    monero_wallet_rpc* create_wallet_random(const std::shared_ptr<monero_wallet_config> &config);
    monero_wallet_rpc* create_wallet_from_seed(const std::shared_ptr<monero_wallet_config> &config);
    monero_wallet_rpc* create_wallet_from_keys(const std::shared_ptr<monero_wallet_config> &config);

    monero_sync_result refresh(const std::shared_ptr<serializable_struct>& params);

    std::map<uint32_t, std::vector<uint32_t>> get_account_indices(bool get_subaddress_indices) const;
    std::vector<uint32_t> get_subaddress_indices(uint32_t account_idx) const;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs_aux(const monero_output_query& query) const;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers_aux(const monero_transfer_query& query) const;
    std::string query_key(const std::string& key_type) const;
    std::vector<std::shared_ptr<monero_tx_wallet>> sweep_account(const monero_tx_config &conf);
    void clear_address_cache();
    void refresh_listening();
    void wait_for_listener_callbacks_idle();
    void poll();
    void clear();
  };
}