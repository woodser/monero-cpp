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

#include "monero_daemon.h"

/**
 * Implements a monero_daemon.h using monero-project's monerod.
 */
namespace monero {

  // forward declaration of internal daemon poller
  class monero_daemon_poller;

  /**
   * Implements a Monero daemon using monerod-rpc.
   */
  class monero_daemon_rpc : public monero_daemon {
  public:

    /**
     * Destruct the daemon.
     */
    ~monero_daemon_rpc() override;
    monero_daemon_rpc(const std::shared_ptr<monero_rpc_connection>& rpc);
    monero_daemon_rpc(const std::string& uri, const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "", const std::string& zmq_uri = "", const boost::optional<uint32_t>& timeout = boost::none);

    /**
     * Get the daemon's RPC connection.
     * 
     * @return the daemon's rpc connection
     */
    std::shared_ptr<monero_rpc_connection> get_rpc_connection() const;

    /**
     * Indicates if the client is connected to the daemon via RPC.
     * 
     * @return true if the client is connected to the daemon, false otherwise
     */
    bool is_connected();

    /**
     * Set the daemon poll period.
     *
     * @param period_ms poll period in milliseconds.
     */
    void set_poll_period_in_ms(uint64_t period_ms);

    /**
     * Supported daemon methods.
     */
    std::set<monero_daemon_listener*> get_listeners() override;
    void add_listener(monero_daemon_listener &listener) override;
    void remove_listener(monero_daemon_listener &listener) override;
    void remove_listeners() override;
    monero_version get_version() override;
    bool is_trusted() override;
    uint64_t get_height() override;
    std::string get_block_hash(uint64_t height) override;
    std::shared_ptr<monero_block_template> get_block_template(const std::string& wallet_address, const boost::optional<int>& reserve_size = boost::none) override;
    std::shared_ptr<monero_miner_data> get_miner_data() override;
    std::string calculate_pow(uint32_t major_version, uint64_t height, const std::string& block_blob, const std::string& seed_hash) override;
    std::shared_ptr<monero_add_auxiliary_pow_result> add_auxiliary_pow(const std::string& block_template_blob, const std::vector<std::shared_ptr<monero_auxiliary_pow>>& aux_pow) override;
    std::shared_ptr<monero_block_header> get_last_block_header() override;
    std::shared_ptr<monero_block_header> get_block_header_by_hash(const std::string& hash) override;
    std::shared_ptr<monero_block_header> get_block_header_by_height(uint64_t height) override;
    std::vector<std::shared_ptr<monero_block_header>> get_block_headers_by_range(uint64_t start_height, uint64_t end_height) override;
    std::shared_ptr<monero_block> get_block_by_hash(const std::string& hash) override;
    std::vector<std::shared_ptr<monero_block>> get_blocks_by_hash(const std::vector<std::string>& block_hashes, uint64_t start_height, bool prune) override;
    std::shared_ptr<monero_block> get_block_by_height(uint64_t height) override;
    std::vector<std::shared_ptr<monero_block>> get_blocks_by_height(const std::vector<uint64_t>& heights) override;
    std::vector<std::shared_ptr<monero_block>> get_blocks_by_range(boost::optional<uint64_t> start_height, boost::optional<uint64_t> end_height) override;
    std::vector<std::shared_ptr<monero_block>> get_blocks_by_range_chunked(boost::optional<uint64_t> start_height, boost::optional<uint64_t> end_height, boost::optional<uint64_t> max_chunk_size) override;
    std::vector<std::string> get_block_hashes(const std::vector<std::string>& block_hashes, uint64_t start_height) override;
    std::vector<std::shared_ptr<monero_tx>> get_txs(const std::vector<std::string>& tx_hashes, bool prune = false) override;
    std::vector<std::string> get_tx_hexes(const std::vector<std::string>& tx_hashes, bool prune = false) override;
    std::shared_ptr<monero_miner_tx_sum> get_miner_tx_sum(uint64_t height, uint64_t num_blocks) override;
    std::shared_ptr<monero_fee_estimate> get_fee_estimate(uint64_t grace_blocks = 0) override;
    std::shared_ptr<monero_submit_tx_result> submit_tx_hex(const std::string& tx_hex, bool do_not_relay = false) override;
    void relay_txs_by_hash(const std::vector<std::string>& tx_hashes) override;
    std::shared_ptr<monero_tx_pool_stats> get_tx_pool_stats() override;
    std::vector<std::shared_ptr<monero_tx>> get_tx_pool() override;
    std::vector<std::string> get_tx_pool_hashes() override;
    void flush_tx_pool(const std::vector<std::string> &hashes) override;
    void flush_tx_pool() override;
    void flush_tx_pool(const std::string &hash) override;
    std::vector<monero_key_image_spent_status> get_key_image_spent_statuses(const std::vector<std::string>& key_images) override;
    std::vector<uint64_t> get_output_indices(const std::string& tx_hash) override;
    std::vector<std::shared_ptr<monero_output>> get_outputs(const std::vector<monero_output>& outputs) override;
    std::vector<std::shared_ptr<monero_output_histogram_entry>> get_output_histogram(const std::vector<uint64_t>& amounts, const boost::optional<int>& min_count, const boost::optional<int>& max_count, const boost::optional<bool>& is_unlocked, const boost::optional<int>& recent_cutoff) override;
    std::vector<std::shared_ptr<monero_output_distribution_entry>> get_output_distribution(const std::vector<uint64_t>& amounts, const boost::optional<bool>& is_cumulative = boost::none, const boost::optional<uint64_t>& start_height = boost::none, const boost::optional<uint64_t>& end_height = boost::none) override;
    std::shared_ptr<monero_daemon_info> get_info() override;
    std::shared_ptr<monero_daemon_sync_info> get_sync_info() override;
    std::shared_ptr<monero_daemon_network_stats> get_network_stats() override;
    std::shared_ptr<monero_hard_fork_info> get_hard_fork_info() override;
    std::vector<std::shared_ptr<monero_alt_chain>> get_alt_chains() override;
    std::vector<std::string> get_alt_block_hashes() override;
    int get_download_limit() override;
    int set_download_limit(int limit) override;
    int reset_download_limit() override;
    int get_upload_limit() override;
    int set_upload_limit(int limit) override;
    int reset_upload_limit() override;
    std::vector<std::shared_ptr<monero_peer>> get_peers() override;
    std::vector<std::shared_ptr<monero_peer>> get_known_peers() override;
    std::vector<std::shared_ptr<monero_peer>> get_public_peers(bool include_offline = false) override;
    void set_outgoing_peer_limit(int limit) override;
    void set_incoming_peer_limit(int limit) override;
    std::vector<std::shared_ptr<monero_ban>> get_peer_bans() override;
    void set_peer_bans(const std::vector<std::shared_ptr<monero_ban>>& bans) override;
    std::shared_ptr<monero_ban> get_peer_ban(const std::string& address) override;
    void start_mining(const std::string &address, boost::optional<uint64_t> num_threads, boost::optional<bool> background_mining, boost::optional<bool> ignore_battery) override;
    void stop_mining() override;
    std::shared_ptr<monero_mining_status> get_mining_status() override;
    std::shared_ptr<monero_generate_blocks_result> generate_blocks(const std::string& wallet_address, uint64_t num_blocks, const boost::optional<std::string>& prev_block_hash = boost::none, const boost::optional<uint32_t>& starting_nonce = boost::none) override;
    void submit_blocks(const std::vector<std::string>& block_blobs) override;
    std::shared_ptr<monero_prune_result> prune_blockchain(bool check) override;
    void save_blockchain() override;
    uint64_t pop_blocks(uint64_t num_blocks) override;
    void flush_cache(bool bad_blocks = false) override;
    void set_bootstrap_daemon(const std::string& address, const std::string& username = "", const std::string& password = "", const std::string& proxy = "") override;
    void set_log_hash_rate(bool is_visible) override;
    void set_log_level(int level) override;
    std::string set_log_categories(const std::string& categories = "") override;
    std::shared_ptr<monero_daemon_update_check_result> check_for_update() override;
    std::shared_ptr<monero_daemon_update_download_result> download_update(const std::string& path = "") override;
    void stop() override;
    std::shared_ptr<monero_block_header> wait_for_next_block_header() override;

  // --------------------------------- PRIVATE --------------------------------

  private:
    friend class monero_daemon_poller;
    mutable boost::recursive_mutex m_listeners_mutex;
    std::set<monero_daemon_listener*> m_listeners;
    std::shared_ptr<monero_rpc_connection> m_rpc;
    boost::mutex m_poller_mutex;
    std::unique_ptr<monero_daemon_poller> m_poller;

    // header_cache is scoped to a single get_blocks_by_range_chunked() call (see below) rather than
    // stored as a member: it only helps avoid re-fetching a header already seen earlier in that one
    // chunking pass, and keeping it as instance state would let it grow unbounded over the connection's
    // lifetime and serve stale headers across reorgs on later calls
    std::vector<std::shared_ptr<monero_block>> get_max_blocks(boost::optional<uint64_t> start_height, boost::optional<uint64_t> max_height, boost::optional<uint64_t> chunk_size, std::unordered_map<uint64_t, std::shared_ptr<monero_block_header>>& header_cache);
    std::shared_ptr<monero_block_header> get_block_header_by_height_cached(uint64_t height, uint64_t max_height, std::unordered_map<uint64_t, std::shared_ptr<monero_block_header>>& header_cache);
    std::shared_ptr<monero_bandwidth_limits> get_bandwidth_limits();
    std::shared_ptr<monero_bandwidth_limits> set_bandwidth_limits(int up, int down);
    void refresh_listening();
    void wait_for_listener_callbacks_idle();
  };

}
