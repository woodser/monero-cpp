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

#include "common/monero_rpc_connection.h"
#include "monero_daemon_model.h"

/**
 * Public library interface.
 */
namespace monero {

  /**
   * Receives notifications as a daemon is updated.
   */
  class monero_daemon_listener {
  public:
    std::shared_ptr<monero_block_header> m_last_header;

    /**
     * Called when a new block is added to the chain.
     *
     * @param header is the header of the block added to the chain
     */
    virtual void on_block_header(const std::shared_ptr<monero_block_header>& header) {
      m_last_header = header;
    }
  };

  /**
   * Monero daemon interface.
   */
  class monero_daemon {
  public:

    /**
     * Virtual destructor.
     */
    virtual ~monero_daemon() {}

    /**
     * Register a listener receive daemon notifications.
     *
     * @param listener is the listener to receive daemon notifications
     */
    virtual void add_listener(monero_daemon_listener &listener) {
      throw std::runtime_error("monero_daemon::add_listener(): not supported");
    }

    /**
     * Unregister a listener to receive daemon notifications.
     *
     * @param listener is the listener to unregister
     */
    virtual void remove_listener(monero_daemon_listener &listener) {
      throw std::runtime_error("monero_daemon::remove_listener(): not supported");
    }

    /**
     * Get the listeners registered with the daemon.
     */
    virtual std::set<monero_daemon_listener*> get_listeners() {
      throw std::runtime_error("monero_daemon::get_listeners(): not supported");
    }

    /**
     * Remove all listeners registered with the daemon.
     */
    virtual void remove_listeners() {
      throw std::runtime_error("monero_daemon::remove_listeners(): not supported");
    }

    /**
     * Get the daemon's version.
     *
     * @return the daemon's version
     */
    virtual monero_version get_version() {
      throw std::runtime_error("monero_daemon::get_version(): not supported");
    }

    /**
     * Indicates if the daemon is trusted or untrusted.
     *
     * @return true if the daemon is trusted, false otherwise
     */
    virtual bool is_trusted() {
      throw std::runtime_error("monero_daemon::is_trusted(): not supported");
    }

    /**
     * Get the number of blocks in the longest chain known to the node.
     *
     * @return the number of blocks
     */
    virtual uint64_t get_height() {
      throw std::runtime_error("monero_daemon::get_height(): not supported");
    }

    /**
     * Get a block's hash by its height.
     *
     * @param height is the height of the block hash to get
     * @return tthe block's hash at the given height
     */
    virtual std::string get_block_hash(uint64_t height) {
      throw std::runtime_error("monero_daemon::get_block_hash(): not supported");
    }

    /**
     * Get a block template for mining a new block.
     * 
     * @param wallet_address is the address of the wallet to receive miner transactions if block is successfully mined
     * @param reserve_size is the reserve size (optional)
     * @return a block template for mining a new block
     */
    virtual std::shared_ptr<monero_block_template> get_block_template(const std::string& wallet_address, const boost::optional<int>& reserve_size = boost::none) {
      throw std::runtime_error("monero_daemon::get_block_template(): not supported");
    }

    /**
     * Get the last block's header.
     * 
     * @return the last block's header
     */
    virtual std::shared_ptr<monero_block_header> get_last_block_header() {
      throw std::runtime_error("monero_daemon::get_last_block_header(): not supported");
    }

    /**
     * Get a block header by its hash.
     * 
     * @param block_hash is the hash of the block to get the header of
     * @return the block's header
     */
    virtual std::shared_ptr<monero_block_header> get_block_header_by_hash(const std::string& block_hash) {
      throw std::runtime_error("monero_daemon::get_block_header_by_hash(): not supported");
    }

    /**
     * Get a block header by its height.
     * 
     * @param height is the height of the block to get the header of
     * @return the block's header
     */
    virtual std::shared_ptr<monero_block_header> get_block_header_by_height(uint64_t height) {
      throw std::runtime_error("monero_daemon::get_block_header_by_height(): not supported");
    }

    /**
     * Get block headers for the given range.
     * 
     * @param start_height is the start height lower bound inclusive (optional)
     * @param end_height is the end height upper bound inclusive (optional)
     * @return block headers in the given range
     */
    virtual std::vector<std::shared_ptr<monero_block_header>> get_block_headers_by_range(uint64_t start_height, uint64_t end_height) {
      throw std::runtime_error("monero_daemon::get_block_headers_by_range(): not supported");
    }

    /**
     * Get a block by hash.
     * 
     * @param block_hash is the hash of the block to get
     * @return the block with the given hash
     */
    virtual std::shared_ptr<monero_block> get_block_by_hash(const std::string& block_hash) {
      throw std::runtime_error("monero_daemon::get_block_by_hash(): not supported");
    }

    /**
     * Get blocks by hash.
     * 
     * @param block_hashes are array of hashes; first 10 blocks hash goes sequential,
     *        next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on,
     *        and the last one is always genesis block
     * @param start_height is the start height to get blocks by hash
     * @param prune specifies if returned blocks should be pruned (defaults to false)  // TODO: test default
     * @return the retrieved blocks
     */
    virtual std::vector<std::shared_ptr<monero_block>> get_blocks_by_hash(const std::vector<std::string>& block_hashes, uint64_t start_height, bool prune) {
      throw std::runtime_error("monero_daemon::get_blocks_by_hash(): not supported");
    }

    /**
     * Get a block by height.
     * 
     * @param height is the height of the block to get
     * @return the block at the given height
     */
    virtual std::shared_ptr<monero_block> get_block_by_height(uint64_t height) {
      throw std::runtime_error("monero_daemon::get_block_by_height(): not supported");
    }

    /**
     * Get blocks at the given heights.
     * 
     * @param heights are the heights of the blocks to get
     * @return blocks at the given heights
     */
    virtual std::vector<std::shared_ptr<monero_block>> get_blocks_by_height(const std::vector<uint64_t>& heights) {
      throw std::runtime_error("monero_daemon::get_blocks_by_height(): not supported");
    }

    /**
     * Get blocks in the given height range.
     * 
     * @param start_height is the start height lower bound inclusive (optional)
     * @param end_height is the end height upper bound inclusive (optional)
     * @return blocks in the given height range
     */
    virtual std::vector<std::shared_ptr<monero_block>> get_blocks_by_range(boost::optional<uint64_t> start_height, boost::optional<uint64_t> end_height) {
      throw std::runtime_error("monero_daemon::get_blocks_by_range(): not supported");
    }

    /**
     * Get blocks in the given height range as chunked requests so that each request is
     * not too big.
     * 
     * @param start_height is the start height lower bound inclusive (optional)
     * @param end_height is the end height upper bound inclusive (optional)
     * @return blocks in the given height range
     */
    virtual std::vector<std::shared_ptr<monero_block>> get_blocks_by_range_chunked(boost::optional<uint64_t> start_height, boost::optional<uint64_t> end_height, boost::optional<uint64_t> max_chunk_size) {
      throw std::runtime_error("monero_daemon::get_blocks_by_range_chunked(): not supported");
    }

    /**
     * Get block hashes as a binary request to the daemon.
     * 
     * @param block_hashes specify block hashes to fetch; first 10 blocks hash goes
     *        sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64
     *        and so on, and the last one is always genesis block
     * @param start_height is the starting height of block hashes to return
     * @return the requested block hashes
     */
    virtual std::vector<std::string> get_block_hashes(const std::vector<std::string>& block_hashes, uint64_t start_height) {
      throw std::runtime_error("monero_daemon::get_block_hashes(): not supported");
    }

    /**
     * Get a transaction by hash.
     * 
     * @param tx_hash is the hash of the transaction to get
     * @param prune specifies if the returned tx should be pruned (defaults to false)
     * @return the transaction with the given hash or null if not found
     */
    virtual std::shared_ptr<monero_tx> get_tx(const std::string& tx_hash, bool prune = false) {
      std::vector<std::string> hashes;
      hashes.push_back(tx_hash);
      auto txs = get_txs(hashes, prune);
      std::shared_ptr<monero_tx> tx;

      if (txs.size() > 0) {
        tx = txs[0];
      }

      return tx;
    }

    /**
     * Get transactions by hashes.
     * 
     * @param tx_hashes are hashes of transactions to get
     * @param prune specifies if the returned txs should be pruned (defaults to false)
     * @return found transactions with the given hashes
     */
    virtual std::vector<std::shared_ptr<monero_tx>> get_txs(const std::vector<std::string>& tx_hashes, bool prune = false) {
      throw std::runtime_error("monero_daemon::get_txs(): not supported");
    }

  
    /**
     * Get a transaction hex by hash.
     * 
     * @param tx_hash is the hash of the transaction to get hex from
     * @param prune specifies if the returned tx hex should be pruned (defaults to false)
     * @return the tx hex with the given hash
     */
    virtual boost::optional<std::string> get_tx_hex(const std::string& tx_hash, bool prune = false) {
      std::vector<std::string> hashes;
      hashes.push_back(tx_hash);
      auto hexes = get_tx_hexes(hashes, prune);
      boost::optional<std::string> hex;
      if (hexes.size() > 0) {
        hex = hexes[0];
      }

      return hex;
    }

    /**
     * Get transaction hexes by hashes.
     * 
     * @param tx_hashes are hashes of transactions to get hexes from
     * @param prune specifies if the returned tx hexes should be pruned (defaults to false)
     * @return are the tx hexes
     */
    virtual std::vector<std::string> get_tx_hexes(const std::vector<std::string>& tx_hashes, bool prune = false) {
      throw std::runtime_error("monero_daemon::get_tx_hexes(): not supported");
    }

    /**
     * Gets the total emissions and fees from the genesis block to the current height.
     * 
     * @param height is the height to start computing the miner sum
     * @param num_blocks are the number of blocks to include in the sum
     * @return the sum emission and fees since the geneis block
     */
    virtual std::shared_ptr<monero_miner_tx_sum> get_miner_tx_sum(uint64_t height, uint64_t num_blocks) {
      throw std::runtime_error("monero_daemon::get_miner_tx_sum(): not supported");
    }

    /**
     * Get mining fee estimates per kB.
     * 
     * @param grace_blocks TODO
     * @return mining fee estimates per kB
     */
    virtual std::shared_ptr<monero_fee_estimate> get_fee_estimate(uint64_t grace_blocks = 0) {
      throw std::runtime_error("monero_daemon::get_fee_estimate(): not supported");
    }

    /**
     * Submits a transaction to the daemon's pool.
     * 
     * @param tx_hex is the raw transaction hex to submit
     * @param do_not_relay specifies if the tx should be relayed (optional)
     * @return the submission results
    */
    virtual std::shared_ptr<monero_submit_tx_result> submit_tx_hex(const std::string& tx_hex, bool do_not_relay = false) {
      throw std::runtime_error("monero_daemon::submit_tx_hex(): not supported");
    }

    /**
     * Relays a transaction by hash.
     * 
     * @param tx_hash identifies the transaction to relay
     */
    virtual void relay_tx_by_hash(const std::string& tx_hash) {
      std::vector<std::string> tx_hashes;
      tx_hashes.push_back(tx_hash);
      relay_txs_by_hash(tx_hashes);
    }

    /**
     * Relays transactions by hash.
     * 
     * @param tx_hashes identify the transactions to relay
     */
    virtual void relay_txs_by_hash(const std::vector<std::string>& tx_hashes) {
      throw std::runtime_error("monero_daemon::relay_txs_by_hash(): not supported");
    }

    /**
     * Get valid transactions seen by the node but not yet mined into a block, as well
     * as spent key image information for the tx pool.
     * 
     * @return transactions in the transaction pool
     */
    virtual std::vector<std::shared_ptr<monero_tx>> get_tx_pool() {
      throw std::runtime_error("monero_daemon::get_tx_pool(): not supported");
    }

    /**
     * Get hashes of transactions in the transaction pool.
     * 
     * @return hashes of transactions in the transaction pool
     */
    virtual std::vector<std::string> get_tx_pool_hashes() {
      throw std::runtime_error("monero_daemon::get_tx_pool_hashes(): not supported");
    }

    /**
     * Get all transaction pool backlog.
     * 
     * @return transaction pool backlog entries
     */
    virtual std::vector<monero_tx_backlog_entry> get_tx_pool_backlog() {
      throw std::runtime_error("monero_daemon::get_tx_pool_backlog(): not supported");
    }

    /**
     * Get transaction pool statistics.
     * 
     * @return statistics about the transaction pool
     */
    virtual std::shared_ptr<monero_tx_pool_stats> get_tx_pool_stats() {
      throw std::runtime_error("monero_daemon::get_tx_pool_stats(): not supported");
    }

    /**
     * Flushes all transactions from the tx pool.
     */
    virtual void flush_tx_pool() {
      throw std::runtime_error("monero_daemon::flush_tx_pool(): not supported");
    }

    /**
     * Flush transactions from the tx pool.
     * 
     * @param hashes are hashes of transactions to flush
     */
    virtual void flush_tx_pool(const std::vector<std::string> &hashes) {
      throw std::runtime_error("monero_daemon::flush_tx_pool(): not supported");
    }

    /**
     * Flush a single transaction from the tx pool.
     * 
     * @param hash is the hash of transaction to flush
     */
    virtual void flush_tx_pool(const std::string &hash) {
      throw std::runtime_error("monero_daemon::flush_tx_pool(): not supported");
    }

    /**
     * Get the spent status of the given key image.
     * 
     * @param key_image is key image hex to get the status of
     * @return the status of the key image
     */
    virtual monero_key_image_spent_status get_key_image_spent_status(const std::string& key_image) {
      std::vector<std::string> key_images;
      key_images.push_back(key_image);
      auto statuses = get_key_image_spent_statuses(key_images);
      if (statuses.empty()) throw std::runtime_error("Could not get key image spent status");
      return statuses[0];
    }

    /**
     * Get the spent status of each given key image.
     * 
     * @param key_image are hex key images to get the statuses of
     * @return the spent status for each key image
     */
    virtual std::vector<monero_key_image_spent_status> get_key_image_spent_statuses(const std::vector<std::string>& key_images) {
      throw std::runtime_error("monero_daemon::get_key_image_spent_statuses(): not supported");
    }

    /**
     * Get outputs identified by a list of output amounts and indices as a binary
     * request.
     * 
     * @param outputs identify each output by amount and index
     * @return the identified outputs
     */
    virtual std::vector<std::shared_ptr<monero_output>> get_outputs(const std::vector<monero_output>& outputs) {
      throw std::runtime_error("monero_daemon::get_outputs(): not supported");
    }

    /**
     * Get a histogram of output amounts. For all amounts (possibly filtered by
     * parameters), gives the number of outputs on the chain for that amount.
     * RingCT outputs counts as 0 amount.
     * 
     * @param amounts are amounts of outputs to make the histogram with
     * @param min_count TODO
     * @param max_count TODO
     * @param is_unlocked makes a histogram with outputs with the specified lock state
     * @param recent_cutoff TODO
     * @return output histogram entries meeting the parameters
     */
    virtual std::vector<std::shared_ptr<monero_output_histogram_entry>> get_output_histogram(const std::vector<uint64_t>& amounts, const boost::optional<int>& min_count, const boost::optional<int>& max_count, const boost::optional<bool>& is_unlocked, const boost::optional<int>& recent_cutoff) {
      throw std::runtime_error("monero_daemon::get_output_histogram(): not supported");
    }

    /**
     * Creates an output distribution.
     * 
     * @param amounts are amounts of outputs to make the distribution with
     * @param is_cumulative specifies if the results should be cumulative (defaults to TODO)
     * @param start_height is the start height lower bound inclusive (optional)
     * @param end_height is the end height upper bound inclusive (optional)
     * @return output distribution entries meeting the parameters
     */
    virtual std::vector<std::shared_ptr<monero_output_distribution_entry>> get_output_distribution(const std::vector<uint64_t>& amounts, const boost::optional<bool>& is_cumulative = boost::none, const boost::optional<uint64_t>& start_height = boost::none, const boost::optional<uint64_t>& end_height = boost::none) {
      throw std::runtime_error("monero_daemon::get_output_distribution(): not supported");
    }

    /**
     * Get general information about the state of the node and the network.
     * 
     * @return general information about the node and network
     */
    virtual std::shared_ptr<monero_daemon_info> get_info() {
      throw std::runtime_error("monero_daemon::get_info(): not supported");
    }

    /**
     * Get synchronization information.
     * 
     * @return contains sync information
     */
    virtual std::shared_ptr<monero_daemon_sync_info> get_sync_info() {
      throw std::runtime_error("monero_daemon::get_sync_info(): not supported");
    }

    /**
     * Look up information regarding hard fork voting and readiness.
     * 
     * @return hard fork information
     */
    virtual std::shared_ptr<monero_hard_fork_info> get_hard_fork_info() {
      throw std::runtime_error("monero_daemon::get_hard_fork_info(): not supported");
    }

    /**
     * Get alternative chains seen by the node.
     * 
     * @return alternative chains seen by the node
     */
    virtual std::vector<std::shared_ptr<monero_alt_chain>> get_alt_chains() {
      throw std::runtime_error("monero_daemon::get_alt_chains(): not supported");
    }

    /**
     * Get known block hashes which are not on the main chain.
     * 
     * @return known block hashes which are not on the main chain
     */
    virtual std::vector<std::string> get_alt_block_hashes() {
      throw std::runtime_error("monero_daemon::get_alt_block_hashes(): not supported");
    }

    /**
     * Get the download bandwidth limit.
     * 
     * @return is the download bandwidth limit
     */
    virtual int get_download_limit() {
      throw std::runtime_error("monero_daemon::get_download_limit(): not supported");
    }

    /**
     * Set the download bandwidth limit.
     * 
     * @param limit is the download limit to set (-1 to reset to default)
     * @return int is the new download limit after setting
     */
    virtual int set_download_limit(int limit) {
      throw std::runtime_error("monero_daemon::set_download_limit(): not supported");
    }

    /**
     * Reset the download bandwidth limit.
     * 
     * @return the download bandwidth limit after resetting
     */
    virtual int reset_download_limit() {
      throw std::runtime_error("monero_daemon::reset_download_limit(): not supported");
    }

    /**
     * Get the upload bandwidth limit.
     * 
     * @return is the upload bandwidth limit
     */
    virtual int get_upload_limit() {
      throw std::runtime_error("monero_daemon::get_upload_limit(): not supported");
    }

    /**
     * Set the upload bandwidth limit.
     * 
     * @param limit is the upload limit to set (-1 to reset to default)
     * @return int is the new upload limit after setting
     */
    virtual int set_upload_limit(int limit) {
      throw std::runtime_error("monero_daemon::set_upload_limit(): not supported");
    }

    /**
     * Reset the upload bandwidth limit.
     * 
     * @return the upload bandwidth limit after resetting
     */
    virtual int reset_upload_limit() {
      throw std::runtime_error("monero_daemon::reset_upload_limit(): not supported");
    }

    /**
     * Get peers with active incoming or outgoing connections to the node.
     * 
     * @return the daemon's peers
     */
    virtual std::vector<std::shared_ptr<monero_peer>> get_peers() {
      throw std::runtime_error("monero_daemon::get_peers(): not supported");
    }

    /**
     * Get all known peers including their last known online status.
     * 
     * @return the daemon's known peers
     */
    virtual std::vector<std::shared_ptr<monero_peer>> get_known_peers() {
      throw std::runtime_error("monero_daemon::get_known_peers(): not supported");
    }

    /**
     * Limit number of outgoing peers.
     * 
     * @param limit is the maximum number of outgoing peers
     */
    virtual void set_outgoing_peer_limit(int limit) {
      throw std::runtime_error("monero_daemon::set_outgoing_peer_limit(): not supported");
    }

    /**
     * Limit number of incoming peers.
     * 
     * @param limit is the maximum number of incoming peers
     */
    virtual void set_incoming_peer_limit(int limit) {
      throw std::runtime_error("monero_daemon::set_incoming_peer_limit(): not supported");
    }

    /**
     * Get peer bans.
     * 
     * @return entries about banned peers
     */
    virtual std::vector<std::shared_ptr<monero_ban>> get_peer_bans() {
      throw std::runtime_error("monero_daemon::get_peer_bans(): not supported");
    }

    /**
     * Ban peers nodes.
     * 
     * @param bans are bans to apply against peer nodes
     */
    virtual void set_peer_bans(const std::vector<std::shared_ptr<monero_ban>>& bans) {
      throw std::runtime_error("monero_daemon::set_peer_bans(): not supported");
    }

    /**
     * Ban a peer node.
     * 
     * @param ban contains information about a node to ban
     */
    virtual void set_peer_ban(const std::shared_ptr<monero_ban>& ban) {
      if (ban == nullptr) throw std::runtime_error("Ban is none");
      std::vector<std::shared_ptr<monero_ban>> bans;
      bans.push_back(ban);
      set_peer_bans(bans);
    }

    /**
     * Start mining.
     * 
     * @param address is the address given miner rewards if the daemon mines a block
     * @param num_threads is the number of mining threads to run
     * @param is_background specifies if the miner should run in the background or not
     * @param ignore_battery specifies if the battery state (e.g. on laptop) should be ignored or not
     */
    virtual void start_mining(const std::string &address, boost::optional<uint64_t> num_threads, boost::optional<bool> is_background, boost::optional<bool> ignore_battery) {
      throw std::runtime_error("monero_daemon::start_mining(): not supported");
    }

    /**
     * Stop mining.
     */
    virtual void stop_mining() {
      throw std::runtime_error("monero_daemon::stop_mining(): not supported");
    }

    /**
     * Get the daemon's mining status.
     * 
     * @return the daemon's mining status
     */
    virtual std::shared_ptr<monero_mining_status> get_mining_status() {
      throw std::runtime_error("monero_daemon::get_mining_status(): not supported");
    }

    /**
     * Generate blocks to a wallet address (regtest only).
     *
     * @param wallet_address is the address of the wallet to receive miner transactions if block is successfully mined
     * @param num_blocks is the number of blocks to generate
     * @param prev_block_hash is the hash of the previous block to build on top of (optional, builds on the current tip if not given)
     * @param starting_nonce is the starting nonce to use (optional)
     * @return the result of generating blocks; height is the height of the last block generated
     */
    virtual std::shared_ptr<monero_generate_blocks_result> generate_blocks(const std::string& wallet_address, uint64_t num_blocks, const boost::optional<std::string>& prev_block_hash = boost::none, const boost::optional<uint32_t>& starting_nonce = boost::none) {
      throw std::runtime_error("monero_daemon::generate_blocks(): not supported");
    }

    /**
     * Submit a mined block to the network.
     * 
     * @param block_blob is the mined block to submit
     */
    virtual void submit_block(const std::string& block_blob) {
      std::vector<std::string> block_blobs;
      block_blobs.push_back(block_blob);
      return submit_blocks(block_blobs);
    }

    /**
     * Submit mined blocks to the network.
     * 
     * @param block_blobs are the mined blocks to submit
     */
    virtual void submit_blocks(const std::vector<std::string>& block_blobs) {
      throw std::runtime_error("monero_daemon::submit_blocks(): not supported");
    }

    /**
     * Prune the blockchain.
     * 
     * @param check specifies to check the pruning (default false)
     * @return the prune result
     */
    virtual std::shared_ptr<monero_prune_result> prune_blockchain(bool check) {
      throw std::runtime_error("monero_daemon::prune_blockchain(): not supported");
    }

    /**
     * Check for update.
     * 
     * @return the result of the update check
     */
    virtual std::shared_ptr<monero_daemon_update_check_result> check_for_update() {
      throw std::runtime_error("monero_daemon::check_for_update(): not supported");
    }

    /**
     * Download an update.
     * 
     * @param path is the path to download the update (optional)
     * @return the result of the update download
     */
    virtual std::shared_ptr<monero_daemon_update_download_result> download_update(const std::string& path = "") {
      throw std::runtime_error("monero_daemon::download_update(): not supported");
    }

    /**
     * Safely disconnect and shut down the daemon.
     */
    virtual void stop() {
      throw std::runtime_error("monero_daemon::stop(): not supported");
    }

    /**
     * Get the header of the next block added to the chain.
     * 
     * @return the header of the next block added to the chain
     */
    virtual std::shared_ptr<monero_block_header> wait_for_next_block_header() {
      throw std::runtime_error("monero_daemon::wait_for_next_block_header(): not supported");
    }

  };
}
