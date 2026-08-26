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
#include "monero_daemon_rpc.h"
#include "monero_daemon_rpc_model.h"
#include "common/monero_error.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"

static const uint64_t MAX_REQ_SIZE = 3000000;
static const uint64_t NUM_HEADERS_PER_REQ = 750;

namespace monero {

  /**
   * Polls daemon and sends notifications in order to notify external daemon listeners.
   */
  class monero_daemon_poller : public gen_utils::thread_poller {
  public:

    explicit monero_daemon_poller(monero_daemon* daemon, uint64_t poll_period_ms = 10000): m_daemon(daemon) {
      init_common("monero_daemon_rpc");
      m_poll_period_ms = poll_period_ms;
    }

    ~monero_daemon_poller() override {
      set_is_polling(false);
    }

    void poll() override {
      if (!m_last_header) {
        m_last_header = m_daemon->get_last_block_header();
        return;
      }

      auto header = m_daemon->get_last_block_header();
      if (header->m_hash != m_last_header->m_hash) {
        m_last_header = header;
        announce_block_header(header);
      }
    }

  private:
    monero_daemon* m_daemon;
    std::shared_ptr<monero_block_header> m_last_header;

    void announce_block_header(const std::shared_ptr<monero_block_header>& header) {
      gen_utils::thread_poller::announce_scope scope(*this); // see wait_for_callbacks_idle()
      auto listeners = m_daemon->get_listeners();
      for (auto& listener : listeners) {
        try {
          listener->on_block_header(header);
        } catch (const std::exception& e) {
          MERROR("Error calling listener on new block header: " << e.what());
        }
      }
    }
  };

  /**
   * Sends a notification on a condition variable when a block is added to blockchain.
   */
  class block_notifier : public monero_daemon_listener {
  public:
    block_notifier(boost::mutex* temp, boost::condition_variable* cv, bool* ready) { this->temp = temp; this->cv = cv; this->ready = ready; }

    void on_block_header(const std::shared_ptr<monero_block_header>& header) override {
      boost::mutex::scoped_lock lock(*temp);
      m_last_header = header;
      *ready = true;
      cv->notify_one();
    }

  private:
    boost::mutex* temp;
    boost::condition_variable* cv;
    bool* ready;
  };

  void monero_daemon_rpc::set_poll_period_in_ms(uint64_t period_ms) {
    boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);
    if (!m_poller) m_poller = std::make_unique<monero_daemon_poller>(this);
    m_poller->set_period_in_ms(period_ms);
  }

  /**
   * Validate RPC response status.
   */
  void check_response_status(const boost::property_tree::ptree& node) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("status")) {
        std::string status = it->second.data();

        // TODO monero-project empty string status is returned for download update response when an update is available
        if (status == std::string("OK") || status == std::string("")) {
          return;
        }
        else throw monero_rpc_error(normalize_daemon_rpc_status(status));
      }
    }

    throw monero_error("Could not get JSON RPC response status");
  }

  monero_daemon_rpc::monero_daemon_rpc(const std::shared_ptr<monero_rpc_connection>& rpc): m_rpc(rpc) {
    if (rpc == nullptr) throw monero_error("Connection cannot be null");
    if (!rpc->is_online().value_or(false) && rpc->m_uri != boost::none) rpc->check_connection();
  }

  monero_daemon_rpc::monero_daemon_rpc(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy_uri, const std::string& zmq_uri, const boost::optional<uint32_t>& timeout):
    m_rpc(std::make_shared<monero_rpc_connection>(uri, username, password, proxy_uri, zmq_uri, 0, timeout)) {
    if (!uri.empty()) m_rpc->check_connection();
  }

  std::set<monero_daemon_listener*> monero_daemon_rpc::get_listeners() {
    boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
    return m_listeners;
  }

  void monero_daemon_rpc::add_listener(monero_daemon_listener &listener) {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      m_listeners.insert(&listener);
    }
    refresh_listening();
  }

  void monero_daemon_rpc::remove_listener(monero_daemon_listener &listener) {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      m_listeners.erase(&listener);
    }
    refresh_listening();
    wait_for_listener_callbacks_idle();
  }

  void monero_daemon_rpc::remove_listeners() {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      m_listeners.clear();
    }
    refresh_listening();
    wait_for_listener_callbacks_idle();
  }

  void monero_daemon_rpc::wait_for_listener_callbacks_idle() {
    // ensures no in-flight callback dispatch can still reference a just-removed listener
    monero_daemon_poller* poller;
    {
      boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);
      poller = m_poller.get();
    }
    if (poller != nullptr) poller->wait_for_callbacks_idle();
  }

  std::shared_ptr<monero_rpc_connection> monero_daemon_rpc::get_rpc_connection() const {
    MTRACE("monero_daemon_rpc::get_rpc_connection()");
    return m_rpc;
  }

  bool monero_daemon_rpc::is_connected() {
    try {
      get_version();
      return true;
    }
    catch (...) {
      return false;
    }
  }

  monero_version monero_daemon_rpc::get_version() {
    auto result = m_rpc->send_json_request("get_version");
    check_response_status(result);
    monero_version version;
    deserialize_version(result, version);
    return version;
  }

  bool monero_daemon_rpc::is_trusted() {
    auto result = m_rpc->send_path_request("get_height");
    check_response_status(result);
    auto get_height_response = std::make_shared<monero_get_block_result>();
    monero_get_block_result::from_property_tree(result, get_height_response);
    return gen_utils::bool_equals(false, get_height_response->m_untrusted);
  }

  uint64_t monero_daemon_rpc::get_height() {
    auto result = m_rpc->send_json_request("get_block_count");
    check_response_status(result);
    std::shared_ptr<monero_get_block_result> block_result = std::make_shared<monero_get_block_result>();
    monero_get_block_result::from_property_tree(result, block_result);
    if (block_result->m_count == boost::none) throw monero_error("Could not get height");
    return block_result->m_count.get();
  }

  std::string monero_daemon_rpc::get_block_hash(uint64_t height) {
    std::shared_ptr<monero_get_block_hash_params> params = std::make_shared<monero_get_block_hash_params>(height);
    auto result = m_rpc->send_json_request("on_get_block_hash", params);
    return result.data();
  }

  std::shared_ptr<monero_block_template> monero_daemon_rpc::get_block_template(const std::string& wallet_address, const boost::optional<int>& reserve_size) {
    MTRACE("monero_daemon_rpc::get_block_template()");
    auto params = std::make_shared<monero_get_block_params>(wallet_address, reserve_size);
    auto result = m_rpc->send_json_request("get_block_template", params);
    check_response_status(result);
    std::shared_ptr<monero_block_template> tmplt = std::make_shared<monero_block_template>();
    deserialize_block_template(result, tmplt);
    return tmplt;
  }

  std::shared_ptr<monero_miner_data> monero_daemon_rpc::get_miner_data() {
    MTRACE("monero_daemon_rpc::get_miner_data()");
    auto result = m_rpc->send_json_request("get_miner_data");
    check_response_status(result);
    auto data = std::make_shared<monero_miner_data>();
    deserialize_miner_data(result, data);
    return data;
  }

  std::string monero_daemon_rpc::calculate_pow(uint32_t major_version, uint64_t height, const std::string& block_blob, const std::string& seed_hash) {
    MTRACE("monero_daemon_rpc::calculate_pow()");
    if (block_blob.empty()) throw monero_error("Must provide a block blob to hash");
    auto params = std::make_shared<monero_calculate_pow_params>(major_version, height, block_blob, seed_hash);
    auto result = m_rpc->send_json_request("calc_pow", params);
    return result.data();
  }

  std::shared_ptr<monero_add_auxiliary_pow_result> monero_daemon_rpc::add_auxiliary_pow(const std::string& block_template_blob, const std::vector<std::shared_ptr<monero_auxiliary_pow>>& aux_pow) {
    MTRACE("monero_daemon_rpc::add_auxiliary_pow()");
    if (block_template_blob.empty()) throw monero_error("Must provide a block template blob to add auxiliary proof of work to");
    if (aux_pow.empty()) throw monero_error("Must provide auxiliary proof of work to add");
    auto params = std::make_shared<monero_add_aux_pow_params>(block_template_blob, aux_pow);
    auto result = m_rpc->send_json_request("add_aux_pow", params);
    check_response_status(result);
    auto add_result = std::make_shared<monero_add_auxiliary_pow_result>();
    deserialize_add_auxiliary_pow_result(result, add_result);
    return add_result;
  }

  std::shared_ptr<monero_block_header> monero_daemon_rpc::get_last_block_header() {
    auto result = m_rpc->send_json_request("get_last_block_header");
    check_response_status(result);
    std::shared_ptr<monero_block_header> header = std::make_shared<monero_block_header>();
    deserialize_block_header(result, header);
    return header;
  }

  std::shared_ptr<monero_block_header> monero_daemon_rpc::get_block_header_by_hash(const std::string& hash) {
    std::shared_ptr<monero_get_block_params> params = std::make_shared<monero_get_block_params>(hash);
    auto result = m_rpc->send_json_request("get_block_header_by_hash", params);
    check_response_status(result);
    std::shared_ptr<monero_block_header> header = std::make_shared<monero_block_header>();
    deserialize_block_header(result, header);
    return header;
  }

  std::shared_ptr<monero_block_header> monero_daemon_rpc::get_block_header_by_height(uint64_t height) {
    std::shared_ptr<monero_get_block_params> params = std::make_shared<monero_get_block_params>(height);
    auto result = m_rpc->send_json_request("get_block_header_by_height", params);
    check_response_status(result);
    std::shared_ptr<monero_block_header> header = std::make_shared<monero_block_header>();
    deserialize_block_header(result, header);
    return header;
  }

  std::vector<std::shared_ptr<monero_block_header>> monero_daemon_rpc::get_block_headers_by_range(uint64_t start_height, uint64_t end_height) {
    auto params = std::make_shared<monero_get_block_params>(start_height, end_height);
    auto result = m_rpc->send_json_request("get_block_headers_range", params);
    check_response_status(result);
    std::vector<std::shared_ptr<monero_block_header>> headers;
    deserialize_block_headers(result, headers);
    return headers;
  }

  std::shared_ptr<monero_block> monero_daemon_rpc::get_block_by_hash(const std::string& hash) {
    std::shared_ptr<monero_get_block_params> params = std::make_shared<monero_get_block_params>(hash);
    auto result = m_rpc->send_json_request("get_block", params);
    check_response_status(result);
    auto block = std::make_shared<monero_block>();
    deserialize_block(result, block);
    return block;
  }

  std::shared_ptr<monero_block_header> monero_daemon_rpc::get_block_header_by_height_cached(uint64_t height, uint64_t max_height, std::unordered_map<uint64_t, std::shared_ptr<monero_block_header>>& header_cache) {
    // get header from cache
    auto found = header_cache.find(height);
    if (found != header_cache.end()) return found->second;

    // fetch and cache headers if not in cache
    uint64_t end_height = std::min(max_height, height + NUM_HEADERS_PER_REQ - 1);
    auto headers = get_block_headers_by_range(height, end_height);

    for(const auto& header : headers) {
      if (header->m_height == boost::none) throw monero_error("Malformed block header: expected height to be defined");
      header_cache[header->m_height.get()] = header;
    }

    // look up rather than default-construct via operator[]: a daemon response missing the
    // requested height must not silently cache (and return) a null header
    found = header_cache.find(height);
    if (found == header_cache.end()) throw monero_error("Daemon did not return a header for height " + std::to_string(height));
    return found->second;
  }

  std::vector<std::shared_ptr<monero_block>> monero_daemon_rpc::get_blocks_by_hash(const std::vector<std::string>& block_hashes, uint64_t start_height, bool prune) {
    throw monero_error("monero_daemon_rpc::get_blocks_by_hash(): not implemented");
  }

  std::shared_ptr<monero_block> monero_daemon_rpc::get_block_by_height(uint64_t height) {
    std::shared_ptr<monero_get_block_params> params = std::make_shared<monero_get_block_params>(height);
    auto result = m_rpc->send_json_request("get_block", params);
    check_response_status(result);
    auto block = std::make_shared<monero_block>();
    deserialize_block(result, block);
    return block;
  }

  std::vector<std::shared_ptr<monero_block>> monero_daemon_rpc::get_blocks_by_height(const std::vector<uint64_t>& heights) {
    // fetch blocks in binary
    monero_get_blocks_by_height_request request(heights);
    auto response = m_rpc->send_binary_request(request);
    if (response.m_binary == boost::none) throw monero_error("Invalid Monero Binary response");
    boost::property_tree::ptree node;
    monero_utils::binary_blocks_to_property_tree(response.m_binary.get(), node);
    check_response_status(node);
    std::vector<std::shared_ptr<monero_block>> blocks;
    deserialize_blocks(node, heights, blocks);
    return blocks;
  }

  std::vector<std::shared_ptr<monero_block>> monero_daemon_rpc::get_blocks_by_range(boost::optional<uint64_t> start_height, boost::optional<uint64_t> end_height) {
    if (start_height == boost::none) start_height = 0;
    if (end_height == boost::none) {
      uint64_t block_height = get_height();
      end_height = block_height == 0 ? 0 : block_height - 1;
    }

    std::vector<uint64_t> heights;
    for (uint64_t height = start_height.get(); height <= end_height.get(); height++) heights.push_back(height);

    return get_blocks_by_height(heights);
  }

  std::vector<std::shared_ptr<monero_block>> monero_daemon_rpc::get_blocks_by_range_chunked(boost::optional<uint64_t> start_height, boost::optional<uint64_t> end_height, boost::optional<uint64_t> max_chunk_size) {
    if (start_height == boost::none) start_height = 0;
    if (end_height == boost::none) {
      uint64_t block_height = get_height();
      end_height = block_height == 0 ? 0 : block_height - 1;
    }

    boost::optional<uint64_t> last_height = boost::none;
    std::vector<std::shared_ptr<monero_block>> blocks;

    if (start_height.get() > end_height.get()) return blocks;

    // scoped to this call: see the comment on get_max_blocks()/get_block_header_by_height_cached() in the header
    std::unordered_map<uint64_t, std::shared_ptr<monero_block_header>> header_cache;

    while (last_height == boost::none || last_height.get() < end_height.get()) {
      uint64_t height_to_get = (last_height == boost::none) ? start_height.get() : last_height.get() + 1;

      auto max_blocks = get_max_blocks(height_to_get, end_height, max_chunk_size, header_cache);
      if (max_blocks.empty()) throw monero_error("Daemon returned an empty block chunk for a non-empty range at height " + std::to_string(height_to_get));
      blocks.insert(blocks.end(), max_blocks.begin(), max_blocks.end());
      last_height = blocks[blocks.size() - 1]->m_height.get();
    }

    return blocks;
  }

  std::vector<std::shared_ptr<monero_block>> monero_daemon_rpc::get_max_blocks(boost::optional<uint64_t> start_height, boost::optional<uint64_t> max_height, boost::optional<uint64_t> chunk_size, std::unordered_map<uint64_t, std::shared_ptr<monero_block_header>>& header_cache) {
    if (start_height == boost::none) start_height = 0;
    if (max_height == boost::none) {
      uint64_t block_height = get_height();
      max_height = block_height == 0 ? 0 : block_height - 1;
    }
    if (chunk_size == boost::none) chunk_size = MAX_REQ_SIZE;

    // determine end height to fetch
    uint64_t req_size = 0;
    boost::optional<uint64_t> end_height = boost::none; // none = no block accepted yet
    uint64_t height_to_get = start_height.get();

    while (req_size < chunk_size.get() && height_to_get <= max_height.get()) {
      // get header of next block
      auto header = get_block_header_by_height_cached(height_to_get, max_height.get(), header_cache);
      if (header->m_size == boost::none) throw monero_error("Malformed block header: expected size to be defined");
      uint64_t header_size = header->m_size.get();
      // block cannot be bigger than max request size
      if (header_size > chunk_size.get()) throw monero_error("Block exceeds maximum request size: " + std::to_string(header_size));

      // done iterating if fetching block would exceed max request size
      if (req_size + header_size > chunk_size.get()) break;

      // otherwise block is included
      req_size += header_size;
      end_height = height_to_get;
      height_to_get++;
    }

    if (end_height != boost::none) {
      return get_blocks_by_range(start_height, end_height.get());
    }

    return std::vector<std::shared_ptr<monero_block>>();
  }

  std::vector<std::string> monero_daemon_rpc::get_block_hashes(const std::vector<std::string>& block_hashes, uint64_t start_height) {
    throw monero_error("monero_daemon_rpc::get_block_hashes(): not implemented");
  }

  std::vector<std::shared_ptr<monero_tx>> monero_daemon_rpc::get_txs(const std::vector<std::string>& tx_hashes, bool prune) {
    MTRACE("monero_daemon_rpc::get_txs()");
    if (tx_hashes.empty()) throw monero_error("Must provide an array of transaction hashes");
    auto params = std::make_shared<monero_get_txs_params>(tx_hashes, prune);
    auto result = m_rpc->send_path_request("get_transactions", params);

    try { check_response_status(result); }
    catch (const std::exception& ex) {
      if (std::string(ex.what()).find("Failed to parse hex representation of transaction hash") != std::string::npos) {
        throw monero_error("Invalid transaction hash");
      }
      throw;
    }

    std::vector<std::shared_ptr<monero_tx>> txs;
    deserialize_txs(result, txs);
    return txs;
  }

  std::vector<std::string> monero_daemon_rpc::get_tx_hexes(const std::vector<std::string>& tx_hashes, bool prune) {
    MTRACE("monero_daemon_rpc::get_tx_hexes()");
    std::vector<std::string> hexes;
    for(const auto& tx : get_txs(tx_hashes, prune)) {
      // tx may be pruned regardless of configuration
      if (tx->m_pruned_hex == boost::none) {
        if (tx->m_full_hex == boost::none) throw monero_error("Tx has no hex");
        hexes.push_back(tx->m_full_hex.get());
      } else {
        hexes.push_back(tx->m_pruned_hex.get());
      }
    }
    return hexes;
  }

  std::shared_ptr<monero_miner_tx_sum> monero_daemon_rpc::get_miner_tx_sum(uint64_t height, uint64_t num_blocks) {
    auto params = std::make_shared<monero_get_miner_tx_sum_params>(height, num_blocks);
    auto result = m_rpc->send_json_request("get_coinbase_tx_sum", params);
    check_response_status(result);
    auto sum = std::make_shared<monero_miner_tx_sum>();
    deserialize_miner_tx_sum(result, sum);
    return sum;
  }

  std::shared_ptr<monero_fee_estimate> monero_daemon_rpc::get_fee_estimate(uint64_t grace_blocks) {
    auto params = std::make_shared<monero_get_fee_estimate_params>(grace_blocks);
    auto result = m_rpc->send_json_request("get_fee_estimate", params);
    check_response_status(result);
    auto estimate = std::make_shared<monero_fee_estimate>();
    deserialize_fee_estimate(result, estimate);
    return estimate;
  }

  std::shared_ptr<monero_submit_tx_result> monero_daemon_rpc::submit_tx_hex(const std::string& tx_hex, bool do_not_relay) {
    MTRACE("monero_daemon_rpc::submit_tx_hex()");
    auto params = std::make_shared<monero_submit_tx_params>(tx_hex, do_not_relay);
    auto result = m_rpc->send_path_request("send_raw_transaction", params);
    auto sum = std::make_shared<monero_submit_tx_result>();
    deserialize_submit_tx_result(result, sum);

    // set m_is_good based on status
    try {
      check_response_status(result);
      sum->m_is_good = true;
    } catch (...) {
      sum->m_is_good = false;
    }
    return sum;
  }

  void monero_daemon_rpc::relay_txs_by_hash(const std::vector<std::string>& tx_hashes) {
    MTRACE("monero_daemon_rpc::relay_txs_by_hash()");
    auto params = std::make_shared<monero_submit_tx_params>(tx_hashes);
    auto result = m_rpc->send_json_request("relay_tx", params);
    check_response_status(result);
  }

  std::shared_ptr<monero_tx_pool_stats> monero_daemon_rpc::get_tx_pool_stats() {
    auto result = m_rpc->send_path_request("get_transaction_pool_stats");
    check_response_status(result);
    auto stats = std::make_shared<monero_tx_pool_stats>();
    deserialize_tx_pool_stats(result, stats);
    return stats;
  }

  std::vector<std::shared_ptr<monero_tx>> monero_daemon_rpc::get_tx_pool() {
    auto result = m_rpc->send_path_request("get_transaction_pool");
    check_response_status(result);
    std::vector<std::shared_ptr<monero_tx>> pool;
    deserialize_txs(result, pool);
    return pool;
  }

  std::vector<std::string> monero_daemon_rpc::get_tx_pool_hashes() {
    auto result = m_rpc->send_path_request("get_transaction_pool_hashes");
    check_response_status(result);
    std::vector<std::string> tx_hashes;
    deserialize_tx_hashes(result, tx_hashes);
    return tx_hashes;
  }

  void monero_daemon_rpc::flush_tx_pool(const std::vector<std::string> &hashes) {
    MTRACE("monero_daemon_rpc::flush_tx_pool()");
    auto params = std::make_shared<monero_submit_tx_params>(hashes);
    auto result = m_rpc->send_json_request("flush_txpool", params);
    check_response_status(result);
  }

  void monero_daemon_rpc::flush_tx_pool() {
    std::vector<std::string> hashes;
    flush_tx_pool(hashes);
  }

  void monero_daemon_rpc::flush_tx_pool(const std::string &hash) {
    std::vector<std::string> hashes;
    hashes.push_back(hash);
    flush_tx_pool(hashes);
  }

  std::vector<monero_key_image_spent_status> monero_daemon_rpc::get_key_image_spent_statuses(const std::vector<std::string>& key_images) {
    if (key_images.empty()) throw monero_error("Must provide key images to check the status of");
    auto params = std::make_shared<monero_is_key_image_spent_params>(key_images);
    auto result = m_rpc->send_path_request("is_key_image_spent", params);
    check_response_status(result);
    std::vector<monero_key_image_spent_status> statuses;
    deserialize_key_image_spent_status(result, statuses);
    return statuses;
  }

  std::vector<uint64_t> monero_daemon_rpc::get_output_indices(const std::string& tx_hash) {
    MTRACE("monero_daemon_rpc::get_output_indices()");
    if (tx_hash.empty()) throw monero_error("Must provide a transaction hash");
    monero_get_output_indices_request request(tx_hash);
    auto response = m_rpc->send_binary_request(request);
    if (response.m_binary == boost::none) throw monero_error("Invalid Monero Binary response");
    std::vector<uint64_t> indices;
    deserialize_output_indices(response.m_binary.get(), indices);
    return indices;
  }

  std::vector<std::shared_ptr<monero_output>> monero_daemon_rpc::get_outputs(const std::vector<monero_output>& outputs) {
    MTRACE("monero_daemon_rpc::get_outputs()");
    if (outputs.empty()) throw monero_error("Must provide outputs to fetch");
    monero_get_outputs_request request(outputs);
    auto response = m_rpc->send_binary_request(request);
    if (response.m_binary == boost::none) throw monero_error("Invalid Monero Binary response");
    std::vector<std::shared_ptr<monero_output>> result;
    deserialize_outputs(response.m_binary.get(), outputs, result);
    return result;
  }

  std::vector<std::shared_ptr<monero_output_histogram_entry>> monero_daemon_rpc::get_output_histogram(const std::vector<uint64_t>& amounts, const boost::optional<int>& min_count, const boost::optional<int>& max_count, const boost::optional<bool>& is_unlocked, const boost::optional<int>& recent_cutoff) {
    MTRACE("monero_daemon_rpc::get_output_histogram()");
    auto params = std::make_shared<monero_get_output_histogram_params>(amounts, min_count, max_count, is_unlocked, recent_cutoff);
    auto result = m_rpc->send_json_request("get_output_histogram", params);
    check_response_status(result);
    std::vector<std::shared_ptr<monero_output_histogram_entry>> entries;
    deserialize_output_histogram_entries(result, entries);
    return entries;
  }

  std::vector<std::shared_ptr<monero_output_distribution_entry>> monero_daemon_rpc::get_output_distribution(const std::vector<uint64_t>& amounts, const boost::optional<bool>& is_cumulative, const boost::optional<uint64_t>& start_height, const boost::optional<uint64_t>& end_height) {
    MTRACE("monero_daemon_rpc::get_output_distribution()");
    auto params = std::make_shared<monero_get_output_distribution_params>(amounts, is_cumulative, start_height, end_height);
    auto result = m_rpc->send_json_request("get_output_distribution", params);
    check_response_status(result);
    std::vector<std::shared_ptr<monero_output_distribution_entry>> entries;
    deserialize_output_distribution_entries(result, entries);
    return entries;
  }

  std::shared_ptr<monero_daemon_info> monero_daemon_rpc::get_info() {
    auto result = m_rpc->send_json_request("get_info");
    check_response_status(result);
    std::shared_ptr<monero_daemon_info> info = std::make_shared<monero_daemon_info>();
    deserialize_daemon_info(result, info);
    return info;
  }

  std::shared_ptr<monero_daemon_sync_info> monero_daemon_rpc::get_sync_info() {
    auto result = m_rpc->send_json_request("sync_info");
    check_response_status(result);
    std::shared_ptr<monero_daemon_sync_info> info = std::make_shared<monero_daemon_sync_info>();
    deserialize_daemon_sync_info(result, info);
    return info;
  }

  std::shared_ptr<monero_daemon_network_stats> monero_daemon_rpc::get_network_stats() {
    MTRACE("monero_daemon_rpc::get_network_stats()");
    auto result = m_rpc->send_path_request("get_net_stats");
    check_response_status(result);
    auto stats = std::make_shared<monero_daemon_network_stats>();
    deserialize_network_stats(result, stats);
    return stats;
  }

  std::shared_ptr<monero_hard_fork_info> monero_daemon_rpc::get_hard_fork_info() {
    auto result = m_rpc->send_json_request("hard_fork_info");
    check_response_status(result);
    std::shared_ptr<monero_hard_fork_info> info = std::make_shared<monero_hard_fork_info>();
    deserialize_hard_fork_info(result, info);
    return info;
  }

  std::vector<std::shared_ptr<monero_alt_chain>> monero_daemon_rpc::get_alt_chains() {
    auto result = m_rpc->send_json_request("get_alternate_chains");
    check_response_status(result);
    std::vector<std::shared_ptr<monero_alt_chain>> alt_chains;
    deserialize_alt_chains(result, alt_chains);
    return alt_chains;
  }

  std::vector<std::string> monero_daemon_rpc::get_alt_block_hashes() {
    auto result = m_rpc->send_path_request("get_alt_blocks_hashes");
    check_response_status(result);
    std::vector<std::string> hashes;
    deserialize_alt_block_hashes(result, hashes);
    return hashes;
  }

  int monero_daemon_rpc::get_download_limit() {
    MTRACE("monero_daemon_rpc::get_download_limit()");
    auto limits = get_bandwidth_limits();
    if (limits->m_down != boost::none) return limits->m_down.get();
    throw monero_error("Could not get download limit");
  }

  int monero_daemon_rpc::set_download_limit(int limit) {
    MTRACE("monero_daemon_rpc::set_download_limit()");
    if (limit == -1) return reset_download_limit();
    if (limit <= 0) throw monero_error("Download limit must be an integer greater than 0");
    auto result = set_bandwidth_limits(0, limit);
    if (result->m_down != boost::none) return result->m_down.get();
    throw monero_error("Could not set download limit");
  }

  int monero_daemon_rpc::reset_download_limit() {
    MTRACE("monero_daemon_rpc::reset_download_limit()");
    auto result = set_bandwidth_limits(0, -1);
    if (result->m_down != boost::none) return result->m_down.get();
    throw monero_error("Could not set download limit");
  }

  int monero_daemon_rpc::get_upload_limit() {
    MTRACE("monero_daemon_rpc::get_upload_limit()");
    auto limits = get_bandwidth_limits();
    if (limits->m_up != boost::none) return limits->m_up.get();
    throw monero_error("Could not get upload limit");
  }

  int monero_daemon_rpc::set_upload_limit(int limit) {
    MTRACE("monero_daemon_rpc::set_upload_limit()");
    if (limit == -1) return reset_upload_limit();
    if (limit <= 0) throw monero_error("Upload limit must be an integer greater than 0");
    auto result = set_bandwidth_limits(limit, 0);
    if (result->m_up != boost::none) return result->m_up.get();
    throw monero_error("Could not set download limit");
  }

  int monero_daemon_rpc::reset_upload_limit() {
    MTRACE("monero_daemon_rpc::reset_upload_limit()");
    auto result = set_bandwidth_limits(-1, 0);
    if (result->m_up != boost::none) return result->m_up.get();
    throw monero_error("Could not set download limit");
  }

  std::vector<std::shared_ptr<monero_peer>> monero_daemon_rpc::get_peers() {
    auto result = m_rpc->send_json_request("get_connections");
    check_response_status(result);
    std::vector<std::shared_ptr<monero_peer>> peers;
    deserialize_peers(result, peers);
    return peers;
  }

  std::vector<std::shared_ptr<monero_peer>> monero_daemon_rpc::get_known_peers() {
    auto result = m_rpc->send_path_request("get_peer_list");
    check_response_status(result);
    std::vector<std::shared_ptr<monero_peer>> peers;
    deserialize_peers(result, peers);
    return peers;
  }

  std::vector<std::shared_ptr<monero_peer>> monero_daemon_rpc::get_public_peers(bool include_offline) {
    MTRACE("monero_daemon_rpc::get_public_peers()");
    auto params = std::make_shared<monero_get_public_nodes_params>(include_offline);
    auto result = m_rpc->send_path_request("get_public_nodes", params);
    check_response_status(result);
    std::vector<std::shared_ptr<monero_peer>> peers;
    deserialize_public_peers(result, peers);
    return peers;
  }

  void monero_daemon_rpc::set_outgoing_peer_limit(int limit) {
    MTRACE("monero_daemon_rpc::set_outgoing_peer_limit()");
    if (limit < 0) throw monero_error("Outgoing peer limit must be >= 0");
    auto params = std::make_shared<monero_peer_limits_params>();
    params->m_out_peers = limit;
    auto result = m_rpc->send_path_request("out_peers", params);
    check_response_status(result);
  }

  void monero_daemon_rpc::set_incoming_peer_limit(int limit) {
    MTRACE("monero_daemon_rpc::set_incoming_peer_limit()");
    if (limit < 0) throw monero_error("Incoming peer limit must be >= 0");
    auto params = std::make_shared<monero_peer_limits_params>();
    params->m_in_peers = limit;
    auto result = m_rpc->send_path_request("in_peers", params);
    check_response_status(result);
  }

  std::vector<std::shared_ptr<monero_ban>> monero_daemon_rpc::get_peer_bans() {
    MTRACE("monero_daemon_rpc::get_peer_bans()");
    auto result = m_rpc->send_json_request("get_bans");
    check_response_status(result);
    std::vector<std::shared_ptr<monero_ban>> bans;
    deserialize_bans(result, bans);
    return bans;
  }

  void monero_daemon_rpc::set_peer_bans(const std::vector<std::shared_ptr<monero_ban>>& bans) {
    MTRACE("monero_daemon_rpc::set_peer_bans()");
    auto params = std::make_shared<monero_set_bans_params>(bans);
    auto result = m_rpc->send_json_request("set_bans", params);
    check_response_status(result);
  }

  std::shared_ptr<monero_ban> monero_daemon_rpc::get_peer_ban(const std::string& address) {
    MTRACE("monero_daemon_rpc::get_peer_ban()");
    if (address.empty()) throw monero_error("Must provide an address to check the ban status of");
    auto params = std::make_shared<monero_banned_params>(address);
    auto result = m_rpc->send_json_request("banned", params);
    check_response_status(result);
    auto ban = std::make_shared<monero_ban>();
    ban->m_host = address;
    for (boost::property_tree::ptree::const_iterator it = result.begin(); it != result.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("banned")) ban->m_is_banned = it->second.get_value<bool>();
      else if (key == std::string("seconds")) ban->m_seconds = it->second.get_value<uint64_t>();
    }
    return ban;
  }

  void monero_daemon_rpc::start_mining(const std::string &address, boost::optional<uint64_t> num_threads, boost::optional<bool> background_mining, boost::optional<bool> ignore_battery) {
    MTRACE("monero_daemon_rpc::start_mining()");
    if (address.empty()) throw monero_error("Must provide address to mine to");
    if (num_threads != boost::none && num_threads.get() == 0) throw monero_error("Number of threads must be an integer greater than 0");
    auto params = std::make_shared<monero_start_mining_params>(address, num_threads, background_mining, ignore_battery);
    auto result = m_rpc->send_path_request("start_mining", params);
    check_response_status(result);
  }

  void monero_daemon_rpc::stop_mining() {
    MTRACE("monero_daemon_rpc::stop_mining()");
    auto result = m_rpc->send_path_request("stop_mining");
    check_response_status(result);
  }

  std::shared_ptr<monero_mining_status> monero_daemon_rpc::get_mining_status() {
    MTRACE("monero_daemon_rpc::get_mining_status()");
    auto result = m_rpc->send_path_request("mining_status");
    check_response_status(result);
    auto status = std::make_shared<monero_mining_status>();
    deserialize_mining_status(result, status);
    return status;
  }

  std::shared_ptr<monero_generate_blocks_result> monero_daemon_rpc::generate_blocks(const std::string& wallet_address, uint64_t num_blocks, const boost::optional<std::string>& prev_block_hash, const boost::optional<uint32_t>& starting_nonce) {
    MTRACE("monero_daemon_rpc::generate_blocks()");
    if (wallet_address.empty()) throw monero_error("Must provide an address to mine to");
    if (num_blocks == 0) throw monero_error("Must provide a number of blocks to generate greater than 0");
    auto params = std::make_shared<monero_generate_blocks_params>(wallet_address, num_blocks, prev_block_hash, starting_nonce);
    auto result = m_rpc->send_json_request("generateblocks", params);
    check_response_status(result);
    auto generate_result = std::make_shared<monero_generate_blocks_result>();
    deserialize_generate_blocks_result(result, generate_result);
    return generate_result;
  }

  void monero_daemon_rpc::submit_blocks(const std::vector<std::string>& block_blobs) {
    MTRACE("monero_daemon_rpc::submit_blocks()");
    if (block_blobs.empty()) throw monero_error("Must provide an array of mined block blobs to submit");
    auto params = std::make_shared<monero_submit_blocks_params>(block_blobs);
    auto result = m_rpc->send_json_request("submit_block", params);
    check_response_status(result);
  }

  std::shared_ptr<monero_prune_result> monero_daemon_rpc::prune_blockchain(bool check) {
    MTRACE("monero_daemon_rpc::prune_blockchain()");
    auto params = std::make_shared<monero_prune_blockchain_params>(check);
    auto result = m_rpc->send_json_request("prune_blockchain", params);
    check_response_status(result);
    std::shared_ptr<monero_prune_result> prune_result = std::make_shared<monero_prune_result>();
    deserialize_prune_result(result, prune_result);
    return prune_result;
  }

  void monero_daemon_rpc::save_blockchain() {
    MTRACE("monero_daemon_rpc::save_blockchain()");
    auto result = m_rpc->send_path_request("save_bc");
    check_response_status(result);
  }

  uint64_t monero_daemon_rpc::pop_blocks(uint64_t num_blocks) {
    MTRACE("monero_daemon_rpc::pop_blocks()");
    if (num_blocks == 0) throw monero_error("Must provide a number of blocks to pop greater than 0");
    auto params = std::make_shared<monero_pop_blocks_params>(num_blocks);
    auto result = m_rpc->send_path_request("pop_blocks", params);
    check_response_status(result);
    for (boost::property_tree::ptree::const_iterator it = result.begin(); it != result.end(); ++it) {
      if (it->first == std::string("height")) return it->second.get_value<uint64_t>();
    }
    throw monero_error("Could not get height after popping blocks");
  }

  void monero_daemon_rpc::flush_cache(bool bad_blocks) {
    MTRACE("monero_daemon_rpc::flush_cache()");
    auto params = std::make_shared<monero_flush_cache_params>(bad_blocks);
    auto result = m_rpc->send_json_request("flush_cache", params);
    check_response_status(result);
  }

  void monero_daemon_rpc::set_bootstrap_daemon(const std::string& address, const std::string& username, const std::string& password, const std::string& proxy) {
    MTRACE("monero_daemon_rpc::set_bootstrap_daemon()");
    auto params = std::make_shared<monero_set_bootstrap_daemon_params>(address, username, password, proxy);
    auto result = m_rpc->send_path_request("set_bootstrap_daemon", params);
    check_response_status(result);
  }

  void monero_daemon_rpc::set_log_hash_rate(bool is_visible) {
    MTRACE("monero_daemon_rpc::set_log_hash_rate()");
    auto params = std::make_shared<monero_set_log_hash_rate_params>(is_visible);
    auto result = m_rpc->send_path_request("set_log_hash_rate", params);
    check_response_status(result);
  }

  void monero_daemon_rpc::set_log_level(int level) {
    MTRACE("monero_daemon_rpc::set_log_level()");
    if (level < 0 || level > 4) throw monero_error("Log level must be an integer between 0 and 4");
    auto params = std::make_shared<monero_set_log_level_params>(level);
    auto result = m_rpc->send_path_request("set_log_level", params);
    check_response_status(result);
  }

  std::string monero_daemon_rpc::set_log_categories(const std::string& categories) {
    MTRACE("monero_daemon_rpc::set_log_categories()");
    auto params = std::make_shared<monero_set_log_categories_params>(categories);
    auto result = m_rpc->send_path_request("set_log_categories", params);
    check_response_status(result);
    for (boost::property_tree::ptree::const_iterator it = result.begin(); it != result.end(); ++it) {
      if (it->first == std::string("categories")) return it->second.data();
    }
    return std::string();
  }

  std::shared_ptr<monero_daemon_update_check_result> monero_daemon_rpc::check_for_update() {
    MTRACE("monero_daemon_rpc::check_for_update()");
    auto params = std::make_shared<monero_download_update_params>("check");
    auto result = m_rpc->send_path_request("update", params);
    check_response_status(result);
    auto check_result = std::make_shared<monero_daemon_update_check_result>();
    deserialize_update_check_result(result, check_result);
    return check_result;
  }

  std::shared_ptr<monero_daemon_update_download_result> monero_daemon_rpc::download_update(const std::string& path) {
    MTRACE("monero_daemon_rpc::download_update()");
    auto params = std::make_shared<monero_download_update_params>("download", path);
    auto result = m_rpc->send_path_request("update", params);
    check_response_status(result);
    auto download_result = std::make_shared<monero_daemon_update_download_result>();
    deserialize_update_download_result(result, download_result);
    return download_result;
  }

  void monero_daemon_rpc::stop() {
    MTRACE("monero_daemon_rpc::stop()");
    auto result = m_rpc->send_path_request("stop_daemon");
    check_response_status(result);
  }

  std::shared_ptr<monero_block_header> monero_daemon_rpc::wait_for_next_block_header() {
    MTRACE("monero_daemon_rpc::wait_for_next_block_header()");

    // use mutex and condition variable with predicate to wait for block
    boost::mutex temp;
    boost::condition_variable cv;
    bool ready = false;

    // create listener which notifies condition variable when block is added
    block_notifier block_listener(&temp, &cv, &ready);

    // register the listener, and unregister it unconditionally on the way out
    // otherwise m_listeners keeps a pointer into this stack
    // frame after it's gone, and the next block dispatch calls through it (UAF)
    struct listener_guard {
      monero_daemon_rpc* daemon;
      monero_daemon_listener& listener;
      ~listener_guard() {
        // never let remove_listener() escape a destructor since if we're
        // already unwinding from another exception, that would call std::terminate
        try { daemon->remove_listener(listener); } catch (...) {}
      }
    } unregister_guard{this, block_listener};

    add_listener(block_listener);

    // guard against an offline/unresponsive daemon (no connection, stalled node, etc.):
    // such a daemon will never announce a new block, so bound the wait instead of hanging
    // this call forever.
    // TODO monero-java waits indefinitely.
    bool timed_out;
    std::shared_ptr<monero_block_header> header;
    {
      boost::mutex::scoped_lock lock(temp);
      cv.timed_wait(lock, boost::posix_time::minutes(30), [&]() { return ready; });
      // check ready directly rather than trust timed_wait's return value, still under the
      // lock: avoids any discrepancy if a header arrives right at the timeout boundary
      timed_out = !ready;
      // copy out while still holding the lock: block_listener stays registered until the
      // unregister_guard destructor runs (at function exit, after this point), so
      // on_block_header() could still write m_last_header under temp concurrently with an
      // unlocked read here
      if (!timed_out) header = block_listener.m_last_header;
    }

    if (timed_out) throw monero_error("Timed out waiting for next block header");

    // return last height
    if (header == nullptr) throw monero_error("Could not get last block header.");
    return header;
  }

  std::shared_ptr<monero_bandwidth_limits> monero_daemon_rpc::get_bandwidth_limits() {
    MTRACE("monero_daemon_rpc::get_bandwidth_limits()");
    auto result = m_rpc->send_path_request("get_limit");
    check_response_status(result);
    auto limits = std::make_shared<monero_bandwidth_limits>();
    monero_bandwidth_limits::from_property_tree(result, limits);
    return limits;
  }

  std::shared_ptr<monero_bandwidth_limits> monero_daemon_rpc::set_bandwidth_limits(int up, int down) {
    MTRACE("monero_daemon_rpc::set_bandwidth_limits()");
    auto limits = std::make_shared<monero_bandwidth_limits>(up, down);
    auto result = m_rpc->send_path_request("set_limit", limits);
    check_response_status(result);
    monero_bandwidth_limits::from_property_tree(result, limits);
    return limits;
  }

  void monero_daemon_rpc::refresh_listening() {
    boost::lock_guard<boost::mutex> poller_lock(m_poller_mutex);

    bool should_poll;
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_listeners_mutex);
      should_poll = m_listeners.size() > 0;
    }

    if (!m_poller && should_poll) {
      m_poller = std::make_unique<monero_daemon_poller>(this);
    }
    if (m_poller) m_poller->request_is_polling(should_poll);
  }

  monero_daemon_rpc::~monero_daemon_rpc() {
    MTRACE("~monero_daemon_rpc()");
    remove_listeners();
  }
}