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

#include "common/monero_rpc_connection.h"

/**
 * Internal data model for monero_daemon_rpc.h.
 */
namespace monero {

  /**
   * Models a Monero RPC banhammer.
   */
  struct monero_rpc_ban : public monero_ban {
    monero_rpc_ban(const std::shared_ptr<monero_ban> &ban);

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  // ------------------------------ Binary Request ---------------------------------

  /**
   * Models paramaters for monerod-rpc `/get_blocks_by_height.bin` method.
   */
  struct monero_get_blocks_by_height_request : public monero_rpc_request {
    std::vector<uint64_t> m_heights;

    monero_get_blocks_by_height_request(uint64_t num_blocks);
    monero_get_blocks_by_height_request(const std::vector<uint64_t>& heights): m_heights(heights) { m_method = "get_blocks_by_height.bin"; }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models paramaters for monerod-rpc `/get_o_indexes.bin` method.
   */
  struct monero_get_output_indices_request : public monero_rpc_request {
    std::string m_tx_hash;

    monero_get_output_indices_request(const std::string& tx_hash): m_tx_hash(tx_hash) { m_method = "get_o_indexes.bin"; }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models paramaters for monerod-rpc `/get_outs.bin` method.
   */
  struct monero_get_outputs_request : public monero_rpc_request {
    std::vector<monero_output> m_outputs;
    bool m_get_txid;

    monero_get_outputs_request(const std::vector<monero_output>& outputs, bool get_txid = true): m_outputs(outputs), m_get_txid(get_txid) { m_method = "get_outs.bin"; }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  // ------------------------------ RPC Params ---------------------------------

  struct monero_download_update_params : public serializable_struct {
    boost::optional<std::string> m_command;
    boost::optional<std::string> m_path;

    monero_download_update_params(const std::string& command = "download", const std::string& path = "");

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_submit_tx_params : public serializable_struct {
    boost::optional<std::string> m_tx_hex;
    boost::optional<bool> m_do_not_relay;
    std::vector<std::string> m_tx_hashes;

    monero_submit_tx_params(const std::vector<std::string>& tx_hashes): m_tx_hashes(tx_hashes) { }
    monero_submit_tx_params(const std::string& tx_hex, bool do_not_relay): m_tx_hex(tx_hex), m_do_not_relay(do_not_relay) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_peer_limits_params : public serializable_struct {
    boost::optional<int> m_in_peers;
    boost::optional<int> m_out_peers;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_public_nodes_params : public serializable_struct {
    boost::optional<bool> m_gray;

    monero_get_public_nodes_params(bool include_gray): m_gray(include_gray) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_txs_params : public serializable_struct {
    std::vector<std::string> m_tx_hashes;
    boost::optional<bool> m_decode_as_json;
    boost::optional<bool> m_prune;

    monero_get_txs_params(const std::vector<std::string> &tx_hashes, bool prune, bool decode_as_json = true): m_tx_hashes(tx_hashes), m_prune(prune), m_decode_as_json(decode_as_json) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_is_key_image_spent_params : public serializable_struct {
    std::vector<std::string> m_key_images;

    monero_is_key_image_spent_params(const std::vector<std::string>& key_images): m_key_images(key_images) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_set_bootstrap_daemon_params : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_username;
    boost::optional<std::string> m_password;
    boost::optional<std::string> m_proxy;

    monero_set_bootstrap_daemon_params(const std::string& address, const std::string& username = "", const std::string& password = "", const std::string& proxy = ""): m_address(address), m_username(username), m_password(password), m_proxy(proxy) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_pop_blocks_params : public serializable_struct {
    boost::optional<uint64_t> m_nblocks;

    monero_pop_blocks_params(uint64_t num_blocks): m_nblocks(num_blocks) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_set_log_hash_rate_params : public serializable_struct {
    boost::optional<bool> m_visible;

    monero_set_log_hash_rate_params(bool visible): m_visible(visible) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_set_log_level_params : public serializable_struct {
    boost::optional<int> m_level;

    monero_set_log_level_params(int level): m_level(level) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_set_log_categories_params : public serializable_struct {
    boost::optional<std::string> m_categories;

    monero_set_log_categories_params(const std::string& categories = ""): m_categories(categories) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  // ------------------------------ JSON-RPC Params ---------------------------------

  struct monero_start_mining_params : public serializable_struct {
    boost::optional<std::string> m_miner_address;
    boost::optional<uint64_t> m_num_threads;
    boost::optional<bool> m_is_background;
    boost::optional<bool> m_ignore_battery;

    monero_start_mining_params(const boost::optional<std::string>& address, const boost::optional<uint64_t>& num_threads, const boost::optional<bool>& is_background, const boost::optional<bool>& ignore_battery): m_miner_address(address), m_num_threads(num_threads), m_is_background(is_background), m_ignore_battery(ignore_battery) { }
    monero_start_mining_params(const boost::optional<uint64_t>& num_threads, const boost::optional<bool>& is_background, const boost::optional<bool>& ignore_battery): m_num_threads(num_threads), m_is_background(is_background), m_ignore_battery(ignore_battery) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_generate_blocks_params : public serializable_struct {
    boost::optional<std::string> m_wallet_address;
    boost::optional<uint64_t> m_num_blocks;
    boost::optional<std::string> m_prev_block_hash;
    boost::optional<uint32_t> m_starting_nonce;

    monero_generate_blocks_params(const std::string& wallet_address, uint64_t num_blocks, const boost::optional<std::string>& prev_block_hash, const boost::optional<uint32_t>& starting_nonce): m_wallet_address(wallet_address), m_num_blocks(num_blocks), m_prev_block_hash(prev_block_hash), m_starting_nonce(starting_nonce) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_prune_blockchain_params : public serializable_struct {
    boost::optional<bool> m_check;

    monero_prune_blockchain_params(bool check = true): m_check(check) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_flush_cache_params : public serializable_struct {
    boost::optional<bool> m_bad_blocks;

    monero_flush_cache_params(bool bad_blocks = false): m_bad_blocks(bad_blocks) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_calculate_pow_params : public serializable_struct {
    boost::optional<uint32_t> m_major_version;
    boost::optional<uint64_t> m_height;
    boost::optional<std::string> m_block_blob;
    boost::optional<std::string> m_seed_hash;

    monero_calculate_pow_params(uint32_t major_version, uint64_t height, const std::string& block_blob, const std::string& seed_hash): m_major_version(major_version), m_height(height), m_block_blob(block_blob), m_seed_hash(seed_hash) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_add_aux_pow_params : public serializable_struct {
    boost::optional<std::string> m_blocktemplate_blob;
    std::vector<std::shared_ptr<monero_auxiliary_pow>> m_aux_pow;

    monero_add_aux_pow_params(const std::string& blocktemplate_blob, const std::vector<std::shared_ptr<monero_auxiliary_pow>>& aux_pow): m_blocktemplate_blob(blocktemplate_blob), m_aux_pow(aux_pow) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_banned_params : public serializable_struct {
    boost::optional<std::string> m_address;

    monero_banned_params(const std::string& address): m_address(address) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_submit_blocks_params : public serializable_struct {
    std::vector<std::string> m_block_blobs;

    monero_submit_blocks_params(const std::vector<std::string>& block_blobs): m_block_blobs(block_blobs) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_block_params : public serializable_struct {
    boost::optional<uint64_t> m_height;
    boost::optional<std::string> m_hash;
    boost::optional<bool> m_fill_pow_hash;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_end_height;
    boost::optional<std::string> m_wallet_address;
    boost::optional<int> m_reserve_size;

    monero_get_block_params(uint64_t height, bool fill_pow_hash = false): m_height(height), m_fill_pow_hash(fill_pow_hash) { }
    monero_get_block_params(const std::string& hash, bool fill_pow_hash = false): m_hash(hash), m_fill_pow_hash(fill_pow_hash) { }
    monero_get_block_params(uint64_t start_height, uint64_t end_height): m_start_height(start_height), m_end_height(end_height) { }
    monero_get_block_params(const std::string& wallet_address, const boost::optional<int>& reserve_size): m_wallet_address(wallet_address), m_reserve_size(reserve_size) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_block_hash_params : public serializable_struct {
    boost::optional<uint64_t> m_height;

    monero_get_block_hash_params(uint64_t height): m_height(height) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_miner_tx_sum_params : public serializable_struct {
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_count;

    monero_get_miner_tx_sum_params(uint64_t height, uint64_t count): m_height(height), m_count(count) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_fee_estimate_params : public serializable_struct {
    boost::optional<uint64_t> m_grace_blocks;

    monero_get_fee_estimate_params(uint64_t grace_blocks = 0): m_grace_blocks(grace_blocks) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_set_bans_params : public serializable_struct {
    std::vector<std::shared_ptr<monero_rpc_ban>> m_bans;

    monero_set_bans_params(const std::vector<std::shared_ptr<monero_ban>>& bans);

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_output_histogram_params : public serializable_struct {
    std::vector<uint64_t> m_amounts;
    boost::optional<int> m_min_count;
    boost::optional<int> m_max_count;
    boost::optional<bool> m_is_unlocked;
    boost::optional<int> m_recent_cutoff;

    monero_get_output_histogram_params(const std::vector<uint64_t>& amounts, const boost::optional<int>& min_count, const boost::optional<int>& max_count, const boost::optional<bool>& is_unlocked, const boost::optional<int>& recent_cutoff) : m_amounts(amounts), m_min_count(min_count), m_max_count(max_count), m_is_unlocked(is_unlocked), m_recent_cutoff(recent_cutoff) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_get_output_distribution_params : public serializable_struct {
    std::vector<uint64_t> m_amounts;
    boost::optional<bool> m_cumulative;
    boost::optional<bool> m_binary;
    boost::optional<uint64_t> m_from_height;
    boost::optional<uint64_t> m_to_height;

    monero_get_output_distribution_params(const std::vector<uint64_t>& amounts, const boost::optional<bool>& cumulative, const boost::optional<uint64_t>& from_height, const boost::optional<uint64_t>& to_height) : m_amounts(amounts), m_cumulative(cumulative), m_from_height(from_height), m_to_height(to_height), m_binary(false) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  // ------------------------------ JSON-RPC Response ---------------------------------

  struct monero_get_block_result {
    boost::optional<uint64_t> m_count;
    boost::optional<uint64_t> m_height;
    boost::optional<bool> m_untrusted;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_block_result>& result);
  };

  // ------------------------------ RPC Deserialization ---------------------------------

  void deserialize_version(const boost::property_tree::ptree& node, monero_version& version);
  void deserialize_block_header(const boost::property_tree::ptree& node, const std::shared_ptr<monero_block_header>& header);
  void deserialize_block_headers(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_block_header>>& headers);
  void deserialize_block(const boost::property_tree::ptree& node, const std::shared_ptr<monero_block>& block, bool is_nested = false);
  void deserialize_blocks(const boost::property_tree::ptree& node, const std::vector<uint64_t>& heights, std::vector<std::shared_ptr<monero_block>>& blocks);
  void deserialize_alt_block_hashes(const boost::property_tree::ptree& node, std::vector<std::string>& block_hashes);
  void deserialize_txs(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_tx>>& txs);
  void deserialize_tx_hashes(const boost::property_tree::ptree& node, std::vector<std::string>& tx_hashes);
  void deserialize_key_image_spent_status(const boost::property_tree::ptree& node, std::vector<monero_key_image_spent_status>& statuses);
  void deserialize_alt_chains(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_alt_chain>>& alt_chains);
  void deserialize_bans(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_ban>>& bans);
  void deserialize_prune_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_prune_result>& result);
  void deserialize_mining_status(const boost::property_tree::ptree& node, const std::shared_ptr<monero_mining_status>& status);
  void deserialize_generate_blocks_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_generate_blocks_result>& result);
  void deserialize_output_indices(const std::string& bin, std::vector<uint64_t>& indices);
  void deserialize_outputs(const std::string& bin, const std::vector<monero_output>& requested_outputs, std::vector<std::shared_ptr<monero_output>>& outputs);
  void deserialize_miner_tx_sum(const boost::property_tree::ptree& node, const std::shared_ptr<monero_miner_tx_sum>& sum);
  void deserialize_block_template(const boost::property_tree::ptree& node, const std::shared_ptr<monero_block_template>& tmplt);
  void deserialize_miner_data(const boost::property_tree::ptree& node, const std::shared_ptr<monero_miner_data>& data);
  void deserialize_add_auxiliary_pow_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_add_auxiliary_pow_result>& result);
  void deserialize_peers(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_peer>>& peers);
  void deserialize_public_peers(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_peer>>& peers);
  void deserialize_submit_tx_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_submit_tx_result>& result);
  void deserialize_output_distribution_entries(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_output_distribution_entry>>& entries);
  void deserialize_output_histogram_entries(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_output_histogram_entry>>& entries);
  void deserialize_tx_pool_stats(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_pool_stats>& stats);
  void deserialize_update_check_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_check_result>& check);
  void deserialize_update_download_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_download_result>& check);
  void deserialize_fee_estimate(const boost::property_tree::ptree& node, const std::shared_ptr<monero_fee_estimate>& estimate);
  void deserialize_daemon_info(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_info>& info);
  void deserialize_daemon_sync_info(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_sync_info>& info);
  void deserialize_network_stats(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_network_stats>& stats);
  void deserialize_hard_fork_info(const boost::property_tree::ptree& node, const std::shared_ptr<monero_hard_fork_info>& info);
  std::string normalize_daemon_rpc_status(const std::string& status);

}