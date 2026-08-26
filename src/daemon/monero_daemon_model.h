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

#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

/**
 * Public interface for libmonero-cpp library.
 */
namespace monero {

  /**
   * Base struct which can be serialized.
   */
  struct serializable_struct {

    virtual ~serializable_struct() = default;

    /**
     * Serializes the struct to a json std::string.
     *
     * @return the struct serialized to a json std::string
     */
    std::string serialize() const;

    /**
     * Converts the struct to a rapidjson Value.
     *
     * @param allocator is the rapidjson document allocator
     * @return the struct as a rapidjson Value
     */
    virtual rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const = 0;
  };

  /**
   * Models connection ssl options.
   */
  struct ssl_options : public serializable_struct {
    boost::optional<std::string> m_ssl_private_key_path;
    boost::optional<std::string> m_ssl_certificate_path;
    boost::optional<std::string> m_ssl_ca_file;
    std::vector<std::string> m_ssl_allowed_fingerprints;
    boost::optional<bool> m_ssl_allow_any_cert;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Enumerates Monero connection types.
   */
  enum monero_connection_type : uint8_t {
    INVALID = 0,
    IPV4,
    IPV6,
    TOR,
    I2P
  };

  /**
   * Enumerates Monero network types.
   */
  enum monero_network_type : uint8_t {
    MAINNET = 0,
    TESTNET,
    STAGENET
  };

  /**
   * Models connection bandwidth limits.
   */
  struct monero_bandwidth_limits : public serializable_struct {
    boost::optional<int> m_up;
    boost::optional<int> m_down;

    monero_bandwidth_limits() { }
    monero_bandwidth_limits(int up, int down): m_up(up), m_down(down) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_bandwidth_limits>& limits);
  };

  /**
   * Models a Monero version.
   */
  struct monero_version : public serializable_struct {
    boost::optional<uint32_t> m_number;
    boost::optional<bool> m_is_release;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_version>& version);
  };

  // forward declarations
  struct monero_tx;
  struct monero_output;

  /**
   * Models a Monero block header which contains information about the block.
   *
   * TODO: a header that is transmitted may have fewer fields like cryptonote::block_header; separate?
   */
  struct monero_block_header : public serializable_struct {
    boost::optional<std::string> m_hash;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_timestamp;
    boost::optional<uint64_t> m_size;
    boost::optional<uint64_t> m_weight;
    boost::optional<uint64_t> m_long_term_weight;
    boost::optional<uint64_t> m_depth;
    boost::optional<uint64_t> m_difficulty_low;
    boost::optional<uint64_t> m_difficulty_high;
    boost::optional<uint64_t> m_cumulative_difficulty_low;
    boost::optional<uint64_t> m_cumulative_difficulty_high;
    boost::optional<uint32_t> m_major_version;
    boost::optional<uint32_t> m_minor_version;
    boost::optional<uint32_t> m_nonce;
    boost::optional<std::string> m_miner_tx_hash;
    boost::optional<uint32_t> m_num_txs;
    boost::optional<bool> m_orphan_status;
    boost::optional<std::string> m_prev_hash;
    boost::optional<uint64_t> m_reward;
    boost::optional<std::string> m_pow_hash;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<monero_block_header> copy(const std::shared_ptr<monero_block_header>& src, const std::shared_ptr<monero_block_header>& tgt) const;
    virtual void merge(const std::shared_ptr<monero_block_header>& self, const std::shared_ptr<monero_block_header>& other);
  };

  /**
   * Models a Monero block in the blockchain.
   */
  struct monero_block : public monero_block_header {
    boost::optional<std::string> m_hex;
    std::shared_ptr<monero_tx> m_miner_tx;
    std::vector<std::shared_ptr<monero_tx>> m_txs;
    std::vector<std::string> m_tx_hashes;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<monero_block> copy(const std::shared_ptr<monero_block>& src, const std::shared_ptr<monero_block>& tgt) const;
    void merge(const std::shared_ptr<monero_block_header>& self, const std::shared_ptr<monero_block_header>& other);
    void merge(const std::shared_ptr<monero_block>& self, const std::shared_ptr<monero_block>& other);
  };

  /**
   * Models a Monero transaction on the blockchain.
   */
  struct monero_tx : public serializable_struct {
    static const std::string DEFAULT_PAYMENT_ID;  // default payment id "0000000000000000"
    static const std::string DEFAULT_ID;

    std::shared_ptr<monero_block> m_block;
    boost::optional<std::string> m_hash;
    boost::optional<uint32_t> m_version;
    boost::optional<bool> m_is_miner_tx;
    boost::optional<std::string> m_payment_id;
    boost::optional<uint64_t> m_fee;
    boost::optional<uint32_t> m_ring_size;
    boost::optional<bool> m_relay;
    boost::optional<bool> m_is_relayed;
    boost::optional<bool> m_is_confirmed;
    boost::optional<bool> m_in_tx_pool;
    boost::optional<bool> m_is_locked;
    boost::optional<uint64_t> m_num_confirmations;
    boost::optional<uint64_t> m_unlock_time;
    boost::optional<uint64_t> m_last_relayed_timestamp;
    boost::optional<uint64_t> m_received_timestamp;
    boost::optional<bool> m_is_double_spend_seen;
    boost::optional<std::string> m_key;
    boost::optional<std::string> m_full_hex;
    boost::optional<std::string> m_pruned_hex;
    boost::optional<std::string> m_prunable_hex;
    boost::optional<std::string> m_prunable_hash;
    boost::optional<uint64_t> m_size;
    boost::optional<uint64_t> m_weight;
    std::vector<std::shared_ptr<monero_output>> m_inputs;
    std::vector<std::shared_ptr<monero_output>> m_outputs;
    std::vector<uint64_t> m_output_indices;
    boost::optional<std::string> m_metadata;
    boost::optional<std::string> m_common_tx_sets;
    std::vector<uint8_t> m_extra;
    boost::optional<std::string> m_rct_signatures;   // TODO: implement
    boost::optional<std::string> m_rct_sig_prunable;  // TODO: implement
    boost::optional<bool> m_is_kept_by_block;
    boost::optional<bool> m_is_failed;
    boost::optional<uint64_t> m_last_failed_height;
    boost::optional<std::string> m_last_failed_hash;
    boost::optional<uint64_t> m_max_used_block_height;
    boost::optional<std::string> m_max_used_block_hash;
    std::vector<std::string> m_signatures;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, std::shared_ptr<monero_tx> tx);
    std::shared_ptr<monero_tx> copy(const std::shared_ptr<monero_tx>& src, const std::shared_ptr<monero_tx>& tgt) const;
    virtual void merge(const std::shared_ptr<monero_tx>& self, const std::shared_ptr<monero_tx>& other);
    boost::optional<uint64_t> get_height() const;
  };

  /**
   * Models a Monero key image.
   */
  struct monero_key_image : public serializable_struct {
    boost::optional<std::string> m_hex;
    boost::optional<std::string> m_signature;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_key_image>& key_image);
    static std::vector<std::shared_ptr<monero_key_image>> deserialize_key_images(const std::string& key_images_json);  // TODO: remove this specialty util used once
    std::shared_ptr<monero_key_image> copy(const std::shared_ptr<monero_key_image>& src, const std::shared_ptr<monero_key_image>& tgt) const;
    void merge(const std::shared_ptr<monero_key_image>& self, const std::shared_ptr<monero_key_image>& other);
  };

  /**
   * Models a Monero transaction output.
   */
  struct monero_output : public serializable_struct {
    std::shared_ptr<monero_tx> m_tx;
    std::shared_ptr<monero_key_image> m_key_image;
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_index;
    std::vector<uint64_t> m_ring_output_indices;
    boost::optional<std::string> m_stealth_public_key;
    boost::optional<std::string> m_mask;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output>& output);
    std::shared_ptr<monero_output> copy(const std::shared_ptr<monero_output>& src, const std::shared_ptr<monero_output>& tgt) const;
    virtual void merge(const std::shared_ptr<monero_output>& self, const std::shared_ptr<monero_output>& other);
  };

  /**
   * Models the status of a Monero key image.
   */
  enum monero_key_image_spent_status : uint8_t {
    NOT_SPENT = 0,
    CONFIRMED,
    TX_POOL
  };

  /**
   * Models a Monero RPC payment information.
   */
  struct monero_rpc_payment_info : public serializable_struct {
    boost::optional<uint64_t> m_credits;
    boost::optional<std::string> m_top_block_hash;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_rpc_payment_info>& rpc_payment_info);
  };

  /**
   * Models an alternative chain seen by the node.
   */
  struct monero_alt_chain : public serializable_struct {
    std::vector<std::string> m_block_hashes;
    boost::optional<uint64_t> m_difficulty_low;
    boost::optional<uint64_t> m_difficulty_high;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_length;
    boost::optional<std::string> m_main_chain_parent_block_hash;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_alt_chain>& alt_chain);
  };

  /**
   * Monero banhammer.
   */
  struct monero_ban : public serializable_struct {
    boost::optional<std::string> m_host;
    boost::optional<uint32_t> m_ip;
    boost::optional<bool> m_is_banned;
    boost::optional<uint64_t> m_seconds;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_ban>& ban);
  };

  /**
   * Result of pruning the blockchain.
   */
  struct monero_prune_result : public serializable_struct {
    boost::optional<bool> m_is_pruned;
    boost::optional<int> m_pruning_seed;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_prune_result>& result);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Monero daemon mining status.
   */
  struct monero_mining_status : public serializable_struct {
    boost::optional<bool> m_is_active;
    boost::optional<bool> m_is_background;
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_speed;
    boost::optional<int> m_num_threads;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_mining_status>& status);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Model for the summation of miner emissions and fees.
   */
  struct monero_miner_tx_sum : public serializable_struct {
    boost::optional<uint64_t> m_emission_sum_low;
    boost::optional<uint64_t> m_emission_sum_high;
    boost::optional<uint64_t> m_fee_sum_low;
    boost::optional<uint64_t> m_fee_sum_high;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_miner_tx_sum>& sum);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Monero block template to mine.
   */
  struct monero_block_template : public serializable_struct {
    boost::optional<std::string> m_block_template_blob;
    boost::optional<std::string> m_block_hashing_blob;
    boost::optional<std::string> m_prev_hash;
    boost::optional<std::string> m_seed_hash;
    boost::optional<std::string> m_next_seed_hash;
    boost::optional<uint64_t> m_difficulty_low;
    boost::optional<uint64_t> m_difficulty_high;
    boost::optional<uint64_t> m_expected_reward;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_reserved_offset;
    boost::optional<uint64_t> m_seed_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_block_template>& tmplt);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Data needed to construct a block template for mining, e.g. for a pool that
   * assembles its own block templates.
   */
  struct monero_miner_data : public monero_rpc_payment_info {
    boost::optional<uint32_t> m_major_version;
    boost::optional<uint64_t> m_height;
    boost::optional<std::string> m_prev_hash;
    boost::optional<std::string> m_seed_hash;
    boost::optional<std::string> m_difficulty;
    boost::optional<uint64_t> m_median_weight;
    boost::optional<uint64_t> m_already_generated_coins;
    std::vector<std::shared_ptr<monero_tx>> m_tx_pool_backlog;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_miner_data>& data);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Identifies an auxiliary chain's block by id and proof-of-work hash for merge mining.
   */
  struct monero_auxiliary_pow : public serializable_struct {
    boost::optional<std::string> m_id;
    boost::optional<std::string> m_hash;

    monero_auxiliary_pow() { }
    monero_auxiliary_pow(const std::string& id, const std::string& hash): m_id(id), m_hash(hash) { }

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_auxiliary_pow>& aux_pow);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Result of adding auxiliary proof-of-work to a block template for merge mining.
   */
  struct monero_add_auxiliary_pow_result : public monero_rpc_payment_info {
    boost::optional<std::string> m_block_template_blob;
    boost::optional<std::string> m_block_hashing_blob;
    boost::optional<std::string> m_merkle_root;
    boost::optional<uint32_t> m_merkle_tree_depth;
    std::vector<std::shared_ptr<monero_auxiliary_pow>> m_aux_pow;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_add_auxiliary_pow_result>& result);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Monero daemon connection span.
   */
  struct monero_connection_span : public serializable_struct {
    boost::optional<std::string> m_connection_id;
    boost::optional<std::string> m_remote_address;
    boost::optional<uint64_t> m_num_blocks;
    boost::optional<uint64_t> m_rate;
    boost::optional<uint64_t> m_speed;
    boost::optional<uint64_t> m_size;
    boost::optional<uint64_t> m_start_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_connection_span>& span);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models a peer to the daemon.
   */
  struct monero_peer : public serializable_struct {
    boost::optional<std::string> m_id;
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_host;
    boost::optional<int> m_port;
    boost::optional<bool> m_is_online;
    boost::optional<uint64_t> m_last_seen_timestamp;
    boost::optional<int> m_pruning_seed;
    boost::optional<int> m_rpc_port;
    boost::optional<uint64_t> m_rpc_credits_per_hash;
    boost::optional<std::string> m_hash;
    boost::optional<uint64_t> m_avg_download;
    boost::optional<uint64_t> m_avg_upload;
    boost::optional<uint64_t> m_current_download;
    boost::optional<uint64_t> m_current_upload;
    boost::optional<uint64_t> m_height;
    boost::optional<bool> m_is_incoming;
    boost::optional<uint64_t> m_live_time;
    boost::optional<bool> m_is_local_ip;
    boost::optional<bool> m_is_local_host;
    boost::optional<uint64_t> m_num_receives;
    boost::optional<uint64_t> m_num_sends;
    boost::optional<uint64_t> m_receive_idle_time;
    boost::optional<uint64_t> m_send_idle_time;
    boost::optional<std::string> m_state;
    boost::optional<int> m_num_support_flags;
    boost::optional<monero_connection_type> m_connection_type;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_peer>& peer);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models the result from submitting a tx to a daemon.
   */
  struct monero_submit_tx_result : public monero_rpc_payment_info {
    boost::optional<bool> m_has_invalid_input;
    boost::optional<bool> m_has_invalid_output;
    boost::optional<bool> m_has_too_few_outputs;
    boost::optional<bool> m_is_good;
    boost::optional<bool> m_is_relayed;
    boost::optional<bool> m_is_double_spend;
    boost::optional<bool> m_is_fee_too_low;
    boost::optional<bool> m_is_mixin_too_low;
    boost::optional<bool> m_is_overspend;
    boost::optional<bool> m_is_too_big;
    boost::optional<bool> m_sanity_check_failed;
    boost::optional<bool> m_is_tx_extra_too_big;
    boost::optional<bool> m_is_nonzero_unlock_time;
    boost::optional<std::string> m_reason;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_submit_tx_result>& result);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * TODO.
   */
  struct monero_tx_backlog_entry {
    // TODO
  };

  /**
   * Monero output distribution entry.
   */
  struct monero_output_distribution_entry : public serializable_struct {
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_base;
    std::vector<uint64_t> m_distribution;
    boost::optional<uint64_t> m_start_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_distribution_entry>& entry);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Entry in a Monero output histogram (see get_output_histogram of Daemon RPC documentation).
   */
  struct monero_output_histogram_entry : public serializable_struct {
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_num_instances;
    boost::optional<uint64_t> m_unlocked_instances;
    boost::optional<uint64_t> m_recent_instances;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_histogram_entry>& entry);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models transaction pool statistics.
   */
  struct monero_tx_pool_stats : public serializable_struct {
    boost::optional<int> m_num_txs;
    boost::optional<int> m_num_not_relayed;
    boost::optional<int> m_num_failing;
    boost::optional<int> m_num_double_spends;
    boost::optional<int> m_num10m;
    boost::optional<uint64_t> m_fee_total;
    boost::optional<uint64_t> m_bytes_max;
    boost::optional<uint64_t> m_bytes_med;
    boost::optional<uint64_t> m_bytes_min;
    boost::optional<uint64_t> m_bytes_total;
    std::map<uint64_t, uint64_t> m_histo;
    boost::optional<uint64_t> m_histo98pc;
    boost::optional<uint64_t> m_oldest_timestamp;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_pool_stats>& stats);
  };

  /**
   * Models the result of checking for a daemon update.
   */
  struct monero_daemon_update_check_result : public serializable_struct {
    boost::optional<bool> m_is_update_available;
    boost::optional<std::string> m_version;
    boost::optional<std::string> m_hash;
    boost::optional<std::string> m_auto_uri;
    boost::optional<std::string> m_user_uri;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_check_result>& check);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models the result of downloading an update.
   */
  struct monero_daemon_update_download_result : public monero_daemon_update_check_result {
    boost::optional<std::string> m_download_path;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_download_result>& check);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models a Monero fee estimate.
   */
  struct monero_fee_estimate : public serializable_struct {
    boost::optional<uint64_t> m_quantization_mask;
    boost::optional<uint64_t> m_fee;
    std::vector<uint64_t> m_fees;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_fee_estimate>& estimate);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Monero daemon info.
   */
  struct monero_daemon_info : public monero_rpc_payment_info {
    boost::optional<std::string> m_version;
    boost::optional<uint64_t> m_num_alt_blocks;
    boost::optional<uint64_t> m_block_size_limit;
    boost::optional<uint64_t> m_block_size_median;
    boost::optional<uint64_t> m_block_weight_limit;
    boost::optional<uint64_t> m_block_weight_median;
    boost::optional<std::string> m_bootstrap_daemon_address;
    boost::optional<uint64_t> m_difficulty_low;
    boost::optional<uint64_t> m_difficulty_high;
    boost::optional<uint64_t> m_cumulative_difficulty_low;
    boost::optional<uint64_t> m_cumulative_difficulty_high;
    boost::optional<uint64_t> m_free_space;
    boost::optional<int> m_num_offline_peers;
    boost::optional<int> m_num_online_peers;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_height_without_bootstrap;
    boost::optional<monero_network_type> m_network_type;
    boost::optional<bool> m_is_offline;
    boost::optional<int> m_num_incoming_connections;
    boost::optional<int> m_num_outgoing_connections;
    boost::optional<int> m_num_rpc_connections;
    boost::optional<uint64_t> m_start_timestamp;
    boost::optional<uint64_t> m_adjusted_timestamp;
    boost::optional<uint64_t> m_target;
    boost::optional<uint64_t> m_target_height;
    boost::optional<int> m_num_txs;
    boost::optional<int> m_num_txs_pool;
    boost::optional<bool> m_was_bootstrap_ever_used;
    boost::optional<uint64_t> m_database_size;
    boost::optional<bool> m_update_available;
    boost::optional<bool> m_is_busy_syncing;
    boost::optional<bool> m_is_synchronized;
    boost::optional<bool> m_is_restricted;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_info>& info);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models daemon synchronization information.
   */
  struct monero_daemon_sync_info : public monero_rpc_payment_info {
    boost::optional<std::string> m_overview;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_target_height;
    boost::optional<int> m_next_needed_pruning_seed;
    std::vector<std::shared_ptr<monero_peer>> m_peers;
    std::vector<std::shared_ptr<monero_connection_span>> m_spans;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_sync_info>& info);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models daemon network (bandwidth) statistics.
   */
  struct monero_daemon_network_stats : public monero_rpc_payment_info {
    boost::optional<uint64_t> m_start_time;
    boost::optional<uint64_t> m_total_packets_in;
    boost::optional<uint64_t> m_total_bytes_in;
    boost::optional<uint64_t> m_total_packets_out;
    boost::optional<uint64_t> m_total_bytes_out;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_network_stats>& stats);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Monero hard fork info.
   */
  struct monero_hard_fork_info : public monero_rpc_payment_info {
    boost::optional<bool> m_is_enabled;
    boost::optional<uint64_t> m_earliest_height;
    boost::optional<int> m_state;
    boost::optional<int> m_threshold;
    boost::optional<int> m_version;
    boost::optional<int> m_num_votes;
    boost::optional<int> m_window;
    boost::optional<int> m_voting;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_hard_fork_info>& info);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models the result of generating blocks.
   */
  struct monero_generate_blocks_result : public serializable_struct {
    std::vector<std::string> m_block_hashes;
    boost::optional<uint64_t> m_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_generate_blocks_result>& result);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

}
