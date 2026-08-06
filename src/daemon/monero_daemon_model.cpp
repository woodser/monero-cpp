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

#include "monero_daemon_model.h"

#include "common/monero_error.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
#include "include_base_utils.h"
#include "common/util.h"

/**
 * Public library interface.
 */
namespace monero {

  // ----------------------- UNDECLARED PRIVATE HELPERS -----------------------

  void merge_tx(std::vector<std::shared_ptr<monero_tx>>& txs, const std::shared_ptr<monero_tx>& tx) {
    for (const std::shared_ptr<monero_tx>& aTx : txs) {
      if (aTx->m_hash.get() == tx->m_hash.get()) {
        aTx->merge(aTx, tx);
        return;
      }
    }
    txs.push_back(tx);
  }

  // ------------------------- INITIALIZE CONSTANTS ---------------------------

  const std::string monero_tx::DEFAULT_PAYMENT_ID = std::string("0000000000000000");

  const std::string monero_tx::DEFAULT_ID = std::string("0000000000000000000000000000000000000000000000000000000000000000");

  // ------------------------- SERIALIZABLE STRUCT ----------------------------

  std::string serializable_struct::serialize() const {
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Value val = to_rapidjson_val(doc.GetAllocator());
    val.Swap(doc);
    return gen_utils::serialize(doc);
  }

  // ----------------------------- MONERO VERSION -----------------------------

  rapidjson::Value monero_version::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_number != boost::none) monero_utils::add_json_member("number", m_number.get(), allocator, root, value_num);

    // set bool values
    if (m_is_release != boost::none) monero_utils::add_json_member("isRelease", m_is_release.get(), allocator, root);

    // return root
    return root;
  }

  void monero_version::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_version>& version) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("number")) version->m_number = it->second.get_value<uint32_t>();
      else if (key == std::string("isRelease")) version->m_is_release = it->second.get_value<bool>();
    }
  }

  // --------------------------- SSL OPTIONS ---------------------------

  rapidjson::Value ssl_options::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_ssl_private_key_path != boost::none) monero_utils::add_json_member("sslPrivateKeyPath", m_ssl_private_key_path.get(), allocator, root, value_str);
    if (m_ssl_certificate_path != boost::none) monero_utils::add_json_member("sslCertificatePath", m_ssl_certificate_path.get(), allocator, root, value_str);
    if (m_ssl_ca_file != boost::none) monero_utils::add_json_member("sslCaFile", m_ssl_ca_file.get(), allocator, root, value_str);
    if (!m_ssl_allowed_fingerprints.empty()) root.AddMember("sslAllowedFingerprints", monero_utils::to_rapidjson_val(allocator, m_ssl_allowed_fingerprints), allocator);

    // set bool values
    if (m_ssl_allow_any_cert != boost::none) monero_utils::add_json_member("sslAllowAnyCert", m_ssl_allow_any_cert.get(), allocator, root);

    return root;
  }

  // ------------------------- MONERO BLOCK HEADER ----------------------------

  rapidjson::Value monero_block_header::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);
    if (m_timestamp != boost::none) monero_utils::add_json_member("timestamp", m_timestamp.get(), allocator, root, value_num);
    if (m_size != boost::none) monero_utils::add_json_member("size", m_size.get(), allocator, root, value_num);
    if (m_weight != boost::none) monero_utils::add_json_member("weight", m_weight.get(), allocator, root, value_num);
    if (m_long_term_weight != boost::none) monero_utils::add_json_member("longTermWeight", m_long_term_weight.get(), allocator, root, value_num);
    if (m_depth != boost::none) monero_utils::add_json_member("depth", m_depth.get(), allocator, root, value_num);
    if (m_difficulty_low != boost::none) monero_utils::add_json_member("difficultyLow", m_difficulty_low.get(), allocator, root, value_num);
    if (m_difficulty_high != boost::none) monero_utils::add_json_member("difficultyHigh", m_difficulty_high.get(), allocator, root, value_num);
    if (m_cumulative_difficulty_low != boost::none) monero_utils::add_json_member("cumulativeDifficultyLow", m_cumulative_difficulty_low.get(), allocator, root, value_num);
    if (m_cumulative_difficulty_high != boost::none) monero_utils::add_json_member("cumulativeDifficultyHigh", m_cumulative_difficulty_high.get(), allocator, root, value_num);
    if (m_major_version != boost::none) monero_utils::add_json_member("majorVersion", m_major_version.get(), allocator, root, value_num);
    if (m_minor_version != boost::none) monero_utils::add_json_member("minorVersion", m_minor_version.get(), allocator, root, value_num);
    if (m_nonce != boost::none) monero_utils::add_json_member("nonce", m_nonce.get(), allocator, root, value_num);
    if (m_miner_tx_hash != boost::none) monero_utils::add_json_member("minerTxHash", m_miner_tx_hash.get(), allocator, root, value_num);
    if (m_num_txs != boost::none) monero_utils::add_json_member("numTxs", m_num_txs.get(), allocator, root, value_num);
    if (m_reward != boost::none) monero_utils::add_json_member("reward", m_reward.get(), allocator, root, value_num);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_hash != boost::none) monero_utils::add_json_member("hash", m_hash.get(), allocator, root, value_str);
    if (m_prev_hash != boost::none) monero_utils::add_json_member("prevHash", m_prev_hash.get(), allocator, root, value_str);
    if (m_pow_hash != boost::none) monero_utils::add_json_member("powHash", m_pow_hash.get(), allocator, root, value_str);

    // set bool values
    if (m_orphan_status != boost::none) monero_utils::add_json_member("orphanStatus", m_orphan_status.get(), allocator, root);

    // return root
    return root;
  }

  std::shared_ptr<monero_block_header> monero_block_header::copy(const std::shared_ptr<monero_block_header>& src, const std::shared_ptr<monero_block_header>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this block header != src");
    tgt->m_hash = src->m_hash;
    tgt->m_height = src->m_height;
    tgt->m_timestamp = src->m_timestamp;
    tgt->m_size = src->m_size;
    tgt->m_weight = src->m_weight;
    tgt->m_long_term_weight = src->m_long_term_weight;
    tgt->m_depth = src->m_depth;
    tgt->m_difficulty_low = src->m_difficulty_low;
    tgt->m_difficulty_high = src->m_difficulty_high;
    tgt->m_cumulative_difficulty_low = src->m_cumulative_difficulty_low;
    tgt->m_cumulative_difficulty_high = src->m_cumulative_difficulty_high;
    tgt->m_major_version = src->m_major_version;
    tgt->m_minor_version = src->m_minor_version;
    tgt->m_nonce = src->m_nonce;
    tgt->m_miner_tx_hash = src->m_miner_tx_hash;
    tgt->m_num_txs = src->m_num_txs;
    tgt->m_orphan_status = src->m_orphan_status;
    tgt->m_prev_hash = src->m_prev_hash;
    tgt->m_reward = src->m_reward;
    tgt->m_pow_hash = src->m_pow_hash;
    tgt->m_hash = src->m_hash;
    return tgt;
  }

  void monero_block_header::merge(const std::shared_ptr<monero_block_header>& self, const std::shared_ptr<monero_block_header>& other) {
    if (this != self.get()) throw std::runtime_error("this != self");
    if (self == other) return;
    m_hash = gen_utils::reconcile(m_hash, other->m_hash, "block header m_hash");
    m_height = gen_utils::reconcile(m_height, other->m_height, boost::none, boost::none, true, "block header m_height"); // height can increase
    m_timestamp = gen_utils::reconcile(m_timestamp, other->m_timestamp, boost::none, boost::none, true, "block header m_timestamp");  // timestamp can increase
    m_size = gen_utils::reconcile(m_size, other->m_size, "block header m_size");
    m_weight = gen_utils::reconcile(m_weight, other->m_weight, "block header m_weight ");
    m_long_term_weight = gen_utils::reconcile(m_long_term_weight, other->m_long_term_weight, "block header m_long_term_weight");
    m_depth = gen_utils::reconcile(m_depth, other->m_depth, "block header m_depth");
    m_difficulty_low = gen_utils::reconcile(m_difficulty_low, other->m_difficulty_low, "block header m_difficulty_low");
    m_difficulty_high = gen_utils::reconcile(m_difficulty_high, other->m_difficulty_high, "block header m_difficulty_high");
    m_cumulative_difficulty_low = gen_utils::reconcile(m_cumulative_difficulty_low, other->m_cumulative_difficulty_low, "block header m_cumulative_difficulty_low");
    m_cumulative_difficulty_high = gen_utils::reconcile(m_cumulative_difficulty_high, other->m_cumulative_difficulty_high, "block header m_cumulative_difficulty_high");
    m_major_version = gen_utils::reconcile(m_major_version, other->m_major_version, "block header m_major_version");
    m_minor_version = gen_utils::reconcile(m_minor_version, other->m_minor_version, "block header m_minor_version");
    m_nonce = gen_utils::reconcile(m_nonce, other->m_nonce, "block header m_nonce");
    m_miner_tx_hash = gen_utils::reconcile(m_miner_tx_hash, other->m_miner_tx_hash, "block header m_miner_tx_hash");
    m_num_txs = gen_utils::reconcile(m_num_txs, other->m_num_txs, "block header m_num_txs");
    m_orphan_status = gen_utils::reconcile(m_orphan_status, other->m_orphan_status, "block header m_orphan_status");
    m_prev_hash = gen_utils::reconcile(m_prev_hash, other->m_prev_hash, "block header m_prev_hash");
    m_reward = gen_utils::reconcile(m_reward, other->m_reward, "block header m_reward");
    m_pow_hash = gen_utils::reconcile(m_pow_hash, other->m_pow_hash, "block header m_pow_hash");
  }

  // ----------------------------- MONERO BLOCK -------------------------------

  rapidjson::Value monero_block::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // serialize root from superclass
    rapidjson::Value root = monero_block_header::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_hex != boost::none) monero_utils::add_json_member("hex", m_hex.get(), allocator, root, value_str);

    // set sub-arrays
    if (!m_txs.empty()) root.AddMember("txs", monero_utils::to_rapidjson_val(allocator, m_txs), allocator);
    if (!m_tx_hashes.empty()) root.AddMember("txHashes", monero_utils::to_rapidjson_val(allocator, m_tx_hashes), allocator);

    // set sub-objects
    if (m_miner_tx != nullptr) root.AddMember("minerTx", m_miner_tx->to_rapidjson_val(allocator), allocator);

    // return root
    return root;
  }

  std::shared_ptr<monero_block> monero_block::copy(const std::shared_ptr<monero_block>& src, const std::shared_ptr<monero_block>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this block != src");
    monero_block_header::copy(std::static_pointer_cast<monero_block_header>(src), std::static_pointer_cast<monero_block_header>(tgt));
    tgt->m_hex = src->m_hex;
    if (src->m_miner_tx) {
      tgt->m_miner_tx = src->m_miner_tx->copy(src->m_miner_tx, std::make_shared<monero_tx>());
      tgt->m_miner_tx->m_block = tgt;
    }
    if (!src->m_txs.empty()) {
      bool use_wallet_types = std::dynamic_pointer_cast<monero_tx_wallet>(src->m_txs[0]) != 0;
      tgt->m_txs = std::vector<std::shared_ptr<monero_tx>>();
      for (const auto& tx : src->m_txs) {
        if (use_wallet_types) {
          std::shared_ptr<monero_tx_wallet> tx_wallet = std::static_pointer_cast<monero_tx_wallet>(tx);
          std::shared_ptr<monero_tx_wallet> tx_copy = tx_wallet->copy(tx_wallet, std::make_shared<monero_tx_wallet>());
          tx_copy->m_block = tgt;
          tgt->m_txs.push_back(tx_copy);
        } else {
          std::shared_ptr<monero_tx> tx_copy = tx->copy(tx, std::make_shared<monero_tx>());
          tx_copy->m_block = tgt;
          tgt->m_txs.push_back(tx_copy);
        }
      }
    }
    if (!src->m_tx_hashes.empty()) tgt->m_tx_hashes = std::vector<std::string>(src->m_tx_hashes);
    return tgt;
  }

  void monero_block::merge(const std::shared_ptr<monero_block_header>& self, const std::shared_ptr<monero_block_header>& other) {
    merge(std::static_pointer_cast<monero_block>(self), std::static_pointer_cast<monero_block>(other));
  }

  void monero_block::merge(const std::shared_ptr<monero_block>& self, const std::shared_ptr<monero_block>& other) {
    if (this != self.get()) throw std::runtime_error("this != self");
    if (self == other) return;

    // merge header fields
    monero_block_header::merge(self, other);

    // merge reconcilable block extensions
    m_hex = gen_utils::reconcile(m_hex, other->m_hex, "block m_hex");
    m_tx_hashes = gen_utils::reconcile(m_tx_hashes, other->m_tx_hashes, "block m_tx_hahes");

    // merge miner tx
    if (m_miner_tx == nullptr) m_miner_tx = other->m_miner_tx;
    if (other->m_miner_tx != nullptr) {
      other->m_miner_tx->m_block = self;
      m_miner_tx->merge(m_miner_tx, other->m_miner_tx);
    }

    // merge non-miner txs
    if (!other->m_txs.empty()) {
      for (const std::shared_ptr<monero_tx> otherTx : other->m_txs) { // NOTE: not using reference so std::shared_ptr is not deleted when block is dereferenced
        otherTx->m_block = self;
        merge_tx(self->m_txs, otherTx);
      }
    }
  }

  // ------------------------------- MONERO TX --------------------------------

  rapidjson::Value monero_tx::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_version != boost::none) monero_utils::add_json_member("version", m_version.get(), allocator, root, value_num);
    if (m_fee != boost::none) monero_utils::add_json_member("fee", m_fee.get(), allocator, root, value_num);
    if (m_ring_size != boost::none) monero_utils::add_json_member("ringSize", m_ring_size.get(), allocator, root, value_num);
    if (m_num_confirmations != boost::none) monero_utils::add_json_member("numConfirmations", m_num_confirmations.get(), allocator, root, value_num);
    if (m_unlock_time != boost::none) monero_utils::add_json_member("unlockTime", m_unlock_time.get(), allocator, root, value_num);
    if (m_last_relayed_timestamp != boost::none) monero_utils::add_json_member("lastRelayedTimestamp", m_last_relayed_timestamp.get(), allocator, root, value_num);
    if (m_received_timestamp != boost::none) monero_utils::add_json_member("receivedTimestamp", m_received_timestamp.get(), allocator, root, value_num);
    if (m_size != boost::none) monero_utils::add_json_member("size", m_size.get(), allocator, root, value_num);
    if (m_weight != boost::none) monero_utils::add_json_member("weight", m_weight.get(), allocator, root, value_num);
    if (m_last_failed_height != boost::none) monero_utils::add_json_member("lastFailedHeight", m_last_failed_height.get(), allocator, root, value_num);
    if (m_max_used_block_height != boost::none) monero_utils::add_json_member("maxUsedBlockHeight", m_max_used_block_height.get(), allocator, root, value_num);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_hash != boost::none) monero_utils::add_json_member("hash", m_hash.get(), allocator, root, value_str);
    if (m_payment_id != boost::none) monero_utils::add_json_member("paymentId", m_payment_id.get(), allocator, root, value_str);
    if (m_key != boost::none) monero_utils::add_json_member("key", m_key.get(), allocator, root, value_str);
    if (m_full_hex != boost::none) monero_utils::add_json_member("fullHex", m_full_hex.get(), allocator, root, value_str);
    if (m_pruned_hex != boost::none) monero_utils::add_json_member("prunedHex", m_pruned_hex.get(), allocator, root, value_str);
    if (m_prunable_hex != boost::none) monero_utils::add_json_member("prunableHex", m_prunable_hex.get(), allocator, root, value_str);
    if (m_prunable_hash != boost::none) monero_utils::add_json_member("prunableHash", m_prunable_hash.get(), allocator, root, value_str);
    if (m_metadata != boost::none) monero_utils::add_json_member("metadata", m_metadata.get(), allocator, root, value_str);
    if (m_common_tx_sets != boost::none) monero_utils::add_json_member("commonTxSets", m_common_tx_sets.get(), allocator, root, value_str);
    if (m_rct_signatures != boost::none) monero_utils::add_json_member("rctSignatures", m_rct_signatures.get(), allocator, root, value_str);
    if (m_rct_sig_prunable != boost::none) monero_utils::add_json_member("rctSigPrunable", m_rct_sig_prunable.get(), allocator, root, value_str);
    if (m_last_failed_hash != boost::none) monero_utils::add_json_member("lastFailedHash", m_last_failed_hash.get(), allocator, root, value_str);
    if (m_max_used_block_hash != boost::none) monero_utils::add_json_member("maxUsedBlockHash", m_max_used_block_hash.get(), allocator, root, value_str);

    // set bool values
    if (m_is_miner_tx != boost::none) monero_utils::add_json_member("isMinerTx", m_is_miner_tx.get(), allocator, root);
    if (m_relay != boost::none) monero_utils::add_json_member("relay", m_relay.get(), allocator, root);
    if (m_is_relayed != boost::none) monero_utils::add_json_member("isRelayed", m_is_relayed.get(), allocator, root);
    if (m_is_confirmed != boost::none) monero_utils::add_json_member("isConfirmed", m_is_confirmed.get(), allocator, root);
    if (m_in_tx_pool != boost::none) monero_utils::add_json_member("inTxPool", m_in_tx_pool.get(), allocator, root);
    if (m_is_double_spend_seen != boost::none) monero_utils::add_json_member("isDoubleSpendSeen", m_is_double_spend_seen.get(), allocator, root);
    if (m_is_kept_by_block != boost::none) monero_utils::add_json_member("isKeptByBlock", m_is_kept_by_block.get(), allocator, root);
    if (m_is_failed != boost::none) monero_utils::add_json_member("isFailed", m_is_failed.get(), allocator, root);

    // set sub-arrays
    if (!m_inputs.empty()) root.AddMember("inputs", monero_utils::to_rapidjson_val(allocator, m_inputs), allocator);
    if (!m_outputs.empty()) root.AddMember("outputs", monero_utils::to_rapidjson_val(allocator, m_outputs), allocator);
    if (!m_output_indices.empty()) root.AddMember("outputIndices", monero_utils::to_rapidjson_val(allocator, m_output_indices), allocator);
    if (!m_extra.empty()) root.AddMember("extra", monero_utils::to_rapidjson_val(allocator, m_extra), allocator);
    if (!m_signatures.empty()) root.AddMember("signatures", monero_utils::to_rapidjson_val(allocator, m_signatures), allocator);

    // return root
    return root;
  }

  void monero_tx::from_property_tree(const boost::property_tree::ptree& node, std::shared_ptr<monero_tx> tx) {

    // initialize tx from node
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("hash")) tx->m_hash = it->second.data();
      else if (key == std::string("version")) throw std::runtime_error("version deserialization not implemented");
      else if (key == std::string("isMinerTx")) tx->m_is_miner_tx = it->second.get_value<bool>();
      else if (key == std::string("paymentId")) tx->m_payment_id = it->second.data();
      else if (key == std::string("fee")) tx->m_fee = it->second.get_value<uint64_t>();
      else if (key == std::string("mixin")) throw std::runtime_error("mixin deserialization not implemented");
      else if (key == std::string("relay")) tx->m_relay = it->second.get_value<bool>();
      else if (key == std::string("isRelayed")) tx->m_is_relayed = it->second.get_value<bool>();
      else if (key == std::string("isConfirmed")) tx->m_is_confirmed = it->second.get_value<bool>();
      else if (key == std::string("inTxPool")) tx->m_in_tx_pool = it->second.get_value<bool>();
      else if (key == std::string("numConfirmations")) tx->m_num_confirmations = it->second.get_value<uint64_t>();
      else if (key == std::string("unlockTime")) tx->m_unlock_time = it->second.get_value<uint64_t>();
      else if (key == std::string("lastRelayedTimestamp")) tx->m_last_relayed_timestamp = it->second.get_value<uint64_t>();
      else if (key == std::string("receivedTimestamp")) tx->m_received_timestamp = it->second.get_value<uint64_t>();
      else if (key == std::string("isDoubleSpendSeen")) tx->m_is_double_spend_seen = it->second.get_value<bool>();
      else if (key == std::string("key")) tx->m_key = it->second.data();
      else if (key == std::string("fullHex")) tx->m_full_hex = it->second.data();
      else if (key == std::string("prunedHex")) tx->m_pruned_hex = it->second.data();
      else if (key == std::string("prunableHex")) tx->m_prunable_hex = it->second.data();
      else if (key == std::string("prunableHash")) tx->m_prunable_hash = it->second.data();
      else if (key == std::string("size")) tx->m_size = it->second.get_value<uint64_t>();
      else if (key == std::string("weight")) tx->m_weight = it->second.get_value<uint64_t>();
      else if (key == std::string("inputs")) throw std::runtime_error("inputs deserialization not implemented");
      else if (key == std::string("outputs")) throw std::runtime_error("outputs deserialization not implemented");
      else if (key == std::string("outputIndices")) throw std::runtime_error("m_output_indices deserialization not implemented");
      else if (key == std::string("metadata")) tx->m_metadata = it->second.data();
      else if (key == std::string("commonTxSets")) throw std::runtime_error("commonTxSets deserialization not implemented");
      else if (key == std::string("extra")) throw std::runtime_error("extra deserialization not implemented");
      else if (key == std::string("rctSignatures")) throw std::runtime_error("rctSignatures deserialization not implemented");
      else if (key == std::string("rctSigPrunable")) throw std::runtime_error("rctSigPrunable deserialization not implemented");
      else if (key == std::string("isKeptByBlock")) tx->m_is_kept_by_block = it->second.get_value<bool>();
      else if (key == std::string("isFailed")) tx->m_is_failed = it->second.get_value<bool>();
      else if (key == std::string("lastFailedHeight")) throw std::runtime_error("lastFailedHeight deserialization not implemented");
      else if (key == std::string("lastFailedHash")) tx->m_last_failed_hash = it->second.data();
      else if (key == std::string("maxUsedBlockHeight")) throw std::runtime_error("maxUsedBlockHeight deserialization not implemented");
      else if (key == std::string("maxUsedBlockHash")) tx->m_max_used_block_hash = it->second.data();
      else if (key == std::string("signatures")) throw std::runtime_error("signatures deserialization not implemented");
    }
  }

  std::shared_ptr<monero_tx> monero_tx::copy(const std::shared_ptr<monero_tx>& src, const std::shared_ptr<monero_tx>& tgt) const {
    MTRACE("monero_tx::copy(const std::shared_ptr<monero_tx>& src, const std::shared_ptr<monero_tx>& tgt)");
    tgt->m_hash = src->m_hash;
    tgt->m_version = src->m_version;
    tgt->m_is_miner_tx = src->m_is_miner_tx;
    tgt->m_payment_id = src->m_payment_id;
    tgt->m_fee = src->m_fee;
    tgt->m_ring_size = src->m_ring_size;
    tgt->m_relay = src->m_relay;
    tgt->m_is_relayed = src->m_is_relayed;
    tgt->m_is_confirmed = src->m_is_confirmed;
    tgt->m_in_tx_pool = src->m_in_tx_pool;
    tgt->m_num_confirmations = src->m_num_confirmations;
    tgt->m_unlock_time = src->m_unlock_time;
    tgt->m_last_relayed_timestamp = src->m_last_relayed_timestamp;
    tgt->m_received_timestamp = src->m_received_timestamp;
    tgt->m_is_double_spend_seen = src->m_is_double_spend_seen;
    tgt->m_key = src->m_key;
    tgt->m_full_hex = src->m_full_hex;
    tgt->m_pruned_hex = src->m_pruned_hex;
    tgt->m_prunable_hex = src->m_prunable_hex;
    tgt->m_prunable_hash = src->m_prunable_hash;
    tgt->m_size = src->m_size;
    tgt->m_weight = src->m_weight;
    if (!src->m_inputs.empty()) {
      tgt->m_inputs = std::vector<std::shared_ptr<monero_output>>();
      for (const std::shared_ptr<monero_output>& input : src->m_inputs) {
        std::shared_ptr<monero_output> input_copy = input->copy(input, std::make_shared<monero_output>());
        input_copy->m_tx = tgt;
        tgt->m_inputs.push_back(input_copy);
      }
    }
    if (!src->m_outputs.empty()) {
      tgt->m_outputs = std::vector<std::shared_ptr<monero_output>>();
      for (const std::shared_ptr<monero_output>& output : src->m_outputs) {
        std::shared_ptr<monero_output> output_copy = output->copy(output, std::make_shared<monero_output>());
        output_copy->m_tx = tgt;
        tgt->m_outputs.push_back(output_copy);
      }
    }
    if (!src->m_output_indices.empty()) tgt->m_output_indices = std::vector<uint64_t>(src->m_output_indices);
    tgt->m_metadata = src->m_metadata;
    tgt->m_common_tx_sets = src->m_common_tx_sets;
    if (!src->m_extra.empty()) throw std::runtime_error("extra deep copy not implemented");  // TODO: implement extra
    tgt->m_rct_signatures = src->m_rct_signatures;
    tgt->m_rct_sig_prunable = src->m_rct_sig_prunable;
    tgt->m_is_kept_by_block = src->m_is_kept_by_block;
    tgt->m_is_failed = src->m_is_failed;
    tgt->m_last_failed_height = src->m_last_failed_height;
    tgt->m_last_failed_hash = src->m_last_failed_hash;
    tgt->m_max_used_block_height = src->m_max_used_block_height;
    tgt->m_max_used_block_hash = src->m_max_used_block_hash;
    if (!src->m_signatures.empty()) tgt->m_signatures = std::vector<std::string>(src->m_signatures);
    return tgt;
  }

  boost::optional<uint64_t> monero_tx::get_height() const {
    if (m_block == nullptr) return boost::none;
    return *(m_block->m_height);
  }

  void monero_tx::merge(const std::shared_ptr<monero_tx>& self, const std::shared_ptr<monero_tx>& other) {
    if (this != self.get()) throw std::runtime_error("this != self");
    if (self == other) return;

    // merge blocks if they're different
    if (m_block != other->m_block) {
      if (m_block == nullptr) {
        m_block = other->m_block;
        std::replace(m_block->m_txs.begin(), m_block->m_txs.end(), other, self); // update block to point to this tx
      } else if (other->m_block != nullptr) {
        m_block->merge(m_block, other->m_block); // comes back to merging txs
        return;
      }
    }

    // otherwise merge tx fields
    m_hash = gen_utils::reconcile(m_hash, other->m_hash, "tx m_hash");
    m_version = gen_utils::reconcile(m_version, other->m_version, "tx m_version");
    m_payment_id = gen_utils::reconcile(m_payment_id, other->m_payment_id, "tx m_payment_id");
    m_fee = gen_utils::reconcile(m_fee, other->m_fee, "tx m_fee");
    m_ring_size = gen_utils::reconcile(m_ring_size, other->m_ring_size, "tx m_ring_size");
    m_is_confirmed = gen_utils::reconcile(m_is_confirmed, other->m_is_confirmed, boost::none, true, boost::none, "tx m_is_confirmed");  // tx can become confirmed
    m_is_miner_tx = gen_utils::reconcile(m_is_miner_tx, other->m_is_miner_tx, "tx m_is_miner_tx");
    m_relay = gen_utils::reconcile(m_relay, other->m_relay, boost::none, true, boost::none, "tx m_relay"); // tx can become relayed
    m_is_relayed = gen_utils::reconcile(m_is_relayed, other->m_is_relayed, boost::none, true, boost::none, "tx m_is_relayed"); // tx can become relayed
    m_is_double_spend_seen = gen_utils::reconcile(m_is_double_spend_seen, other->m_is_double_spend_seen, boost::none, true, boost::none, "tx m_is_double_spend_seen"); // double spend can become seen
    m_key = gen_utils::reconcile(m_key, other->m_key, "tx m_key");
    m_full_hex = gen_utils::reconcile(m_full_hex, other->m_full_hex, "tx m_full_hex");
    m_pruned_hex = gen_utils::reconcile(m_pruned_hex, other->m_pruned_hex, "tx m_pruned_hex");
    m_prunable_hex = gen_utils::reconcile(m_prunable_hex, other->m_prunable_hex, "tx m_prunable_hex");
    m_prunable_hash = gen_utils::reconcile(m_prunable_hash, other->m_prunable_hash, "tx m_prunable_hash");
    m_size = gen_utils::reconcile(m_size, other->m_size, "tx m_size");
    m_weight = gen_utils::reconcile(m_weight, other->m_weight, "tx m_weight");
    //m_output_indices = gen_utils::reconcile(m_output_indices, other->m_output_indices, "tx m_output_indices");  // TODO
    m_metadata = gen_utils::reconcile(m_metadata, other->m_metadata, "tx m_metadata");
    m_common_tx_sets = gen_utils::reconcile(m_common_tx_sets, other->m_common_tx_sets, "tx m_common_tx_sets");
    //m_extra = gen_utils::reconcile(m_extra, other->m_extra, "tx m_extra");  // TODO
    m_rct_signatures = gen_utils::reconcile(m_rct_signatures, other->m_rct_signatures, "tx m_rct_signatures");
    m_rct_sig_prunable = gen_utils::reconcile(m_rct_sig_prunable, other->m_rct_sig_prunable, "tx m_rct_sig_prunable");
    m_is_kept_by_block = gen_utils::reconcile(m_is_kept_by_block, other->m_is_kept_by_block, "tx m_is_kept_by_block");
    m_is_failed = gen_utils::reconcile(m_is_failed, other->m_is_failed, boost::none, true, boost::none, "tx m_is_failed"); // tx can become failed
    m_last_failed_height = gen_utils::reconcile(m_last_failed_height, other->m_last_failed_height, "tx m_last_failed_height");
    m_last_failed_hash = gen_utils::reconcile(m_last_failed_hash, other->m_last_failed_hash, "tx m_last_failed_hash");
    m_max_used_block_height = gen_utils::reconcile(m_max_used_block_height, other->m_max_used_block_height, "tx m_max_used_block_height");
    m_max_used_block_hash = gen_utils::reconcile(m_max_used_block_hash, other->m_max_used_block_hash, "tx m_max_used_block_hash");
    //m_signatures = gen_utils::reconcile(m_signatures, other->m_signatures, "tx m_signatures"); // TODO
    m_unlock_time = gen_utils::reconcile(m_unlock_time, other->m_unlock_time, "tx m_unlock_time");
    m_num_confirmations = gen_utils::reconcile(m_num_confirmations, other->m_num_confirmations, boost::none, boost::none, true, "tx m_num_confirmations"); // num confirmations can increase

    // merge inputs
    if (!other->m_inputs.empty()) {
      for (const std::shared_ptr<monero_output>& merger : other->m_inputs) {
        bool merged = false;
        merger->m_tx = self;
        for (const std::shared_ptr<monero_output>& mergee : m_inputs) {
          if (mergee->m_key_image->m_hex == merger->m_key_image->m_hex) {
            mergee->merge(mergee, merger);
            merged = true;
            break;
          }
        }
        if (!merged) m_inputs.push_back(merger);
      }
    }

    // merge outputs
    if (!other->m_outputs.empty()) {
      for (const std::shared_ptr<monero_output>& output : other->m_outputs) output->m_tx = self;
      if (m_outputs.empty()) m_outputs = other->m_outputs;
      else {

        // merge outputs if key image or stealth public key present, otherwise append
        for (const std::shared_ptr<monero_output>& merger : other->m_outputs) {
          bool merged = false;
          merger->m_tx = self;
          for (const std::shared_ptr<monero_output>& mergee : m_outputs) {
            if ((merger->m_key_image != nullptr && mergee->m_key_image->m_hex == merger->m_key_image->m_hex) ||
                (merger->m_stealth_public_key != boost::none && *mergee->m_stealth_public_key == *merger->m_stealth_public_key)) {
              mergee->merge(mergee, merger);
              merged = true;
              break;
            }
          }
          if (!merged) m_outputs.push_back(merger); // append output
        }
      }
    }

    // handle unrelayed -> relayed -> confirmed
    if (*m_is_confirmed) {
      m_in_tx_pool = false;
      m_received_timestamp = boost::none;
      m_last_relayed_timestamp = boost::none;
    } else {
      m_in_tx_pool = gen_utils::reconcile(m_in_tx_pool, other->m_in_tx_pool, boost::none, true, boost::none, "tx m_in_tx_pool"); // unrelayed -> tx pool
      m_received_timestamp = gen_utils::reconcile(m_received_timestamp, other->m_received_timestamp, boost::none, boost::none, false, "tx m_received_timestamp"); // take earliest receive time
      m_last_relayed_timestamp = gen_utils::reconcile(m_last_relayed_timestamp, other->m_last_relayed_timestamp, boost::none, boost::none, true, "tx m_last_relayed_timestamp"); // take latest relay time
    }
  }

  // --------------------------- MONERO KEY IMAGE -----------------------------

  rapidjson::Value monero_key_image::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_hex != boost::none) monero_utils::add_json_member("hex", m_hex.get(), allocator, root, value_str);
    if (m_signature != boost::none) monero_utils::add_json_member("signature", m_signature.get(), allocator, root, value_str);

    // return root
    return root;
  }

  void monero_key_image::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_key_image>& key_image) {

    // initialize key image from node
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("hex")) key_image->m_hex = it->second.data();
      else if (key == std::string("signature")) key_image->m_signature = it->second.data();
    }
  }

  std::vector<std::shared_ptr<monero_key_image>> monero_key_image::deserialize_key_images(const std::string& key_images_json) {

    // deserialize json to property node
    std::istringstream iss = key_images_json.empty() ? std::istringstream() : std::istringstream(key_images_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert property tree to key images
    std::vector<std::shared_ptr<monero_key_image>> key_images;
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("keyImages")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_key_image> key_image = std::make_shared<monero_key_image>();
          monero_key_image::from_property_tree(it2->second, key_image);
          key_images.push_back(key_image);
        }
      }
      else MWARNING("WARNING MoneroWalletJni::deserialize_key_images() unrecognized key: " << key);
    }
    return key_images;
  }

  std::shared_ptr<monero_key_image> monero_key_image::copy(const std::shared_ptr<monero_key_image>& src, const std::shared_ptr<monero_key_image>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this != src");
    tgt->m_hex = src->m_hex;
    tgt->m_signature = src->m_signature;
    return tgt;
  }

  void monero_key_image::merge(const std::shared_ptr<monero_key_image>& self, const std::shared_ptr<monero_key_image>& other) {
    MTRACE("monero_key_image::merge(self, other)");
    if (this != self.get()) throw std::runtime_error("this != self");
    if (self == other) return;
    m_hex = gen_utils::reconcile(m_hex, other->m_hex, "key image m_hex");
    m_signature = gen_utils::reconcile(m_signature, other->m_signature, "key image m_signature");
  }

  // ------------------------------ MONERO OUTPUT -----------------------------

  rapidjson::Value monero_output::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_num);
    if (m_index != boost::none) monero_utils::add_json_member("index", m_index.get(), allocator, root, value_num);
    if (m_stealth_public_key != boost::none) monero_utils::add_json_member("stealthPublicKey", m_stealth_public_key.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_ring_output_indices.empty()) root.AddMember("ringOutputIndices", monero_utils::to_rapidjson_val(allocator, m_ring_output_indices), allocator);

    // set sub-objects
    if (m_key_image != nullptr) root.AddMember("keyImage", m_key_image->to_rapidjson_val(allocator), allocator);

    // return root
    return root;
  }

  void monero_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output>& output) {

    // initialize output from node
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("keyImage")) {
        output->m_key_image = std::make_shared<monero_key_image>();
        monero_key_image::from_property_tree(it->second, output->m_key_image);
      }
      else if (key == std::string("amount")) output->m_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("index")) output->m_index = it->second.get_value<uint32_t>();
      else if (key == std::string("ringOutputIndices")) throw std::runtime_error("node_to_tx() deserialize ringOutputIndices not implemented");
      else if (key == std::string("stealthPublicKey")) throw std::runtime_error("node_to_tx() deserialize stealthPublicKey not implemented");
    }
  }

  std::shared_ptr<monero_output> monero_output::copy(const std::shared_ptr<monero_output>& src, const std::shared_ptr<monero_output>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this != src");
    tgt->m_tx = src->m_tx;  // reference same parent tx by default
    if (src->m_key_image != nullptr) tgt->m_key_image = src->m_key_image->copy(src->m_key_image, std::make_shared<monero_key_image>());
    tgt->m_amount = src->m_amount;
    tgt->m_index = src->m_index;
    if (!src->m_ring_output_indices.empty()) tgt->m_ring_output_indices = std::vector<uint64_t>(src->m_ring_output_indices);
    tgt->m_stealth_public_key = src->m_stealth_public_key;
    return tgt;
  }

  void monero_output::merge(const std::shared_ptr<monero_output>& self, const std::shared_ptr<monero_output>& other) {
    if (this != self.get()) throw std::runtime_error("this != self");
    if (self == other) return;

    // merge txs if they're different which comes back to merging outputs
    if (m_tx != other->m_tx) {
      m_tx->merge(m_tx, other->m_tx);
      return;
    }

    // otherwise merge output fields
    if (m_key_image == nullptr) m_key_image = other->m_key_image;
    else if (other->m_key_image != nullptr) m_key_image->merge(m_key_image, other->m_key_image);
    m_amount = gen_utils::reconcile(m_amount, other->m_amount, "output amount");
    m_index = gen_utils::reconcile(m_index, other->m_index, "output index");
  }

  // --------------------------- MONERO RPC PAYMENT INFO ---------------------------

  void monero_rpc_payment_info::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_rpc_payment_info>& rpc_payment_info) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if ((key == std::string("topBlockHash")) && !it->second.data().empty()) rpc_payment_info->m_top_block_hash = it->second.data();
      else if (key == std::string("credits")) rpc_payment_info->m_credits = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_rpc_payment_info::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_top_block_hash != boost::none) monero_utils::add_json_member("topBlockHash", m_top_block_hash.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_credits != boost::none) monero_utils::add_json_member("credits", m_credits.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO ALT CHAIN ---------------------------

  void monero_alt_chain::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_alt_chain>& alt_chain) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("difficultyLow")) alt_chain->m_difficulty_low = it->second.get_value<uint64_t>();
      else if (key == std::string("difficultyHigh")) alt_chain->m_difficulty_high = it->second.get_value<uint64_t>();
      else if (key == std::string("blockHashes")) {
        for (const auto& child : it->second) alt_chain->m_block_hashes.push_back(child.second.data());
      }
      else if (key == std::string("height")) alt_chain->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("length")) alt_chain->m_length = it->second.get_value<uint64_t>();
      else if (key == std::string("mainChainParentBlockHash")) alt_chain->m_main_chain_parent_block_hash = it->second.data();
    }
  }

  rapidjson::Value monero_alt_chain::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_main_chain_parent_block_hash != boost::none) monero_utils::add_json_member("mainChainParentBlockHash", m_main_chain_parent_block_hash.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_difficulty_low != boost::none) monero_utils::add_json_member("difficultyLow", m_difficulty_low.get(), allocator, root, value_num);
    if (m_difficulty_high != boost::none) monero_utils::add_json_member("difficultyHigh", m_difficulty_high.get(), allocator, root, value_num);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);
    if (m_length != boost::none) monero_utils::add_json_member("length", m_length.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_block_hashes.empty()) root.AddMember("blockHashes", monero_utils::to_rapidjson_val(allocator, m_block_hashes), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO BAN ---------------------------

  void monero_ban::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_ban>& ban) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("host")) ban->m_host = it->second.data();
      else if (key == std::string("ip")) ban->m_ip = it->second.get_value<uint32_t>();
      else if (key == std::string("isBanned")) ban->m_is_banned = it->second.get_value<bool>();
      else if (key == std::string("seconds")) ban->m_seconds = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_ban::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_host != boost::none) monero_utils::add_json_member("host", m_host.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_ip != boost::none) monero_utils::add_json_member("ip", m_ip.get(), allocator, root, value_num);
    if (m_seconds != boost::none) monero_utils::add_json_member("seconds", m_seconds.get(), allocator, root, value_num);

    // set bool values
    if (m_is_banned != boost::none) monero_utils::add_json_member("isBanned", m_is_banned.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO PRUNE RESULT ---------------------------

  void monero_prune_result::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_prune_result>& result) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("pruned")) result->m_is_pruned = it->second.get_value<bool>();
      else if (key == std::string("pruningSeed")) result->m_pruning_seed = it->second.get_value<int>();
    }
  }

  rapidjson::Value monero_prune_result::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_pruning_seed != boost::none) monero_utils::add_json_member("pruningSeed", m_pruning_seed.get(), allocator, root, value_num);

    // set bool values
    if (m_is_pruned != boost::none) monero_utils::add_json_member("isPruned", m_is_pruned.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO MINING STATUS ---------------------------

  void monero_mining_status::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_mining_status>& status) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("isActive")) status->m_is_active = it->second.get_value<bool>();
      else if (key == std::string("isBackground")) status->m_is_background = it->second.get_value<bool>();
      else if (key == std::string("address") && !it->second.data().empty()) status->m_address = it->second.data();
      else if (key == std::string("speed")) status->m_speed = it->second.get_value<uint64_t>();
      else if (key == std::string("numThreads")) status->m_num_threads = it->second.get_value<int>();
    }

    if (status->m_is_active != boost::none && *status->m_is_active == false) {
      status->m_is_background = boost::none;
      status->m_address = boost::none;
    }
  }

  rapidjson::Value monero_mining_status::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_speed != boost::none) monero_utils::add_json_member("speed", m_speed.get(), allocator, root, value_num);
    if (m_num_threads != boost::none) monero_utils::add_json_member("numThreads", m_num_threads.get(), allocator, root, value_num);

    // set bool values
    if (m_is_active != boost::none) monero_utils::add_json_member("isActive", m_is_active.get(), allocator, root);
    if (m_is_background != boost::none) monero_utils::add_json_member("isBackground", m_is_background.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO MINER TX SUM ---------------------------

  void monero_miner_tx_sum::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_miner_tx_sum>& sum) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("emissionSumLow")) sum->m_emission_sum_low = it->second.get_value<uint64_t>();
      else if (key == std::string("emissionSumHigh")) sum->m_emission_sum_high = it->second.get_value<uint64_t>();
      else if (key == std::string("feeSumLow")) sum->m_fee_sum_low = it->second.get_value<uint64_t>();
      else if (key == std::string("feeSumHigh")) sum->m_fee_sum_high = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_miner_tx_sum::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_emission_sum_low != boost::none) monero_utils::add_json_member("emissionSumLow", m_emission_sum_low.get(), allocator, root, value_num);
    if (m_emission_sum_high != boost::none) monero_utils::add_json_member("emissionSumHigh", m_emission_sum_high.get(), allocator, root, value_num);
    if (m_fee_sum_low != boost::none) monero_utils::add_json_member("feeSumLow", m_fee_sum_low.get(), allocator, root, value_num);
    if (m_fee_sum_high != boost::none) monero_utils::add_json_member("feeSumHigh", m_fee_sum_high.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO BLOCK TEMPLATE ---------------------------

  void monero_block_template::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_block_template>& tmplt) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("blockTemplateBlob")) tmplt->m_block_template_blob = it->second.data();
      else if (key == std::string("blockHashingBlob")) tmplt->m_block_hashing_blob = it->second.data();
      else if (key == std::string("difficultyLow")) tmplt->m_difficulty_low = it->second.get_value<uint64_t>();
      else if (key == std::string("difficultyHigh")) tmplt->m_difficulty_high = it->second.get_value<uint64_t>();
      else if (key == std::string("expectedReward")) tmplt->m_expected_reward = it->second.get_value<uint64_t>();
      else if (key == std::string("height")) tmplt->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("prevHash")) tmplt->m_prev_hash = it->second.data();
      else if (key == std::string("reservedOffset")) tmplt->m_reserved_offset = it->second.get_value<uint64_t>();
      else if (key == std::string("seedHeight")) tmplt->m_seed_height = it->second.get_value<uint64_t>();
      else if (key == std::string("seedHash")) tmplt->m_seed_hash = it->second.data();
      else if (key == std::string("nextSeedHash")) tmplt->m_next_seed_hash = it->second.data();
    }
  }

  rapidjson::Value monero_block_template::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_block_template_blob != boost::none) monero_utils::add_json_member("blockTemplateBlob", m_block_template_blob.get(), allocator, root, value_str);
    if (m_block_hashing_blob != boost::none) monero_utils::add_json_member("blockHashingBlob", m_block_hashing_blob.get(), allocator, root, value_str);
    if (m_prev_hash != boost::none) monero_utils::add_json_member("prevHash", m_prev_hash.get(), allocator, root, value_str);
    if (m_seed_hash != boost::none) monero_utils::add_json_member("seedHash", m_seed_hash.get(), allocator, root, value_str);
    if (m_next_seed_hash != boost::none) monero_utils::add_json_member("nextSeedHash", m_next_seed_hash.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_difficulty_low != boost::none) monero_utils::add_json_member("difficultyLow", m_difficulty_low.get(), allocator, root, value_num);
    if (m_difficulty_high != boost::none) monero_utils::add_json_member("difficultyHigh", m_difficulty_high.get(), allocator, root, value_num);
    if (m_expected_reward != boost::none) monero_utils::add_json_member("expectedReward", m_expected_reward.get(), allocator, root, value_num);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);
    if (m_reserved_offset != boost::none) monero_utils::add_json_member("reservedOffset", m_reserved_offset.get(), allocator, root, value_num);
    if (m_seed_height != boost::none) monero_utils::add_json_member("seedHeight", m_seed_height.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO CONNECTION SPAN ---------------------------

  void monero_connection_span::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_connection_span>& span) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("connectionId")) span->m_connection_id = it->second.data();
      else if (key == std::string("numBlocks")) span->m_num_blocks = it->second.get_value<uint64_t>();
      else if (key == std::string("remoteAddress")) span->m_remote_address = it->second.data();
      else if (key == std::string("rate")) span->m_rate = it->second.get_value<uint64_t>();
      else if (key == std::string("speed")) span->m_speed = it->second.get_value<uint64_t>();
      else if (key == std::string("size")) span->m_size = it->second.get_value<uint64_t>();
      else if (key == std::string("startHeight")) span->m_start_height = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_connection_span::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_connection_id != boost::none) monero_utils::add_json_member("connectionId", m_connection_id.get(), allocator, root, value_str);
    if (m_remote_address != boost::none) monero_utils::add_json_member("remoteAddress", m_remote_address.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_num_blocks != boost::none) monero_utils::add_json_member("numBlocks", m_num_blocks.get(), allocator, root, value_num);
    if (m_rate != boost::none) monero_utils::add_json_member("rate", m_rate.get(), allocator, root, value_num);
    if (m_speed != boost::none) monero_utils::add_json_member("speed", m_speed.get(), allocator, root, value_num);
    if (m_size != boost::none) monero_utils::add_json_member("size", m_size.get(), allocator, root, value_num);
    if (m_start_height != boost::none) monero_utils::add_json_member("startHeight", m_start_height.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO PEER ---------------------------

  void monero_peer::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_peer>& peer) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("host")) peer->m_host = it->second.data();
      else if (key == std::string("address")) peer->m_address = it->second.data();
      else if (key == std::string("currentDownload")) peer->m_current_download = it->second.get_value<uint64_t>();
      else if (key == std::string("currentUpload")) peer->m_current_upload = it->second.get_value<uint64_t>();
      else if (key == std::string("avgDownload")) peer->m_avg_download = it->second.get_value<uint64_t>();
      else if (key == std::string("avgUpload")) peer->m_avg_upload = it->second.get_value<uint64_t>();
      else if (key == std::string("hash")) peer->m_hash = it->second.data();
      else if (key == std::string("height")) peer->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("isIncoming")) peer->m_is_incoming = it->second.get_value<bool>();
      else if (key == std::string("liveTime")) peer->m_live_time = it->second.get_value<uint64_t>();
      else if (key == std::string("isLocalIp")) peer->m_is_local_ip = it->second.get_value<bool>();
      else if (key == std::string("isLocalHost")) peer->m_is_local_host = it->second.get_value<bool>();
      else if (key == std::string("numReceives")) peer->m_num_receives = it->second.get_value<uint64_t>();
      else if (key == std::string("numSends")) peer->m_num_sends = it->second.get_value<uint64_t>();
      else if (key == std::string("receiveIdleTime")) peer->m_receive_idle_time = it->second.get_value<uint64_t>();
      else if (key == std::string("sendIdleTime")) peer->m_send_idle_time = it->second.get_value<uint64_t>();
      else if (key == std::string("state")) peer->m_state = it->second.data();
      else if (key == std::string("numSupportFlags")) peer->m_num_support_flags = it->second.get_value<int>();
      else if (key == std::string("id")) peer->m_id = it->second.data();
      else if (key == std::string("lastSeenTimestamp")) peer->m_last_seen_timestamp = it->second.get_value<uint64_t>();
      else if (key == std::string("port")) peer->m_port = it->second.get_value<int>();
      else if (key == std::string("rpcPort")) peer->m_rpc_port = it->second.get_value<int>();
      else if (key == std::string("pruningSeed")) peer->m_pruning_seed = it->second.get_value<int>();
      else if (key == std::string("rpcCreditsPerHash")) peer->m_rpc_credits_per_hash = it->second.get_value<uint64_t>();
      else if (key == std::string("addressType")) {
        int rpc_type = it->second.get_value<int>();
        // TODO: epee's address_type enum (net/enums.h) is invalid=0, ipv4=1, ipv6=2, i2p=3,
        // tor=4. Fix this with monero-java/ts together once the reference.
        if (rpc_type == 0) peer->m_connection_type = monero_connection_type::INVALID;
        else if (rpc_type == 1) peer->m_connection_type = monero_connection_type::IPV4;
        else if (rpc_type == 2) peer->m_connection_type = monero_connection_type::IPV6;
        else if (rpc_type == 3) peer->m_connection_type = monero_connection_type::TOR;
        else if (rpc_type == 4) peer->m_connection_type = monero_connection_type::I2P;
        else throw monero_error("Invalid RPC peer type, expected 0-4: " + std::to_string(rpc_type));
      }
    }
  }

  rapidjson::Value monero_peer::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_id != boost::none) monero_utils::add_json_member("id", m_id.get(), allocator, root, value_str);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_host != boost::none) monero_utils::add_json_member("host", m_host.get(), allocator, root, value_str);
    if (m_hash != boost::none) monero_utils::add_json_member("hash", m_hash.get(), allocator, root, value_str);
    if (m_state != boost::none) monero_utils::add_json_member("state", m_state.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_num);
    if (m_rpc_port != boost::none) monero_utils::add_json_member("rpcPort", m_rpc_port.get(), allocator, root, value_num);
    if (m_last_seen_timestamp != boost::none) monero_utils::add_json_member("lastSeenTimestamp", m_last_seen_timestamp.get(), allocator, root, value_num);
    if (m_pruning_seed != boost::none) monero_utils::add_json_member("pruningSeed", m_pruning_seed.get(), allocator, root, value_num);
    if (m_rpc_credits_per_hash != boost::none) monero_utils::add_json_member("rpcCreditsPerHash", m_rpc_credits_per_hash.get(), allocator, root, value_num);
    if (m_avg_download != boost::none) monero_utils::add_json_member("avgDownload", m_avg_download.get(), allocator, root, value_num);
    if (m_avg_upload != boost::none) monero_utils::add_json_member("avgUpload", m_avg_upload.get(), allocator, root, value_num);
    if (m_current_download != boost::none) monero_utils::add_json_member("currentDownload", m_current_download.get(), allocator, root, value_num);
    if (m_current_upload != boost::none) monero_utils::add_json_member("currentUpload", m_current_upload.get(), allocator, root, value_num);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);
    if (m_live_time != boost::none) monero_utils::add_json_member("liveTime", m_live_time.get(), allocator, root, value_num);
    if (m_num_receives != boost::none) monero_utils::add_json_member("numReceives", m_num_receives.get(), allocator, root, value_num);
    if (m_num_sends != boost::none) monero_utils::add_json_member("numSends", m_num_sends.get(), allocator, root, value_num);
    if (m_receive_idle_time != boost::none) monero_utils::add_json_member("receiveIdleTime", m_receive_idle_time.get(), allocator, root, value_num);
    if (m_send_idle_time != boost::none) monero_utils::add_json_member("sendIdleTime", m_send_idle_time.get(), allocator, root, value_num);
    if (m_num_support_flags != boost::none) monero_utils::add_json_member("numSupportFlags", m_num_support_flags.get(), allocator, root, value_num);

    // set bool values
    if (m_is_online != boost::none) monero_utils::add_json_member("isOnline", m_is_online.get(), allocator, root);
    if (m_is_incoming != boost::none) monero_utils::add_json_member("isIncoming", m_is_incoming.get(), allocator, root);
    if (m_is_local_ip != boost::none) monero_utils::add_json_member("isLocalIp", m_is_local_ip.get(), allocator, root);
    if (m_is_local_host != boost::none) monero_utils::add_json_member("isLocalHost", m_is_local_host.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO SUBMIT TX RESULT ---------------------------

  void monero_submit_tx_result::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_submit_tx_result>& result) {
    monero_rpc_payment_info::from_property_tree(node, result);

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("isDoubleSpend")) result->m_is_double_spend = it->second.get_value<bool>();
      else if (key == std::string("isFeeTooLow")) result->m_is_fee_too_low = it->second.get_value<bool>();
      else if (key == std::string("hasInvalidInput")) result->m_has_invalid_input = it->second.get_value<bool>();
      else if (key == std::string("hasInvalidOutput")) result->m_has_invalid_output = it->second.get_value<bool>();
      else if (key == std::string("hasTooFewOutputs")) result->m_has_too_few_outputs = it->second.get_value<bool>();
      else if (key == std::string("isMixinTooLow")) result->m_is_mixin_too_low = it->second.get_value<bool>();
      else if (key == std::string("isRelayed")) result->m_is_relayed = it->second.get_value<bool>();
      else if (key == std::string("isOverspend")) result->m_is_overspend = it->second.get_value<bool>();
      else if (key == std::string("reason") && !it->second.data().empty()) result->m_reason = it->second.data();
      else if (key == std::string("isTooBig")) result->m_is_too_big = it->second.get_value<bool>();
      else if (key == std::string("sanityCheckFailed")) result->m_sanity_check_failed = it->second.get_value<bool>();
      else if (key == std::string("isTxExtraTooBig")) result->m_is_tx_extra_too_big = it->second.get_value<bool>();
      else if (key == std::string("isNonZeroUnlockTime")) result->m_is_nonzero_unlock_time = it->second.get_value<bool>();
    }
  }

  rapidjson::Value monero_submit_tx_result::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root = monero_rpc_payment_info::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_reason != boost::none) monero_utils::add_json_member("reason", m_reason.get(), allocator, root, value_str);

    // set bool values
    if (m_has_invalid_input != boost::none) monero_utils::add_json_member("hasInvalidInput", m_has_invalid_input.get(), allocator, root);
    if (m_has_invalid_output != boost::none) monero_utils::add_json_member("hasInvalidOutput", m_has_invalid_output.get(), allocator, root);
    if (m_has_too_few_outputs != boost::none) monero_utils::add_json_member("hasTooFewOutputs", m_has_too_few_outputs.get(), allocator, root);
    if (m_is_good != boost::none) monero_utils::add_json_member("isGood", m_is_good.get(), allocator, root);
    if (m_is_relayed != boost::none) monero_utils::add_json_member("isRelayed", m_is_relayed.get(), allocator, root);
    if (m_is_double_spend != boost::none) monero_utils::add_json_member("isDoubleSpend", m_is_double_spend.get(), allocator, root);
    if (m_is_fee_too_low != boost::none) monero_utils::add_json_member("isFeeTooLow", m_is_fee_too_low.get(), allocator, root);
    if (m_is_mixin_too_low != boost::none) monero_utils::add_json_member("isMixinTooLow", m_is_mixin_too_low.get(), allocator, root);
    if (m_is_overspend != boost::none) monero_utils::add_json_member("isOverspend", m_is_overspend.get(), allocator, root);
    if (m_is_too_big != boost::none) monero_utils::add_json_member("isTooBig", m_is_too_big.get(), allocator, root);
    if (m_is_tx_extra_too_big != boost::none) monero_utils::add_json_member("isTxExtraTooBig", m_is_tx_extra_too_big.get(), allocator, root);
    if (m_is_nonzero_unlock_time != boost::none) monero_utils::add_json_member("isNonZeroUnlockTime", m_is_nonzero_unlock_time.get(), allocator, root);
    if (m_sanity_check_failed != boost::none) monero_utils::add_json_member("sanityCheckFailed", m_sanity_check_failed.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO OUTPUT DISTRIBUTION ENTRY ---------------------------

  void monero_output_distribution_entry::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_distribution_entry>& entry) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("amount")) entry->m_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("base")) entry->m_base = it->second.get_value<uint64_t>();
      else if (key == std::string("distribution")) {
        for(auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          entry->m_distribution.push_back(it2->second.get_value<uint64_t>());
        }
      }
      else if (key == std::string("startHeight")) entry->m_start_height = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_output_distribution_entry::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_num);
    if (m_base != boost::none) monero_utils::add_json_member("base", m_base.get(), allocator, root, value_num);
    if (m_start_height != boost::none) monero_utils::add_json_member("startHeight", m_start_height.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_distribution.empty()) root.AddMember("distribution", monero_utils::to_rapidjson_val(allocator, m_distribution), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO OUTPUT HISTOGRAM ENTRY ---------------------------

  void monero_output_histogram_entry::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_histogram_entry>& entry) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("amount")) entry->m_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("numInstances")) entry->m_num_instances = it->second.get_value<uint64_t>();
      else if (key == std::string("unlockedInstances")) entry->m_unlocked_instances = it->second.get_value<uint64_t>();
      else if (key == std::string("recentInstances")) entry->m_recent_instances = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_output_histogram_entry::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_num);
    if (m_num_instances != boost::none) monero_utils::add_json_member("numInstances", m_num_instances.get(), allocator, root, value_num);
    if (m_unlocked_instances != boost::none) monero_utils::add_json_member("unlockedInstances", m_unlocked_instances.get(), allocator, root, value_num);
    if (m_recent_instances != boost::none) monero_utils::add_json_member("recentInstances", m_recent_instances.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO TX POOL STATS ---------------------------

  void monero_tx_pool_stats::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_pool_stats>& stats) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("numTxs")) stats->m_num_txs = it->second.get_value<int>();
      else if (key == std::string("numNotRelayed")) stats->m_num_not_relayed = it->second.get_value<int>();
      else if (key == std::string("numFailing")) stats->m_num_failing = it->second.get_value<int>();
      else if (key == std::string("numDoubleSpends")) stats->m_num_double_spends = it->second.get_value<int>();
      else if (key == std::string("num10m")) stats->m_num10m = it->second.get_value<int>();
      else if (key == std::string("feeTotal")) stats->m_fee_total = it->second.get_value<uint64_t>();
      else if (key == std::string("bytesMax")) stats->m_bytes_max = it->second.get_value<uint64_t>();
      else if (key == std::string("bytesMed")) stats->m_bytes_med = it->second.get_value<uint64_t>();
      else if (key == std::string("bytesMin")) stats->m_bytes_min = it->second.get_value<uint64_t>();
      else if (key == std::string("bytesTotal")) stats->m_bytes_total = it->second.get_value<uint64_t>();
      else if (key == std::string("histo98pc")) stats->m_histo98pc = it->second.get_value<uint64_t>();
      else if (key == std::string("oldestTimestamp")) stats->m_oldest_timestamp = it->second.get_value<uint64_t>();
      else if (key == std::string("histo")) {
        // TODO implement histogram deserialization
      }
    }
  }

  rapidjson::Value monero_tx_pool_stats::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_num_txs != boost::none) monero_utils::add_json_member("numTxs", m_num_txs.get(), allocator, root, value_num);
    if (m_num_not_relayed != boost::none) monero_utils::add_json_member("numNotRelayed", m_num_not_relayed.get(), allocator, root, value_num);
    if (m_num_failing != boost::none) monero_utils::add_json_member("numFailing", m_num_failing.get(), allocator, root, value_num);
    if (m_num_double_spends != boost::none) monero_utils::add_json_member("numDoubleSpends", m_num_double_spends.get(), allocator, root, value_num);
    if (m_num10m != boost::none) monero_utils::add_json_member("num10m", m_num10m.get(), allocator, root, value_num);
    if (m_fee_total != boost::none) monero_utils::add_json_member("feeTotal", m_fee_total.get(), allocator, root, value_num);
    if (m_bytes_max != boost::none) monero_utils::add_json_member("bytesMax", m_bytes_max.get(), allocator, root, value_num);
    if (m_bytes_med != boost::none) monero_utils::add_json_member("bytesMed", m_bytes_med.get(), allocator, root, value_num);
    if (m_bytes_min != boost::none) monero_utils::add_json_member("bytesMin", m_bytes_min.get(), allocator, root, value_num);
    if (m_bytes_total != boost::none) monero_utils::add_json_member("bytesTotal", m_bytes_total.get(), allocator, root, value_num);
    if (m_histo98pc != boost::none) monero_utils::add_json_member("histo98pc", m_histo98pc.get(), allocator, root, value_num);
    if (m_oldest_timestamp != boost::none) monero_utils::add_json_member("oldestTimestamp", m_oldest_timestamp.get(), allocator, root, value_num);

    // set object values
    rapidjson::Value histo(rapidjson::kObjectType);
    for(const auto& kv : m_histo) {
      std::string key = std::to_string(kv.first);
      rapidjson::Value field_key(key.c_str(), key.size(), allocator);
      histo.AddMember(field_key, kv.second, allocator);
    }
    root.AddMember("histo", histo, allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO DAEMON UPDATE CHECK RESULT ---------------------------

  void monero_daemon_update_check_result::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_check_result>& check) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("isUpdateAvailable")) check->m_is_update_available = it->second.get_value<bool>();
      else if (key == std::string("version") && !it->second.data().empty()) check->m_version = it->second.data();
      else if (key == std::string("hash") && !it->second.data().empty()) check->m_hash = it->second.data();
      else if (key == std::string("autoUri") && !it->second.data().empty()) check->m_auto_uri = it->second.data();
      else if (key == std::string("userUri") && !it->second.data().empty()) check->m_user_uri = it->second.data();
    }
  }

  rapidjson::Value monero_daemon_update_check_result::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_version != boost::none) monero_utils::add_json_member("version", m_version.get(), allocator, root, value_str);
    if (m_hash != boost::none) monero_utils::add_json_member("hash", m_hash.get(), allocator, root, value_str);
    if (m_auto_uri != boost::none) monero_utils::add_json_member("autoUri", m_auto_uri.get(), allocator, root, value_str);
    if (m_user_uri != boost::none) monero_utils::add_json_member("userUri", m_user_uri.get(), allocator, root, value_str);

    // set bool values
    if (m_is_update_available != boost::none) monero_utils::add_json_member("isUpdateAvailable", m_is_update_available.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO DAEMON UPDATE DOWNLOAD RESULT ---------------------------

  void monero_daemon_update_download_result::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_download_result>& check) {
    monero_daemon_update_check_result::from_property_tree(node, check);

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("downloadPath") && !it->second.data().empty()) check->m_download_path = it->second.data();
    }
  }

  rapidjson::Value monero_daemon_update_download_result::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root = monero_daemon_update_check_result::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_download_path != boost::none) monero_utils::add_json_member("downloadPath", m_download_path.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO FEE ESTIMATE ---------------------------

  void monero_fee_estimate::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_fee_estimate>& estimate) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("fee")) estimate->m_fee = it->second.get_value<uint64_t>();
      else if (key == std::string("quantizationMask")) estimate->m_quantization_mask = it->second.get_value<uint64_t>();
      else if (key == std::string("fees")) {
        auto node2 = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = node2.begin(); it2 != node2.end(); ++it2) {
          uint64_t fee = it2->second.get_value<uint64_t>();
          estimate->m_fees.push_back(fee);
        }
      }
    }
  }

  rapidjson::Value monero_fee_estimate::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_fee != boost::none) monero_utils::add_json_member("fee", m_fee.get(), allocator, root, value_num);
    if (m_quantization_mask != boost::none) monero_utils::add_json_member("quantizationMask", m_quantization_mask.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_fees.empty()) root.AddMember("fees", monero_utils::to_rapidjson_val(allocator, m_fees), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO DAEMON INFO ---------------------------

  void monero_daemon_info::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_info>& info) {
    monero_rpc_payment_info::from_property_tree(node, info);

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("version")) info->m_version = it->second.data();
      else if (key == std::string("numAltBlocks")) info->m_num_alt_blocks = it->second.get_value<uint64_t>();
      else if (key == std::string("blockSizeLimit")) info->m_block_size_limit = it->second.get_value<uint64_t>();
      else if (key == std::string("blockSizeMedian")) info->m_block_size_median = it->second.get_value<uint64_t>();
      else if (key == std::string("blockWeightLimit")) info->m_block_weight_limit = it->second.get_value<uint64_t>();
      else if (key == std::string("blockWeightMedian")) info->m_block_weight_median = it->second.get_value<uint64_t>();
      else if (key == std::string("bootstrapDaemonAddress") && !it->second.data().empty()) info->m_bootstrap_daemon_address = it->second.data();
      else if (key == std::string("difficultyLow")) info->m_difficulty_low = it->second.get_value<uint64_t>();
      else if (key == std::string("difficultyHigh")) info->m_difficulty_high = it->second.get_value<uint64_t>();
      else if (key == std::string("cumulativeDifficultyLow")) info->m_cumulative_difficulty_low = it->second.get_value<uint64_t>();
      else if (key == std::string("cumulativeDifficultyHigh")) info->m_cumulative_difficulty_high = it->second.get_value<uint64_t>();
      else if (key == std::string("freeSpace")) info->m_free_space = it->second.get_value<uint64_t>();
      else if (key == std::string("numOfflinePeers")) info->m_num_offline_peers = it->second.get_value<int>();
      else if (key == std::string("numOnlinePeers")) info->m_num_online_peers = it->second.get_value<int>();
      else if (key == std::string("height")) info->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("heightWithoutBootstrap")) info->m_height_without_bootstrap = it->second.get_value<uint64_t>();
      else if (key == std::string("networkType")) {
        uint8_t nettype = it->second.get_value<uint8_t>();
        if (nettype == 0) info->m_network_type = monero::monero_network_type::MAINNET;
        else if (nettype == 1) info->m_network_type = monero::monero_network_type::TESTNET;
        else if (nettype == 2) info->m_network_type = monero::monero_network_type::STAGENET;
        else throw std::runtime_error("Could not deserialize daemon info: invalid network type " + std::to_string(nettype));
      }
      else if (key == std::string("isOffline")) info->m_is_offline = it->second.get_value<bool>();
      else if (key == std::string("numIncomingConnections")) info->m_num_incoming_connections = it->second.get_value<int>();
      else if (key == std::string("numOutgoingConnections")) info->m_num_outgoing_connections = it->second.get_value<int>();
      else if (key == std::string("numRpcConnections")) info->m_num_rpc_connections = it->second.get_value<int>();
      else if (key == std::string("startTimestamp")) info->m_start_timestamp = it->second.get_value<uint64_t>();
      else if (key == std::string("adjustedTimestamp")) info->m_adjusted_timestamp = it->second.get_value<uint64_t>();
      else if (key == std::string("target")) info->m_target = it->second.get_value<uint64_t>();
      else if (key == std::string("targetHeight")) info->m_target_height = it->second.get_value<uint64_t>();
      else if (key == std::string("numTxs")) info->m_num_txs = it->second.get_value<int>();
      else if (key == std::string("numTxsPool")) info->m_num_txs_pool = it->second.get_value<int>();
      else if (key == std::string("wasBootstrapEverUsed")) info->m_was_bootstrap_ever_used = it->second.get_value<bool>();
      else if (key == std::string("databaseSize")) info->m_database_size = it->second.get_value<uint64_t>();
      else if (key == std::string("updateAvailable")) info->m_update_available = it->second.get_value<bool>();
      else if (key == std::string("isBusySyncing")) info->m_is_busy_syncing = it->second.get_value<bool>();
      else if (key == std::string("isSynchronized")) info->m_is_synchronized = it->second.get_value<bool>();
      else if (key == std::string("isRestricted")) info->m_is_restricted = it->second.get_value<bool>();
    }
  }

  rapidjson::Value monero_daemon_info::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root = monero_rpc_payment_info::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_version != boost::none) monero_utils::add_json_member("version", m_version.get(), allocator, root, value_str);
    if (m_bootstrap_daemon_address != boost::none) monero_utils::add_json_member("bootstrapDaemonAddress", m_bootstrap_daemon_address.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_num_alt_blocks != boost::none) monero_utils::add_json_member("numAltBlocks", m_num_alt_blocks.get(), allocator, root, value_num);
    if (m_block_size_limit != boost::none) monero_utils::add_json_member("blockSizeLimit", m_block_size_limit.get(), allocator, root, value_num);
    if (m_block_size_median != boost::none) monero_utils::add_json_member("blockSizeMedian", m_block_size_median.get(), allocator, root, value_num);
    if (m_block_weight_limit != boost::none) monero_utils::add_json_member("blockWeightLimit", m_block_weight_limit.get(), allocator, root, value_num);
    if (m_block_weight_median != boost::none) monero_utils::add_json_member("blockWeightMedian", m_block_weight_median.get(), allocator, root, value_num);
    if (m_difficulty_low != boost::none) monero_utils::add_json_member("difficultyLow", m_difficulty_low.get(), allocator, root, value_num);
    if (m_difficulty_high != boost::none) monero_utils::add_json_member("difficultyHigh", m_difficulty_high.get(), allocator, root, value_num);
    if (m_cumulative_difficulty_low != boost::none) monero_utils::add_json_member("cumulativeDifficultyLow", m_cumulative_difficulty_low.get(), allocator, root, value_num);
    if (m_cumulative_difficulty_high != boost::none) monero_utils::add_json_member("cumulativeDifficultyHigh", m_cumulative_difficulty_high.get(), allocator, root, value_num);
    if (m_free_space != boost::none) monero_utils::add_json_member("freeSpace", m_free_space.get(), allocator, root, value_num);
    if (m_num_offline_peers != boost::none) monero_utils::add_json_member("numOfflinePeers", m_num_offline_peers.get(), allocator, root, value_num);
    if (m_num_online_peers != boost::none) monero_utils::add_json_member("numOnlinePeers", m_num_online_peers.get(), allocator, root, value_num);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);
    if (m_height_without_bootstrap != boost::none) monero_utils::add_json_member("heightWithoutBootstrap", m_height_without_bootstrap.get(), allocator, root, value_num);
    if (m_network_type != boost::none) monero_utils::add_json_member("networkType", (uint8_t)m_network_type.get(), allocator, root, value_num);
    if (m_num_incoming_connections != boost::none) monero_utils::add_json_member("numIncomingConnections", m_num_incoming_connections.get(), allocator, root, value_num);
    if (m_num_outgoing_connections != boost::none) monero_utils::add_json_member("numOutgoingConnections", m_num_outgoing_connections.get(), allocator, root, value_num);
    if (m_num_rpc_connections != boost::none) monero_utils::add_json_member("numRpcConnections", m_num_rpc_connections.get(), allocator, root, value_num);
    if (m_start_timestamp != boost::none) monero_utils::add_json_member("startTimestamp", m_start_timestamp.get(), allocator, root, value_num);
    if (m_adjusted_timestamp != boost::none) monero_utils::add_json_member("adjustedTimestamp", m_adjusted_timestamp.get(), allocator, root, value_num);
    if (m_target != boost::none) monero_utils::add_json_member("target", m_target.get(), allocator, root, value_num);
    if (m_target_height != boost::none) monero_utils::add_json_member("targetHeight", m_target_height.get(), allocator, root, value_num);
    if (m_num_txs != boost::none) monero_utils::add_json_member("numTxs", m_num_txs.get(), allocator, root, value_num);
    if (m_num_txs_pool != boost::none) monero_utils::add_json_member("numTxsPool", m_num_txs_pool.get(), allocator, root, value_num);
    if (m_database_size != boost::none) monero_utils::add_json_member("databaseSize", m_database_size.get(), allocator, root, value_num);

    // set bool values
    if (m_is_offline != boost::none) monero_utils::add_json_member("isOffline", m_is_offline.get(), allocator, root);
    if (m_was_bootstrap_ever_used != boost::none) monero_utils::add_json_member("wasBootstrapEverUsed", m_was_bootstrap_ever_used.get(), allocator, root);
    if (m_update_available != boost::none) monero_utils::add_json_member("updateAvailable", m_update_available.get(), allocator, root);
    if (m_is_busy_syncing != boost::none) monero_utils::add_json_member("isBusySyncing", m_is_busy_syncing.get(), allocator, root);
    if (m_is_synchronized != boost::none) monero_utils::add_json_member("isSynchronized", m_is_synchronized.get(), allocator, root);
    if (m_is_restricted != boost::none) monero_utils::add_json_member("isRestricted", m_is_restricted.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO DAEMON SYNC INFO ---------------------------

  void monero_daemon_sync_info::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_sync_info>& info) {
    monero_rpc_payment_info::from_property_tree(node, info);

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("height")) info->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("targetHeight")) info->m_target_height = it->second.get_value<uint64_t>();
      else if (key == std::string("nextNeededPruningSeed")) info->m_next_needed_pruning_seed = it->second.get_value<int>();
      else if (key == std::string("overview") && !it->second.data().empty() && it->second.data() != std::string("[]")) info->m_overview = it->second.data();
    }
  }

  rapidjson::Value monero_daemon_sync_info::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root = monero_rpc_payment_info::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_overview != boost::none) monero_utils::add_json_member("overview", m_overview.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);
    if (m_target_height != boost::none) monero_utils::add_json_member("targetHeight", m_target_height.get(), allocator, root, value_num);
    if (m_next_needed_pruning_seed != boost::none) monero_utils::add_json_member("nextNeededPruningSeed", m_next_needed_pruning_seed.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_peers.empty()) root.AddMember("peers", monero_utils::to_rapidjson_val(allocator, m_peers), allocator);
    if (!m_spans.empty()) root.AddMember("spans", monero_utils::to_rapidjson_val(allocator, m_spans), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO HARD FORK INFO ---------------------------

  void monero_hard_fork_info::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_hard_fork_info>& info) {
    monero_rpc_payment_info::from_property_tree(node, info);

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("earliestHeight")) info->m_earliest_height = it->second.get_value<uint64_t>();
      else if (key == std::string("isEnabled")) info->m_is_enabled = it->second.get_value<bool>();
      else if (key == std::string("state")) info->m_state = it->second.get_value<int>();
      else if (key == std::string("threshold")) info->m_threshold = it->second.get_value<int>();
      else if (key == std::string("version")) info->m_version = it->second.get_value<int>();
      else if (key == std::string("numVotes")) info->m_num_votes = it->second.get_value<int>();
      else if (key == std::string("window")) info->m_window = it->second.get_value<int>();
      else if (key == std::string("voting")) info->m_voting = it->second.get_value<int>();
    }
  }

  rapidjson::Value monero_hard_fork_info::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root = monero_rpc_payment_info::to_rapidjson_val(allocator);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_earliest_height != boost::none) monero_utils::add_json_member("earliestHeight", m_earliest_height.get(), allocator, root, value_num);
    if (m_state != boost::none) monero_utils::add_json_member("state", m_state.get(), allocator, root, value_num);
    if (m_threshold != boost::none) monero_utils::add_json_member("threshold", m_threshold.get(), allocator, root, value_num);
    if (m_version != boost::none) monero_utils::add_json_member("version", m_version.get(), allocator, root, value_num);
    if (m_num_votes != boost::none) monero_utils::add_json_member("numVotes", m_num_votes.get(), allocator, root, value_num);
    if (m_window != boost::none) monero_utils::add_json_member("window", m_window.get(), allocator, root, value_num);
    if (m_voting != boost::none) monero_utils::add_json_member("voting", m_voting.get(), allocator, root, value_num);

    // set bool values
    if (m_is_enabled != boost::none) monero_utils::add_json_member("isEnabled", m_is_enabled.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO GENERATE BLOCKS RESULT ---------------------------

  void monero_generate_blocks_result::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_generate_blocks_result>& result) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("blockHashes")) {
        for (const auto& child : it->second) result->m_block_hashes.push_back(child.second.data());
      }
      else if (key == std::string("height")) result->m_height = it->second.get_value<uint64_t>();
    }
  }

  rapidjson::Value monero_generate_blocks_result::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_block_hashes.empty()) root.AddMember("blockHashes", monero_utils::to_rapidjson_val(allocator, m_block_hashes), allocator);

    // return root
    return root;
  }

}
