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

#ifndef monero_utils_h
#define monero_utils_h

#include "wallet/monero_wallet_model.h"
#include "wallet/monero_wallet.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "wallet/wallet2.h"
#include "serialization/keyvalue_serialization.h" // TODO: consolidate with other binary deps?
#include "storages/portable_storage.h"

/**
 * Collection of utilities for the Monero library.
 */
namespace monero_utils
{
  using namespace cryptonote;

  // ------------------------------ CONSTANTS ---------------------------------

  static const int RING_SIZE = 12;  // network-enforced ring size
  static const uint64_t TAIL_EMISSION_REWARD = 600000000000;

  // -------------------------------- UTILS -----------------------------------

  void start_profile(const std::string& name);
  void end_profile(const std::string& name);

  void set_log_level(int level);
  void configure_logging(const std::string& path, bool console);
  monero_integrated_address get_integrated_address(monero_network_type network_type, const std::string& standard_address, const std::string& payment_id);
  bool is_valid_address(const std::string& address, monero_network_type network_type);
  bool is_valid_private_view_key(const std::string& private_view_key);
  bool is_valid_private_spend_key(const std::string& private_spend_key);
  void validate_address(const std::string& address, monero_network_type network_type);
  void validate_private_view_key(const std::string& private_view_key);
  void validate_private_spend_key(const std::string& private_spend_key);
  void json_to_binary(const std::string &json, std::string &bin);
  void binary_to_json(const std::string &bin, std::string &json);
  void binary_blocks_to_json(const std::string &bin, std::string &json);
  bool parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id);
  bool parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id);

  std::shared_ptr<monero_tx_query> decontextualize(std::shared_ptr<monero_tx_query> query);
  bool is_contextual(const monero_transfer_query& query);
  bool is_contextual(const monero_output_query& query);

  std::string make_uri(const std::string &address, cryptonote::network_type nettype, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error);
  bool parse_uri(const std::string &uri, std::string &address, cryptonote::network_type nettype, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error);

  /**
  * Merges a transaction into a unique set of transactions.
  *
  * @param tx is the transaction to merge into the existing txs
  * @param tx_map maps tx hashes to txs
  * @param block_map maps block heights to blocks
  */
  void merge_tx(const std::shared_ptr<monero_tx_wallet>& tx, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map);

  // ------------------------------ RAPIDJSON ---------------------------------

  std::string serialize(const rapidjson::Document& doc);

  /**
   * Add number, string, and boolean json members using template specialization.
   *
   * TODO: add_json_member("key", "val", ...) treated as integer instead of string literal
   */
  template <class T>
  void add_json_member(std::string key, T val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field) {
    rapidjson::Value field_key(key.c_str(), key.size(), allocator);
    field.SetInt64((uint64_t) val);
    root.AddMember(field_key, field, allocator);
  }
  void add_json_member(std::string key, std::string val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field);
  void add_json_member(std::string key, bool val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root);

  // TODO: template implementation here, could move to monero_utils.hpp per https://stackoverflow.com/questions/3040480/c-template-function-compiles-in-header-but-not-implementation
  template <class T> rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::shared_ptr<T>>& vals) {
    rapidjson::Value value_arr(rapidjson::kArrayType);
    for (const auto& val : vals) {
      value_arr.PushBack(val->to_rapidjson_val(allocator), allocator);
    }
    return value_arr;
  }

  // TODO: template implementation here, could move to monero_utils.hpp per https://stackoverflow.com/questions/3040480/c-template-function-compiles-in-header-but-not-implementation
  template <class T> rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<T>& vals) {
    rapidjson::Value value_arr(rapidjson::kArrayType);
    for (const auto& val : vals) {
      value_arr.PushBack(val.to_rapidjson_val(allocator), allocator);
    }
    return value_arr;
  }

  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::string>& strs);
  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint8_t>& nums);
  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint32_t>& nums);
  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint64_t>& nums);

  // ------------------------ PROPERTY TREES ---------------------------

  // TODO: fully switch from property trees to rapidjson

  std::string serialize(const boost::property_tree::ptree& node);
  void deserialize(const std::string& json, boost::property_tree::ptree& root);

  // --------------------------------------------------------------------------

  /**
   * Indicates if the given language is valid.
   *
   * @param language is the language to validate
   * @return true if the language is valid, false otherwise
   */
  bool is_valid_language(const std::string& language);

  /**
   * Convert a cryptonote::block to a block in this library's native model.
   *
   * @param cn_block is the block to convert
   * @return a block in this library's native model
   */
  std::shared_ptr<monero_block> cn_block_to_block(const cryptonote::block& cn_block);

  /**
   * Convert a cryptonote::transaction to a transaction in this library's
   * native model.
   *
   * @param cn_tx is the transaction to convert
   * @param init_as_tx_wallet specifies if a monero_tx xor monero_tx_wallet should be initialized
   */
  std::shared_ptr<monero_tx> cn_tx_to_tx(const cryptonote::transaction& cn_tx, bool init_as_tx_wallet = false);

  std::shared_ptr<monero_tx_wallet> ptx_to_tx(const tools::wallet2::pending_tx &ptx, cryptonote::network_type nettype, monero_wallet* wallet);

  /**
   * Modified from core_rpc_server.cpp to return a std::string.
   *
   * TODO: remove this duplicate, use core_rpc_server instead
   */
  static std::string get_pruned_tx_json(cryptonote::transaction &tx) {
    std::stringstream ss;
    json_archive<true> ar(ss);
    bool r = tx.serialize_base(ar);
    CHECK_AND_ASSERT_MES(r, std::string(), "Failed to serialize rct signatures base");
    return ss.str();
  }

  void add_pid_to_tx_extra(const boost::optional<std::string>& payment_id_string, std::vector<uint8_t> &extra);

  bool rct_hex_to_decrypted_mask(const std::string &rct_string, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask);

  bool rct_hex_to_rct_commit(const std::string &rct_string, rct::key &rct_commit);

  static std::string dump_ptx(const tools::wallet2::pending_tx &ptx) {
    std::ostringstream oss;
    boost::archive::portable_binary_oarchive ar(oss);
    try
    {
      ar << ptx;
    }
    catch (...)
    {
      return "";
    }
    return epee::string_tools::buff_to_hex_nodelimer(oss.str());
  }

  // ----------------------------- GATHER BLOCKS ------------------------------

  static std::vector<std::shared_ptr<monero_block>> get_blocks_from_txs(std::vector<std::shared_ptr<monero_tx_wallet>> txs) {
    std::shared_ptr<monero_block> unconfirmed_block = nullptr; // placeholder for unconfirmed txs
    std::vector<std::shared_ptr<monero_block>> blocks;
    std::unordered_set<std::shared_ptr<monero_block>> seen_block_ptrs;
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      if (tx->m_block == boost::none) {
        if (unconfirmed_block == nullptr) unconfirmed_block = std::make_shared<monero_block>();
        tx->m_block = unconfirmed_block;
        unconfirmed_block->m_txs.push_back(tx);
      }
      std::unordered_set<std::shared_ptr<monero_block>>::const_iterator got = seen_block_ptrs.find(tx->m_block.get());
      if (got == seen_block_ptrs.end()) {
        seen_block_ptrs.insert(tx->m_block.get());
        blocks.push_back(tx->m_block.get());
      }
    }
    return blocks;
  }

  static std::vector<std::shared_ptr<monero_block>> get_blocks_from_transfers(std::vector<std::shared_ptr<monero_transfer>> transfers) {
    std::shared_ptr<monero_block> unconfirmed_block = nullptr; // placeholder for unconfirmed txs in return json
    std::vector<std::shared_ptr<monero_block>> blocks;
    std::unordered_set<std::shared_ptr<monero_block>> seen_block_ptrs;
    for (auto const& transfer : transfers) {
      std::shared_ptr<monero_tx_wallet> tx = transfer->m_tx;
      if (tx->m_block == boost::none) {
        if (unconfirmed_block == nullptr) unconfirmed_block = std::make_shared<monero_block>();
        tx->m_block = unconfirmed_block;
        unconfirmed_block->m_txs.push_back(tx);
      }
      std::unordered_set<std::shared_ptr<monero_block>>::const_iterator got = seen_block_ptrs.find(tx->m_block.get());
      if (got == seen_block_ptrs.end()) {
        seen_block_ptrs.insert(tx->m_block.get());
        blocks.push_back(tx->m_block.get());
      }
    }
    return blocks;
  }

  static std::vector<std::shared_ptr<monero_block>> get_blocks_from_outputs(std::vector<std::shared_ptr<monero_output_wallet>> outputs) {
    std::vector<std::shared_ptr<monero_block>> blocks;
    std::unordered_set<std::shared_ptr<monero_block>> seen_block_ptrs;
    for (auto const& output : outputs) {
      std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(output->m_tx);
      if (tx->m_block == boost::none) throw std::runtime_error("Need to handle unconfirmed output");
      std::unordered_set<std::shared_ptr<monero_block>>::const_iterator got = seen_block_ptrs.find(*tx->m_block);
      if (got == seen_block_ptrs.end()) {
        seen_block_ptrs.insert(*tx->m_block);
        blocks.push_back(*tx->m_block);
      }
    }
    return blocks;
  }

  // compute m_num_suggested_confirmations  TODO monero-project: this logic is based on wallet_rpc_server.cpp `set_confirmations` but it should be encapsulated in wallet2
  static void set_num_suggested_confirmations(std::shared_ptr<monero_incoming_transfer>& incoming_transfer, uint64_t blockchain_height, uint64_t block_reward, uint64_t unlock_time) {    
    if (block_reward == 0) incoming_transfer->m_num_suggested_confirmations = 0;
    else incoming_transfer->m_num_suggested_confirmations = (incoming_transfer->m_amount.get() + block_reward - 1) / block_reward;
    
    if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER) {
      if (unlock_time > blockchain_height) incoming_transfer->m_num_suggested_confirmations = std::max(incoming_transfer->m_num_suggested_confirmations.get(), unlock_time - blockchain_height);
    } else {
      const uint64_t now = time(NULL);
      if (unlock_time > now) incoming_transfer->m_num_suggested_confirmations = std::max(incoming_transfer->m_num_suggested_confirmations.get(), (unlock_time - now + DIFFICULTY_TARGET_V2 - 1) / DIFFICULTY_TARGET_V2);
    }
  }

  /**
   * Returns true iff tx1's height is known to be less than tx2's height for sorting.
   */
  static bool tx_height_less_than(const std::shared_ptr<monero_tx>& tx1, const std::shared_ptr<monero_tx>& tx2) {
    if (tx1->m_block != boost::none && tx2->m_block != boost::none) return tx1->get_height() < tx2->get_height();
    else if (tx1->m_block == boost::none) return false;
    else return true;
  }

  /**
   * Returns true iff transfer1 is ordered before transfer2 by ascending account and subaddress indices.
   */
  static bool incoming_transfer_before(const std::shared_ptr<monero_incoming_transfer>& transfer1, const std::shared_ptr<monero_incoming_transfer>& transfer2) {

    // compare by height
    if (tx_height_less_than(transfer1->m_tx, transfer2->m_tx)) return true;

    // compare by account and subaddress index
    if (transfer1->m_account_index.get() < transfer2->m_account_index.get()) return true;
    else if (transfer1->m_account_index.get() == transfer2->m_account_index.get()) return transfer1->m_subaddress_index.get() < transfer2->m_subaddress_index.get();
    else return false;
  }

  /**
   * Returns true iff wallet vout1 is ordered before vout2 by ascending account and subaddress indices then index.
   */
  static bool vout_before(const std::shared_ptr<monero_output>& o1, const std::shared_ptr<monero_output>& o2) {
    if (o1 == o2) return false; // ignore equal references
    std::shared_ptr<monero_output_wallet> ow1 = std::dynamic_pointer_cast<monero_output_wallet>(o1);
    std::shared_ptr<monero_output_wallet> ow2 = std::dynamic_pointer_cast<monero_output_wallet>(o2);
    if (ow1 == nullptr) return true;
    if (ow1 == nullptr) return false;
    // compare by height
    if (tx_height_less_than(ow1->m_tx, ow2->m_tx)) return true;

    // compare by account index, subaddress index, output index, then key image hex
    if (ow1->m_account_index.get() < ow2->m_account_index.get()) return true;
    if (ow1->m_account_index.get() == ow2->m_account_index.get()) {
      if (ow1->m_subaddress_index.get() < ow2->m_subaddress_index.get()) return true;
      if (ow1->m_subaddress_index.get() == ow2->m_subaddress_index.get()) {
        if (ow1->m_index.get() < ow2->m_index.get()) return true;
        if (ow1->m_index.get() == ow2->m_index.get()) throw std::runtime_error("Should never sort outputs with duplicate indices");
      }
    }
    return false;
  }

  // ------------------------------ FREE MEMORY -------------------------------

  static void free(std::shared_ptr<monero_block> block) {
    for (std::shared_ptr<monero_tx>& tx : block->m_txs) {
      tx->m_block->reset();
      monero_tx_wallet* tx_wallet = dynamic_cast<monero_tx_wallet*>(tx.get());
      if (tx_wallet != nullptr) {
        if (tx_wallet->m_tx_set != boost::none) tx_wallet->m_tx_set->reset();
        if (tx_wallet->m_outgoing_transfer != boost::none) tx_wallet->m_outgoing_transfer.get()->m_tx.reset();
        for (std::shared_ptr<monero_transfer> transfer : tx_wallet->m_incoming_transfers) transfer->m_tx.reset();
        for (std::shared_ptr<monero_output> output : tx_wallet->m_outputs) output->m_tx.reset();
        for (std::shared_ptr<monero_output> input : tx_wallet->m_inputs) {
          input->m_key_image.reset();
          input->m_tx.reset();
        }
      }
      monero_tx_query* tx_query = dynamic_cast<monero_tx_query*>(tx.get());
      if (tx_query != nullptr) {
        if (tx_query->m_transfer_query != boost::none) {
          tx_query->m_transfer_query.get()->m_tx_query->reset();
          tx_query->m_transfer_query.get().reset();
        }
        if (tx_query->m_output_query != boost::none) {
          tx_query->m_output_query.get()->m_tx_query->reset();
          tx_query->m_output_query.get().reset();
        }
      }
    }
    block.reset();
  }

  static void free(std::vector<std::shared_ptr<monero_block>> blocks) {
    for (std::shared_ptr<monero_block>& block : blocks) monero_utils::free(block);
  }

  static void free(std::shared_ptr<monero_tx> tx) {
    if (tx->m_block == boost::none) {
      std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
      tx->m_block = block;
      block->m_txs.push_back(tx);
    }
    monero_utils::free(tx->m_block.get());
  }

  static void free(std::vector<std::shared_ptr<monero_tx_wallet>> txs) {
    return monero_utils::free(monero_utils::get_blocks_from_txs(txs));
  }

  static void free(std::vector<std::shared_ptr<monero_transfer>> transfers) {
    return monero_utils::free(monero_utils::get_blocks_from_transfers(transfers));
  }

  static void free(std::vector<std::shared_ptr<monero_output_wallet>> outputs) {
    return monero_utils::free(monero_utils::get_blocks_from_outputs(outputs));
  }


  template<typename T>
  T pop_index(std::vector<T>& vec, size_t idx)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

    T res = std::move(vec[idx]);
    if (idx + 1 != vec.size()) {
      vec[idx] = std::move(vec.back());
    }
    vec.resize(vec.size() - 1);
    
    return res;
  }
  //
  template<typename T>
  T pop_random_value(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    
    size_t idx = crypto::rand<size_t>() % vec.size();
    return pop_index (vec, idx);
  }
}
#endif /* monero_utils_h */
