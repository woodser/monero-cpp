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
#include "wallet/wallet_rpc_server_commands_defs.h"
#include "wallet/wallet_errors.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "serialization/keyvalue_serialization.h" // TODO: consolidate with other binary deps?
#include "storages/portable_storage.h"
#include "wallet/wallet2.h"

/**
 * Collection of utilities for the Monero library.
 */
namespace monero_utils
{
  using namespace cryptonote;

  // ------------------------------ CONSTANTS ---------------------------------

  static const int RING_SIZE = 12;  // network-enforced ring size

  // -------------------------------- UTILS -----------------------------------

  struct key_image_list
  {
    std::list<std::string> key_images;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(key_images)
    END_KV_SERIALIZE_MAP()
  };
  
  std::shared_ptr<monero_tx_query> decontextualize(std::shared_ptr<monero_tx_query> query);
  bool is_contextual(const monero_transfer_query& query);
  bool is_contextual(const monero_output_query& query);
  bool bool_equals(bool val, const boost::optional<bool>& opt_val);
  void set_num_confirmations(std::shared_ptr<monero_tx_wallet>& tx, uint64_t blockchain_height);
  void set_num_suggested_confirmations(std::shared_ptr<monero_incoming_transfer>& incoming_transfer, uint64_t blockchain_height, uint64_t block_reward, uint64_t unlock_time);
  std::shared_ptr<monero_tx_wallet> build_tx_with_incoming_transfer(tools::wallet2& m_w2, uint64_t height, const crypto::hash &payment_id, const tools::wallet2::payment_details &pd);
  std::shared_ptr<monero_tx_wallet> build_tx_with_outgoing_transfer(tools::wallet2& m_w2, uint64_t height, const crypto::hash &txid, const tools::wallet2::confirmed_transfer_details &pd);
  std::shared_ptr<monero_tx_wallet> build_tx_with_incoming_transfer_unconfirmed(const tools::wallet2& m_w2, uint64_t height, const crypto::hash &payment_id, const tools::wallet2::pool_payment_details &ppd);
  std::shared_ptr<monero_tx_wallet> build_tx_with_outgoing_transfer_unconfirmed(const tools::wallet2& m_w2, const crypto::hash &txid, const tools::wallet2::unconfirmed_transfer_details &pd);
  std::shared_ptr<monero_tx_wallet> build_tx_with_vout(tools::wallet2& m_w2, const tools::wallet2::transfer_details& td);
  void merge_tx(const std::shared_ptr<monero_tx_wallet>& tx, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map);
  bool tx_height_less_than(const std::shared_ptr<monero_tx>& tx1, const std::shared_ptr<monero_tx>& tx2);
  bool incoming_transfer_before(const std::shared_ptr<monero_incoming_transfer>& transfer1, const std::shared_ptr<monero_incoming_transfer>& transfer2);
  bool vout_before(const std::shared_ptr<monero_output>& o1, const std::shared_ptr<monero_output>& o2);
  std::string get_default_ringdb_path(cryptonote::network_type nettype);

  bool validate_transfer(tools::wallet2* m_w2, const std::list<tools::wallet_rpc::transfer_destination>& destinations, const std::string& payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, bool at_least_one_destination, epee::json_rpc::error& er);
  std::string ptx_to_string(const tools::wallet2::pending_tx &ptx);
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T> bool is_error_value(const T &val) { return false; }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  bool fill(T &where, V s)
  {
    if (is_error_value(s)) return false;
    where = std::move(s);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  bool fill(std::list<T> &where, V s)
  {
    if (is_error_value(s)) return false;
    where.emplace_back(std::move(s));
    return true;
  }
  uint64_t total_amount(const tools::wallet2::pending_tx &ptx);

  static bool is_uint64_t(const std::string& str) {
    try {
      size_t sz;
      std::stol(str, &sz);
      return sz == str.size();
    } 
    catch (const std::invalid_argument&) {
      // if no conversion could be performed.
      return false;   
    } 
    catch (const std::out_of_range&) {
      //  if the converted value would fall out of the range of the result type.
      return false;
    }
  }

  static uint64_t uint64_t_cast(const std::string& str) {
    if (!monero_utils::is_uint64_t(str)) {
      throw std::out_of_range("String provided is not a valid uint64_t");
    }

    uint64_t value;
    
    std::istringstream itr(str);

    itr >> value;

    return value;
  }
  
  std::string tx_hex_to_hash(std::string hex);

  bool is_error_value(const std::string &s);

  //------------------------------------------------------------------------------------------------------------------------------
  template<typename Ts, typename Tu, typename Tk, typename Ta>
  bool fill_response(tools::wallet2* m_w2, std::vector<tools::wallet2::pending_tx> &ptx_vector,
      bool get_tx_key, Ts& tx_key, Tu &amount, Ta &amounts_by_dest, Tu &fee, Tu &weight, std::string &multisig_txset, std::string &unsigned_txset, bool do_not_relay,
      Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata, Tk &spent_key_images, epee::json_rpc::error &er)
  {
    for (const auto & ptx : ptx_vector)
    {
      if (get_tx_key)
      {
        epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
          s += epee::to_hex::wipeable_string(additional_tx_key);
        fill(tx_key, std::string(s.data(), s.size()));
      }
      // Compute amount leaving wallet in tx. By convention dests does not include change outputs
      fill(amount, total_amount(ptx));
      fill(fee, ptx.fee);
      fill(weight, cryptonote::get_transaction_weight(ptx.tx));

      // add amounts by destination
      tools::wallet_rpc::amounts_list abd;
      for (const auto& dst : ptx.dests)
        abd.amounts.push_back(dst.amount);
      fill(amounts_by_dest, abd);

      // add spent key images
      key_image_list key_image_list;
      bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
      {
        CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
        key_image_list.key_images.push_back(epee::string_tools::pod_to_hex(in.k_image));
        return true;
      });
      THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, tools::error::unexpected_txin_type, ptx.tx);
      fill(spent_key_images, key_image_list);
    }

    if (m_w2->multisig())
    {
      multisig_txset = epee::string_tools::buff_to_hex_nodelimer(m_w2->save_multisig_tx(ptx_vector));
      if (multisig_txset.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to save multisig tx set after creation";
        return false;
      }
    }
    else
    {
      if (m_w2->watch_only()){
        unsigned_txset = epee::string_tools::buff_to_hex_nodelimer(m_w2->dump_tx_to_str(ptx_vector));
        if (unsigned_txset.empty())
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to save unsigned tx set after creation";
          return false;
        }
      }
      else if (!do_not_relay)
        m_w2->commit_tx(ptx_vector);

      // populate response with tx hashes
      for (auto & ptx : ptx_vector)
      {
        bool r = fill(tx_hash, epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
        r = r && (!get_tx_hex || fill(tx_blob, epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx))));
        r = r && (!get_tx_metadata || fill(tx_metadata, ptx_to_string(ptx)));
        if (!r)
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to save tx info";
          return false;
        }
      }
    }
    return true;
  }

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

  /**
   * Modified from core_rpc_server.cpp to return a std::string.
   *
   * TODO: remove this duplicate, use core_rpc_server instead
   */
  static std::string get_pruned_tx_json(cryptonote::transaction &tx)
  {
    std::stringstream ss;
    json_archive<true> ar(ss);
    bool r = tx.serialize_base(ar);
    CHECK_AND_ASSERT_MES(r, std::string(), "Failed to serialize rct signatures base");
    return ss.str();
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
}
#endif /* monero_utils_h */
