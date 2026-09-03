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

#include "monero_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "string_tools.h"
#include "byte_stream.h"
#include "gen_utils.h"

using namespace cryptonote;
using namespace monero_utils;

// ----------------------- INTERNAL PRIVATE HELPERS -----------------------

namespace {
  // shared by monero_utils::binary_blocks_to_json() and monero_utils::binary_blocks_fast_to_json()
  void add_blocks_and_txs_to_ptree(const std::vector<cryptonote::block_complete_entry>& blocks, boost::property_tree::ptree& root) {
    boost::property_tree::ptree blocksNode; // array of block strings
    boost::property_tree::ptree txsNodes;   // array of txs per block (array of array)
    boost::property_tree::ptree hashesNode; // array of block hashes
    for (int blockIdx = 0; blockIdx < blocks.size(); blockIdx++) {

      // parse and validate block
      cryptonote::block block;
      if (cryptonote::parse_and_validate_block_from_blob(blocks[blockIdx].block, block)) {

        // add block node to blocks node
        boost::property_tree::ptree blockNode;
        blockNode.put("", cryptonote::obj_to_json_str(block));  // TODO: no pretty print
        blocksNode.push_back(std::make_pair("", blockNode));

        // compute block's hash and add to hashes node in parallel
        boost::property_tree::ptree hashNode;
        hashNode.put("", epee::string_tools::pod_to_hex(cryptonote::get_block_hash(block)));
        hashesNode.push_back(std::make_pair("", hashNode));
      } else {
        throw std::runtime_error("failed to parse block blob at index " + std::to_string(blockIdx));
      }

      // parse and validate txs: a pruned blob only has the base (no prunable section), so it
      // must go through the base-only parser or the full parser fails on every non-miner tx
      boost::property_tree::ptree txs_node;
      for (int txIdx = 0; txIdx < blocks[blockIdx].txs.size(); txIdx++) {
        cryptonote::transaction tx;
        bool parsed = blocks[blockIdx].pruned
          ? cryptonote::parse_and_validate_tx_base_from_blob(blocks[blockIdx].txs[txIdx].blob, tx)
          : cryptonote::parse_and_validate_tx_from_blob(blocks[blockIdx].txs[txIdx].blob, tx);
        if (parsed) {

          // add tx node to txs node
          boost::property_tree::ptree txNode;
          //MTRACE("PRUNED:\n" << monero_utils::get_pruned_tx_json(tx));
          txNode.put("", monero_utils::get_pruned_tx_json(tx)); // TODO: no pretty print
          txs_node.push_back(std::make_pair("", txNode));
        } else {
          throw std::runtime_error("failed to parse tx blob at index " + std::to_string(txIdx));
        }
      }
      txsNodes.push_back(std::make_pair("", txs_node)); // array of array of transactions, one array per block
    }
    root.add_child("blocks", blocksNode);
    root.add_child("txs", txsNodes);
    root.add_child("block_hashes", hashesNode);
  }

  // shared by monero_utils::binary_blocks_to_property_tree() and monero_utils::binary_blocks_fast_to_property_tree()
  void bin_blocks_to_property_tree(const std::string &bin, boost::property_tree::ptree &node, bool is_fast) {
    std::string response_json;
    if (is_fast) monero_utils::binary_blocks_fast_to_json(bin, response_json);
    else monero_utils::binary_blocks_to_json(bin, response_json);
    std::istringstream iss(response_json);
    boost::property_tree::read_json(iss, node);

    auto blocks = node.get_child("blocks");
    auto block_hashes = node.get_child("block_hashes"); // parallel to "blocks", see add_blocks_and_txs_to_ptree()
    boost::property_tree::ptree parsed_blocks;

    auto hash_it = block_hashes.begin();
    for (auto &entry : blocks) {
      const std::string &block_str = entry.second.get_value<std::string>();
      boost::property_tree::ptree block_node;
      gen_utils::deserialize(block_str, block_node);
      if (hash_it != block_hashes.end()) {
        block_node.put("hash", hash_it->second.get_value<std::string>());
        ++hash_it;
      }
      parsed_blocks.push_back(std::make_pair("", block_node));
    }

    node.put_child("blocks", parsed_blocks);
    node.erase("block_hashes"); // merged into each block above

    auto txs = node.get_child("txs");
    boost::property_tree::ptree all_txs;

    for (auto &rpc_txs_entry : txs) {
      boost::property_tree::ptree txs_for_block;
      const auto &rpc_txs = rpc_txs_entry.second;

      if (!rpc_txs.empty() || !rpc_txs.data().empty()) {
        for (auto &tx_entry : rpc_txs) {
          std::string tx_str = tx_entry.second.get_value<std::string>();

          auto pos = tx_str.find(',');
          if (pos != std::string::npos) {
            tx_str.replace(pos, 1, "{");
            tx_str += "}";
          }

          boost::property_tree::ptree tx_node;
          gen_utils::deserialize(tx_str, tx_node);
          txs_for_block.push_back(std::make_pair("", tx_node));
        }
      }

      all_txs.push_back(std::make_pair("", txs_for_block));
    }

    node.put_child("txs", all_txs);
  }
}

void monero_utils::set_log_level(int level) {
  mlog_set_log_level(level);
}

void monero_utils::set_log_categories(const std::string& categories) {
  mlog_set_categories(categories.c_str());
}

void monero_utils::configure_logging(const std::string& path, bool console) {
  mlog_configure(path, console);
}

// --------------------------- VALIDATION UTILS -------------------------------

monero_integrated_address monero_utils::get_integrated_address(monero_network_type network_type, const std::string& standard_address, const std::string& payment_id) {

  // parse and validate address
  cryptonote::address_parse_info address_info;
  if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(network_type), standard_address)) throw std::runtime_error("Invalid address");
  if (address_info.has_payment_id) throw std::runtime_error("The given address already has a payment id");

  // randomly generate payment id if not given, else validate
  crypto::hash8 payment_id_h8;
  if (payment_id.empty()) {
    payment_id_h8 = crypto::rand<crypto::hash8>();
  } else {
    cryptonote::blobdata payment_id_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id, payment_id_data) || sizeof(crypto::hash8) != payment_id_data.size()) throw std::runtime_error("Invalid payment id");
    payment_id_h8 = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  }

  // build integrated address
  monero_integrated_address integrated_address;
  integrated_address.m_integrated_address = cryptonote::get_account_integrated_address_as_str(static_cast<cryptonote::network_type>(network_type), address_info.address, payment_id_h8);
  integrated_address.m_standard_address = standard_address;
  integrated_address.m_payment_id = epee::string_tools::pod_to_hex(payment_id_h8);
  return integrated_address;
}

bool monero_utils::is_valid_address(const std::string& address, monero_network_type network_type) {
  try {
    validate_address(address, network_type);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_private_view_key(const std::string& private_view_key) {
  try {
    validate_private_view_key(private_view_key);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_private_spend_key(const std::string& private_spend_key) {
  try {
    validate_private_spend_key(private_spend_key);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_public_view_key(const std::string& public_view_key) {
  try {
    validate_public_view_key(public_view_key);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_public_spend_key(const std::string& public_spend_key) {
  try {
    validate_public_spend_key(public_spend_key);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_payment_id(const std::string& payment_id) {
  try {
    validate_payment_id(payment_id);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_mnemonic(const std::string& mnemonic, const std::string& language) {
  try {
    validate_mnemonic(mnemonic, language);
    return true;
  }
  catch (...) {
    return false;
  }
}

void monero_utils::validate_address(const std::string& address, monero_network_type network_type) {
  cryptonote::address_parse_info info;
  if (!get_account_address_from_str(info, static_cast<cryptonote::network_type>(network_type), address)) throw std::runtime_error("Invalid address");
}

void monero_utils::validate_private_view_key(const std::string& private_view_key) {
  if (private_view_key.length() != 64) throw std::runtime_error("private view key expected to be 64 hex characters");
  cryptonote::blobdata private_view_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(private_view_key, private_view_key_data) || private_view_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("private view key expected to be 64 hex characters");
  }
}

void monero_utils::validate_private_spend_key(const std::string& private_spend_key) {
  if (private_spend_key.length() != 64) throw std::runtime_error("private spend key expected to be 64 hex characters");
  cryptonote::blobdata private_spend_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(private_spend_key, private_spend_key_data) || private_spend_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("private spend key expected to be 64 hex characters");
  }
}

void monero_utils::validate_public_view_key(const std::string& public_view_key) {
  if (public_view_key.length() != 64) throw std::runtime_error("public view key expected to be 64 hex characters");
  cryptonote::blobdata public_view_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(public_view_key, public_view_key_data) || public_view_key_data.size() != sizeof(crypto::public_key)) {
    throw std::runtime_error("public view key expected to be 64 hex characters");
  }
}

void monero_utils::validate_public_spend_key(const std::string& public_spend_key) {
  if (public_spend_key.length() != 64) throw std::runtime_error("public spend key expected to be 64 hex characters");
  cryptonote::blobdata public_spend_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(public_spend_key, public_spend_key_data) || public_spend_key_data.size() != sizeof(crypto::public_key)) {
    throw std::runtime_error("public spend key expected to be 64 hex characters");
  }
}

void monero_utils::validate_payment_id(const std::string& payment_id) {
  if (payment_id.length() != 64 && payment_id.length() != 16) throw std::runtime_error("payment id expected to be 64 or 16 hex characters");
  cryptonote::blobdata payment_id_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id, payment_id_data) || (payment_id_data.size() != sizeof(crypto::hash8) && payment_id_data.size() != sizeof(crypto::hash))) {
    throw std::runtime_error("payment id expected to be 64 or 16 hex characters");
  }
}

void monero_utils::validate_mnemonic(const std::string& mnemonic, const std::string& language) {
  if (mnemonic.empty()) throw std::runtime_error("Mnemonic phrase is empty");
  std::string seed_language;
  crypto::secret_key recovery_key;

  if (crypto::ElectrumWords::get_is_old_style_seed(mnemonic)) throw std::runtime_error("Mnemonic phrased words must be 25");
  if(!crypto::ElectrumWords::words_to_bytes(mnemonic, recovery_key, seed_language)) throw std::runtime_error("Invalid mnemonic");
  if (seed_language == crypto::ElectrumWords::old_language_name) seed_language = "English";

  // validate language
  if (!language.empty()) {
    if (!crypto::ElectrumWords::is_valid_language(language)) throw std::runtime_error("Invalid language: " + language);
    if (language != seed_language) throw std::runtime_error("Seed language mismatch");
  }

}

// -------------------------- BINARY SERIALIZATION ----------------------------

void monero_utils::json_to_binary(const std::string &json, std::string &bin) {
  epee::serialization::portable_storage ps;
  ps.load_from_json(json);
  epee::byte_stream bs;
  ps.store_to_binary(bs);
  bin = std::string((char*) bs.data(), bs.size());
}

void monero_utils::binary_to_json(const std::string &bin, std::string &json) {
  epee::serialization::portable_storage ps;
  ps.load_from_binary(bin);
  ps.dump_as_json(json);
}

void monero_utils::binary_blocks_to_json(const std::string &bin, std::string &json) {

  // load binary rpc response to struct
  cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response resp_struct;
  if (!epee::serialization::load_t_from_binary(resp_struct, bin)) throw std::runtime_error("failed to parse get_blocks_by_height.bin response");

  // build property tree from deserialized blocks and transactions
  boost::property_tree::ptree root;
  add_blocks_and_txs_to_ptree(resp_struct.blocks, root);
  root.put("status", resp_struct.status);
  root.put("untrusted", resp_struct.untrusted); // TODO: loss of ints and bools

  // convert root to string // TODO: common utility with serial_bridge
  std::stringstream ss;
  boost::property_tree::write_json(ss, root, false/*pretty*/);
  json = ss.str();
}

void monero_utils::binary_blocks_fast_to_json(const std::string &bin, std::string &json) {

  // load binary rpc response to struct
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response resp_struct;
  if (!epee::serialization::load_t_from_binary(resp_struct, bin)) throw std::runtime_error("failed to parse get_blocks.bin response");

  // build property tree from deserialized blocks and transactions
  boost::property_tree::ptree root;
  add_blocks_and_txs_to_ptree(resp_struct.blocks, root);
  root.put("status", resp_struct.status);
  root.put("untrusted", resp_struct.untrusted); // TODO: loss of ints and bools
  root.put("start_height", resp_struct.start_height);
  root.put("current_height", resp_struct.current_height);

  // convert root to string // TODO: common utility with serial_bridge
  std::stringstream ss;
  boost::property_tree::write_json(ss, root, false/*pretty*/);
  json = ss.str();
}

// ------------------------------- RAPIDJSON ----------------------------------

void monero_utils::add_json_member(std::string key, std::string val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field) {
  rapidjson::Value field_key(key.c_str(), key.size(), allocator);
  field.SetString(val.c_str(), val.size(), allocator);
  root.AddMember(field_key, field, allocator);
}

void monero_utils::add_json_member(std::string key, bool val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root) {
  rapidjson::Value field_key(key.c_str(), key.size(), allocator);
  if (val) {
    rapidjson::Value field_val(rapidjson::kTrueType);
    root.AddMember(field_key, field_val, allocator);
  } else {
    rapidjson::Value field_val(rapidjson::kFalseType);
    root.AddMember(field_key, field_val, allocator);
  }
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::string>& strs) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_str(rapidjson::kStringType);
  for (const std::string& str : strs) {
    value_str.SetString(str.c_str(), str.size(), allocator);
    value_arr.PushBack(value_str, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<int>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetInt(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint8_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetInt(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

// TODO: remove these redundant implementations for different sizes?
rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint32_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetUint64(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint64_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetUint64(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

// ----------------------------------------------------------------------------

bool monero_utils::is_valid_language(const std::string& language) {
  std::vector<std::string> languages;
  crypto::ElectrumWords::get_language_list(languages, false);
  std::vector<std::string>::iterator it = std::find(languages.begin(), languages.end(), language);
  if (it == languages.end()) {
    crypto::ElectrumWords::get_language_list(languages, true);
    it = std::find(languages.begin(), languages.end(), language);
  }
  if (it == languages.end()) return false;
  return true;
}

// TODO: this is unused
std::shared_ptr<monero_block> monero_utils::cn_block_to_block(const cryptonote::block& cn_block) {
  cryptonote::block temp = cn_block;
  std::cout << cryptonote::obj_to_json_str(temp) << std::endl;
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_major_version = cn_block.major_version;
  block->m_minor_version = cn_block.minor_version;
  block->m_timestamp = cn_block.timestamp;
  block->m_prev_hash = epee::string_tools::pod_to_hex(cn_block.prev_id);
  block->m_nonce = cn_block.nonce;
  block->m_miner_tx = monero_utils::cn_tx_to_tx(cn_block.miner_tx);
  for (const crypto::hash& tx_hash : cn_block.tx_hashes) {
    block->m_tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
  }
  return block;
}

std::shared_ptr<monero_tx> monero_utils::cn_tx_to_tx(const cryptonote::transaction& cn_tx, bool init_as_tx_wallet) {
  std::shared_ptr<monero_tx> tx = init_as_tx_wallet ? std::make_shared<monero_tx_wallet>() : std::make_shared<monero_tx>();
  tx->m_version = cn_tx.version;
  tx->m_unlock_time = cn_tx.unlock_time;
  tx->m_hash = epee::string_tools::pod_to_hex(cn_tx.hash);
  tx->m_extra = cn_tx.extra;

  // init inputs
  for (const txin_v& cnVin : cn_tx.vin) {
    if (cnVin.which() != 0 && cnVin.which() != 3) throw std::runtime_error("Unsupported variant type");
    if (tx->m_is_miner_tx == boost::none) tx->m_is_miner_tx = cnVin.which() == 0;
    if (cnVin.which() != 3) continue; // only process txin_to_key of variant  TODO: support other types, like 0 "gen" which is miner tx?
    std::shared_ptr<monero_output> input = init_as_tx_wallet ? std::make_shared<monero_output_wallet>() : std::make_shared<monero_output>();
    input->m_tx = tx;
    tx->m_inputs.push_back(input);
    const txin_to_key& txin = boost::get<txin_to_key>(cnVin);
    input->m_amount = txin.amount;
    input->m_ring_output_indices = txin.key_offsets;
    crypto::key_image cnKeyImage = txin.k_image;
    input->m_key_image = std::make_shared<monero_key_image>();
    input->m_key_image->m_hex = epee::string_tools::pod_to_hex(cnKeyImage);
  }

  // init outputs
  for (const tx_out& cnVout : cn_tx.vout) {
    std::shared_ptr<monero_output> output = init_as_tx_wallet ? std::make_shared<monero_output_wallet>() : std::make_shared<monero_output>();
    output->m_tx = tx;
    tx->m_outputs.push_back(output);
    output->m_amount = cnVout.amount;

    // before HF_VERSION_VIEW_TAGS, outputs with public keys are of type txout_to_key
    // after HF_VERSION_VIEW_TAGS, outputs with public keys are of type txout_to_tagged_key
    crypto::public_key cnStealthPublicKey;
    if (cnVout.target.type() == typeid(txout_to_key))
      cnStealthPublicKey = boost::get<txout_to_key>(cnVout.target).key;
    else if (cnVout.target.type() == typeid(txout_to_tagged_key))
      cnStealthPublicKey = boost::get<txout_to_tagged_key>(cnVout.target).key;
    else
      throw std::runtime_error(std::string("Unexpected output target type found: ") + std::string(cnVout.target.type().name()));
    output->m_stealth_public_key = epee::string_tools::pod_to_hex(cnStealthPublicKey);
  }

  return tx;

  // TODO: finish this, cryptonote::transaction has:
//  std::vector<std::vector<crypto::signature> > m_signatures;
//  rct::rctSig m_rct_signatures;
//  mutable size_t blob_size;
}

void monero_utils::binary_blocks_to_property_tree(const std::string &bin, boost::property_tree::ptree &node) {
  bin_blocks_to_property_tree(bin, node, false);
}

void monero_utils::binary_blocks_fast_to_property_tree(const std::string &bin, boost::property_tree::ptree &node) {
  bin_blocks_to_property_tree(bin, node, true);
}

void monero_utils::merge_tx(const std::shared_ptr<monero_tx_wallet>& tx, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map) {
  if (tx->m_hash == boost::none) throw std::runtime_error("Tx hash is not initialized");

  // merge tx
  std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.find(*tx->m_hash);
  if (tx_iter == tx_map.end()) {
    tx_map[*tx->m_hash] = tx; // cache new tx
  } else {
    std::shared_ptr<monero_tx_wallet>& a_tx = tx_map[*tx->m_hash];
    a_tx->merge(a_tx, tx); // merge with existing tx
  }

  // merge tx's block if confirmed
  if (tx->get_height() != boost::none) {
    std::map<uint64_t, std::shared_ptr<monero_block>>::const_iterator block_iter = block_map.find(tx->get_height().get());
    if (block_iter == block_map.end()) {
      block_map[tx->get_height().get()] = tx->m_block; // cache new block
    } else {
      std::shared_ptr<monero_block>& a_block = block_map[tx->get_height().get()];
      a_block->merge(a_block, tx->m_block); // merge with existing block
    }
  }
}

bool monero_utils::tx_height_less_than(const std::shared_ptr<monero_tx>& tx1, const std::shared_ptr<monero_tx>& tx2) {
  if (tx1->m_block != nullptr && tx2->m_block != nullptr) return tx1->get_height() < tx2->get_height();
  else if (tx1->m_block == nullptr) return false;
  else return true;
}

bool monero_utils::incoming_transfer_before(const std::shared_ptr<monero_incoming_transfer>& transfer1, const std::shared_ptr<monero_incoming_transfer>& transfer2) {

  // compare by height
  if (tx_height_less_than(transfer1->m_tx, transfer2->m_tx)) return true;

  // compare by account and subaddress index
  if (transfer1->m_account_index.get() < transfer2->m_account_index.get()) return true;
  else if (transfer1->m_account_index.get() == transfer2->m_account_index.get()) return transfer1->m_subaddress_index.get() < transfer2->m_subaddress_index.get();
  else return false;
}

bool monero_utils::vout_before(const std::shared_ptr<monero_output>& o1, const std::shared_ptr<monero_output>& o2) {
  if (o1 == o2) return false; // ignore equal references
  std::shared_ptr<monero_output_wallet> ow1 = std::static_pointer_cast<monero_output_wallet>(o1);
  std::shared_ptr<monero_output_wallet> ow2 = std::static_pointer_cast<monero_output_wallet>(o2);

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

static std::string make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, monero_network_type network_type) {
  cryptonote::address_parse_info info;

  if(!get_account_address_from_str(info, static_cast<cryptonote::network_type>(network_type), address)) {
    throw std::runtime_error(std::string("Invalid address: ") + address);
  }
  if (!payment_id.empty()) {
    throw std::runtime_error("Standalone payment id deprecated, use integrated address instead");
  }

  std::string uri = "monero:" + address;
  unsigned int n_fields = 0;

  if (amount > 0) {
    // URI encoded amount is in decimal units, not atomic units
    uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
  }
  if (!recipient_name.empty()) {
    uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
  }
  if (!tx_description.empty()) {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
  }

  return uri;
}

std::string monero_utils::get_payment_uri(const monero_tx_config& config, monero_network_type network_type) {
  // validate config
  std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
  if (destinations.size() != 1) throw std::runtime_error("Cannot make URI from supplied parameters: must provide exactly one destination to send funds");
  if (destinations.at(0)->m_address == boost::none) throw std::runtime_error("Cannot make URI from supplied parameters: must provide destination address");
  if (destinations.at(0)->m_amount == boost::none) throw std::runtime_error("Cannot make URI from supplied parameters: must provide destination amount");

  // prepare wallet2 params
  std::string address = destinations.at(0)->m_address.get();
  std::string payment_id = config.m_payment_id == boost::none ? "" : config.m_payment_id.get();
  uint64_t amount = destinations.at(0)->m_amount.get();
  std::string note = config.m_note == boost::none ? "" : config.m_note.get();
  std::string m_recipient_name = config.m_recipient_name == boost::none ? "" : config.m_recipient_name.get();

  // make uri
  std::string uri = make_uri(address, payment_id, amount, note, m_recipient_name, network_type);
  if (uri.empty()) throw std::runtime_error("Cannot make URI from supplied parameters");
  return uri;
}

// implementation based on monero-project's wallet2::parse_uri()
static bool parse_uri(const std::string &uri, std::string &address, monero_network_type network_type, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) {
  if (uri.substr(0, 7) != "monero:") {
    error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
    return false;
  }

  std::string remainder = uri.substr(7);
  const char *ptr = strchr(remainder.c_str(), '?');
  address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, static_cast<cryptonote::network_type>(network_type), address)) {
    error = std::string("URI has wrong address: ") + address;
    return false;
  }
  if (!strchr(remainder.c_str(), '?')) return true;

  std::vector<std::string> arguments;
  std::string body = remainder.substr(address.size() + 1);
  if (body.empty()) return true;

  boost::split(arguments, body, boost::is_any_of("&"));
  std::set<std::string> have_arg;
  for (const auto &arg: arguments) {
    std::vector<std::string> kv;
    boost::split(kv, arg, boost::is_any_of("="));
    if (kv.size() != 2) {
      error = std::string("URI has wrong parameter: ") + arg;
      return false;
    }
    if (have_arg.find(kv[0]) != have_arg.end()) {
      error = std::string("URI has more than one instance of " + kv[0]);
      return false;
    }
    have_arg.insert(kv[0]);

    if (kv[0] == "tx_amount") {
      amount = 0;
      if (!cryptonote::parse_amount(amount, kv[1])) {
        error = std::string("URI has invalid amount: ") + kv[1];
        return false;
      }
    }
    else if (kv[0] == "tx_payment_id") {
      if (info.has_payment_id) {
        error = "Separate payment id given with an integrated address";
        return false;
      }
      crypto::hash hash;
      if (!monero_utils::parse_payment_id_long(kv[1], hash)) {
        error = "Invalid payment id: " + kv[1];
        return false;
      }
      payment_id = kv[1];
    }
    else if (kv[0] == "recipient_name") recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
    else if (kv[0] == "tx_description") tx_description = epee::net_utils::convert_from_url_format(kv[1]);
    else unknown_parameters.push_back(arg);
  }
  return true;
}

std::shared_ptr<monero_tx_config> monero_utils::parse_payment_uri(const std::string& uri, monero_network_type network_type) {
  // decode uri to parameters
  std::string address;
  std::string payment_id;
  uint64_t amount = 0;
  std::string note;
  std::string recipient_name;
  std::vector<std::string> unknown_parameters;
  std::string error;
  if (!parse_uri(uri, address, network_type, payment_id, amount, note, recipient_name, unknown_parameters, error)) {
    throw std::runtime_error("Error parsing URI: " + error);
  }

  // initialize config
  std::shared_ptr<monero_tx_config> config = std::make_shared<monero_tx_config>();
  std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
  config->m_destinations.push_back(destination);
  if (!address.empty()) destination->m_address = address;
  destination->m_amount = amount;
  if (!payment_id.empty()) config->m_payment_id = payment_id;
  if (!note.empty()) config->m_note = note;
  if (!recipient_name.empty()) config->m_recipient_name = recipient_name;
  if (!unknown_parameters.empty()) MWARNING("monero_utils::parse_payment_uri: URI contains unknown parameters which are discarded"); // TODO: return unknown parameters?
  return config;
}

uint64_t monero_utils::xmr_to_atomic_units(double amount_xmr) {
  if (!std::isfinite(amount_xmr) || amount_xmr < 0) throw std::invalid_argument("amount must be a finite, non-negative number");

  long double atomic = std::round(static_cast<long double>(amount_xmr) * static_cast<long double>(XMR_AU_MULTIPLIER));

  // validate the actual rounded value about to be cast, not a precomputed "amount_xmr" threshold:
  // a threshold like UINT64_MAX / XMR_AU_MULTIPLIER carries its own division rounding error and can
  // let a value that overflows uint64_t slip through, and casting an out-of-range floating point
  // value to uint64_t is undefined behavior (not a wraparound). 2^64 is exactly representable in any
  // binary floating point type with enough exponent range (it's a pure power of two), so this bound
  // check is exact regardless of long double's precision on a given platform.
  static const long double MAX_ATOMIC_UNITS_EXCLUSIVE = std::ldexp(1.0L, 64); // 2^64
  if (atomic < 0.0L || atomic >= MAX_ATOMIC_UNITS_EXCLUSIVE) throw std::invalid_argument("amount exceeds maximum representable atomic units");

  return static_cast<uint64_t>(atomic);
}

double monero_utils::atomic_units_to_xmr(uint64_t amount_atomic_units) {
  return static_cast<double>(amount_atomic_units) / static_cast<double>(XMR_AU_MULTIPLIER);
}

// implementation based on monero-project's wallet2::parse_long_payment_id()
bool monero_utils::parse_payment_id_long(const std::string& payment_id_str, crypto::hash& payment_id) {
  cryptonote::blobdata payment_id_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data) || sizeof(crypto::hash) != payment_id_data.size()) return false;
  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
  return true;
}

// implementation based on monero-project's wallet2::parse_short_payment_id()
bool monero_utils::parse_payment_id_short(const std::string& payment_id_str, crypto::hash8& payment_id) {
  cryptonote::blobdata payment_id_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data) || sizeof(crypto::hash8) != payment_id_data.size()) return false;
  payment_id = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  return true;
}
