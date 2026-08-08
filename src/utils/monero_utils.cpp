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
#include "common/monero_error.h"

#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\005"
#define SIGNED_TX_PREFIX "Monero signed tx set\005"

using namespace cryptonote;
using namespace monero_utils;

cryptonote::network_type get_nettype(monero_network_type network_type) {
  if (network_type == monero_network_type::STAGENET) return cryptonote::network_type::STAGENET;
  else if (network_type == monero_network_type::TESTNET) return cryptonote::network_type::TESTNET;
  return cryptonote::network_type::MAINNET;
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

// implementation based on monero-project's wallet2::parse_long_payment_id()
bool monero_utils::parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id) {
  cryptonote::blobdata payment_id_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data) || sizeof(crypto::hash) != payment_id_data.size()) return false;
  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
  return true;
}

// implementation based on monero-project's wallet2::parse_short_payment_id()
bool monero_utils::parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id) {
  cryptonote::blobdata payment_id_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data) || sizeof(crypto::hash8) != payment_id_data.size()) return false;
  payment_id = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  return true;
}

// implementation based on monero-project's wallet2::make_uri()
std::string monero_utils::make_uri(const std::string &address, monero_network_type network_type, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name) {
  // validate address
  cryptonote::address_parse_info info;

  if(!get_account_address_from_str(info, get_nettype(network_type), address)) {
    throw monero_error("Cannot make URI from supplied parameters: wrong address: " + address);
  }

  // we want only one payment id
  if (!payment_id.empty()) {
    if (info.has_payment_id) throw monero_error("A single payment id is allowed");
    throw monero_error("Cannot make URI from supplied parameters: Standalone payment id deprecated, use integrated address instead");
  }

  std::string uri = "monero:" + address;
  unsigned int n_fields = 0;

  if (!payment_id.empty()) uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
  // URI encoded amount is in decimal units, not atomic units
  if (amount > 0) uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
  if (!recipient_name.empty()) uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
  if (!tx_description.empty()) uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);

  return uri;
}

// implementation based on monero-project's wallet2::parse_uri()
bool monero_utils::parse_uri(const std::string &uri, std::string &address, monero_network_type network_type, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) {
  if (uri.substr(0, 7) != "monero:") {
    error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
    return false;
  }

  std::string remainder = uri.substr(7);
  const char *ptr = strchr(remainder.c_str(), '?');
  address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, get_nettype(network_type), address)) {
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
      if (!monero_utils::parse_long_payment_id(kv[1], hash)) {
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
  epee::serialization::load_t_from_binary(resp_struct, bin);

  // build property tree from deserialized blocks and transactions
  boost::property_tree::ptree root;
  boost::property_tree::ptree blocksNode; // array of block strings
  boost::property_tree::ptree txsNodes;   // array of txs per block (array of array)
  for (int blockIdx = 0; blockIdx < resp_struct.blocks.size(); blockIdx++) {

    // parse and validate block
    cryptonote::block block;
    if (cryptonote::parse_and_validate_block_from_blob(resp_struct.blocks[blockIdx].block, block)) {

      // add block node to blocks node
      boost::property_tree::ptree blockNode;
      blockNode.put("", cryptonote::obj_to_json_str(block));  // TODO: no pretty print
      blocksNode.push_back(std::make_pair("", blockNode));
    } else {
      throw std::runtime_error("failed to parse block blob at index " + std::to_string(blockIdx));
    }

    // parse and validate txs
    boost::property_tree::ptree txs_node;
    for (int txIdx = 0; txIdx < resp_struct.blocks[blockIdx].txs.size(); txIdx++) {
      cryptonote::transaction tx;
      if (cryptonote::parse_and_validate_tx_from_blob(resp_struct.blocks[blockIdx].txs[txIdx].blob, tx)) {

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
  root.put("status", resp_struct.status);
  root.put("untrusted", resp_struct.untrusted); // TODO: loss of ints and bools

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

uint64_t monero_utils::estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
  const size_t estimated_tx_weight = estimate_tx_weight(n_inputs, mixin, n_outputs, extra_size);
  return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
}

uint64_t monero_utils::get_fee_multiplier(uint32_t priority) {
  // v8 enforced fee algorithm 3
  if (priority == 2) return 5;
  if (priority == 3) return 25;
  if (priority == 4) return 1000;
  return 1;
}

size_t monero_utils::estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size) {
  size_t size = 1 + 6; // tx prefix first few bytes
  size += n_inputs * (1+6+(mixin+1)*2+32); // vin
  size += n_outputs * (6+32); // vuout
  size += extra_size; // extra
  if (!extra_size && n_outputs <= 2) size += 3 + sizeof(crypto::hash8);
  size += 1; // rct signatures

  size_t log_padded_outputs = 0; // rangeSigs
  while ((1<<log_padded_outputs) < n_outputs) ++log_padded_outputs;
  size += (2 * (6 + log_padded_outputs) + 6) * 32 + 3;
  size += n_inputs * (32 * (mixin+1) + 64); // MGs/CLSAGs
  size += n_outputs * sizeof(crypto::view_tag); // View tags
  // size += 2 * 32 * (mixin+1) * n_inputs; // mixRing - not serialized, can be reconstructed
  size += 32 * n_inputs; // pseudoOuts
  size += 8 * n_outputs; // ecdhInfo
  size += 32 * n_outputs; // outPk - only commitment is saved
  size += 4; // txnFee

  return size;
}

uint64_t monero_utils::calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
  uint64_t fee = weight * base_fee * fee_multiplier;
  fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
  return fee;
}

uint64_t monero_utils::estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size) {
  size_t size = estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size);
  if (n_outputs > 2) {
    const uint64_t bp_base = (32 * (6 + 7 * 2)) / 2; // notional size of a 2-output bulletproof+ proof, normalized to 1 proof
    size_t log_padded_outputs = 2;
    while ((1<<log_padded_outputs) < n_outputs) ++log_padded_outputs;
    uint64_t nlr = 2 * (6 + log_padded_outputs);
    const uint64_t bp_size = 32 * (6 + nlr);
    const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
    MDEBUG("clawback on size " << size << ": " << bp_clawback);
    size += bp_clawback;
  }
  return size;
}

uint64_t monero_utils::get_tx_weight_limit(uint64_t default_limit) {
  if (default_limit > 0) return default_limit;
  return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE; // v8
}

void monero_utils::validate_cn_tx(const cryptonote::transaction &tx) {
  if (get_tx_weight_limit() <= cryptonote::get_transaction_weight(tx)) throw std::runtime_error("transaction is too big");
  if(tx.rct_signatures.p.bulletproofs_plus.empty()) throw std::runtime_error("Expected tx to use bulletproofs");
  auto tx_blob = cryptonote::t_serializable_object_to_blob(tx);
  size_t tx_blob_size = tx_blob.size();
  if(tx_blob_size <= 0) throw std::runtime_error("Expected tx blob byte length > 0");
}

void monero_utils::binary_blocks_to_property_tree(const std::string &bin, boost::property_tree::ptree &node) {
  std::string response_json;
  monero_utils::binary_blocks_to_json(bin, response_json);
  std::istringstream iss(response_json);
  boost::property_tree::read_json(iss, node);

  auto blocks = node.get_child("blocks");
  boost::property_tree::ptree parsed_blocks;

  for (auto &entry : blocks) {
    const std::string &block_str = entry.second.get_value<std::string>();
    boost::property_tree::ptree block_node;
    gen_utils::deserialize(block_str, block_node);
    parsed_blocks.push_back(std::make_pair("", block_node));
  }

  node.put_child("blocks", parsed_blocks);

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
  std::string uri = make_uri(address, network_type, payment_id, amount, note, m_recipient_name);
  if (uri.empty()) throw std::runtime_error("Cannot make URI from supplied parameters");
  return uri;
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

std::shared_ptr<monero_tx_wallet> monero_utils::ptx_to_tx(const tools::wallet2::pending_tx &ptx, cryptonote::network_type nettype, monero_wallet* wallet, std::string* out_change_pubkey) {
  if (out_change_pubkey != nullptr) *out_change_pubkey = "";
  const auto &cn_tx = ptx.tx;
  const auto &cd = ptx.construction_data;
  std::shared_ptr<monero_tx_wallet> tx = std::dynamic_pointer_cast<monero_tx_wallet>(monero_utils::cn_tx_to_tx(cn_tx, true));
  tx->m_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(cn_tx));
  tx->m_relay = true;
  tx->m_is_relayed = true;
  tx->m_is_confirmed = false;
  tx->m_in_tx_pool = true;
  tx->m_is_miner_tx = false;
  tx->m_is_locked = true;
  tx->m_num_confirmations = 0;
  tx->m_is_failed = false;
  tx->m_ring_size = monero_utils::RING_SIZE;
  tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
  tx->m_is_double_spend_seen = false;
  tx->m_prunable_hash = epee::string_tools::pod_to_hex(cn_tx.prunable_hash);
  tx->m_is_outgoing = false;
  tx->m_fee = ptx.fee;

  // dump wallet2 pending tx
  try {
    std::ostringstream oss;
    boost::archive::portable_binary_oarchive ar(oss);
    ar << ptx;
    tx->m_metadata = epee::string_tools::buff_to_hex_nodelimer(oss.str());
  } catch (...) {
    tx->m_metadata = "";
  }

  tx->m_weight = cryptonote::get_transaction_weight(cn_tx);
  tx->m_change_amount = cd.change_dts.amount;
  tx->m_change_address = cryptonote::get_account_address_as_str(nettype, cd.subaddr_account > 0, cd.change_dts.addr);

  uint32_t sender_account_idx = cd.subaddr_account;
  size_t i = 0;
  std::vector<uint32_t> subaddresses_indices;
  bool first = true;
  for (const auto& in : tx->m_inputs) {
    auto input = std::dynamic_pointer_cast<monero_output_wallet>(in);
    uint32_t subaddress_idx = *next(cd.subaddr_indices.begin(), i);
    input->m_account_index = sender_account_idx;
    input->m_subaddress_index = subaddress_idx;
    input->m_is_spent = true;
    input->m_is_frozen = false;

    if (first) subaddresses_indices.push_back(subaddress_idx);
    first = false;
    i++;
  }
 
  std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
  outgoing_transfer->m_tx = tx;
  tx->m_outgoing_transfer = outgoing_transfer;
  uint32_t subaddress_idx = 0;
  outgoing_transfer->m_account_index = sender_account_idx;
  outgoing_transfer->m_subaddress_indices = subaddresses_indices;
  
  std::shared_ptr<monero_output_wallet> change_output = nullptr;
  std::vector<std::shared_ptr<monero_output_wallet>> external_outputs;

  uint64_t out_amount = 0;
  i = 0;

  std::map<uint32_t, std::map<uint32_t, std::shared_ptr<monero_destination>>> destination_index;

  for (const auto& out : tx->m_outputs) {
    const auto &dest = ptx.dests[i];
    out->m_amount = dest.amount;
    out->m_index = i;
    auto output = std::dynamic_pointer_cast<monero_output_wallet>(out);
    if (output == nullptr) {
      i++;
      continue;
    }

    crypto::hash payment_id = crypto::null_hash;
    std::string dest_address = dest.address(nettype, payment_id);

    try {
      monero_subaddress subaddress = wallet->get_address_index(dest_address);
      uint32_t receiver_account_idx = subaddress.m_account_index.get();
      uint32_t subaddress_idx = subaddress.m_index.get();
      output->m_account_index = receiver_account_idx;
      output->m_subaddress_index = subaddress_idx;
      output->m_is_spent = false;
      output->m_is_frozen = false;
      bool is_change = cd.change_dts.amount > 0 && dest.amount == cd.change_dts.amount && change_output == nullptr;
      if (is_change) {
        change_output = output;
      }
      if (!is_change) {
        out_amount += output->m_amount.get();
        auto transfer = std::make_shared<monero_incoming_transfer>();
        transfer->m_tx = tx;
        transfer->m_amount = output->m_amount;
        transfer->m_address = dest_address;
        transfer->m_account_index = receiver_account_idx;
        transfer->m_subaddress_index = subaddress_idx;
        transfer->m_num_suggested_confirmations = 10;
        tx->m_incoming_transfers.push_back(transfer);
        auto destination = std::make_shared<monero_destination>();
        destination->m_amount = dest.amount;
        destination->m_address = dest_address;
        destination_index[receiver_account_idx][subaddress_idx] = destination;
      }
    }
    catch (...) {
      // external output
      out_amount += output->m_amount.get();
      external_outputs.push_back(output);
    }
    i++;
  }
  
  tx->m_is_incoming = !tx->m_incoming_transfers.empty();
  tx->m_is_outgoing = tx->m_outgoing_transfer != nullptr;
  
  if (change_output != nullptr) {
    if (out_change_pubkey != nullptr) *out_change_pubkey = change_output->m_stealth_public_key.value_or("");
    tx->m_outputs.erase(
      std::remove(tx->m_outputs.begin(), tx->m_outputs.end(), change_output),
      tx->m_outputs.end()
    );
  }

  for(const auto& ext_out : external_outputs) {
    tx->m_outputs.erase(
      std::remove(tx->m_outputs.begin(), tx->m_outputs.end(), ext_out),
      tx->m_outputs.end()
    );

    auto ext_output = std::make_shared<monero_output_wallet>();
    ext_output->m_tx = tx; // required by monero_utils::vout_before()/tx_height_less_than(), which assume every tx output has its tx set
    ext_output->m_stealth_public_key = ext_out->m_stealth_public_key;
    ext_output->m_index = ext_out->m_index;
    ext_output->m_amount = ext_out->m_amount;
    tx->m_outputs.push_back(ext_output);
  }

  outgoing_transfer->m_amount = out_amount;

  sort(tx->m_outputs.begin(), tx->m_outputs.end(), monero_utils::vout_before);
  sort(tx->m_incoming_transfers.begin(), tx->m_incoming_transfers.end(), monero_utils::incoming_transfer_before);

  // order destinations
  for(const auto &kv_index : destination_index) {
    for(const auto  &kv : kv_index.second) {
      outgoing_transfer->m_destinations.push_back(kv.second);
    }
  }

  return tx;
}

void monero_utils::add_pid_to_tx_extra(const boost::optional<std::string>& payment_id_string, std::vector<uint8_t> &extra) { 
  if (payment_id_string == boost::none || payment_id_string->size() == 0) return;

  // detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
  crypto::hash payment_id;
  if (monero_utils::parse_long_payment_id(*payment_id_string, payment_id)) {
    std::string extra_nonce;
    cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
    if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) throw std::runtime_error("Couldn't add pid nonce to tx extra");
  } else {
    crypto::hash8 payment_id8;
    // a PID has been specified by the user but the last resort in validating it fails; error
    if (!monero_utils::parse_short_payment_id(*payment_id_string, payment_id8)) throw std::runtime_error("Invalid pid");
    std::string extra_nonce;
    cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
    if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) throw std::runtime_error("Couldn't add pid nonce to tx extra");
  }
}

bool monero_utils::rct_hex_to_decrypted_mask(const std::string &rct_str, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask) {
  // rct string is empty if output is non RCT
  if (rct_str.empty()) return false;

  // rct_str is a magic value if output is RCT and coinbase
  if (rct_str == "coinbase") {
    decrypted_mask = rct::identity();
    return true;
  }

  auto make_key_derivation = [&]() {
    crypto::key_derivation derivation;
    if(!generate_key_derivation(tx_pub_key, view_secret_key, derivation)) throw std::runtime_error("Failed to generate key derivation");
    crypto::secret_key scalar;
    crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
    return rct::sk2rct(scalar);
  };

  rct::key encrypted_mask;
  // rct_str is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
  if (rct_str.size() < 64 * 2) {
    decrypted_mask = rct::genCommitmentMask(make_key_derivation());
    return true;
  }

  // rct_str is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  std::string encrypted_mask_str = rct_str.substr(64,64);
  if(!epee::string_tools::validate_hex(64, encrypted_mask_str)) throw std::runtime_error("Invalid rct mask: " + encrypted_mask_str);
  epee::string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);

  if (encrypted_mask == rct::identity()) {
    // backward compatibility; should no longer be needed after v11 mainnet fork
    decrypted_mask = encrypted_mask;
    return true;
  }

  // decrypt the mask
  sc_sub(decrypted_mask.bytes, encrypted_mask.bytes, rct::hash_to_scalar(make_key_derivation()).bytes);

  return true;
}

bool monero_utils::rct_hex_to_rct_commit(const std::string &rct_str, rct::key &rct_commit) {
  // rct string is empty if output is non RCT
  if (rct_str.empty()) return false;

  // rct_str is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  std::string rct_commit_str = rct_str.substr(0,64);
  if(!epee::string_tools::validate_hex(64, rct_commit_str)) throw std::runtime_error("Invalid rct commit hash: " + rct_commit_str);
  epee::string_tools::hex_to_pod(rct_commit_str, rct_commit);
  return true;
}

bool monero_utils::is_rct_hex_unblinded_coinbase(const std::string &rct_str) {
  if (rct_str == "coinbase") return true;
  if (rct_str.size() < 64 * 3) return false;

  std::string commit_str = rct_str.substr(0, 64);
  std::string mask_str = rct_str.substr(64, 64);
  if (!epee::string_tools::validate_hex(64, commit_str) || !epee::string_tools::validate_hex(64, mask_str)) return false;

  rct::key commit;
  rct::key mask;
  epee::string_tools::hex_to_pod(commit_str, commit);
  epee::string_tools::hex_to_pod(mask_str, mask);
  return commit == rct::zero() && mask == rct::identity();
}

std::string monero_utils::encrypt(const std::string &plaintext_str, const crypto::secret_key &skey, bool authenticated) {
  const char *plaintext = plaintext_str.data();
  size_t len = plaintext_str.size();
  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, 1);
  std::string ciphertext;
  crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
  ciphertext.resize(len + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
  crypto::chacha20(plaintext, len, key, iv, &ciphertext[sizeof(iv)]);
  memcpy(&ciphertext[0], &iv, sizeof(iv));
  if (authenticated) {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(crypto::signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    crypto::signature &signature = *(crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, pkey, skey, signature);
  }
  return ciphertext;
}

std::vector<tools::wallet2::pending_tx> monero_utils::parse_signed_tx(const std::string &signed_tx_st, const crypto::secret_key &view_secret_key) {
  std::string s = signed_tx_st;
  tools::wallet2::signed_tx_set signed_txs;

  const size_t magiclen = strlen(SIGNED_TX_PREFIX) - 1;
  if (strncmp(s.c_str(), SIGNED_TX_PREFIX, magiclen)) throw std::runtime_error("Bad magic from signed transaction");
  s = s.substr(magiclen);
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003' || version == '\004') throw std::runtime_error("Not loading deprecated format");
  else if (version == '\005') {
    try {
      // decrypt with private view key
      s = monero_utils::decrypt(s, view_secret_key);
    }
    catch (const std::exception &e) { throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what()); }
    try {
      binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
      if (!::serialization::serialize(ar, signed_txs)) throw std::runtime_error("Failed to deserialize signed transaction");
    }
    catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what());
    }
  }
  else throw std::runtime_error("Unsupported version in signed transaction");

  LOG_PRINT_L0("Loaded signed tx data from binary: " << signed_txs.ptx.size() << " transactions");
  for (auto &c_ptx: signed_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));

  return signed_txs.ptx;
}

tools::wallet2::unsigned_tx_set monero_utils::parse_unsigned_tx(const std::string &unsigned_tx_st, const crypto::secret_key &view_secret_key) {
  tools::wallet2::unsigned_tx_set exported_txs;

  std::string s = unsigned_tx_st;
  const size_t magiclen = strlen(UNSIGNED_TX_PREFIX) - 1;
  if (strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen)) throw std::runtime_error("Bad magic from unsigned tx");
  s = s.substr(magiclen);
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003' || version == '\004') throw std::runtime_error("Not loading deprecated format");
  else if (version == '\005') {
    try {
      // decrypt with private view key
      s = monero_utils::decrypt(s, view_secret_key);
    }
    catch(const std::exception &e) { 
      std::string msg = std::string("Failed to decrypt unsigned tx: ") + e.what();
      throw std::runtime_error(msg); 
    }
    try {
      binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
      if (!::serialization::serialize(ar, exported_txs)) throw std::runtime_error("Failed to parse data from unsigned tx");
    }
    catch (...) {
      throw std::runtime_error("Failed to parse data from unsigned tx");
    }
  }
  else throw std::runtime_error("Unsupported version in unsigned tx");

  LOG_PRINT_L1("Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions");

  return exported_txs;
}

std::string monero_utils::dump_unsigned_tx(tools::wallet2::tx_construction_data &construction_data, const boost::optional<std::string>& payment_id, const wallet2_exported_outputs& outputs, const crypto::secret_key &view_secret_key) {
  tools::wallet2::unsigned_tx_set txs;
  if (payment_id != boost::none && !payment_id->empty()) {
    // wallet2.cpp get_construction_data_with_decrypted_short_payment_id
    crypto::hash8 pid = crypto::null_hash8;
    if (!monero_utils::parse_short_payment_id(payment_id.get(), pid)) throw std::runtime_error("invalid short payment id: " + payment_id.get());
    // remove encrypted
    cryptonote::remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
    // add encrypted
    std::string extra_nonce;
    cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, pid);
    if(!cryptonote::add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce)) throw std::runtime_error("Failed to add decrypted payment id to tx extra");
    LOG_PRINT_L0("Successfully decrypted payment ID: " << payment_id.get());
  }
  else LOG_PRINT_L0("Payment ID not set");

  txs.txes.push_back(construction_data);
  txs.new_transfers = outputs;

  // save as binary
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  try { if (!::serialization::serialize(ar, txs)) return std::string(); }
  catch (...) { return std::string(); }
  LOG_PRINT_L0("Saving unsigned tx data: " << oss.str());

  // encrypt with private view key
  std::string ciphertext = monero_utils::encrypt(oss.str(), view_secret_key);
  return epee::string_tools::buff_to_hex_nodelimer(std::string(UNSIGNED_TX_PREFIX) + ciphertext);
}

std::string monero_utils::sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes, std::vector<std::string>& signed_kis, const cryptonote::account_base& account, const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& subaddresses) {
  // sign the transactions
  for (size_t n = 0; n < exported_txs.txes.size(); ++n) {
    tools::wallet2::tx_construction_data &sd = exported_txs.txes[n];
    if(sd.sources.empty()) throw std::runtime_error("empty sources");
    if(sd.unlock_time) throw std::runtime_error("unlock time is non-zero");
    LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size());
    signed_txes.ptx.push_back(tools::wallet2::pending_tx());
    tools::wallet2::pending_tx &ptx = signed_txes.ptx.back();
    rct::RCTConfig rct_config = sd.rct_config;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    
    bool r = cryptonote::construct_tx_and_get_tx_key(account.get_keys(), subaddresses, sd.sources, sd.splitted_dsts, sd.change_dts.addr, sd.extra, ptx.tx, tx_key, additional_tx_keys, sd.use_rct, rct_config, sd.use_view_tags);
    if(!r) throw std::runtime_error("tx not constructed");
    // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
    // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
    // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
    // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

    // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
    // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
    // to see that info, so we save it here

    // TODO wallet cache
    //if (tx_key != crypto::null_skey) {
    //  const crypto::hash txid = get_transaction_hash(ptx.tx);
    //  m_tx_keys[txid] = tx_key;
    //  m_additional_tx_keys[txid] = additional_tx_keys;
    //}

    std::string key_images;
    bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool {
      CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
      key_images += boost::to_string(in.k_image) + " ";
      return true;
    });
    if(!all_are_txin_to_key) throw std::runtime_error("unexpected txin type");

    ptx.key_images = key_images;
    ptx.fee = 0;
    for (const auto &i: sd.sources) ptx.fee += i.amount;
    for (const auto &i: sd.splitted_dsts) ptx.fee -= i.amount;
    ptx.dust = 0;
    ptx.dust_added_to_fee = false;
    ptx.change_dts = sd.change_dts;
    ptx.selected_transfers = sd.selected_transfers;
    ptx.tx_key = rct::rct2sk(rct::identity()); // don't send it back to the untrusted view wallet
    ptx.dests = sd.dests;
    ptx.construction_data = sd;

    txs.push_back(ptx);

    // add tx keys only to ptx
    txs.back().tx_key = tx_key;
    txs.back().additional_tx_keys = additional_tx_keys;
  }

  // add key image mapping for these txes
  const auto &keys = account.get_keys();
  hw::device &hwdev = account.get_device();
  for (size_t n = 0; n < exported_txs.txes.size(); ++n) {
    const cryptonote::transaction &tx = signed_txes.ptx[n].tx;

    crypto::key_derivation derivation;
    std::vector<crypto::key_derivation> additional_derivations;

    // compute public keys from out secret keys
    crypto::public_key tx_pub_key;
    crypto::secret_key_to_public_key(txs[n].tx_key, tx_pub_key);
    std::vector<crypto::public_key> additional_tx_pub_keys;
    for (const crypto::secret_key &skey: txs[n].additional_tx_keys) {
      additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
      crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
    }

    // compute derivations
    hwdev.set_mode(hw::device::TRANSACTION_PARSE);
    if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation)) {
      MWARNING("Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
      static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
      memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
    }
    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i) {
      additional_derivations.push_back({});
      if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back())) {
        MWARNING("Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
        memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
      }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i) {
      crypto::public_key output_public_key;
      if (!get_output_public_key(tx.vout[i], output_public_key)) continue;
      // if this output is back to this wallet, we can calculate its key image already
      if (!is_out_to_acc_precomp(subaddresses, output_public_key, derivation, additional_derivations, i, hwdev, get_output_view_tag(tx.vout[i]))) continue;

      crypto::key_image ki;
      cryptonote::keypair in_ephemeral;
      if (cryptonote::generate_key_image_helper(keys, subaddresses, output_public_key, tx_pub_key, additional_tx_pub_keys, i, in_ephemeral, ki, hwdev)) signed_txes.tx_key_images[output_public_key] = ki;
      else MERROR("Failed to calculate key image");
    }
  }

  // add key images
  signed_txes.key_images.resize(signed_kis.size());
  for (size_t i = 0; i < signed_kis.size(); ++i) {
    std::string& signed_ki = signed_kis[i];
    crypto::key_image ski;
    if (signed_ki.empty()) LOG_PRINT_L0("WARNING: key image not known in signing wallet at index " << i);
    else epee::string_tools::hex_to_pod(signed_ki, ski);
    signed_txes.key_images[i] = ski;
  }

  // save as binary
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  try { if (!::serialization::serialize(ar, signed_txes)) return std::string(); }
  catch(...) { return std::string(); }
  LOG_PRINT_L3("Saving signed tx data (with encryption): " << oss.str());

  // encrypt with private view key
  std::string ciphertext = monero_utils::encrypt(oss.str(), keys.m_view_secret_key);
  return std::string(SIGNED_TX_PREFIX) + ciphertext;
}

std::shared_ptr<monero_key_image> monero_utils::generate_key_image(const crypto::public_key &ephem_pubkey, const size_t tx_output_index, const cryptonote::subaddress_index &received_subaddr, const cryptonote::account_base& account) {
  //   - R: ephem_pubkey
  //   - a: ack.m_view_secret_key [private viewkey]
  //   - b: ack.m_spend_secret_key [private spendkey]
  //   - idx: tx_output_index
  //   - index_major: received_subaddr.major
  //   - index_minor: received_subaddr.minor
  //   - Hs() [hash-to-scalar]
  //   - Hp() [hash-to-point]

  const cryptonote::account_keys &ack = account.get_keys();
  hw::device &hwdev = account.get_device();

  // 1. Diffie-Helman derived secret D = a R
  crypto::key_derivation recv_derivation;
  CHECK_AND_ASSERT_THROW_MES(hwdev.generate_key_derivation(ephem_pubkey, ack.m_view_secret_key, recv_derivation), "Failed to perform Diffie-Helman exchange against tx ephem pubkey");

  // 2. Non-address-extended onetime key secret u = Hs(D || idx) + b
  crypto::secret_key onetime_privkey_unextended;
  hwdev.derive_secret_key(recv_derivation, tx_output_index, ack.m_spend_secret_key, onetime_privkey_unextended);

  // 3. Subaddress key extension s = Hs(a || index_major || index_minor) if is subaddress, else s = 0
  const crypto::secret_key subaddr_ext{received_subaddr.is_zero() ? crypto::secret_key{} : hwdev.get_subaddress_secret_key(ack.m_view_secret_key, received_subaddr)};

  // 4. Onetime address private key x = u + s
  crypto::secret_key onetime_privkey;
  hwdev.sc_secret_add(onetime_privkey, onetime_privkey_unextended, subaddr_ext);

  // 5. Onetime address K = x G
  crypto::public_key onetime_pubkey;
  CHECK_AND_ASSERT_THROW_MES(hwdev.secret_key_to_public_key(onetime_privkey, onetime_pubkey), "Failed to make public key");

  // 6. Key image I = x Hp(K)
  crypto::key_image ki;
  hwdev.generate_key_image(onetime_pubkey, onetime_privkey, ki);

  // sign the key image with the output secret key
  crypto::signature signature;
  std::vector<const crypto::public_key*> key_ptrs;
  key_ptrs.push_back(&ephem_pubkey);

  crypto::generate_ring_signature((const crypto::hash&)ki, ki, key_ptrs, onetime_privkey, 0, &signature);

  std::shared_ptr<monero_key_image> key_image = std::make_shared<monero_key_image>();
  key_image->m_hex = epee::string_tools::pod_to_hex(ki);
  key_image->m_signature = epee::string_tools::pod_to_hex(signature);
  return key_image;
}
