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
#include <mutex>

using namespace cryptonote;
using namespace monero_utils;

static std::unordered_map<std::string,
  std::chrono::high_resolution_clock::time_point> starts_{};

static std::mutex mutex_;

void monero_utils::set_log_level(int level) {
  mlog_set_log_level(level);
}

void monero_utils::configure_logging(const std::string& path, bool console) {
  mlog_configure(path, console);
}

void monero_utils::start_profile(const std::string& name) {
  auto now = std::chrono::high_resolution_clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  starts_[name] = now;
}

void monero_utils::end_profile(const std::string& name) {
  auto now = std::chrono::high_resolution_clock::now();

  std::chrono::high_resolution_clock::time_point start;

  {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = starts_.find(name);
    if (it == starts_.end()) {
      std::cerr << "Profiler: missing startProfile(\"" << name << "\")\n";
      return;
    }

    start = it->second;
  }

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);

  std::cout << "[PROFILE] " << name << " took "
            << duration.count() << " ms\n";
}
// --------------------------- VALIDATION UTILS -------------------------------

monero_integrated_address monero_utils::get_integrated_address(monero_network_type network_type, const std::string& standard_address, const std::string& payment_id) {

  // parse and validate address
  cryptonote::address_parse_info address_info;
  if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(network_type), standard_address)) throw std::runtime_error("Invalid address");
  //if (address_info.is_subaddress) throw std::runtime_error("Subaddress shouldn't be used");
  if (address_info.has_payment_id) throw std::runtime_error("The given address already has a payment id");

  // randomly generate payment id if not given, else validate
  crypto::hash8 payment_id_h8;
  if (payment_id.empty()) {
    payment_id_h8 = crypto::rand<crypto::hash8>();
  } else {
    cryptonote::blobdata payment_id_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id, payment_id_data) || sizeof(crypto::hash8) != payment_id_data.size()) throw std::runtime_error("Invalid payment ID: " + payment_id);
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

bool monero_utils::parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id)
{
  // monero-project logic based on wallet2::parse_short_payment_id()
  cryptonote::blobdata payment_id_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data)) {
    return false;
  }
  if (sizeof(crypto::hash) != payment_id_data.size()) {
    return false;
  }

  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
  return true;
}

bool monero_utils::parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id)
{
  // monero-project logic based on wallet2::parse_short_payment_id()
  cryptonote::blobdata payment_id_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data)) {
    return false;
  }
  if (sizeof(crypto::hash8) != payment_id_data.size()) {
    return false;
  }
  payment_id = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  return true;
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
      block_map[tx->get_height().get()] = tx->m_block.get(); // cache new block
    } else {
      std::shared_ptr<monero_block>& a_block = block_map[tx->get_height().get()];
      a_block->merge(a_block, tx->m_block.get()); // merge with existing block
    }
  }
}

/**
  * Remove query criteria which require looking up other transfers/outputs to
  * fulfill query.
  *
  * @param query the query to decontextualize
  * @return a reference to the query for convenience
  */
std::shared_ptr<monero_tx_query> monero_utils::decontextualize(std::shared_ptr<monero_tx_query> query) {
  query->m_is_incoming = boost::none;
  query->m_is_outgoing = boost::none;
  query->m_transfer_query = boost::none;
  query->m_input_query = boost::none;
  query->m_output_query = boost::none;
  return query;
}

bool monero_utils::is_contextual(const monero_transfer_query& query) {
  if (query.m_tx_query == boost::none) return false;
  if (query.m_tx_query.get()->m_is_incoming != boost::none) return true;    // requires context of all transfers
  if (query.m_tx_query.get()->m_is_outgoing != boost::none) return true;
  if (query.m_tx_query.get()->m_input_query != boost::none) return true;    // requires context of inputs
  if (query.m_tx_query.get()->m_output_query != boost::none) return true;   // requires context of outputs
  return false;
}

bool monero_utils::is_contextual(const monero_output_query& query) {
  if (query.m_tx_query == boost::none) return false;
  if (query.m_tx_query.get()->m_is_incoming != boost::none) return true;    // requires context of all transfers
  if (query.m_tx_query.get()->m_is_outgoing != boost::none) return true;
  if (query.m_tx_query.get()->m_transfer_query != boost::none) return true; // requires context of transfers
  return false;
}

std::string monero_utils::make_uri(const std::string &address, cryptonote::network_type nettype, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) {
  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype, address))
  {
    error = std::string("wrong address: ") + address;
    return std::string();
  }

  // we want only one payment id
  if (info.has_payment_id && !payment_id.empty())
  {
    error = "A single payment id is allowed";
    return std::string();
  }

  if (!payment_id.empty())
  {
    error = "Standalone payment id deprecated, use integrated address instead";
    return std::string();
  }

  std::string uri = "monero:" + address;
  unsigned int n_fields = 0;

  if (!payment_id.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
  }

  if (amount > 0)
  {
    // URI encoded amount is in decimal units, not atomic units
    uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
  }

  if (!recipient_name.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
  }

  if (!tx_description.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
  }

  return uri;
}

bool monero_utils::parse_uri(const std::string &uri, std::string &address, cryptonote::network_type nettype, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) {
  if (uri.substr(0, 7) != "monero:")
  {
    error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
    return false;
  }

  std::string remainder = uri.substr(7);
  const char *ptr = strchr(remainder.c_str(), '?');
  address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype, address))
  {
    error = std::string("URI has wrong address: ") + address;
    return false;
  }
  if (!strchr(remainder.c_str(), '?'))
    return true;

  std::vector<std::string> arguments;
  std::string body = remainder.substr(address.size() + 1);
  if (body.empty())
    return true;
  boost::split(arguments, body, boost::is_any_of("&"));
  std::set<std::string> have_arg;
  for (const auto &arg: arguments)
  {
    std::vector<std::string> kv;
    boost::split(kv, arg, boost::is_any_of("="));
    if (kv.size() != 2)
    {
      error = std::string("URI has wrong parameter: ") + arg;
      return false;
    }
    if (have_arg.find(kv[0]) != have_arg.end())
    {
      error = std::string("URI has more than one instance of " + kv[0]);
      return false;
    }
    have_arg.insert(kv[0]);

    if (kv[0] == "tx_amount")
    {
      amount = 0;
      if (!cryptonote::parse_amount(amount, kv[1]))
      {
        error = std::string("URI has invalid amount: ") + kv[1];
        return false;
      }
    }
    else if (kv[0] == "tx_payment_id")
    {
      if (info.has_payment_id)
      {
        error = "Separate payment id given with an integrated address";
        return false;
      }
      crypto::hash hash;
      if (!monero_utils::parse_long_payment_id(kv[1], hash))
      {
        error = "Invalid payment id: " + kv[1];
        return false;
      }
      payment_id = kv[1];
    }
    else if (kv[0] == "recipient_name")
    {
      recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else if (kv[0] == "tx_description")
    {
      tx_description = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else
    {
      unknown_parameters.push_back(arg);
    }
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

std::string monero_utils::serialize(const rapidjson::Document& doc) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  return buffer.GetString();
}

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

// ------------------------ PROPERTY TREES ---------------------------

std::string monero_utils::serialize(const boost::property_tree::ptree& node) {
  std::stringstream ss;
  boost::property_tree::write_json(ss, node, false);
  std::string str = ss.str();
  return str.substr(0, str.size() - 1); // strip newline
}

void monero_utils::deserialize(const std::string& json, boost::property_tree::ptree& root) {
  std::istringstream iss = json.empty() ? std::istringstream() : std::istringstream(json);
  try {
    boost::property_tree::read_json(iss, root);
  } catch (std::exception const& e) {
    throw std::runtime_error("Invalid JSON");
  }
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
    input->m_key_image.get()->m_hex = epee::string_tools::pod_to_hex(cnKeyImage);
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

std::shared_ptr<monero_tx_wallet> monero_utils::ptx_to_tx(const tools::wallet2::pending_tx &ptx, cryptonote::network_type nettype, monero_wallet* wallet) {
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
  tx->m_metadata = monero_utils::dump_ptx(ptx);
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
  tx->m_is_outgoing = tx->m_outgoing_transfer != boost::none;
  
  if (change_output != nullptr) {
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

    auto ext_output = std::make_shared<monero_output>();
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
  // Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
  bool r = false;
  if (payment_id_string != boost::none && payment_id_string->size() > 0) {
    crypto::hash payment_id;
    r = monero_utils::parse_long_payment_id(*payment_id_string, payment_id);
    if (r) {
      std::string extra_nonce;
      cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
      r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
      if (!r) {
        throw std::runtime_error("Couldn't add pid nonce to tx extra");
      }
    } else {
      crypto::hash8 payment_id8;
      r = monero_utils::parse_short_payment_id(*payment_id_string, payment_id8);
      if (!r) { // a PID has been specified by the user but the last resort in validating it fails; error
        throw std::runtime_error("Invalid pid");
      }
      std::string extra_nonce;
      cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
      r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
      if (!r) {
        throw std::runtime_error("Couldn't add pid nonce to tx extra");
      }
    }
  }
}

bool monero_utils::rct_hex_to_decrypted_mask(const std::string &rct_string, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask) {
  // rct string is empty if output is non RCT
  if (rct_string.empty()) {
    return false;
  }
  // rct_string is a magic value if output is RCT and coinbase
  if (rct_string == "coinbase") {
    decrypted_mask = rct::identity();
    return true;
  }
  auto make_key_derivation = [&]() {
    crypto::key_derivation derivation;
    bool r = generate_key_derivation(tx_pub_key, view_secret_key, derivation);
    if(!r) throw std::runtime_error("Failed to generate key derivation");
    crypto::secret_key scalar;
    crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
    return rct::sk2rct(scalar);
  };
  rct::key encrypted_mask;
  // rct_string is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
  if (rct_string.size() < 64 * 2) {
    decrypted_mask = rct::genCommitmentMask(make_key_derivation());
    return true;
  }
  // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  std::string encrypted_mask_str = rct_string.substr(64,64);
  if(!epee::string_tools::validate_hex(64, encrypted_mask_str)) throw std::runtime_error("Invalid rct mask: " + encrypted_mask_str);
  epee::string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
  
  if (encrypted_mask == rct::identity()) {
    // backward compatibility; should no longer be needed after v11 mainnet fork
    decrypted_mask = encrypted_mask;
    return true;
  }
  
  // Decrypt the mask
  sc_sub(decrypted_mask.bytes,
    encrypted_mask.bytes,
    rct::hash_to_scalar(make_key_derivation()).bytes);
  
  return true;
}

bool monero_utils::rct_hex_to_rct_commit(const std::string &rct_string, rct::key &rct_commit) {
  // rct string is empty if output is non RCT
  if (rct_string.empty()) {
    return false;
  }
  // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  std::string rct_commit_str = rct_string.substr(0,64);
  if(!epee::string_tools::validate_hex(64, rct_commit_str)) throw std::runtime_error("Invalid rct commit hash: " + rct_commit_str);
  epee::string_tools::hex_to_pod(rct_commit_str, rct_commit);
  return true;
}
