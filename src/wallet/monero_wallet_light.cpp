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

#include "monero_wallet_light.h"

#include "utils/monero_utils.h"
#include <thread>
#include <chrono>
#include <iostream>
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "string_tools.h"
#include "device/device.hpp"

using namespace epee;
using namespace tools;
using namespace crypto;

/**
 * Public library interface.
 */
namespace monero {

  bool monero_wallet_light_utils::is_uint64_t(const std::string& str) {
    try {
      uint64_t sz;
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

  uint64_t monero_wallet_light_utils::uint64_t_cast(const std::string& str) {
    if (!is_uint64_t(str)) {
      throw std::out_of_range("String provided is not a valid uint64_t");
    }

    uint64_t value;
    
    std::istringstream itr(str);

    itr >> value;

    return value;
  }

  std::string monero_wallet_light_utils::tx_hex_to_hash(std::string hex) {
    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(hex, blob))
    {
      throw std::runtime_error("Failed to parse hex.");
    }

    bool loaded = false;
    tools::wallet2::pending_tx ptx;

    try
    {
      binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
      if (::serialization::serialize(ar, ptx))
        loaded = true;
    }
    catch(...) {}

    if (!loaded)
    {
      try
      {
        std::istringstream iss(blob);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> ptx;
      }
      catch (...) {
        throw std::runtime_error("Failed to parse tx metadata.");
      }
    }

    return epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
  }


  std::shared_ptr<monero_light_output> monero_light_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
        else if (key == std::string("amount")) output->m_amount = it->second.data();
        else if (key == std::string("index")) output->m_index = it->second.get_value<uint16_t>();
        else if (key == std::string("global_index")) output->m_global_index = it->second.data();
        else if (key == std::string("rct")) output->m_rct = it->second.data();
        else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
        else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
        else if (key == std::string("public_key")) output->m_public_key = it->second.data();
        else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
        else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
        else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
        else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
    }

    return output;
  }

  std::shared_ptr<monero_light_rates> monero_light_rates::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_rates> rates = std::make_shared<monero_light_rates>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("AUD")) rates->m_aud = it->second.get_value<float>();
        else if (key == std::string("BRL")) rates->m_brl = it->second.get_value<float>();
        else if (key == std::string("BTC")) rates->m_btc = it->second.get_value<float>();
        else if (key == std::string("CAD")) rates->m_cad = it->second.get_value<float>();
        else if (key == std::string("CHF")) rates->m_chf = it->second.get_value<float>();
        else if (key == std::string("CNY")) rates->m_cny = it->second.get_value<float>();
        else if (key == std::string("EUR")) rates->m_eur = it->second.get_value<float>();
        else if (key == std::string("GBP")) rates->m_gbp = it->second.get_value<float>();
        else if (key == std::string("HKD")) rates->m_hkd = it->second.get_value<float>();
        else if (key == std::string("INR")) rates->m_inr = it->second.get_value<float>();
        else if (key == std::string("JPY")) rates->m_jpy = it->second.get_value<float>();
        else if (key == std::string("KRW")) rates->m_krw = it->second.get_value<float>();
        else if (key == std::string("MXN")) rates->m_mxn = it->second.get_value<float>();
        else if (key == std::string("NOK")) rates->m_nok = it->second.get_value<float>();
        else if (key == std::string("NZD")) rates->m_nzd = it->second.get_value<float>();
        else if (key == std::string("SEK")) rates->m_sek = it->second.get_value<float>();
        else if (key == std::string("SGD")) rates->m_sgd = it->second.get_value<float>();
        else if (key == std::string("TRY")) rates->m_try = it->second.get_value<float>();
        else if (key == std::string("USD")) rates->m_usd = it->second.get_value<float>();
        else if (key == std::string("RUB")) rates->m_rub = it->second.get_value<float>();
        else if (key == std::string("ZAR")) rates->m_zar = it->second.get_value<float>();
    }

    return rates;
  }

  std::shared_ptr<monero_light_spend> monero_light_spend::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_spend> spend = std::make_shared<monero_light_spend>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) spend->m_amount = it->second.data();
        else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
        else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
        else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint16_t>();
        else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
    }

    return spend;
  }

  std::shared_ptr<monero_light_transaction> monero_light_transaction::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_transaction> transaction = std::make_shared<monero_light_transaction>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("id")) transaction->m_id = it->second.get_value<uint64_t>();
        else if (key == std::string("hash")) transaction->m_hash = it->second.data();
        else if (key == std::string("timestamp")) transaction->m_timestamp = it->second.data();
        else if (key == std::string("total_received")) transaction->m_total_received = it->second.data();
        else if (key == std::string("total_sent")) transaction->m_total_sent = it->second.data();
        else if (key == std::string("fee")) transaction->m_fee = it->second.data();
        else if (key == std::string("unlock_time")) transaction->m_unlock_time = it->second.get_value<uint64_t>();
        else if (key == std::string("height")) transaction->m_height = it->second.get_value<uint64_t>();
        else if (key == std::string("spent_outputs")) {
            // deserialize monero_light_spend
            
            transaction->m_spent_outputs = std::vector<monero_light_spend>();

            for(auto& output : it->second.get_child("spent_outputs")) {
                std::shared_ptr<monero_light_spend> spend = std::make_shared<monero_light_spend>();
                monero_light_spend::from_property_tree(output.second, spend);
                transaction->m_spent_outputs->push_back(*spend);
            }
        }
        else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
        else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
        else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
        else if (key == std::string("mixin")) transaction->m_height = it->second.get_value<uint32_t>();
    }

    return transaction;
  }

  std::shared_ptr<monero_light_random_output> monero_light_random_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_random_output> random_output = std::make_shared<monero_light_random_output>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
        else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
        else if (key == std::string("rct")) random_output->m_rct = it->second.data();
    }

    return random_output;
  }

  std::shared_ptr<monero_light_random_outputs> monero_light_random_outputs::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_random_outputs> random_outputs = std::make_shared<monero_light_random_outputs>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) random_outputs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            random_outputs->m_outputs = std::vector<monero_light_random_output>();

            for(auto& output : it->second.get_child("outputs")) {
                std::shared_ptr<monero_light_random_output> random_output = std::make_shared<monero_light_random_output>();
                monero_light_random_output::from_property_tree(output.second, random_output);
                random_outputs->m_outputs->push_back(*random_output);
            }
        }
    }

    return random_outputs;
  }

  std::shared_ptr<monero_light_get_address_info_response> monero_light_get_address_info_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_address_info_response> address_info = std::make_shared<monero_light_get_address_info_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("locked_funds")) address_info->m_locked_funds = it->second.data();
        else if (key == std::string("total_received")) address_info->m_total_received = it->second.data();
        else if (key == std::string("total_sent")) address_info->m_total_sent = it->second.data();
        else if (key == std::string("scanned_height")) address_info->m_scanned_height = it->second.get_value<uint64_t>();
        else if (key == std::string("scanned_block_height")) address_info->m_scanned_block_height = it->second.get_value<uint64_t>();
        else if (key == std::string("start_height")) address_info->m_start_height = it->second.get_value<uint64_t>();
        else if (key == std::string("transaction_height")) address_info->m_transaction_height = it->second.get_value<uint64_t>();
        else if (key == std::string("blockchain_height")) address_info->m_blockchain_height = it->second.get_value<uint64_t>();
        else if (key == std::string("spent_outputs")) {
            address_info->m_spent_outputs = std::vector<monero_light_spend>();

            for(auto& output : it->second.get_child("spent_outputs")) {
                std::shared_ptr<monero_light_spend> spent_output;
                monero_light_spend::from_property_tree(output.second, spent_output);
                address_info->m_spent_outputs->push_back(*spent_output);
            }

        } else if (key == std::string("rates")) {
            std::shared_ptr<monero_light_rates> rates = std::make_shared<monero_light_rates>();
            monero_light_rates::from_property_tree(it->second, rates);
            address_info->m_rates = *rates;
        }
    }

    return address_info;
  }

  std::shared_ptr<monero_light_get_address_txs_response> monero_light_get_address_txs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_address_txs_response> address_txs = std::make_shared<monero_light_get_address_txs_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("total_received")) address_txs->m_total_received = it->second.data();
        else if (key == std::string("scanned_height")) address_txs->m_scanned_height = it->second.get_value<uint64_t>();
        else if (key == std::string("scanned_block_height")) address_txs->m_scanned_block_height = it->second.get_value<uint64_t>();
        else if (key == std::string("start_height")) address_txs->m_start_height = it->second.get_value<uint64_t>();
        else if (key == std::string("blockchain_height")) address_txs->m_blockchain_height = it->second.get_value<uint64_t>();
        else if (key == std::string("transactions")) {
            address_txs->m_transactions = std::vector<monero_light_transaction>();

            for(auto& output : it->second.get_child("transactions")) {
                std::shared_ptr<monero_light_transaction> transaction;
                monero_light_transaction::from_property_tree(output.second, transaction);
                address_txs->m_transactions->push_back(*transaction);
            }
        }
    }

    return address_txs;
  }

  std::shared_ptr<monero_light_get_random_outs_response> monero_light_get_random_outs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_random_outs_response> random_outs = std::make_shared<monero_light_get_random_outs_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount_outs")) {
            random_outs->m_amount_outs = std::vector<monero_light_random_output>();

            for(auto& output : it->second.get_child("transactions")) {
                std::shared_ptr<monero_light_random_output> out;
                monero_light_random_output::from_property_tree(output.second, out);
                random_outs->m_amount_outs->push_back(*out);
            }
        }
    }

    return random_outs;
  }

  std::shared_ptr<monero_light_get_unspent_outs_response> monero_light_get_unspent_outs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_unspent_outs_response> unspent_outs = std::make_shared<monero_light_get_unspent_outs_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("per_byte_fee")) unspent_outs->m_per_byte_fee = it->second.data();
        else if (key == std::string("fee_mask")) unspent_outs->m_fee_mask = it->second.data();
        else if (key == std::string("amount")) unspent_outs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            unspent_outs->m_outputs = std::vector<monero_light_output>();

            for(auto& out : it->second.get_child("outputs")) {
                std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
                monero_light_output::from_property_tree(out.second, output);
                unspent_outs->m_outputs->push_back(*output);
            }
        }
    }

    return unspent_outs;
  }

  std::shared_ptr<monero_light_import_request_response> monero_light_import_request_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_import_request_response> import_request = std::make_shared<monero_light_import_request_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("payment_address")) import_request->m_payment_address = it->second.data();
        else if (key == std::string("payment_id")) import_request->m_payment_id = it->second.data();
        else if (key == std::string("import_fee")) import_request->m_import_fee = it->second.data();
        else if (key == std::string("new_request")) import_request->m_new_request = it->second.get_value<bool>();
        else if (key == std::string("request_fulfilled")) import_request->m_request_fullfilled = it->second.get_value<bool>();
        else if (key == std::string("status")) import_request->m_status = it->second.data();
    }

    return import_request;
  }

  std::shared_ptr<monero_light_login_response> monero_light_login_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_login_response> login = std::make_shared<monero_light_login_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("new_address")) login->m_new_address = it->second.get_value<bool>();
        else if (key == std::string("generated_locally")) login->m_generated_locally = it->second.get_value<bool>();
        else if (key == std::string("start_height")) login->m_start_height = it->second.get_value<uint64_t>();
    }

    return login;
  }

  std::shared_ptr<monero_light_submit_raw_tx_response> monero_light_submit_raw_tx_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_submit_raw_tx_response> tx = std::make_shared<monero_light_submit_raw_tx_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("status")) tx->m_status = it->second.data();
    }

    return tx;
  }

  std::shared_ptr<monero_light_account> monero_light_account::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("address")) account->m_address = it->second.data();
        else if (key == std::string("scan_height")) account->m_scan_height = it->second.get_value<uint64_t>();
        else if (key == std::string("access_time")) account->m_access_time = it->second.get_value<uint64_t>();
    }

    return account;
  }

  std::shared_ptr<monero_light_list_accounts_response> monero_light_list_accounts_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_list_accounts_response> accounts = std::make_shared<monero_light_list_accounts_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("active")) {
            accounts->m_active = std::vector<monero_light_account>();

            for (auto& active_account : it->second.get_child("active")) {
                std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
                monero_light_account::from_property_tree(active_account.second, account);
                accounts->m_active->push_back(*account);
            }
        }
        else if (key == std::string("inactive")) {
            accounts->m_inactive = std::vector<monero_light_account>();

            for (auto& inactive_account : it->second.get_child("inactive")) {
                std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
                monero_light_account::from_property_tree(inactive_account.second, account);
                accounts->m_inactive->push_back(*account);
            }
        }
        else if (key == std::string("hidden")) {
            accounts->m_hidden = std::vector<monero_light_account>();

            for (auto& hidden_account : it->second.get_child("hidden")) {
                std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
                monero_light_account::from_property_tree(hidden_account.second, account);
                accounts->m_hidden->push_back(*account);
            }
        }
    }

    return accounts;
  }

  std::shared_ptr<monero_light_list_requests_response> monero_light_list_requests_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_list_requests_response> requests = std::make_shared<monero_light_list_requests_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;
        
        if (key == std::string("create")) {
          std::shared_ptr<monero_light_create_account_request> request;
          monero_light_create_account_request::from_property_tree(it->second, request);
          requests->m_create->push_back(*request);
        }
        else if (key == std::string("import")) {
          std::shared_ptr<monero_light_import_account_request> request;
          monero_light_import_account_request::from_property_tree(it->second, request);
          requests->m_import->push_back(*request);
        }
    }

    return requests;
  }

  monero_lws_connection monero_lws_connection::from_property_tree(const boost::property_tree::ptree& node) {
    monero_lws_connection *connection = new monero_lws_connection();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("uri")) connection->m_uri = it->second.data();
        else if (key == std::string("port")) connection->m_port = it->second.data();
    }

    return *connection;
  }

  monero_lws_admin_connection monero_lws_admin_connection::from_property_tree(const boost::property_tree::ptree& node) {
    monero_lws_admin_connection *connection = new monero_lws_admin_connection();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("uri")) connection->m_uri = it->second.data();
        else if (key == std::string("port")) connection->m_port = it->second.data();
        else if (key == std::string("admin_uri")) connection->m_admin_uri = it->second.data();
        else if (key == std::string("admin_port")) connection->m_admin_port = it->second.data();
        else if (key == std::string("token")) connection->m_token = it->second.data();
    }

    return *connection;
  }

  void monero_light_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
        else if (key == std::string("amount")) output->m_amount = it->second.data();
        else if (key == std::string("index")) output->m_index = it->second.get_value<uint16_t>();
        else if (key == std::string("global_index")) output->m_global_index = it->second.data();
        else if (key == std::string("rct")) output->m_rct = it->second.data();
        else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
        else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
        else if (key == std::string("public_key")) output->m_public_key = it->second.data();
        else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
        else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
        else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
        else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
    }
  }

  void monero_light_rates::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_rates>& rates) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("AUD")) rates->m_aud = it->second.get_value<float>();
        else if (key == std::string("BRL")) rates->m_brl = it->second.get_value<float>();
        else if (key == std::string("BTC")) rates->m_btc = it->second.get_value<float>();
        else if (key == std::string("CAD")) rates->m_cad = it->second.get_value<float>();
        else if (key == std::string("CHF")) rates->m_chf = it->second.get_value<float>();
        else if (key == std::string("CNY")) rates->m_cny = it->second.get_value<float>();
        else if (key == std::string("EUR")) rates->m_eur = it->second.get_value<float>();
        else if (key == std::string("GBP")) rates->m_gbp = it->second.get_value<float>();
        else if (key == std::string("HKD")) rates->m_hkd = it->second.get_value<float>();
        else if (key == std::string("INR")) rates->m_inr = it->second.get_value<float>();
        else if (key == std::string("JPY")) rates->m_jpy = it->second.get_value<float>();
        else if (key == std::string("KRW")) rates->m_krw = it->second.get_value<float>();
        else if (key == std::string("MXN")) rates->m_mxn = it->second.get_value<float>();
        else if (key == std::string("NOK")) rates->m_nok = it->second.get_value<float>();
        else if (key == std::string("NZD")) rates->m_nzd = it->second.get_value<float>();
        else if (key == std::string("SEK")) rates->m_sek = it->second.get_value<float>();
        else if (key == std::string("SGD")) rates->m_sgd = it->second.get_value<float>();
        else if (key == std::string("TRY")) rates->m_try = it->second.get_value<float>();
        else if (key == std::string("USD")) rates->m_usd = it->second.get_value<float>();
        else if (key == std::string("RUB")) rates->m_rub = it->second.get_value<float>();
        else if (key == std::string("ZAR")) rates->m_zar = it->second.get_value<float>();
    }
  }

  void monero_light_spend::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) spend->m_amount = it->second.data();
        else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
        else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
        else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint16_t>();
        else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
    }
  }

  void monero_light_transaction::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_transaction>& transaction) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("id")) transaction->m_id = it->second.get_value<uint64_t>();
        else if (key == std::string("hash")) transaction->m_hash = it->second.data();
        else if (key == std::string("timestamp")) transaction->m_timestamp = it->second.data();
        else if (key == std::string("total_received")) transaction->m_total_received = it->second.data();
        else if (key == std::string("total_sent")) transaction->m_total_sent = it->second.data();
        else if (key == std::string("fee")) transaction->m_fee = it->second.data();
        else if (key == std::string("unlock_time")) transaction->m_unlock_time = it->second.get_value<uint64_t>();
        else if (key == std::string("height")) transaction->m_height = it->second.get_value<uint64_t>();
        else if (key == std::string("spent_outputs")) {
            // deserialize monero_light_spend
            
            transaction->m_spent_outputs = std::vector<monero_light_spend>();

            for(auto& output : it->second.get_child("spent_outputs")) {
                std::shared_ptr<monero_light_spend> spend = std::make_shared<monero_light_spend>();
                monero_light_spend::from_property_tree(output.second, spend);
                transaction->m_spent_outputs->push_back(*spend);
            }
        }
        else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
        else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
        else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
        else if (key == std::string("mixin")) transaction->m_height = it->second.get_value<uint32_t>();
    }
  }

  void monero_light_random_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
        else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
        else if (key == std::string("rct")) random_output->m_rct = it->second.data();
    }
  }

  void monero_light_account::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_account>& account) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;
        if (key == std::string("address")) account->m_address = it->second.data();
        else if (key == std::string("scan_height")) account->m_scan_height = it->second.get_value<uint64_t>();
        else if (key == std::string("access_time")) account->m_access_time = it->second.get_value<uint64_t>();
    }
  }

  void monero_light_create_account_request::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_create_account_request>& request) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;
        if (key == std::string("address")) request->m_address = it->second.data();
        else if (key == std::string("start_height")) request->m_start_height = it->second.get_value<uint64_t>();
    }
  }

  void monero_light_import_account_request::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_import_account_request>& request) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;
        if (key == std::string("address")) request->m_address = it->second.data();
    }
  }

  rapidjson::Value monero_lws_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
    if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_str);

    
    // return root
    return root;
  }

  rapidjson::Value monero_lws_admin_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
    if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_str);
    if (m_admin_uri != boost::none) monero_utils::add_json_member("admin_uri", m_admin_uri.get(), allocator, root, value_str);
    if (m_admin_port != boost::none) monero_utils::add_json_member("admin_port", m_admin_port.get(), allocator, root, value_str);
    if (m_token != boost::none) monero_utils::add_json_member("token", m_token.get(), allocator, root, value_str);
    
    // return root
    return root;
  }

  rapidjson::Value monero_light_get_address_info_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

    
    // return root
    return root;
  }

  rapidjson::Value monero_light_get_address_txs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

    
    // return root
    return root;
  }

  rapidjson::Value monero_light_get_random_outs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_count != boost::none) monero_utils::add_json_member("count", m_count.get(), allocator, root, value_str);

    // set sub-arrays
    if (m_amounts != boost::none) root.AddMember("amounts", monero_utils::to_rapidjson_val(allocator, m_amounts.get()), allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_import_request_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

    
    // return root
    return root;
  }

  rapidjson::Value monero_light_get_unspent_outs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_str);
    if (m_mixin != boost::none) monero_utils::add_json_member("mixin", m_mixin.get(), allocator, root, value_str);
    if (m_use_dust != boost::none) monero_utils::add_json_member("use_dust", m_use_dust.get(), allocator, root, value_str);
    if (m_dust_threshold != boost::none) monero_utils::add_json_member("dust_threshold", m_dust_threshold.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_login_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
    if (m_create_account != boost::none) monero_utils::add_json_member("create_account", m_create_account.get(), allocator, root, value_str);
    if (m_generated_locally != boost::none) monero_utils::add_json_member("generated_locally", m_generated_locally.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_submit_raw_tx_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_tx != boost::none) monero_utils::add_json_member("tx", m_tx.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_accept_requests_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);
    rapidjson::Value parameters(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_obj(rapidjson::kObjectType);
    rapidjson::Value value_arr(rapidjson::kArrayType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
    if (m_type != boost::none) monero_utils::add_json_member("type", m_type.get(), allocator, parameters, value_str);
    if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
    
    //monero_utils::add_json_member("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator, parameters, value_arr);

    root.AddMember("parameters", parameters, allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_add_account_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);
    rapidjson::Value parameters(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_obj(rapidjson::kObjectType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, parameters, value_str);
    if (m_key != boost::none) monero_utils::add_json_member("key", m_key.get(), allocator, parameters, value_str);

    root.AddMember("parameters", parameters, allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_list_accounts_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_list_requests_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_modify_account_status_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);
    rapidjson::Value parameters(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_obj(rapidjson::kObjectType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
    if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
    if (m_status != boost::none) monero_utils::add_json_member("key", m_status.get(), allocator, parameters, value_str);

    root.AddMember("parameters", parameters, allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_reject_requests_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);
    rapidjson::Value parameters(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_obj(rapidjson::kObjectType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
    if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
    if (m_type != boost::none) monero_utils::add_json_member("type", m_type.get(), allocator, parameters, value_str);

    root.AddMember("parameters", parameters, allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_rescan_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);
    rapidjson::Value parameters(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_obj(rapidjson::kObjectType);

    if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
    if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
    if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, parameters, value_str);

    root.AddMember("parameters", parameters, allocator);

    // return root
    return root;
  }

  std::shared_ptr<monero_light_spend> monero_light_spend::copy(const std::shared_ptr<monero_light_spend>& src, const std::shared_ptr<monero_light_spend>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this spend != src");
    // copy wallet extensions
    tgt->m_amount = src->m_amount;
    tgt->m_key_image = src->m_key_image;
    tgt->m_tx_pub_key = src->m_tx_pub_key;
    tgt->m_out_index = src->m_out_index;
    tgt->m_mixin = src->m_mixin;

    return tgt;
  }

  std::shared_ptr<monero_light_transaction> monero_light_transaction::copy(const std::shared_ptr<monero_light_transaction>& src, const std::shared_ptr<monero_light_transaction>& tgt, bool exclude_spend) const {
    if (this != src.get()) throw std::runtime_error("this light_tx != src");

    // copy wallet extensions
    tgt->m_id = src->m_id;
    tgt->m_hash = src->m_hash;
    tgt->m_timestamp = src->m_timestamp;
    tgt->m_total_received = src->m_total_received;
    tgt->m_total_sent = src->m_total_sent;
    tgt->m_fee = src->m_fee;
    tgt->m_unlock_time = src->m_unlock_time;
    tgt->m_height = src->m_height;
    tgt->m_payment_id = src->m_payment_id;
    tgt->m_coinbase = src->m_coinbase;
    tgt->m_mempool = src->m_mempool;
    tgt->m_mixin = src->m_mixin;

    if (exclude_spend) {
      return tgt;
    }

    if (!src->m_spent_outputs.get().empty()) {
      tgt->m_spent_outputs = std::vector<monero_light_spend>();
      for (const monero_light_spend& spent_output : src->m_spent_outputs.get()) {
        std::shared_ptr<monero_light_spend> spent_output_copy = spent_output->copy(std::make_shared<monero_light_spend>(spent_output), std::make_shared<monero_light_spend>());
        tgt->m_spent_outputs.get().push_back(*spent_output_copy);
      }
    }

    return tgt;
  }

  // ---------------------------- WALLET MANAGEMENT ---------------------------

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
    if (config.m_private_spend_key == boost::none) config_normalized.m_private_spend_key = std::string("");
    if (config.m_private_view_key == boost::none) config_normalized.m_private_view_key = std::string("");
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

    // parse and validate private spend key
    crypto::secret_key spend_key_sk;
    bool has_spend_key = false;
    if (!config_normalized.m_private_spend_key.get().empty()) {
      cryptonote::blobdata spend_key_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(config.m_private_spend_key.get(), spend_key_data) || spend_key_data.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("failed to parse secret spend key");
      }
      has_spend_key = true;
      spend_key_sk = *reinterpret_cast<const crypto::secret_key*>(spend_key_data.data());
    }

    // parse and validate private view key
    crypto::secret_key view_key_sk;
    if (config_normalized.m_private_view_key.get().empty()) {
      throw std::runtime_error("Must provide view key");
    }

    cryptonote::blobdata view_key_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(config_normalized.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("failed to parse secret view key");
    }
    view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());

    // parse and validate address
    cryptonote::address_parse_info address_info;
    if (config_normalized.m_primary_address.get().empty()) {
      throw std::runtime_error("must provide primary address");
    } else {
      if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config_normalized.m_network_type.get()), config_normalized.m_primary_address.get())) throw std::runtime_error("failed to parse address");

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(view_key_sk, pkey)) throw std::runtime_error("failed to verify secret view key");
      if (address_info.address.m_view_public_key != pkey) throw std::runtime_error("view key does not match address");
    }

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light();
    if (has_spend_key) {
      wallet->m_account.create_from_keys(address_info.address, spend_key_sk, view_key_sk);
    }
    else {
      wallet->m_account.create_from_viewkey(address_info.address, view_key_sk);
    }

    // initialize remaining wallet
    wallet->m_is_view_only = !has_spend_key;
    wallet->m_network_type = config_normalized.m_network_type.get();

    if (!config_normalized.m_private_spend_key.get().empty()) {
      wallet->m_language = config_normalized.m_language.get();
      epee::wipeable_string wipeable_mnemonic;
      if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
        throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
      }
      wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    }
    wallet->m_http_client = http_client_factory != nullptr ? http_client_factory->create() : net::http::client_factory().create();
    wallet->m_http_admin_client = http_client_factory != nullptr ? http_client_factory->create() : net::http::client_factory().create();
    wallet->init_common();

    return wallet;
  }

  // ----------------------------- WALLET METHODS -----------------------------

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close();
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_lws_connection>& connection) {
    if (connection == boost::none) set_daemon_connection("", "");
    else set_daemon_connection(connection->m_uri == boost::none ? "" : connection->m_uri.get(), connection->m_port == boost::none ? "" : connection->m_port.get());
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_lws_admin_connection>& connection) {
    if (connection == boost::none) set_daemon_connection("", "");
    else set_daemon_connection(
      connection->m_uri == boost::none ? "" : connection->m_uri.get(), connection->m_port == boost::none ? "" : connection->m_port.get(), 
      connection->m_admin_uri == boost::none ? "" : connection->m_admin_uri.get(), connection->m_admin_port == boost::none ? "" : connection->m_admin_port.get(), 
      connection->m_token == boost::none ? "" : connection->m_token.get()
      );
  }

  void monero_wallet_light::set_daemon_connection(std::string host, std::string port, std::string admin_uri, std::string admin_port, std::string token) {
    m_host = host;
    m_port = port;
    m_admin_uri = admin_uri;
    m_admin_port = admin_port;
    m_token = token;
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    return m_http_client->is_connected();
  }

  bool monero_wallet_light::is_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_blockchain_height.get() == m_blockchain_height;
  }

  bool monero_wallet_light::is_daemon_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_blockchain_height.get() == address_info.m_scanned_height.get();
  }

  monero_version monero_wallet_light::get_version() const {
    monero_version version;
    version.m_number = 65552; // same as monero-wallet-rpc v0.15.0.1 release
    version.m_is_release = false; // TODO: could pull from MONERO_VERSION_IS_RELEASE in version.cpp
    return version;
  }

  void monero_wallet_light::set_restore_height(uint64_t restore_height) {
    rescan(restore_height);
  }

  monero_sync_result monero_wallet_light::sync() {
    monero_sync_result result;
    monero_light_get_address_txs_response response = get_address_txs();
    uint64_t old_scanned_height = m_scanned_block_height;

    m_start_height = response.m_start_height.get();
    m_scanned_block_height = response.m_scanned_block_height.get();
    m_blockchain_height = response.m_blockchain_height.get();

    m_raw_transactions = response.m_transactions.get();

    if (is_view_only()) {
      m_transactions = m_raw_transactions;
    } else {
      m_transactions = std::vector<monero_light_transaction>();

      for (const monero_light_transaction& raw_transaction : m_raw_transactions) {
        monero_light_transaction transaction = raw_transaction.copy(raw_transaction, std::make_shared<monero_light_transaction>(),true);

        for(monero_light_spend spent_output : raw_transaction.m_spent_outputs.get()) {
          std::string key_img = generate_key_image(spent_output.m_tx_pub_key.get(), spent_output.m_out_index.get());
          if (key_img == spent_output.m_key_image.get()) {
            transaction.m_spent_outputs.get().push_back(spent_output);
            break;
          }
        }

        m_transactions.push_back(transaction);
      }
    }

    calculate_balances();

    result.m_num_blocks_fetched = m_scanned_block_height - old_scanned_height;
    result.m_received_money = false; // to do
    return result;
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
    rescan(start_height, m_primary_address);
    monero_sync_result last_sync = sync();

    while(!is_synced()) {
      std::this_thread::sleep_for(std::chrono::seconds(120));
      last_sync = sync();
    }

    monero_sync_result result;
    uint64_t height = get_height();

    result.m_num_blocks_fetched = (start_height > height) ? 0 : height - start_height;
    result.m_received_money = last_sync.m_received_money;

    return result;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs() const {
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();
    monero_light_get_address_txs_response response = get_address_txs();

    std::vector<monero_light_transaction> light_txs = response.m_transactions.get();

    for (monero_light_transaction light_tx : light_txs) {
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::shared_ptr<monero_tx_wallet>();

      tx_wallet->m_block.get()->m_height = light_tx.m_height;
      tx_wallet->m_hash = light_tx.m_hash;
      tx_wallet->m_is_relayed = true;
      
      uint64_t total_sent;
      uint64_t total_received;

      std::istringstream tss(light_tx.m_total_sent.get());
      std::istringstream trs(light_tx.m_total_received.get());

      tss >> total_sent;
      trs >> total_received;

      if (total_sent == 0 && total_received > 0) {
        tx_wallet->m_is_incoming = true;
        tx_wallet->m_is_outgoing = false;
        tx_wallet->m_change_amount = total_received;
      } else if (total_received == 0 && total_sent > 0) {
        tx_wallet->m_is_outgoing = true;
        tx_wallet->m_is_incoming = false;
        tx_wallet->m_change_amount = total_sent;
      } else if (light_tx.m_coinbase.get()) {
        tx_wallet->m_is_incoming = true;
        tx_wallet->m_is_outgoing = false;
        tx_wallet->m_change_amount = total_received;
        
      }

      if (light_tx.m_unlock_time.get() == 0) {
        tx_wallet->m_is_confirmed = true;
      } else {
        tx_wallet->m_is_confirmed = false;
      }
    
      tx_wallet->m_unlock_time = light_tx.m_unlock_time;
      tx_wallet->m_payment_id = light_tx.m_payment_id;
      tx_wallet->m_in_tx_pool = light_tx.m_mempool;
      tx_wallet->m_is_miner_tx = light_tx.m_coinbase;
      tx_wallet->m_is_locked = light_tx.m_unlock_time.get() != 0;
      uint64_t num_confirmations = response.m_blockchain_height.get() - light_tx.m_height.get();
      tx_wallet->m_num_confirmations = num_confirmations;
      tx_wallet->m_is_confirmed = num_confirmations > 0;
      tx_wallet->m_fee = monero_wallet_light_utils::uint64_t_cast(light_tx.m_fee.get());
      tx_wallet->m_is_failed = false;
      
      txs.push_back(tx_wallet);
    }

    return txs;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
    monero_light_get_unspent_outs_response response = get_unspent_outs();

    std::vector<std::shared_ptr<monero_output_wallet>> outputs;

    for(monero_light_output light_output : response.m_outputs.get()) {
      std::shared_ptr<monero_output_wallet> output = std::shared_ptr<monero_output_wallet>();
      output->m_account_index = 0;
      output->m_index = light_output.m_index;
      output->m_amount = monero_wallet_light_utils::uint64_t_cast(light_output.m_amount.get());
      output->m_stealth_public_key = light_output.m_public_key;
      
      output->m_tx = std::make_shared<monero_tx>();
      output->m_tx->m_hash = light_output.m_tx_hash;
      output->m_tx->m_key = light_output.m_tx_pub_key;
      output->m_tx->m_rct_signatures = light_output.m_rct;
      
      outputs.push_back(output);
    }

    return outputs;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    std::vector<std::string> result = std::vector<std::string>();
    
    for (std::string tx_metadata : tx_metadatas) {
      monero_light_submit_raw_tx_response response = submit_raw_tx(tx_metadata);

      std::string status = response.m_status.get();

      if (status != std::string("success")) {
        throw std::runtime_error("Invalid tx metadata.");
      }

      std::string tx_hash = monero_wallet_light_utils::tx_hex_to_hash(tx_metadata);
      result.push_back(tx_hash);
    }

    return result;
  }

  uint64_t monero_wallet_light::wait_for_next_block() {
    uint64_t last_block = get_daemon_height();
        
    while(true) {
      uint64_t current_block = get_daemon_height();

      if (current_block > last_block) {
        last_block = current_block;
        break;
      }

      std::this_thread::sleep_for(std::chrono::seconds(120));
    }

    return last_block;
  }

  void monero_wallet_light::close(bool save) {
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    m_http_client->disconnect();
    m_http_admin_client->disconnect();

    epee::net_utils::http::abstract_http_client *release_client = m_http_client.release();
    delete release_client;

    epee::net_utils::http::abstract_http_client *release_admin_client = m_http_admin_client.release();
    delete release_admin_client;

    // no pointers to destroy
  }

  // ------------------------------- PROTECTED HELPERS ----------------------------

  void monero_wallet_light::init_common() {
    m_primary_address = m_account.get_public_address_str(static_cast<cryptonote::network_type>(m_network_type));
    const cryptonote::account_keys& keys = m_account.get_keys();
    m_pub_spend_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_spend_public_key);
    m_prv_view_key = epee::string_tools::pod_to_hex(keys.m_view_secret_key);
    m_prv_spend_key = epee::string_tools::pod_to_hex(keys.m_spend_secret_key);
    if (m_prv_spend_key == "0000000000000000000000000000000000000000000000000000000000000000") m_prv_spend_key = "";


    if (m_host != "") {
      std::string address = m_host;

      if (m_port != "") {
        address = address + ":" + m_port;
      }

      m_http_client->set_server(address, boost::none);
      m_http_client->connect(m_timeout);
    }

    if (m_admin_uri != "") {
      std::string address = m_admin_uri;

      if (m_admin_port != "") {
        address = address + ":" + m_admin_port;
      }

      m_http_admin_client->set_server(address, boost::none);
      m_http_client->connect(m_timeout);
    }

  }

  void monero_wallet_light::calculate_balances() {
   uint64_t total_received = 0;
   uint64_t total_sent = 0;
   uint64_t total_pending_received = 0;
   uint64_t total_pending_sent = 0;
   uint64_t total_locked_received = 0;
   uint64_t total_locked_sent = 0;

   for (monero_light_transaction transaction : m_transactions) {
    if (transaction.m_mempool != boost::none && transaction.m_mempool.get()) {
      total_pending_sent += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_sent.get());
      total_pending_received += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_received.get());
    } else {
      // transaction has confirmations
      uint64_t tx_confirmations = m_scanned_block_height - transaction.m_height.get();
      if (tx_confirmations < 10) {
        total_locked_sent += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_sent.get());
        total_locked_received += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_received.get());
      }

      total_received += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_received.get());
      total_sent += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_sent.get());
    }
   }

   m_balance = total_received - total_sent;
   m_balance_pending = total_pending_received - total_pending_sent;
   m_balance_unlocked = m_balance - total_locked_received - total_locked_sent;
  }

  std::string monero_wallet_light::generate_key_image(std::string tx_public_key, uint64_t output_index) {
    crypto::secret_key sec_view_key{};
    crypto::secret_key sec_spend_key{};
    crypto::public_key pub_spend_key{};
    crypto::public_key tx_pub_key{};
    bool r = false;

    r = epee::string_tools::hex_to_pod(m_prv_view_key, sec_view_key);
    if (!r) {
      throw std::runtime_error("Invalid secret view key");
    }

    r = epee::string_tools::hex_to_pod(m_prv_spend_key, sec_spend_key);
    if (!r) {
      throw std::runtime_error("Invalid secret spend key");
    }

    r = epee::string_tools::hex_to_pod(m_pub_spend_key, pub_spend_key);
    if (!r) {
      throw std::runtime_error("Invalid public spend key");
    }

    r = epee::string_tools::hex_to_pod(tx_public_key, tx_pub_key);
    if (!r) {
      throw std::runtime_error("Invalid tx pub key");
    }

    crypto::key_image key_image;

    r = monero_utils::generate_key_image(pub_spend_key, sec_spend_key, sec_view_key, tx_pub_key, output_index, key_image);    
    if (!r) {
      throw std::runtime_error("Error while generating key image");
    }
    
    return epee::string_tools::pod_to_hex(key_image);
  }

  // ------------------------------- PROTECTED LWS HELPERS ----------------------------

  const epee::net_utils::http::http_response_info* monero_wallet_light::post(std::string method, std::string &body, bool admin) const {
    const epee::net_utils::http::http_response_info *response = nullptr;
    
    if (admin) {
      if (!m_http_admin_client->invoke_post(method, body, m_timeout, &response)) {
        throw std::runtime_error("Network error");
      }    
    }
    else {
      if (!m_http_client->invoke_post(method, body, m_timeout, &response)) {
        throw std::runtime_error("Network error");
      }
    }

    return response;
  }

  monero_light_get_address_info_response monero_wallet_light::get_address_info(monero_light_get_address_info_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);

    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_address_info", body);

    return *monero_light_get_address_info_response::deserialize(response->m_body);
  }

  monero_light_get_address_txs_response monero_wallet_light::get_address_txs(monero_light_get_address_txs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_address_txs", body);

    return *monero_light_get_address_txs_response::deserialize(response->m_body);
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(monero_light_get_random_outs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_random_outs", body);

    return *monero_light_get_random_outs_response::deserialize(response->m_body);
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(monero_light_get_unspent_outs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_unspent_outs", body);

    return *monero_light_get_unspent_outs_response::deserialize(response->m_body);
  }

  monero_light_import_request_response monero_wallet_light::import_request(monero_light_import_request_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/import_request", body);

    return *monero_light_import_request_response::deserialize(response->m_body);
  }

  monero_light_submit_raw_tx_response monero_wallet_light::submit_raw_tx(monero_light_submit_raw_tx_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/submit_raw_tx", body);

    return *monero_light_submit_raw_tx_response::deserialize(response->m_body);
  }

  monero_light_login_response monero_wallet_light::login(monero_light_login_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/login", body);

    return *monero_light_login_response::deserialize(response->m_body);
  }

  // ------------------------------- PROTECTED LWS ADMIN HELPERS ----------------------------

  void monero_wallet_light::accept_requests(monero_light_accept_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/accept_requests", body, true);
  }

  void monero_wallet_light::reject_requests(monero_light_reject_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/reject_requests", body, true);
  }
  
  void monero_wallet_light::add_account(monero_light_add_account_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/add_account", body, true);
  }
  
  monero_light_list_accounts_response monero_wallet_light::list_accounts(monero_light_list_accounts_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/list_accounts", body, true);

    return *monero_light_list_accounts_response::deserialize(response->m_body);
  }
  
  monero_light_list_requests_response monero_wallet_light::list_requests(monero_light_list_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/list_requests", body, true);

    return *monero_light_list_requests_response::deserialize(response->m_body);
  }
  
  void monero_wallet_light::modify_account_status(monero_light_modify_account_status_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/modify_account_status", body, true);
  }
  
  void monero_wallet_light::rescan(monero_light_rescan_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());

    std::string body = req.GetString();

    const epee::net_utils::http::http_response_info *response = post("/rescan", body, true);
  }

}