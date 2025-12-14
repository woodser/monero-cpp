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

#include "monero_wallet_light_model.h"

#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
#include <iostream>
#include "net/http.h"

namespace monero {

  // ------------------------------- DESERIALIZE UTILS -------------------------------

  std::shared_ptr<monero_light_version> monero_light_version::deserialize(const std::string& version_json) {
    std::istringstream iss = version_json.empty() ? std::istringstream() : std::istringstream(version_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    std::shared_ptr<monero_light_version> version = std::make_shared<monero_light_version>();
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("server_type")) version->m_server_type = it->second.data();
      else if (key == std::string("server_version")) version->m_server_version = it->second.data();
      else if (key == std::string("last_git_commit_hash")) version->m_last_git_commit_hash = it->second.data();
      else if (key == std::string("last_git_commit_date")) version->m_last_git_commit_date = it->second.data();
      else if (key == std::string("git_branch_name")) version->m_git_branch_name = it->second.data();
      else if (key == std::string("monero_version_full")) version->m_monero_version_full = it->second.data();
      else if (key == std::string("blockchain_height")) version->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("api")) version->m_api = it->second.get_value<uint32_t>();
      else if (key == std::string("max_subaddresses")) version->m_max_subaddresses = it->second.get_value<uint32_t>();
      else if (key == std::string("testnet")) version->m_testnet = it->second.get_value<bool>();
      else if (key == std::string("network")) {
        std::string network_str = it->second.data();
        if (network_str == std::string("main")) version->m_network_type = monero_network_type::MAINNET;
        else if (network_str == std::string("test")) version->m_network_type = monero_network_type::TESTNET;
        else if (network_str == std::string("stage")) version->m_network_type = monero_network_type::STAGENET;
        throw std::runtime_error("Cannot deserialize lws version: invalid network provided " + network_str);
      }
    }

    return version;
  }

  std::shared_ptr<monero_light_address_meta> monero_light_address_meta::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_address_meta> address_meta = std::make_shared<monero_light_address_meta>();
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }

    return address_meta;
  }

  std::shared_ptr<monero_light_output> monero_light_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
    std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
      else if (key == std::string("amount")) output->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("index")) output->m_index = it->second.get_value<uint64_t>();
      else if (key == std::string("global_index")) output->m_global_index = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("rct")) output->m_rct = it->second.data();
      else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
      else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
      else if (key == std::string("public_key")) output->m_public_key = it->second.data();
      else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
      else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.push_back(it2->second.data());
      else if (key == std::string("timestamp")) output->m_timestamp = gen_utils::timestamp_to_epoch(it->second.data());
      else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("recipient")) {
        monero_light_address_meta::from_property_tree(it->second, recipient);
      }
    }
    
    output->m_recipient = *recipient;

    return output;
  }

  std::shared_ptr<monero_light_spend> monero_light_spend::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_spend> spend = std::make_shared<monero_light_spend>();
    std::shared_ptr<monero_light_address_meta> sender = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) spend->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
      else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
      else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint64_t>();
      else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("sender")) {
        monero_light_address_meta::from_property_tree(it->second, sender);
      }
    }
    
    spend->m_sender = *sender;

    return spend;
  }

  std::shared_ptr<monero_light_tx> monero_light_tx::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_tx> transaction = std::make_shared<monero_light_tx>();
    transaction->m_coinbase = false;
    transaction->m_total_received = 0;
    transaction->m_total_sent = 0;

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("id")) transaction->m_id = it->second.get_value<uint64_t>();
      else if (key == std::string("hash")) transaction->m_hash = it->second.data();
      else if (key == std::string("timestamp")) transaction->m_timestamp = gen_utils::timestamp_to_epoch(it->second.data());
      else if (key == std::string("total_received")) transaction->m_total_received = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("total_sent")) transaction->m_total_sent = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("fee")) transaction->m_fee = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("unlock_time")) transaction->m_unlock_time = it->second.get_value<uint64_t>();
      else if (key == std::string("height")) transaction->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        // deserialize monero_light_spend
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_spend> out = std::make_shared<monero_light_spend>();
          monero_light_spend::from_property_tree(it2->second, out);
          transaction->m_spent_outputs.push_back(*out);
        }
      }
      else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
      else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
      else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
      else if (key == std::string("mixin")) transaction->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("recipient")) {
        std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, recipient);
        transaction->m_recipient = *recipient;
      }
    }

    return transaction;
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

      if (key == std::string("amount")) random_outputs->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("outputs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_output> out = std::make_shared<monero_light_output>();
          monero_light_output::from_property_tree(it2->second, out);
          random_outputs->m_outputs.push_back(*out);
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

      if (key == std::string("locked_funds")) address_info->m_locked_funds = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("total_received")) address_info->m_total_received = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("total_sent")) address_info->m_total_sent = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("scanned_height")) address_info->m_scanned_height = it->second.get_value<uint64_t>();
      else if (key == std::string("scanned_block_height")) address_info->m_scanned_block_height = it->second.get_value<uint64_t>();
      else if (key == std::string("start_height")) address_info->m_start_height = it->second.get_value<uint64_t>();
      else if (key == std::string("transaction_height")) address_info->m_transaction_height = it->second.get_value<uint64_t>();
      else if (key == std::string("blockchain_height")) address_info->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        boost::property_tree::ptree spent_outputs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = spent_outputs_node.begin(); it2 != spent_outputs_node.end(); ++it2) {
          std::shared_ptr<monero_light_spend> spent_output = std::make_shared<monero_light_spend>();
          monero_light_spend::from_property_tree(it2->second, spent_output);
          address_info->m_spent_outputs.push_back(*spent_output);
        }
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

      if (key == std::string("total_received")) address_txs->m_total_received = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("scanned_height")) address_txs->m_scanned_height = it->second.get_value<uint64_t>();
      else if (key == std::string("scanned_block_height")) address_txs->m_scanned_block_height = it->second.get_value<uint64_t>();
      else if (key == std::string("start_height")) address_txs->m_start_height = it->second.get_value<uint64_t>();
      else if (key == std::string("blockchain_height")) address_txs->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("transactions")) {
        boost::property_tree::ptree transactions_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = transactions_node.begin(); it2 != transactions_node.end(); ++it2) {
          std::shared_ptr<monero_light_tx> transaction = std::make_shared<monero_light_tx>();
          monero_light_tx::from_property_tree(it2->second, transaction);
          address_txs->m_transactions.push_back(*transaction);
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
        boost::property_tree::ptree outs_node = it->second;

        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_random_outputs> out = std::make_shared<monero_light_random_outputs>();
          monero_light_random_outputs::from_property_tree(it2->second, out);
          random_outs->m_amount_outs.push_back(*out);
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
    unspent_outs->m_outputs = std::vector<monero_light_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("per_byte_fee")) unspent_outs->m_per_byte_fee = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("fee_mask")) unspent_outs->m_fee_mask = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("amount")) unspent_outs->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("outputs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_output> out = std::make_shared<monero_light_output>();
          monero_light_output::from_property_tree(it2->second, out);
          unspent_outs->m_outputs.push_back(*out);
        }
      }
    }

    return unspent_outs;
  }

  std::shared_ptr<monero_light_import_wallet_response> monero_light_import_wallet_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_import_wallet_response> import_request = std::make_shared<monero_light_import_wallet_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("payment_address")) import_request->m_payment_address = it->second.data();
      else if (key == std::string("payment_id")) import_request->m_payment_id = it->second.data();
      else if (key == std::string("import_fee")) import_request->m_import_fee = gen_utils::uint64_t_cast(it->second.data());
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

  std::shared_ptr<monero_light_upsert_subaddrs_response> monero_light_upsert_subaddrs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_upsert_subaddrs_response> response = std::make_shared<monero_light_upsert_subaddrs_response>();
    response->m_all_subaddrs = monero_light_subaddrs();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("new_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> new_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, new_subaddrs);
        response->m_new_subaddrs = *new_subaddrs;
      } else if (key == std::string("all_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> all_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, all_subaddrs);
        response->m_all_subaddrs = *all_subaddrs;
      }
    }

    return response;
  }

  std::shared_ptr<monero_light_get_subaddrs_response> monero_light_get_subaddrs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_subaddrs_response> response = std::make_shared<monero_light_get_subaddrs_response>();
    response->m_all_subaddrs = monero_light_subaddrs();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      
      if (key == std::string("all_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> all_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, all_subaddrs);
        response->m_all_subaddrs = *all_subaddrs;
      }
    }

    return response;
  }

  // ------------------------------- PROPERTY TREE UTILS -------------------------------

  void monero_light_version::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_version>& version) {
    // convert config property tree to monero_light_version
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("server_type")) version->m_server_type = it->second.data();
      else if (key == std::string("server_version")) version->m_server_version = it->second.data();
      else if (key == std::string("last_git_commit_hash")) version->m_last_git_commit_hash = it->second.data();
      else if (key == std::string("last_git_commit_date")) version->m_last_git_commit_date = it->second.data();
      else if (key == std::string("git_branch_name")) version->m_git_branch_name = it->second.data();
      else if (key == std::string("monero_version_full")) version->m_monero_version_full = it->second.data();
      else if (key == std::string("blockchain_height")) version->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("api")) version->m_api = it->second.get_value<uint32_t>();
      else if (key == std::string("max_subaddresses")) version->m_max_subaddresses = it->second.get_value<uint32_t>();
      else if (key == std::string("testnet")) version->m_testnet = it->second.get_value<bool>();
      else if (key == std::string("network")) {
        std::string network_str = it->second.data();
        if (network_str == std::string("mainnet") || network_str == "fakechain") version->m_network_type = monero_network_type::MAINNET;
        else if (network_str == std::string("testnet")) version->m_network_type = monero_network_type::TESTNET;
        else if (network_str == std::string("stagenet")) version->m_network_type = monero_network_type::STAGENET;
        throw std::runtime_error("Cannot deserialize lws version: invalid network provided " + network_str);
      }
    }
  }

  void monero_light_address_meta::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta) {
    // convert config property tree to monero_light_address_meta
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }
  }

  void monero_light_index_range::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_index_range>& index_range) {
    // convert config property tree to monero_wallet_config
    int length = 0;
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      uint32_t value = it->second.get_value<uint32_t>();
      index_range->push_back(value);
      
      length++;
      if (length > 2) throw std::runtime_error("Invalid index range length");
      //if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      //else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }

    if (length != 2) throw std::runtime_error("Invalid index range length");
  }

  void monero_light_subaddrs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_subaddrs>& subaddrs) {  
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      boost::property_tree::ptree key_value_node = it->second;
      boost::optional<uint32_t> _key;
      std::vector<monero_light_index_range> index_ranges;
      
      for (boost::property_tree::ptree::const_iterator it2 = key_value_node.begin(); it2 != key_value_node.end(); ++it2) {
        std::string key = it2->first;
        if (key == std::string("key")) _key = it2->second.get_value<uint32_t>();
        else if (key == std::string("value")) {
          for (boost::property_tree::ptree::const_iterator it3 = it2->second.begin(); it3 != it2->second.end(); ++it3) {
            std::shared_ptr<monero_light_index_range> ir = std::make_shared<monero_light_index_range>();
            monero_light_index_range::from_property_tree(it3->second, ir);
            index_ranges.push_back(*ir);
          }
        }
      }

      if (_key == boost::none) throw std::runtime_error("Invalid subaddress");
      
      subaddrs->emplace(_key.get(), index_ranges);
    }
  }

  void monero_light_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
      else if (key == std::string("amount")) output->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("index")) output->m_index = it->second.get_value<uint64_t>();
      else if (key == std::string("global_index")) output->m_global_index = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("rct")) output->m_rct = it->second.data();
      else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
      else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
      else if (key == std::string("public_key")) output->m_public_key = it->second.data();
      else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
      else if (key == std::string("spend_key_images")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.push_back(it2->second.data());
      }
      else if (key == std::string("timestamp")) output->m_timestamp = gen_utils::timestamp_to_epoch(it->second.data());
      else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("recipient")) {
        std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, recipient);
        output->m_recipient = *recipient;
      }
    }
  }

  void monero_light_spend::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) spend->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
      else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
      else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint64_t>();
      else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("sender")) {
        std::shared_ptr<monero_light_address_meta> sender = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, sender);
        spend->m_sender = *sender;
      }
    }
  }

  void monero_light_tx::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_tx>& transaction) {
    std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("id")) transaction->m_id = it->second.get_value<uint64_t>();
      else if (key == std::string("hash")) transaction->m_hash = it->second.data();
      else if (key == std::string("timestamp")) transaction->m_timestamp = gen_utils::timestamp_to_epoch(it->second.data());
      else if (key == std::string("total_received")) transaction->m_total_received = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("total_sent")) transaction->m_total_sent = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("fee")) transaction->m_fee = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("unlock_time")) transaction->m_unlock_time = it->second.get_value<uint64_t>();
      else if (key == std::string("height")) transaction->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        // deserialize monero_light_spend          
        boost::property_tree::ptree outs = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs.begin(); it2 != outs.end(); ++it2) {
          std::shared_ptr<monero_light_spend> out = std::make_shared<monero_light_spend>();
          monero_light_spend::from_property_tree(it2->second, out);
          transaction->m_spent_outputs.push_back(*out);
        }
      }
      else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
      else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
      else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
      else if (key == std::string("mixin")) transaction->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("recipient")) {
        monero_light_address_meta::from_property_tree(it->second, recipient);
      }
    }
    
    transaction->m_recipient = *recipient;
  }

  void monero_light_random_outputs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_outputs>& random_outputs) {
    // convert config property tree to monero_wallet_config

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) random_outputs->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("outputs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_output> out = std::make_shared<monero_light_output>();
          monero_light_output::from_property_tree(it2->second, out);
          random_outputs->m_outputs.push_back(*out);
        }
      }
    }
  }

  // ------------------------------- SERIALIZE UTILS -------------------------------

  rapidjson::Value monero_light_subaddrs::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    rapidjson::Value root(rapidjson::kArrayType);
    rapidjson::Value value_num(rapidjson::kNumberType);
    rapidjson::Value value_arr(rapidjson::kArrayType);

    for(auto subaddr : *this) {
      rapidjson::Value obj_value(rapidjson::kObjectType);
      monero_utils::add_json_member("key", subaddr.first, allocator, obj_value, value_num);
      std::vector<monero_light_index_range> index_ranges = subaddr.second;
      //obj_value.AddMember("value", monero_utils::to_rapidjson_val(allocator, index_ranges), allocator);
      rapidjson::Value obj_index_ranges(rapidjson::kArrayType);

      for (monero_light_index_range index_range : index_ranges) {
        obj_index_ranges.PushBack(monero_utils::to_rapidjson_val(allocator, (std::vector<uint32_t>)index_range), allocator);
      }

      obj_value.AddMember("value", obj_index_ranges, allocator);

      root.PushBack(obj_value, allocator);
    }

    return root;
  }

  rapidjson::Value monero_light_wallet_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

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
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_count != boost::none) monero_utils::add_json_member("count", m_count.get(), allocator, root, value_num);

    std::vector<std::string> amounts;

    for(const auto amount : m_amounts) {
      amounts.push_back(std::to_string(amount));
    }

    // set sub-arrays
    root.AddMember("amounts", monero_utils::to_rapidjson_val(allocator, amounts), allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_import_wallet_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_from_height != boost::none) monero_utils::add_json_member("from_height", m_from_height.get(), allocator, root, value_num);

    // return root
    return root;
  }

  rapidjson::Value monero_light_get_unspent_outs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_num(rapidjson::kNumberType);

    if (m_amount != boost::none) monero_utils::add_json_member("amount", std::to_string(m_amount.get()), allocator, root, value_str);
    if (m_mixin != boost::none) monero_utils::add_json_member("mixin", m_mixin.get(), allocator, root, value_num);
    if (m_use_dust != boost::none) monero_utils::add_json_member("use_dust", m_use_dust.get(), allocator, root);
    if (m_dust_threshold != boost::none) monero_utils::add_json_member("dust_threshold", std::to_string(m_dust_threshold.get()), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_login_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    if (m_create_account != boost::none) monero_utils::add_json_member("create_account", m_create_account.get(), allocator, root);
    if (m_generated_locally != boost::none) monero_utils::add_json_member("generated_locally", m_generated_locally.get(), allocator, root);

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

  rapidjson::Value monero_light_upsert_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    
    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    if (m_subaddrs != boost::none) root.AddMember("subaddrs", m_subaddrs.get().to_rapidjson_val(allocator), allocator);
    if (m_get_all != boost::none) monero_utils::add_json_member("get_all", m_get_all.get(), allocator, root);

    // return root
    return root;
  }

  // ------------------------------- COPY UTILS -------------------------------

  std::shared_ptr<monero_light_spend> monero_light_spend::copy(const std::shared_ptr<monero_light_spend>& src, const std::shared_ptr<monero_light_spend>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this spend != src");
    // copy wallet extensions
    tgt->m_amount = src->m_amount;
    tgt->m_key_image = src->m_key_image;
    tgt->m_tx_pub_key = src->m_tx_pub_key;
    tgt->m_out_index = src->m_out_index;
    tgt->m_mixin = src->m_mixin;
    tgt->m_sender = src->m_sender;

    return tgt;
  }

  std::shared_ptr<monero_light_tx> monero_light_tx::copy(const std::shared_ptr<monero_light_tx>& src, const std::shared_ptr<monero_light_tx>& tgt, bool exclude_spend) const {
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
    tgt->m_recipient = src->m_recipient;
    tgt->m_spent_outputs.clear();

    if (exclude_spend) {
      return tgt;
    }

    if (!src->m_spent_outputs.empty()) {
      for (const monero_light_spend& spent_output : src->m_spent_outputs) {
        std::shared_ptr<monero_light_spend> spent_output_ptr = std::make_shared<monero_light_spend>(spent_output);
        std::shared_ptr<monero_light_spend> spent_output_copy = spent_output_ptr->copy(spent_output_ptr, std::make_shared<monero_light_spend>());
        tgt->m_spent_outputs.push_back(*spent_output_copy);
      }
    }

    return tgt;
  }

  // ------------------------------- LWS CLIENT -------------------------------

  void monero_light_client::disconnect() {
    if (m_http_client->is_connected()) {
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      m_http_client->disconnect();
      m_connected = false;
    }
  }

  monero_light_client::monero_light_client(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    if (http_client_factory != nullptr) m_http_client = http_client_factory->create();
    else {
      auto factory = new net::http::client_factory();
      m_http_client = factory->create();
    }
  }

  monero_light_client::~monero_light_client() {
    MTRACE("~monero_light_client()");
    disconnect();
  }

  void monero_light_client::set_connection(const boost::optional<monero_rpc_connection>& connection) {
    std::string uri;
    std::string username;
    std::string password;
    std::string proxy;

    if (connection != boost::none) {
      if (connection->m_uri != boost::none) uri = connection->m_uri.get();
      if (connection->m_proxy_uri != boost::none) proxy = connection->m_proxy_uri.get();
      if (connection->m_username != boost::none) username = connection->m_username.get();
      if (connection->m_password != boost::none) password = connection->m_password.get();
    }

    if (username.empty() && !password.empty()) throw std::runtime_error("username cannot be empty because password is not empty");
    if (!username.empty() && password.empty()) throw std::runtime_error("password cannot be empty because username is not empty");

    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    disconnect();

    if(!m_http_client->set_proxy(proxy)) {
      throw std::runtime_error("failed to set proxy address");
    }

    epee::net_utils::http::login creds;
    creds.username = username;
    creds.password = password;

    if (!m_http_client->set_server(uri, creds)) {
      throw std::runtime_error("Could not set monero-lws: " + uri);
    }
    
    m_connected = false;
    try {
      if (m_http_client->connect(std::chrono::seconds(15))) {
        get_version();
        m_connected = true;
      } else if (!uri.empty()) MWARNING("Could not connect to monero-lws at " << uri);
    } catch (const std::exception& ex) { MERROR("Could not connect to monero-lws at " << uri << ": " << ex.what()); }

    m_credentials = creds;
    m_server = uri;
    m_proxy = proxy;
  }

  void monero_light_client::set_connection(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy) {
    monero_rpc_connection connection;
    connection.m_uri = uri;
    connection.m_username = username;
    connection.m_password = password;
    connection.m_proxy_uri = proxy;
    set_connection(connection);
  }

  boost::optional<monero_rpc_connection> monero_light_client::get_connection() const {
    if (m_server.empty()) return boost::none;
    
    monero_rpc_connection connection;
    connection.m_uri = m_server;
    connection.m_proxy_uri = m_proxy;
    if (!m_credentials.username.empty() && !m_credentials.password.empty()) {
      connection.m_username = m_credentials.username;
      epee::wipeable_string wipeablePassword = m_credentials.password;
      connection.m_password = std::string(wipeablePassword.data(), wipeablePassword.size());
    }

    return connection;
  }

  monero_light_get_address_info_response monero_light_client::get_address_info(const std::string &address, const std::string &view_key) const {
    monero_light_wallet_request req;
    monero_light_get_address_info_response res;

    req.m_address = address;
    req.m_view_key = view_key;

    int response_code = invoke_post("/get_address_info", req, res);
    if (response_code != 200) {
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not get address info");
    }

    return res;
  }

  monero_light_get_address_txs_response monero_light_client::get_address_txs(const std::string &address, const std::string &view_key) const {
    monero_light_wallet_request req;
    monero_light_get_address_txs_response res;

    req.m_address = address;
    req.m_view_key = view_key;

    int response_code = invoke_post("/get_address_txs", req, res);
    if (response_code != 200) {
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not get address txs");
    }

    return res;
  }

  monero_light_get_unspent_outs_response monero_light_client::get_unspent_outs(const std::string &address, const std::string &view_key, uint64_t amount, uint32_t mixin, bool use_dust, uint64_t dust_threshold) const {
    monero_light_get_unspent_outs_request req;
    monero_light_get_unspent_outs_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_amount = amount;
    req.m_mixin = mixin;
    req.m_use_dust = use_dust;
    req.m_dust_threshold = dust_threshold;

    int response_code = invoke_post("/get_unspent_outs", req, res);
    if (response_code != 200) {
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not get unspent outputs");
    }

    return res;
  }

  monero_light_get_random_outs_response monero_light_client::get_random_outs(uint32_t count, const std::vector<uint64_t> &amounts) const {
    monero_light_get_random_outs_request req;
    monero_light_get_random_outs_response res;

    req.m_count = count;
    req.m_amounts = amounts;

    int response_code = invoke_post("/get_random_outs", req, res);
    if (response_code != 200) {
      throw std::runtime_error("Could not get random outputs");
    }

    return res;
  }

  monero_light_get_subaddrs_response monero_light_client::get_subaddrs(const std::string &address, const std::string &view_key) const {
    monero_light_wallet_request req;
    monero_light_get_subaddrs_response res;

    req.m_address = address;
    req.m_view_key = view_key;

    int response_code = invoke_post("/get_subaddrs", req, res);
    if (response_code != 200) {
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not get subaddresses");
    }

    return res;
  }

  monero_light_upsert_subaddrs_response monero_light_client::upsert_subaddrs(const std::string &address, const std::string &view_key, const monero_light_subaddrs& subaddrs, bool get_all) const {
    monero_light_upsert_subaddrs_request req;
    monero_light_upsert_subaddrs_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_subaddrs = subaddrs;
    req.m_get_all = get_all;

    int response_code = invoke_post("/upsert_subaddrs", req, res);
    if (response_code != 200) {
      if (response_code == 409) throw std::runtime_error("Max subaddresses exceeded");
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not upsert subaddresses");
    }

    return res;    
  }

  monero_light_login_response monero_light_client::login(const std::string &address, const std::string &view_key, bool create_account, bool generated_locally) const {
    monero_light_login_request req;
    monero_light_login_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_create_account = create_account;
    req.m_generated_locally = generated_locally;

    int response_code = invoke_post("/login", req, res);
    if (response_code != 200) {
      if (response_code == 501) throw std::runtime_error("Account creation not allowed");
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not login on account: " + address);
    }

    return res;
  }

  monero_light_import_wallet_response monero_light_client::import_request(const std::string &address, const std::string &view_key, uint64_t from_height) const {
    monero_light_import_wallet_request req;
    monero_light_import_wallet_response res;
    req.m_address = address;
    req.m_view_key = view_key;
    req.m_from_height = from_height;

    int response_code = invoke_post("/import_wallet_request", req, res);
    if (response_code != 200) {
      if (response_code == 403) throw std::runtime_error("Unauthorized");
      throw std::runtime_error("Could not import wallet");
    }

    return res;
  }

  monero_light_submit_raw_tx_response monero_light_client::submit_raw_tx(const std::string& tx) const {
    monero_light_submit_raw_tx_response res;
    monero_light_submit_raw_tx_request req;
    req.m_tx = tx;

    int response_code = invoke_post("/submit_raw_tx", req, res);
    if (response_code != 200) {
      throw std::runtime_error("Could not relay tx: " + tx);
    }

    return res;
  }

  monero_light_version monero_light_client::get_version() const {
    monero_light_version res;

    int response_code = invoke_post("/get_version", monero_light_wallet_request{}, res);
    if (response_code != 200) {
      throw std::runtime_error("Could not get lws version");
    }

    return res;
  }

  // ------------------------------- OUTPUT CONTAINER UTILS -------------------------------

  std::vector<size_t> monero_light_output_store::get_indexes(const std::vector<monero_light_output> &outputs) const {
    std::vector<size_t> indexes;

    for (const auto &output : outputs) {
      std::string public_key = output.m_public_key.get();
      auto it = m_index.find(public_key);

      if (it == m_index.end()) throw std::runtime_error("output doesn't belong to the wallet");

      indexes.push_back(it->second);
    }

    return indexes;
  }

  std::vector<monero_light_output> monero_light_output_store::get(uint32_t account_idx) const {
    auto all = get_spent(account_idx);
    auto unspent = get_unspent(account_idx);
    all.insert(all.end(), unspent.begin(), unspent.end());
    return all;
  }

  std::vector<monero_light_output> monero_light_output_store::get(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto all = get_spent(account_idx, subaddress_idx);
    auto unspent = get_unspent(account_idx, subaddress_idx);
    all.insert(all.end(), unspent.begin(), unspent.end());
    return all;
  }

  std::vector<monero_light_output> monero_light_output_store::get_unspent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_unspent.find(account_idx);
    if (it1 == m_unspent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      m_unspent[account_idx][subaddress_idx] = empty_result;
      return empty_result;
    }
    else {
      // account found
      auto& subaddresses_map = it1->second;
      auto it2 = subaddresses_map.find(subaddress_idx);

      if (it2 == subaddresses_map.end()) {
        // subaddress not found
        std::vector<monero_light_output> empty_result;
        m_unspent[account_idx][subaddress_idx] = empty_result;
        return empty_result;
      }

      // subaddress found
      return it2->second;
    }
  }

  std::vector<monero_light_output> monero_light_output_store::get_spent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_spent.find(account_idx);
    if (it1 == m_spent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      m_spent[account_idx][subaddress_idx] = empty_result;
      return empty_result;
    }
    else {
      // account found
      auto& subaddresses_map = it1->second;
      auto it2 = subaddresses_map.find(subaddress_idx);

      if (it2 == subaddresses_map.end()) {
        // subaddress not found
        std::vector<monero_light_output> empty_result;
        m_spent[account_idx][subaddress_idx] = empty_result;
        return empty_result;
      }

      // subaddress found
      return it2->second;
    }
  }

  std::vector<monero_light_output> monero_light_output_store::get_spent(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_spent.find(account_idx);
    if (it1 == m_spent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      return empty_result;
    }
    else {
      // account found
      std::vector<monero_light_output> result;
      for (const auto &kv : it1->second) {
        result.insert(result.end(), kv.second.begin(), kv.second.end());
      }
      
      return result;
    }
  }

  std::vector<monero_light_output> monero_light_output_store::get_unspent(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_unspent.find(account_idx);
    if (it1 == m_unspent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      return empty_result;
    }

    // account found
    std::vector<monero_light_output> result;
    for (const auto &kv : it1->second) {
      result.insert(result.end(), kv.second.begin(), kv.second.end());
    }
    
    return result;
  }

  std::vector<monero_light_output> monero_light_output_store::get_spendable(uint32_t account_idx, const std::vector<uint32_t> &subaddresses_indices, const monero_light_tx_store& tx_store, uint64_t height) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_unspent.find(account_idx);
    if (it == m_unspent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      return empty_result;
    }

    std::vector<monero_light_output> spendable;
    bool by_subaddress_idx = !subaddresses_indices.empty();
    for(const auto& kv : it->second) {
      uint32_t subaddress_index = kv.first;
      if (by_subaddress_idx) {
        bool found = std::find(subaddresses_indices.begin(), subaddresses_indices.end(), subaddress_index) != subaddresses_indices.end();
        if (!found) continue;
      }

      for (const auto& output : kv.second) {
        if (is_frozen(output) || tx_store.is_locked(output, height)) continue;
        spendable.push_back(output);
      }
    }

    return spendable;
  }

  std::vector<monero_light_output> monero_light_output_store::get_by_tx_hash(const std::string& tx_hash, bool filter_spent) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_tx_hash_index.find(tx_hash);
    if (it == m_tx_hash_index.end()) return std::vector<monero_light_output>();
    if (!filter_spent) {
      return it->second;
    }
    std::vector<monero_light_output> outputs;
    for (const auto &output : it->second) {
      if (!output.is_spent()) outputs.push_back(output);
    }

    return outputs;
  }

  std::string monero_light_output_store::get_tx_prefix_hash(const std::string& tx_hash) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto outputs = get_by_tx_hash(tx_hash);
    if (outputs.empty()) return std::string("");
    auto& output = outputs[0];
    return output.m_tx_prefix_hash.get();
  }

  void monero_light_output_store::set(const monero_light_tx_store& tx_store, const monero_light_get_unspent_outs_response& response) {
    clear();
    if (response.m_outputs.empty()) return;
    const std::vector<monero_light_output>& outputs = response.m_outputs;
    std::vector<monero_light_output> spent;
    std::vector<monero_light_output> unspent;
    size_t index = 0;
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    for (const auto &output : outputs) {
      if (output.is_spent() || (output.key_image_is_known() && tx_store.is_key_image_in_pool(output.m_key_image.get()))) spent.push_back(output);
      else unspent.push_back(output);
      m_index[output.m_public_key.get()] = index;
      
      if (output.key_image_is_known()) {
        std::string output_key_image = output.m_key_image.get();
        m_key_image_index[output_key_image] = index;
      }

      std::string tx_hash = output.m_tx_hash.get();

      auto tx_hash_it = m_tx_hash_index.find(tx_hash);

      if (tx_hash_it == m_tx_hash_index.end()) {
        m_tx_hash_index[tx_hash] = std::vector<monero_light_output>();
        tx_hash_it = m_tx_hash_index.find(tx_hash);
      }

      tx_hash_it->second.push_back(output);
      index++;
    }

    set(spent, unspent);
    m_all = outputs;
  }

  void monero_light_output_store::set(const std::vector<monero_light_output>& spent, const std::vector<monero_light_output>& unspent) {
    set_spent(spent);
    set_unspent(unspent);
  }

  void monero_light_output_store::set_spent(const std::vector<monero_light_output>& outputs) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &output : outputs) {
      const auto& address_meta = output.m_recipient;
      uint32_t account_idx = address_meta.m_maj_i;
      uint32_t subaddress_idx = address_meta.m_min_i;

      auto account_it = m_spent.find(account_idx);
      if (account_it == m_spent.end()) {
        m_spent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        account_it = m_spent.find(account_idx);
      }

      auto subaddress_it = account_it->second.find(subaddress_idx);
      if (subaddress_it == account_it->second.end()) {
        m_spent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        subaddress_it = account_it->second.find(subaddress_idx);
      }

      subaddress_it->second.push_back(output);
    }
    m_num_spent = outputs.size();
  }

  void monero_light_output_store::set_key_image_spent(const std::string& key_image, bool spent) {
    m_key_image_status_index[key_image] = spent;
  }

  void monero_light_output_store::set_unspent(const std::vector<monero_light_output>& outputs) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &output : outputs) {
      const auto& address_meta = output.m_recipient;
      uint32_t account_idx = address_meta.m_maj_i;
      uint32_t subaddress_idx = address_meta.m_min_i;

      auto account_it = m_unspent.find(account_idx);
      if (account_it == m_unspent.end()) {
        m_unspent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        account_it = m_unspent.find(account_idx);
      }

      auto subaddress_it = account_it->second.find(subaddress_idx);
      if (subaddress_it == account_it->second.end()) {
        m_unspent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        subaddress_it = account_it->second.find(subaddress_idx);
      }

      subaddress_it->second.push_back(output);
    }
    m_num_unspent = outputs.size();
  }

  bool monero_light_output_store::is_used(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto outputs = get(account_idx, subaddress_idx);
    return !outputs.empty();
  }

  uint64_t monero_light_output_store::get_num_unspent(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto unspent = get_unspent(account_idx, subaddress_idx);
    return unspent.size();
  }

  void monero_light_output_store::clear_balance() {
    m_account_balance.clear();
    m_account_unlocked_balance.clear();
    m_subaddress_balance.clear();
    m_subaddress_unlocked_balance.clear();
    m_balance = 0;
    m_unlocked_balance = 0;
  }

  void monero_light_output_store::clear() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_index.clear();
    m_key_image_index.clear();
    m_tx_hash_index.clear();
    m_unspent.clear();
    m_spent.clear();
    m_all.clear();
    clear_balance();
  }

  void monero_light_output_store::clear_frozen() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_frozen_key_image_index.clear();
  }

  void monero_light_output_store::calculate_balance(const monero_light_tx_store& tx_store, uint64_t current_height) {
    clear_balance();
    for (const auto &kv : m_unspent) {
      uint32_t account_idx = kv.first;
      uint64_t account_balance = 0;
      uint64_t account_unlocked_balance = 0;
      
      for (const auto &kv2 : kv.second) {
        uint32_t subaddress_idx = kv2.first;
        uint64_t subaddress_balance = 0;
        uint64_t subaddress_unlocked_balance = 0;
      
        for(const auto &output : kv2.second) {
          if (output.key_image_is_known() && tx_store.is_key_image_in_pool(output.m_key_image.get())) continue;
          bool is_locked = tx_store.is_locked(output, current_height);
          uint64_t amount = output.m_amount.get();
          subaddress_balance += amount;
          if (!is_locked) subaddress_unlocked_balance += amount;
        }

        account_balance += subaddress_balance;
        account_unlocked_balance += subaddress_unlocked_balance;

        m_subaddress_balance[account_idx][subaddress_idx] = subaddress_balance;
        m_subaddress_unlocked_balance[account_idx][subaddress_idx] = subaddress_unlocked_balance;
      }

      m_balance += account_balance;
      m_unlocked_balance += account_unlocked_balance;

      m_account_balance[account_idx] = account_balance;
      m_account_unlocked_balance[account_idx] = account_unlocked_balance;
    }

    // consider also unconfirmed txs
    for (const auto &kv : tx_store.get_unconfirmed_txs()) {
      const auto &tx = kv.second;

      if (tx->m_is_relayed != true || tx->m_is_failed == true) continue;

      uint64_t change_amount = 0;

      if (tx->m_change_amount != boost::none) change_amount = tx->m_change_amount.get();

      m_balance += change_amount;
      m_account_balance[0] += change_amount;
      m_subaddress_balance[0][0] += change_amount;

      for (const std::shared_ptr<monero_output> &out : tx->m_outputs) {
        std::shared_ptr<monero_output_wallet> output = std::dynamic_pointer_cast<monero_output_wallet>(out);
        if (output == nullptr) {
          continue;
        }
        
        if (output->m_account_index == boost::none) throw std::runtime_error("output account index is none");
        if (output->m_subaddress_index == boost::none) throw std::runtime_error("output subaddress index is none");
        if (output->m_amount == boost::none) throw std::runtime_error("output amount is none");

        uint32_t account_idx = output->m_account_index.get();
        uint32_t subaddress_idx = output->m_subaddress_index.get();
        uint64_t output_amount = output->m_amount.get();

        auto account_it = m_account_balance.find(account_idx);
        if (account_it == m_account_balance.end()) {
          m_account_balance[account_idx] = output_amount;
          m_account_unlocked_balance[account_idx] = 0;
          m_subaddress_balance[account_idx][subaddress_idx] = output_amount;
        }
        else {
          m_account_balance[account_idx] += output_amount;

          auto subaddr_it = m_subaddress_balance[account_idx].find(subaddress_idx);
          if (subaddr_it == m_subaddress_balance[account_idx].end()) {
            m_subaddress_balance[account_idx][subaddress_idx] = output_amount;
          }
          else m_subaddress_balance[account_idx][subaddress_idx] += output_amount;
        }
        m_balance += output_amount;
      }
    }
  }

  uint64_t monero_light_output_store::get_balance(uint32_t account_idx) const {
    auto it = m_account_balance.find(account_idx);
    if (it == m_account_balance.end()) return 0;
    return it->second;
  }

  uint64_t monero_light_output_store::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto it = m_subaddress_balance.find(account_idx);
    if (it == m_subaddress_balance.end()) return 0;
    auto it2 = it->second.find(subaddress_idx);
    if (it2 == it->second.end()) return 0;
    return it2->second;
  }

  uint64_t monero_light_output_store::get_unlocked_balance(uint32_t account_idx) const {
    auto it = m_account_unlocked_balance.find(account_idx);
    if (it == m_account_unlocked_balance.end()) return 0;
    return it->second;
  }

  uint64_t monero_light_output_store::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto it = m_subaddress_unlocked_balance.find(account_idx);
    if (it == m_subaddress_unlocked_balance.end()) return 0;
    auto it2 = it->second.find(subaddress_idx);
    if (it2 == it->second.end()) return 0;
    return it2->second;
  }

  void validate_key_image(const std::string& key_image) {
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key image: " + key_image);
  }

  void monero_light_output_store::freeze(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to freeze");
    validate_key_image(key_image);
    auto key_it = m_key_image_index.find(key_image);
    if (key_it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    size_t index = key_it->second;
    m_frozen_key_image_index[index] = true;
  }

  void monero_light_output_store::thaw(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    validate_key_image(key_image);
    auto key_it = m_key_image_index.find(key_image);
    if (key_it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    size_t index = key_it->second;
    m_frozen_key_image_index[index] = false;
  }

  bool monero_light_output_store::is_frozen(const std::string& key_image) const {
    validate_key_image(key_image);
    auto key_it = m_key_image_index.find(key_image);
    if (key_it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    size_t index = key_it->second;
    auto frozen_it = m_frozen_key_image_index.find(index);
    if (frozen_it == m_frozen_key_image_index.end()) return false;
    return frozen_it->second;
  }

  bool monero_light_output_store::is_frozen(const monero_light_output& output) const {
    return is_frozen(output.m_key_image == boost::none ? "" : output.m_key_image.get());
  }

  void monero_light_output_store::set_key_image(const std::string& key_image, size_t index) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_key_image_index[key_image] = index;
  }

  wallet2_exported_outputs monero_light_output_store::export_outputs(const monero_light_tx_store& tx_store, monero_key_image_cache& key_image_cache, bool all, uint32_t start, uint32_t count) const {
    std::vector<tools::wallet2::exported_transfer_details> outs;

    // invalid cases
    if(count == 0) throw std::runtime_error("Nothing requested");
    if(!all && start > 0) throw std::runtime_error("Incremental mode is incompatible with non-zero start");

    // valid cases:
    // all: all outputs, subject to start/count
    // !all: incremental, subject to count
    // for convenience, start/count are allowed to go past the valid range, then nothing is returned
    const auto &unspent_outs = m_all;

    size_t offset = 0;    
    if (!all)
      while (offset < unspent_outs.size() && (unspent_outs[offset].key_image_is_known() && !key_image_cache.request(unspent_outs[offset].m_tx_pub_key.get(), unspent_outs[offset].m_index.get(), unspent_outs[offset].m_recipient.m_maj_i, unspent_outs[offset].m_recipient.m_min_i)))
        ++offset;
    else
      offset = start;

    outs.reserve(unspent_outs.size() - offset);
    for (size_t n = offset; n < unspent_outs.size() && n - offset < count; ++n)
    {
      const auto &out = unspent_outs[n];
      uint64_t out_amount = out.m_amount.get();
      auto internal_output_index = out.m_index.get();
      std::string tx_hash = out.m_tx_hash.get();

      uint64_t unlock_time = tx_store.get_unlock_time(tx_hash);

      tools::wallet2::exported_transfer_details etd;
      
      crypto::public_key public_key;
      crypto::public_key tx_pub_key;

      epee::string_tools::hex_to_pod(out.m_public_key.get(), public_key);
      epee::string_tools::hex_to_pod(out.m_tx_pub_key.get(), tx_pub_key);

      cryptonote::transaction_prefix tx_prefix;

      add_tx_pub_key_to_extra(tx_prefix, tx_pub_key);

      cryptonote::tx_out txout;
      txout.target = cryptonote::txout_to_key(public_key);
      txout.amount = out_amount;
      tx_prefix.vout.resize(internal_output_index + 1);
      tx_prefix.vout[internal_output_index] = txout;
      tx_prefix.unlock_time = unlock_time;

      etd.m_pubkey = public_key;
      etd.m_tx_pubkey = tx_pub_key; // pk_index?
      etd.m_internal_output_index = internal_output_index;
      etd.m_global_output_index = out.m_global_index.get();
      etd.m_flags.flags = 0;
      etd.m_flags.m_spent = out.is_spent();
      etd.m_flags.m_frozen = false;
      etd.m_flags.m_rct = out.is_rct();
      etd.m_flags.m_key_image_known = out.key_image_is_known();
      etd.m_flags.m_key_image_request = false; //td.m_key_image_request;
      etd.m_flags.m_key_image_partial = false;
      etd.m_amount = out_amount;
      etd.m_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx_prefix);
      etd.m_subaddr_index_major = out.m_recipient.m_maj_i;
      etd.m_subaddr_index_minor = out.m_recipient.m_min_i;

      outs.push_back(etd);
    }

    return std::make_tuple(offset, unspent_outs.size(), outs);
  }

  // ------------------------------- TX CONTAINER UTILS -------------------------------

  monero_light_tx monero_light_tx_store::get(const std::string& hash) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_txs.find(hash);
    if (it == m_txs.end()) throw std::runtime_error("tx not found in store");
    return it->second;
  }

  monero_light_tx monero_light_tx_store::get(const monero_light_output& output) const {
    return get(output.m_tx_hash.get());
  }

  uint64_t monero_light_tx_store::get_unlock_time(const std::string& hash) const {
    const auto &tx = get(hash);
    return tx.m_unlock_time.get();
  }

  void monero_light_tx_store::set(const monero_light_get_address_txs_response& response, const monero_light_get_address_info_response& addr_info_response) {
    clear();
    set(response.m_transactions);

    for (const auto &spend : addr_info_response.m_spent_outputs) {
      if (spend.m_key_image != boost::none) {
        m_spent_key_images[spend.m_key_image.get()] = true;
      }
    }
  }

  void monero_light_tx_store::set(const monero_light_tx& tx) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_txs[tx.m_hash.get()] = tx;
  }

  void monero_light_tx_store::add_key_images_to_pool(const std::shared_ptr<monero_tx_wallet>& tx) {
    if (tx->m_is_relayed != true) {
      return;
    }
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    std::string tx_hash = tx->m_hash.get();
    m_pool_key_images.erase(tx_hash);
    std::vector<std::string> key_images;

    for(const auto &in : tx->m_inputs) {
      std::shared_ptr<monero_output_wallet> input = std::static_pointer_cast<monero_output_wallet>(in);
        
      if (input == nullptr) {
        throw std::runtime_error("Expected input monero_output_wallet");
      }

      if (input->m_key_image == boost::none || input->m_key_image.get()->m_hex == boost::none || input->m_key_image.get()->m_hex->empty()) throw std::runtime_error("Input key image is none");
      std::string key_image = input->m_key_image.get()->m_hex.get();
      key_images.push_back(key_image);
    }

    if (key_images.size() > 0) m_pool_key_images[tx_hash] = key_images;
  }

  void monero_light_tx_store::set_unconfirmed(const std::shared_ptr<monero_tx_wallet>& tx) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    if (tx->m_hash == boost::none) throw std::runtime_error("Cannot set none unconfirmed tx hash");
    std::string tx_hash = tx->m_hash.get();
    if (tx_hash.empty()) throw std::runtime_error("Cannot set empty unconfirmed tx hash");
    m_unconfirmed_txs[tx_hash] = tx;
    add_key_images_to_pool(tx);
  }

  void monero_light_tx_store::remove_unconfirmed(const std::string& hash) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_unconfirmed_txs.erase(hash);
    m_pool_key_images.erase(hash);
  }

  void monero_light_tx_store::set_relayed(const std::string& hash) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_unconfirmed_txs.find(hash);
    if (it == m_unconfirmed_txs.end()) {
      return;
    }
    it->second->m_in_tx_pool = true;
    it->second->m_is_locked = true;
    it->second->m_is_relayed = true;
    it->second->m_relay = true;
    it->second->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
    it->second->m_is_failed = false;
    it->second->m_is_double_spend_seen = false;
    add_key_images_to_pool(it->second);
  }

  void monero_light_tx_store::set(const std::vector<monero_light_tx>& txs, bool clear_txs) {
    if (clear_txs) clear();
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for(const auto &tx : txs) {
      std::string tx_hash = tx.m_hash.get();
      bool confirmed = !tx.m_mempool.get();
      bool is_miner_tx = tx.m_coinbase.get();
      m_txs[tx_hash] = tx;
      if (confirmed) remove_unconfirmed(tx_hash);
      if (is_miner_tx) {
        uint64_t amount = tx.m_total_received.get();
        if (m_block_reward == 0 || amount < m_block_reward) m_block_reward = amount;
      }
    }

    if (m_block_reward == 0) m_block_reward = monero_utils::TAIL_EMISSION_REWARD;
  }

  uint64_t monero_light_tx_store::calculate_num_blocks_to_unlock(const std::string& hash, uint64_t current_height) const {
    monero_light_tx tx = get(hash);
    uint64_t tx_height = tx.m_mempool.get() ? current_height : tx.m_height.get();
    uint64_t unlock_time = tx.m_unlock_time.get();
    uint64_t default_spendable_age = tx_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    uint64_t confirmations_needed = default_spendable_age > current_height ? default_spendable_age - current_height : 0;
    uint64_t num_blocks_to_unlock = unlock_time <= current_height ? 0 : unlock_time - current_height;
    return num_blocks_to_unlock > confirmations_needed ? num_blocks_to_unlock : confirmations_needed;
  }

  uint64_t monero_light_tx_store::calculate_num_blocks_to_unlock(const std::vector<std::string>& hashes, uint64_t current_height) const {
    uint64_t num_blocks = 0;
    for(const std::string& hash : hashes) {
      uint64_t blocks = calculate_num_blocks_to_unlock(hash, current_height);
      if (blocks > num_blocks) num_blocks = blocks;
    }
    return num_blocks;
  }

  uint64_t monero_light_tx_store::calculate_num_blocks_to_unlock(const std::vector<monero_light_output>& outputs, uint64_t current_height) const {
    std::vector<std::string> hashes;

    for(const auto &output : outputs) {
      if (output.m_tx_hash == boost::none) continue;
      hashes.push_back(output.m_tx_hash.get());
    }

    return calculate_num_blocks_to_unlock(hashes, current_height);
  }

  uint64_t monero_light_tx_store::calculate_num_blocks_to_unlock(const monero_light_output& output, uint64_t current_height) const {
    return calculate_num_blocks_to_unlock(output.m_tx_hash.get(), current_height);
  }

  bool monero_light_tx_store::is_locked(const std::string& hash, uint64_t current_height) const {
    return calculate_num_blocks_to_unlock(hash, current_height) > 0;
  }

  bool monero_light_tx_store::is_locked(const monero_light_output& output, uint64_t current_height) const {
    return is_locked(output.m_tx_hash.get(), current_height);
  }

  bool monero_light_tx_store::is_confirmed(const std::string& hash) const {
    monero_light_tx tx = get(hash);
    return tx.m_mempool == false;
  }

  bool monero_light_tx_store::is_key_image_in_pool(const std::string& key_image) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &kv : m_pool_key_images) {
      for(const std::string &pool_key_image : kv.second) {
        if (key_image == pool_key_image) return true;
      }
    }
    return false;
  }

  bool monero_light_tx_store::is_key_image_spent(const std::string& key_image) const {
    if (is_key_image_in_pool(key_image)) return true;
    auto it = m_spent_key_images.find(key_image);
    if (it == m_spent_key_images.end()) return false;
    return it->second;
  }

  bool monero_light_tx_store::is_key_image_spent(const crypto::key_image& key_image) const {
    std::string key_image_str = epee::string_tools::pod_to_hex(key_image);
    return is_key_image_spent(key_image_str);
  }

  bool monero_light_tx_store::is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image) const {
    if (key_image == nullptr) throw std::runtime_error("key image is null");
    return is_key_image_spent(*key_image);
  }

  bool monero_light_tx_store::is_key_image_spent(const monero_key_image& key_image) const {
    if (key_image.m_hex == boost::none) return false;
    return is_key_image_spent(key_image.m_hex.get());
  }

  void monero_light_tx_store::clear_unconfirmed() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_unconfirmed_txs.clear();
    m_pool_key_images.clear();
  }

  void monero_light_tx_store::clear() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_txs.clear();
    m_spent_key_images.clear();
    m_block_reward = 0;
  }

}