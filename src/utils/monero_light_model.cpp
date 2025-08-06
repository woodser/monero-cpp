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

#include "monero_light_model.h"

#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
#include <iostream>

namespace monero {

  // ------------------------------- DESERIALIZE UTILS -------------------------------

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
  };

  std::shared_ptr<monero_light_output> monero_light_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
    output->m_spend_key_images = std::vector<std::string>();
    std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
        else if (key == std::string("amount")) output->m_amount = it->second.data();
        else if (key == std::string("index")) output->m_index = it->second.get_value<uint64_t>();
        else if (key == std::string("global_index")) output->m_global_index = it->second.data();
        else if (key == std::string("rct")) output->m_rct = it->second.data();
        else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
        else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
        else if (key == std::string("public_key")) output->m_public_key = it->second.data();
        else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
        else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
        else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
        else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
        else if (key == std::string("recipient")) {
          monero_light_address_meta::from_property_tree(it->second, recipient);
        }
    }
    
    output->m_recipient = *recipient;

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
    std::shared_ptr<monero_light_address_meta> sender = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) spend->m_amount = it->second.data();
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

  std::shared_ptr<monero_light_transaction> monero_light_transaction::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_transaction> transaction = std::make_shared<monero_light_transaction>();
    transaction->m_spent_outputs = std::vector<monero_light_spend>();
    transaction->m_coinbase = false;
    transaction->m_total_received = "0";
    transaction->m_total_sent = "0";

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
          boost::property_tree::ptree outs_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
            std::shared_ptr<monero_light_spend> out = std::make_shared<monero_light_spend>();
            monero_light_spend::from_property_tree(it2->second, out);
            transaction->m_spent_outputs->push_back(*out);
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
    random_outputs->m_outputs = std::vector<monero_light_random_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) random_outputs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            boost::property_tree::ptree outs_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
              std::shared_ptr<monero_light_random_output> out = std::make_shared<monero_light_random_output>();
              monero_light_random_output::from_property_tree(it2->second, out);
              random_outputs->m_outputs->push_back(*out);
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
    address_info->m_spent_outputs = std::vector<monero_light_spend>();

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
          boost::property_tree::ptree spent_outputs_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = spent_outputs_node.begin(); it2 != spent_outputs_node.end(); ++it2) {
            std::shared_ptr<monero_light_spend> spent_output = std::make_shared<monero_light_spend>();
            monero_light_spend::from_property_tree(it2->second, spent_output);
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
    address_txs->m_transactions = std::vector<monero_light_transaction>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("total_received")) address_txs->m_total_received = it->second.data();
        else if (key == std::string("scanned_height")) address_txs->m_scanned_height = it->second.get_value<uint64_t>();
        else if (key == std::string("scanned_block_height")) address_txs->m_scanned_block_height = it->second.get_value<uint64_t>();
        else if (key == std::string("start_height")) address_txs->m_start_height = it->second.get_value<uint64_t>();
        else if (key == std::string("blockchain_height")) address_txs->m_blockchain_height = it->second.get_value<uint64_t>();
        else if (key == std::string("transactions")) {
          boost::property_tree::ptree transactions_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = transactions_node.begin(); it2 != transactions_node.end(); ++it2) {
            std::shared_ptr<monero_light_transaction> transaction = std::make_shared<monero_light_transaction>();
            monero_light_transaction::from_property_tree(it2->second, transaction);
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
    random_outs->m_amount_outs = std::vector<monero_light_random_outputs>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount_outs")) {
          boost::property_tree::ptree outs_node = it->second;

          for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
            std::shared_ptr<monero_light_random_outputs> out = std::make_shared<monero_light_random_outputs>();
            monero_light_random_outputs::from_property_tree(it2->second, out);
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
    unspent_outs->m_outputs = std::vector<monero_light_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("per_byte_fee")) unspent_outs->m_per_byte_fee = it->second.data();
        else if (key == std::string("fee_mask")) unspent_outs->m_fee_mask = it->second.data();
        else if (key == std::string("amount")) unspent_outs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            boost::property_tree::ptree outs_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
              std::shared_ptr<monero_light_output> out = std::make_shared<monero_light_output>();
              monero_light_output::from_property_tree(it2->second, out);
              unspent_outs->m_outputs->push_back(*out);
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

  std::shared_ptr<monero_light_provision_subaddrs_response> monero_light_provision_subaddrs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_provision_subaddrs_response> response = std::make_shared<monero_light_provision_subaddrs_response>();
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
    accounts->m_active = std::vector<monero_light_account>();
    accounts->m_inactive = std::vector<monero_light_account>();
    accounts->m_hidden = std::vector<monero_light_account>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("active")) {
            boost::property_tree::ptree accounts_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
              std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
              monero_light_account::from_property_tree(it2->second, account);
              accounts->m_active->push_back(*account);
            }
        }
        else if (key == std::string("inactive")) {
            boost::property_tree::ptree accounts_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
              std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
              monero_light_account::from_property_tree(it2->second, account);
              accounts->m_inactive->push_back(*account);
            }
        }
        else if (key == std::string("hidden")) {
            boost::property_tree::ptree accounts_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
              std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
              monero_light_account::from_property_tree(it2->second, account);
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
    requests->m_create = std::vector<monero_light_create_account_request>();
    requests->m_import = std::vector<monero_light_import_account_request>();
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

  // ------------------------------- PROPERTY TREE UTILS -------------------------------

  void monero_light_address_meta::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta) {
    // convert config property tree to monero_wallet_config
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }
  };

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
  };

  void monero_light_subaddrs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_subaddrs>& subaddrs) {  
    // convert config property tree to monero_wallet_config
    boost::optional<uint32_t> _key = boost::none;
    boost::optional<monero_light_index_range> _index_range = boost::none;

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
  };

  void monero_light_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output) {
    output->m_spend_key_images = std::vector<std::string>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
        else if (key == std::string("amount")) output->m_amount = it->second.data();
        else if (key == std::string("index")) output->m_index = it->second.get_value<uint64_t>();
        else if (key == std::string("global_index")) output->m_global_index = it->second.data();
        else if (key == std::string("rct")) output->m_rct = it->second.data();
        else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
        else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
        else if (key == std::string("public_key")) output->m_public_key = it->second.data();
        else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
        else if (key == std::string("spend_key_images")) {
          output->m_spend_key_images = std::vector<std::string>();
          for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
        }
        else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
        else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
        else if (key == std::string("recipient")) {
          std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();
          monero_light_address_meta::from_property_tree(it->second, recipient);
          output->m_recipient = *recipient;
        }
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
        else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint64_t>();
        else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
        else if (key == std::string("sender")) {
          std::shared_ptr<monero_light_address_meta> sender = std::make_shared<monero_light_address_meta>();
          monero_light_address_meta::from_property_tree(it->second, sender);
          spend->m_sender = *sender;
        }
    }
  }

  void monero_light_transaction::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_transaction>& transaction) {
    transaction->m_spent_outputs = std::vector<monero_light_spend>();
    std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();

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
          boost::property_tree::ptree outs = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = outs.begin(); it2 != outs.end(); ++it2) {
            std::shared_ptr<monero_light_spend> out = std::make_shared<monero_light_spend>();
            monero_light_spend::from_property_tree(it2->second, out);
            transaction->m_spent_outputs->push_back(*out);
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

  void monero_light_random_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
        else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
        else if (key == std::string("rct")) random_output->m_rct = it->second.data();
    }
  }

  void monero_light_random_outputs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_outputs>& random_outputs) {
    // convert config property tree to monero_wallet_config
    random_outputs->m_outputs = std::vector<monero_light_random_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) random_outputs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            boost::property_tree::ptree outs_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
              std::shared_ptr<monero_light_random_output> out = std::make_shared<monero_light_random_output>();
              monero_light_random_output::from_property_tree(it2->second, out);
              random_outputs->m_outputs->push_back(*out);
            }
        }
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
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_count != boost::none) monero_utils::add_json_member("count", m_count.get(), allocator, root, value_num);

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
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_str);
    if (m_mixin != boost::none) monero_utils::add_json_member("mixin", m_mixin.get(), allocator, root, value_num);
    if (m_use_dust != boost::none) monero_utils::add_json_member("use_dust", m_use_dust.get(), allocator, root);
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

  rapidjson::Value monero_light_provision_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
      // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
    if (m_maj_i != boost::none) monero_utils::add_json_member("maj_i", m_maj_i.get(), allocator, root, value_str);
    if (m_min_i != boost::none) monero_utils::add_json_member("min_i", m_min_i.get(), allocator, root, value_str);
    if (m_n_maj != boost::none) monero_utils::add_json_member("n_maj", m_n_maj.get(), allocator, root, value_str);
    if (m_n_min != boost::none) monero_utils::add_json_member("n_min", m_n_min.get(), allocator, root, value_str);
    if (m_get_all != boost::none) monero_utils::add_json_member("get_all", m_get_all.get(), allocator, root, value_str);
    else monero_utils::add_json_member("get_all", true, allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_upsert_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
      // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
    if (m_subaddrs != boost::none) {
      root.AddMember("subaddrs", m_subaddrs.get().to_rapidjson_val(allocator), allocator);
    }
    if (m_get_all != boost::none) monero_utils::add_json_member("get_all", m_get_all.get(), allocator, root);

    // return root
    return root;
  }

  rapidjson::Value monero_light_get_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
      // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

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
    tgt->m_recipient = src->m_recipient;
    tgt->m_spent_outputs = std::vector<monero_light_spend>();

    if (exclude_spend) {
      return tgt;
    }

    if (!src->m_spent_outputs.get().empty()) {
      for (const monero_light_spend& spent_output : src->m_spent_outputs.get()) {
        std::shared_ptr<monero_light_spend> spent_output_ptr = std::make_shared<monero_light_spend>(spent_output);
        std::shared_ptr<monero_light_spend> spent_output_copy = spent_output_ptr->copy(spent_output_ptr, std::make_shared<monero_light_spend>());
        tgt->m_spent_outputs.get().push_back(*spent_output_copy);
      }
    }

    return tgt;
  }

}