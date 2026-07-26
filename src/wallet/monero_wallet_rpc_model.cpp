/**
 * Copyright (c) everoddandeven
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
 * Parts of this file are originally copyright (c) 2025-2026 woodser
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

#include "monero_wallet_rpc_model.h"
#include "common/monero_error.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"

namespace monero {

  // --------------------------- KEY VALUE ---------------------------

  void key_value::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<key_value>& attributes) {
    attributes->m_key = boost::none;
    attributes->m_value = boost::none;

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("key")) attributes->m_key = it->second.data();
      else if (key == std::string("value")) attributes->m_value = it->second.data();
    }
  }

  rapidjson::Value key_value::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_key != boost::none) monero_utils::add_json_member("key", m_key.get(), allocator, root, value_str);
    if (m_value != boost::none) monero_utils::add_json_member("value", m_value.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO RPC KEY IMAGE ---------------------------

  monero_rpc_key_image::monero_rpc_key_image(const std::shared_ptr<monero_key_image> &key_image) {
    m_hex = key_image->m_hex;
    m_signature = key_image->m_signature;
  }

  rapidjson::Value monero_rpc_key_image::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_hex != boost::none) monero_utils::add_json_member("key_image", m_hex.get(), allocator, root, value_str);
    if (m_signature != boost::none) monero_utils::add_json_member("signature", m_signature.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO GET PAYMENT URI ---------------------------

  monero_payment_uri_params::monero_payment_uri_params(const monero_tx_config& config):
    m_recipient_name(config.m_recipient_name),
    m_tx_description(config.m_note),
    m_payment_id(config.m_payment_id) {

    if (config.m_destinations.empty()) {
      m_address = config.m_address;
      m_amount = config.m_amount;
    } else {
      const auto& dest = config.m_destinations[0];
      m_address = dest->m_address;
      m_amount = dest->m_amount;
    }
  }

  rapidjson::Value monero_payment_uri_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_payment_id != boost::none) monero_utils::add_json_member("payment_id", m_payment_id.get(), allocator, root, value_str);
    if (m_recipient_name != boost::none) monero_utils::add_json_member("recipient_name", m_recipient_name.get(), allocator, root, value_str);
    if (m_tx_description != boost::none) monero_utils::add_json_member("tx_description", m_tx_description.get(), allocator, root, value_str);
    if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO GET BALANCE PARAMS ---------------------------

  monero_get_balance_params::monero_get_balance_params(uint32_t account_idx, boost::optional<uint32_t> address_idx, bool all_accounts, bool strict):
    m_account_idx(account_idx),
    m_all_accounts(all_accounts),
    m_strict(strict) {
    if (address_idx != boost::none) m_address_indices.push_back(address_idx.get());
  }

  rapidjson::Value monero_get_balance_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_account_idx != boost::none) monero_utils::add_json_member("account_index", m_account_idx.get(), allocator, root, value_num);

    // set bool values
    if (m_all_accounts != boost::none) monero_utils::add_json_member("all_accounts", m_all_accounts.get(), allocator, root);
    if (m_strict != boost::none) monero_utils::add_json_member("strict", m_strict.get(), allocator, root);

    // set sub-arrays
    if (!m_address_indices.empty()) root.AddMember("address_indices", monero_utils::to_rapidjson_val(allocator, m_address_indices), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO WALLET DATA PARAMS ---------------------------

  rapidjson::Value monero_wallet_data_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_outputs_hex != boost::none) monero_utils::add_json_member("outputs_data_hex", m_outputs_hex.get(), allocator, root, value_str);

    // set bool values
    if (m_all != boost::none) monero_utils::add_json_member("all", m_all.get(), allocator, root);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_offset != boost::none) monero_utils::add_json_member("offset", m_offset.get(), allocator, root, value_num);

    // set sub-arrays
    std::vector<std::shared_ptr<monero_rpc_key_image>> signed_key_images;
    for (const auto& ki : m_key_images) signed_key_images.push_back(std::make_shared<monero_rpc_key_image>(ki));
    if (m_all == boost::none && signed_key_images.size() > 0) root.AddMember("signed_key_images", monero_utils::to_rapidjson_val(allocator, signed_key_images), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO SWEEP PARAMS ---------------------------

  monero_sweep_params::monero_sweep_params(const monero_tx_config& config):
    m_account_index(config.m_account_index),
    m_subaddr_indices(config.m_subaddress_indices),
    m_key_image(config.m_key_image),
    m_relay(config.m_relay),
    m_priority(config.m_priority),
    m_payment_id(config.m_payment_id),
    m_below_amount(config.m_below_amount),
    m_get_tx_key(true),
    m_get_tx_hex(true),
    m_get_tx_metadata(true) {
    auto destinations = config.get_normalized_destinations();
    m_address = destinations.empty() ? config.m_address : destinations[0]->m_address;
  }

  rapidjson::Value monero_sweep_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_key_image != boost::none) monero_utils::add_json_member("key_image", m_key_image.get(), allocator, root, value_str);
    if (m_payment_id != boost::none) monero_utils::add_json_member("payment_id", m_payment_id.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value val_num(rapidjson::kNumberType);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, val_num);
    if (m_priority != boost::none) monero_utils::add_json_member("priority", m_priority.get(), allocator, root, val_num);
    if (m_below_amount != boost::none) monero_utils::add_json_member("below_amount", m_below_amount.get(), allocator, root, val_num);

    // set bool values
    if (m_get_tx_key != boost::none) monero_utils::add_json_member("get_tx_key", m_get_tx_key.get(), allocator, root);
    if (m_get_tx_keys != boost::none) monero_utils::add_json_member("get_tx_keys", m_get_tx_keys.get(), allocator, root);
    if (m_get_tx_hex != boost::none) monero_utils::add_json_member("get_tx_hex", m_get_tx_hex.get(), allocator, root);
    if (m_get_tx_metadata != boost::none) monero_utils::add_json_member("get_tx_metadata", m_get_tx_metadata.get(), allocator, root);
    monero_utils::add_json_member("do_not_relay", !gen_utils::bool_equals(true, m_relay), allocator, root);

    // set sub-arrays
    if (m_subaddr_indices.size() > 0) root.AddMember("subaddr_indices", monero_utils::to_rapidjson_val(allocator, m_subaddr_indices), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO TRANSFER PARAMS ---------------------------

  monero_transfer_params::monero_transfer_params(const monero_tx_config &config) {
    for (const auto& sub_idx : config.m_subaddress_indices) {
      m_subaddress_indices.push_back(sub_idx);
    }

    for (const auto &dest : config.get_normalized_destinations()) {
      if (dest->m_address == boost::none) throw monero_error("Destination address is not defined");
      if (dest->m_amount == boost::none) throw monero_error("Destination amount is not defined");
      m_destinations.push_back(dest);
    }

    m_subtract_fee_from_outputs = config.m_subtract_fee_from;
    m_account_index = config.m_account_index;
    m_payment_id = config.m_payment_id;
    if (gen_utils::bool_equals(true, config.m_relay)) {
      m_do_not_relay = false;
    }
    else {
      m_do_not_relay = true;
    }
    if (config.m_priority == monero_tx_priority::DEFAULT) {
      m_priority = 0;
    }
    else if (config.m_priority == monero_tx_priority::UNIMPORTANT) {
      m_priority = 1;
    }
    else if (config.m_priority == monero_tx_priority::NORMAL) {
      m_priority = 2;
    }
    else if (config.m_priority == monero_tx_priority::ELEVATED) {
      m_priority = 3;
    }
    m_get_tx_hex = true;
    m_get_tx_metadata = true;
    if (gen_utils::bool_equals(true, config.m_can_split)) m_get_tx_keys = true;
    else m_get_tx_key = true;
  }

  rapidjson::Value monero_transfer_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_payment_id != boost::none) monero_utils::add_json_member("payment_id", m_payment_id.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, value_num);
    if (m_priority != boost::none) monero_utils::add_json_member("priority", m_priority.get(), allocator, root, value_num);

    // set bool values
    if (m_do_not_relay != boost::none) monero_utils::add_json_member("do_not_relay", m_do_not_relay.get(), allocator, root);
    if (m_get_tx_hex != boost::none) monero_utils::add_json_member("get_tx_hex", m_get_tx_hex.get(), allocator, root);
    if (m_get_tx_metadata != boost::none) monero_utils::add_json_member("get_tx_metadata", m_get_tx_metadata.get(), allocator, root);
    if (m_get_tx_keys != boost::none) monero_utils::add_json_member("get_tx_keys", m_get_tx_keys.get(), allocator, root);
    if (m_get_tx_key != boost::none) monero_utils::add_json_member("get_tx_key", m_get_tx_key.get(), allocator, root);

    // set sub-arrays
    if (!m_subtract_fee_from_outputs.empty()) root.AddMember("subtract_fee_from_outputs", monero_utils::to_rapidjson_val(allocator, m_subtract_fee_from_outputs), allocator);
    if (!m_subaddress_indices.empty()) root.AddMember("subaddr_indices", monero_utils::to_rapidjson_val(allocator, m_subaddress_indices), allocator);
    if (!m_destinations.empty()) root.AddMember("destinations", monero_utils::to_rapidjson_val(allocator, m_destinations), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO QUERY KEY PARAMS ---------------------------

  rapidjson::Value monero_query_key_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_key_type != boost::none) monero_utils::add_json_member("key_type", m_key_type.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO QUERY OUTPUT PARAMS ---------------------------

  rapidjson::Value monero_query_output_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_key_image != boost::none) monero_utils::add_json_member("key_image", m_key_image.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO GET ADDRESS PARAMS ---------------------------

  rapidjson::Value monero_get_address_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, value_num);

    // set sub-arrays
    if (!m_subaddress_indices.empty()) root.AddMember("address_index", monero_utils::to_rapidjson_val(allocator, m_subaddress_indices), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO INTEGRATED ADDRESS PARAMS ---------------------------

  rapidjson::Value monero_integrated_address_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_standard_address != boost::none) monero_utils::add_json_member("standard_address", m_standard_address.get(), allocator, root, value_str);
    if (m_payment_id != boost::none) monero_utils::add_json_member("payment_id", m_payment_id.get(), allocator, root, value_str);
    if (m_integrated_address != boost::none) monero_utils::add_json_member("integrated_address", m_integrated_address.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO MULTISIG PARAMS ---------------------------

  rapidjson::Value monero_multisig_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_password != boost::none) monero_utils::add_json_member("password", m_password.get(), allocator, root, value_str);
    if (m_multisig_tx_hex != boost::none) monero_utils::add_json_member("tx_data_hex", m_multisig_tx_hex.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value val_num(rapidjson::kNumberType);
    if (m_threshold != boost::none) monero_utils::add_json_member("threshold", m_threshold.get(), allocator, root, val_num);

    // set bool values
    if (m_enable_multisig_experimental != boost::none) monero_utils::add_json_member("enable_multisig_experimental", m_enable_multisig_experimental.get(), allocator, root);
    if (m_refresh_after_import != boost::none) monero_utils::add_json_member("refresh_after_import", m_refresh_after_import.get(), allocator, root);

    // set sub-arrays
    if (!m_multisig_info.empty()) root.AddMember("multisig_info", monero_utils::to_rapidjson_val(allocator, m_multisig_info), allocator);
    if (!m_multisig_hexes.empty()) root.AddMember("info", monero_utils::to_rapidjson_val(allocator, m_multisig_hexes), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO CLOSE WALLET PARAMS ---------------------------

  rapidjson::Value monero_close_wallet_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set bool values
    if (m_save != boost::none) monero_utils::add_json_member("autosave_current", m_save.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO CHANGE WALLET PASSWORD PARAMS ---------------------------

  rapidjson::Value monero_change_wallet_password_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_old_password != boost::none) monero_utils::add_json_member("old_password", m_old_password.get(), allocator, root, value_str);
    if (m_new_password != boost::none) monero_utils::add_json_member("new_password", m_new_password.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO SET DAEMON PARAMS ---------------------------

  rapidjson::Value monero_set_daemon_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_username != boost::none) monero_utils::add_json_member("username", m_username.get(), allocator, root, value_str);
    if (m_password != boost::none) monero_utils::add_json_member("password", m_password.get(), allocator, root, value_str);
    if (m_proxy != boost::none) monero_utils::add_json_member("proxy", m_proxy.get(), allocator, root, value_str);
    if (m_ssl_support != boost::none) monero_utils::add_json_member("ssl_support", m_ssl_support.get(), allocator, root, value_str);
    if (m_ssl_options != boost::none && m_ssl_options->m_ssl_private_key_path != boost::none) monero_utils::add_json_member("ssl_private_key_path", m_ssl_options->m_ssl_private_key_path.get(), allocator, root, value_str);
    if (m_ssl_options != boost::none && m_ssl_options->m_ssl_certificate_path != boost::none) monero_utils::add_json_member("ssl_certificate_path", m_ssl_options->m_ssl_certificate_path.get(), allocator, root, value_str);
    if (m_ssl_options != boost::none && m_ssl_options->m_ssl_ca_file != boost::none) monero_utils::add_json_member("ssl_ca_file", m_ssl_options->m_ssl_ca_file.get(), allocator, root, value_str);

    // set bool values
    if (m_trusted != boost::none) monero_utils::add_json_member("trusted", m_trusted.get(), allocator, root);
    if (m_ssl_options != boost::none && m_ssl_options->m_ssl_allow_any_cert != boost::none) monero_utils::add_json_member("ssl_allow_any_cert", m_ssl_options->m_ssl_allow_any_cert.get(), allocator, root);

    // set sub-arrays
    if (m_ssl_options != boost::none && !m_ssl_options->m_ssl_allowed_fingerprints.empty()) root.AddMember("ssl_allowed_fingerprints", monero_utils::to_rapidjson_val(allocator, m_ssl_options->m_ssl_allowed_fingerprints), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO TAG ACCOUNT PARAMS ---------------------------

  rapidjson::Value monero_account_tag_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_tag != boost::none) monero_utils::add_json_member("tag", m_tag.get(), allocator, root, value_str);
    if (m_label != boost::none) monero_utils::add_json_member("label", m_label.get(), allocator, root, value_str);
    if (m_description != boost::none) monero_utils::add_json_member("description", m_description.get(), allocator, root, value_str);

    // set sub-arrays
    if (!m_account_indices.empty()) root.AddMember("accounts", monero_utils::to_rapidjson_val(allocator, m_account_indices), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO TX NOTES PARAMS ---------------------------

  rapidjson::Value monero_tx_notes_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set sub-arrays
    if (!m_tx_hashes.empty()) root.AddMember("txids", monero_utils::to_rapidjson_val(allocator, m_tx_hashes), allocator);
    if (!m_notes.empty()) root.AddMember("notes", monero_utils::to_rapidjson_val(allocator, m_notes), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO ADDRESS BOOK ENTRY PARAMS ---------------------------

  rapidjson::Value monero_address_book_entry_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_description != boost::none) monero_utils::add_json_member("description", m_description.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_index != boost::none) monero_utils::add_json_member("index", m_index.get(), allocator, root, value_num);

    // set bool values
    if (m_set_address != boost::none) monero_utils::add_json_member("set_address", m_set_address.get(), allocator, root);
    if (m_set_description != boost::none) monero_utils::add_json_member("set_description", m_set_description.get(), allocator, root);

    // set sub-arrays
    if (!m_entries.empty()) root.AddMember("entries", monero_utils::to_rapidjson_val(allocator, m_entries), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO VERIFY SIGN MESSAGE PARAMS ---------------------------

  rapidjson::Value monero_verify_sign_message_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_data != boost::none) monero_utils::add_json_member("data", m_data.get(), allocator, root, value_str);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_signature != boost::none) monero_utils::add_json_member("signature", m_signature.get(), allocator, root, value_str);
    if (m_signature_type != boost::none) {
      if (m_signature_type == monero_message_signature_type::SIGN_WITH_VIEW_KEY) {
        monero_utils::add_json_member("signature_type", std::string("view"), allocator, root, value_str);
      }
      else {
        monero_utils::add_json_member("signature_type", std::string("spend"), allocator, root, value_str);
      }
    }

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, value_num);
    if (m_address_index != boost::none) monero_utils::add_json_member("address_index", m_address_index.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO CHECK TX KEY PARAMS ---------------------------

  rapidjson::Value monero_check_tx_key_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_tx_hash != boost::none) monero_utils::add_json_member("txid", m_tx_hash.get(), allocator, root, value_str);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_tx_key != boost::none) monero_utils::add_json_member("tx_key", m_tx_key.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO SIGN DESCRIBE TRANSFER PARAMS ---------------------------

  rapidjson::Value monero_sign_describe_transfer_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_unsigned_txset != boost::none) monero_utils::add_json_member("unsigned_txset", m_unsigned_txset.get(), allocator, root, value_str);
    if (m_multisig_txset != boost::none) monero_utils::add_json_member("multisig_txset", m_multisig_txset.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO WALLET RELAY TX PARAMS ---------------------------

  rapidjson::Value monero_wallet_relay_tx_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_hex != boost::none) monero_utils::add_json_member("hex", m_hex.get(), allocator, root, value_str);
    if (m_signed_tx_hex != boost::none) monero_utils::add_json_member("tx_data_hex", m_signed_tx_hex.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO CREATE EDIT SUBADDRESS PARAMS ---------------------------

  rapidjson::Value monero_create_edit_subaddress_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_label != boost::none) monero_utils::add_json_member("label", m_label.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value val_num(rapidjson::kNumberType);
    if (m_account_index != boost::none && m_subaddress_index != boost::none) {
      rapidjson::Value index(rapidjson::kObjectType);
      monero_utils::add_json_member("major", m_account_index.get(), allocator, index, val_num);
      monero_utils::add_json_member("minor", m_subaddress_index.get(), allocator, index, val_num);
      root.AddMember("index", index, allocator);
    }
    else if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, val_num);

    // return root
    return root;
  }

  // --------------------------- MONERO CREATE OPEN WALLET PARAMS ---------------------------

  rapidjson::Value monero_create_open_wallet_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none && !m_view_key->empty()) monero_utils::add_json_member("viewkey", m_view_key.get(), allocator, root, value_str);
    if (m_spend_key != boost::none && !m_spend_key->empty()) monero_utils::add_json_member("spendkey", m_spend_key.get(), allocator, root, value_str);
    if (m_filename != boost::none) monero_utils::add_json_member("filename", m_filename.get(), allocator, root, value_str);
    if (m_password != boost::none) monero_utils::add_json_member("password", m_password.get(), allocator, root, value_str);
    if (m_language != boost::none) monero_utils::add_json_member("language", m_language.get(), allocator, root, value_str);
    if (m_seed != boost::none) monero_utils::add_json_member("seed", m_seed.get(), allocator, root, value_str);
    if (m_seed_offset != boost::none) monero_utils::add_json_member("seed_offset", m_seed_offset.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value val_num(rapidjson::kNumberType);
    if (m_restore_height != boost::none) monero_utils::add_json_member("restore_height", m_restore_height.get(), allocator, root, val_num);

    // set bool values
    if (m_autosave_current != boost::none) monero_utils::add_json_member("autosave_current", m_autosave_current.get(), allocator, root);
    if (m_enable_multisig_experimental != boost::none) monero_utils::add_json_member("enable_multisig_experimental", m_enable_multisig_experimental.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO RESERVE PROOF PARAMS ---------------------------

  rapidjson::Value monero_reserve_proof_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_message != boost::none) monero_utils::add_json_member("message", m_message.get(), allocator, root, value_str);
    if (m_tx_hash != boost::none) monero_utils::add_json_member("txid", m_tx_hash.get(), allocator, root, value_str);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_signature != boost::none) monero_utils::add_json_member("signature", m_signature.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, value_num);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_num);

    // set bool values
    if (m_all != boost::none) monero_utils::add_json_member("all", m_all.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO REFRESH WALLET PARAMS ---------------------------

  rapidjson::Value monero_wallet_refresh_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_period != boost::none) monero_utils::add_json_member("period", m_period.get(), allocator, root, value_num);
    if (m_start_height != boost::none) monero_utils::add_json_member("start_height", m_start_height.get(), allocator, root, value_num);

    // set bool values
    if (m_enable != boost::none) monero_utils::add_json_member("enable", m_enable.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO GET INCOMING TRANSFERS PARAMS ---------------------------

  rapidjson::Value monero_get_incoming_transfers_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_transfer_type != boost::none) monero_utils::add_json_member("transfer_type", m_transfer_type.get(), allocator, root, value_str);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, value_num);

    // set bool values
    if (m_verbose != boost::none) monero_utils::add_json_member("verbose", m_verbose.get(), allocator, root);

    // set sub-arrays
    if (!m_subaddr_indices.empty()) root.AddMember("subaddr_indices", monero_utils::to_rapidjson_val(allocator, m_subaddr_indices), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO GET TRANSFERS PARAMS ---------------------------

  rapidjson::Value monero_get_transfers_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);

    if (m_min_height != boost::none) monero_utils::add_json_member("min_height", m_min_height.get(), allocator, root, value_num);
    if (m_max_height != boost::none) monero_utils::add_json_member("max_height", m_max_height.get(), allocator, root, value_num);
    if (m_account_index != boost::none) monero_utils::add_json_member("account_index", m_account_index.get(), allocator, root, value_num);

    // set bool values
    monero_utils::add_json_member("filter_by_height", m_min_height != boost::none || m_max_height != boost::none, allocator, root);
    if (m_in != boost::none) monero_utils::add_json_member("in", m_in.get(), allocator, root);
    if (m_out != boost::none) monero_utils::add_json_member("out", m_out.get(), allocator, root);
    if (m_pool != boost::none) monero_utils::add_json_member("pool", m_pool.get(), allocator, root);
    if (m_pending != boost::none) monero_utils::add_json_member("pending", m_pending.get(), allocator, root);
    if (m_failed != boost::none) monero_utils::add_json_member("failed", m_failed.get(), allocator, root);
    if (m_all_accounts != boost::none) monero_utils::add_json_member("all_accounts", m_all_accounts.get(), allocator, root);

    // set sub-arrays
    if (!m_subaddr_indices.empty()) root.AddMember("subaddr_indices", monero_utils::to_rapidjson_val(allocator, m_subaddr_indices), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO MULTISIG RESPONSE ---------------------------

  void monero_multisig_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_multisig_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("n_outputs")) response->m_num_outputs = it->second.get_value<int>();
      else if ((key == std::string("info") || key == std::string("multisig_info")) && !it->second.data().empty()) response->m_multisig_info = it->second.data();
      else if (key == std::string("tx_hash_list")) {
        const auto& tx_hash_list_node = it->second;
        std::vector<std::string> hashes;
        for (auto it2 = tx_hash_list_node.begin(); it2 != tx_hash_list_node.end(); ++it2) {
          response->m_tx_hashes.push_back(it2->second.data());
        }
      }
    }
  }

  // --------------------------- MONERO GET BALANCE RESPONSE ---------------------------

  void monero_get_balance_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_balance_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("balance")) response->m_balance = it->second.get_value<uint64_t>();
      else if (key == std::string("unlocked_balance")) response->m_unlocked_balance = it->second.get_value<uint64_t>();
      else if (key == std::string("multisig_import_needed")) response->m_multisig_import_needed = it->second.get_value<bool>();
      else if (key == std::string("time_to_unlock")) response->m_time_to_unlock = it->second.get_value<uint64_t>();
      else if (key == std::string("blocks_to_unlock")) response->m_blocks_to_unlock = it->second.get_value<uint64_t>();
      else if (key == std::string("per_subaddress")) {
        auto node2 = it->second;

        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto sub = std::make_shared<monero_subaddress>();
          deserialize_subaddress(it2->second, sub);
          response->m_per_subaddress.push_back(sub);
        }
      }
    }
  }

  // --------------------------- RPC Deserialization ---------------------------

  void deserialize_subaddress(const boost::property_tree::ptree& node, const std::shared_ptr<monero_subaddress>& subaddress) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("account_index") || key == std::string("major")) subaddress->m_account_index = it->second.get_value<uint32_t>();
      else if (key == std::string("address_index") || key == std::string("minor")) subaddress->m_index = it->second.get_value<uint32_t>();
      else if (key == std::string("address")) subaddress->m_address = it->second.data();
      else if (key == std::string("balance")) subaddress->m_balance = it->second.get_value<uint64_t>();
      else if (key == std::string("unlocked_balance")) subaddress->m_unlocked_balance = it->second.get_value<uint64_t>();
      else if (key == std::string("label") && !it->second.data().empty()) subaddress->m_label = it->second.data();
      else if (key == std::string("used")) subaddress->m_is_used = it->second.get_value<bool>();
      else if (key == std::string("num_unspent_outputs")) subaddress->m_num_unspent_outputs = it->second.get_value<uint64_t>();
      else if (key == std::string("blocks_to_unlock")) subaddress->m_num_blocks_to_unlock = it->second.get_value<uint64_t>();
      else if (key == std::string("index")) deserialize_subaddress(it->second, subaddress);
    }
  }

  void deserialize_subaddresses(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_subaddress>>& subaddresses) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("per_subaddress") || key == std::string("addresses")) {
        auto per_subaddress_node = it->second;

        for (auto it2 = per_subaddress_node.begin(); it2 != per_subaddress_node.end(); ++it2) {
          auto sub = std::make_shared<monero_subaddress>();
          deserialize_subaddress(it2->second, sub);
          subaddresses.push_back(sub);
        }
      }
    }
  }

  void deserialize_account(const boost::property_tree::ptree& node, monero_account& account) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("account_index")) account.m_index = it->second.get_value<uint32_t>();
      else if (key == std::string("address")) account.m_primary_address = it->second.data();
      else if (key == std::string("balance")) account.m_balance = it->second.get_value<uint64_t>();
      else if (key == std::string("unlocked_balance")) account.m_unlocked_balance = it->second.get_value<uint64_t>();
      else if (key == std::string("base_address")) account.m_primary_address = it->second.data();
      else if (key == std::string("tag") && !it->second.data().empty()) account.m_tag = it->second.data();
      else if (key == std::string("label")) {
        // label belongs to first subaddress
      }
    }
  }

  void deserialize_accounts(const boost::property_tree::ptree& node, std::vector<monero_account>& accounts) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("subaddress_accounts")) {
        auto accounts_node = it->second;
        for (auto account_it = accounts_node.begin(); account_it != accounts_node.end(); ++account_it) {
          monero_account account;
          deserialize_account(account_it->second, account);
          accounts.push_back(account);
        }
      }
    }
  }

  bool decode_rpc_tx_type(const std::string &rpc_type, const std::shared_ptr<monero_tx_wallet> &tx) {
    bool is_outgoing = false;
    if (rpc_type == std::string("in")) {
      tx->m_is_confirmed = true;
      tx->m_in_tx_pool = false;
      tx->m_is_relayed = true;
      tx->m_relay = true;
      tx->m_is_failed = false;
      tx->m_is_miner_tx = false;
    } else if (rpc_type == std::string("out")) {
      is_outgoing = true;
      tx->m_is_confirmed = true;
      tx->m_in_tx_pool = false;
      tx->m_is_relayed = true;
      tx->m_relay = true;
      tx->m_is_failed = false;
      tx->m_is_miner_tx = false;
    } else if (rpc_type == std::string("pool")) {
      tx->m_is_confirmed = false;
      tx->m_in_tx_pool = true;
      tx->m_is_relayed = true;
      tx->m_relay = true;
      tx->m_is_failed = false;
      tx->m_is_miner_tx = false;  // TODO: but could it be?
    } else if (rpc_type == std::string("pending")) {
      is_outgoing = true;
      tx->m_is_confirmed = false;
      tx->m_in_tx_pool = true;
      tx->m_is_relayed = true;
      tx->m_relay = true;
      tx->m_is_failed = false;
      tx->m_is_miner_tx = false;
    } else if (rpc_type == std::string("block")) {
      tx->m_is_confirmed = true;
      tx->m_in_tx_pool = false;
      tx->m_is_relayed = true;
      tx->m_relay = true;
      tx->m_is_failed = false;
      tx->m_is_miner_tx = true;
    } else if (rpc_type == std::string("failed")) {
      is_outgoing = true;
      tx->m_is_confirmed = false;
      tx->m_in_tx_pool = false;
      tx->m_is_relayed = false;
      tx->m_relay = true;
      tx->m_is_failed = true;
      tx->m_is_miner_tx = false;
    } else throw monero_error(std::string("Unrecognized transfer type: ") + rpc_type);
    return is_outgoing;
  }

  void init_sent_tx(const monero_tx_config &config, std::shared_ptr<monero_tx_wallet> &tx, bool copy_destinations) {
    bool relay = gen_utils::bool_equals(true, config.m_relay);
    tx->m_is_outgoing = true;
    tx->m_is_confirmed = false;
    tx->m_num_confirmations = 0;
    tx->m_in_tx_pool = relay;
    tx->m_relay = relay;
    tx->m_is_relayed = relay;
    tx->m_is_miner_tx = false;
    tx->m_is_failed = false;
    tx->m_is_locked = true;
    tx->m_ring_size = monero_utils::RING_SIZE;

    auto outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
    outgoing_transfer->m_tx = tx;

    if (config.m_subaddress_indices.size() == 1) {
      // we know src subaddress indices iff request specifies 1
      outgoing_transfer->m_subaddress_indices = config.m_subaddress_indices;
    }

    if (copy_destinations) {
      auto conf_dests = config.get_normalized_destinations();
      for(const auto &conf_dest : conf_dests) {
        auto dest = std::make_shared<monero_destination>();
        conf_dest->copy(conf_dest, dest);
        outgoing_transfer->m_destinations.push_back(dest);
      }
    }

    tx->m_outgoing_transfer = outgoing_transfer;
    tx->m_payment_id = config.m_payment_id;
    if (tx->m_unlock_time == boost::none) tx->m_unlock_time = 0;
    if (gen_utils::bool_equals(true, tx->m_relay)) {
      if (tx->m_last_relayed_timestamp == boost::none) {
        // set last relayed timestamp to current time iff relayed
        // TODO (monero-wallet-rpc): provide timestamp on response; unconfirmed timestamps vary
        tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
      }
      if (tx->m_is_double_spend_seen == boost::none) tx->m_is_double_spend_seen = false;
    }
  }

  void deserialize_tx_with_transfer(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_wallet>& tx, boost::optional<bool> &is_outgoing, const monero_tx_config &config) {
    std::shared_ptr<monero_block> header = nullptr;
    std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = nullptr;
    std::shared_ptr<monero_incoming_transfer> incoming_transfer = nullptr;

    bool key_found = false;

    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("type")) {
        is_outgoing = decode_rpc_tx_type(it->second.data(), tx);
        key_found = true;
      }
    }

    if (!key_found && is_outgoing == boost::none) throw monero_error("Must indicate if tx is outgoing (true) xor incoming (false) since unknown");

    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("txid") || key == std::string("tx_hash")) tx->m_hash = it->second.data();
      else if (key == std::string("fee")) tx->m_fee = it->second.get_value<uint64_t>();
      else if (key == std::string("note") && !it->second.data().empty()) tx->m_note = it->second.data();
      else if (key == std::string("tx_key") && !it->second.data().empty()) tx->m_key = it->second.data();
      else if (key == std::string("tx_size")) tx->m_size = it->second.get_value<uint64_t>();
      else if (key == std::string("unlock_time")) tx->m_unlock_time = it->second.get_value<uint64_t>();
      else if (key == std::string("weight")) tx->m_weight = it->second.get_value<uint64_t>();
      else if (key == std::string("locked")) tx->m_is_locked = it->second.get_value<bool>();
      else if (key == std::string("tx_blob") && !it->second.data().empty()) tx->m_full_hex = it->second.data();
      else if (key == std::string("tx_metadata") && !it->second.data().empty()) tx->m_metadata = it->second.data();
      else if (key == std::string("double_spend_seen")) tx->m_is_double_spend_seen = it->second.get_value<bool>();
      else if (key == std::string("block_height") || key == std::string("height")) {
        if (gen_utils::bool_equals(true, tx->m_is_confirmed)) {
          if (header == nullptr) header = std::make_shared<monero_block>();
          header->m_height = it->second.get_value<uint64_t>();
        }
      }
      else if (key == std::string("timestamp")) {
        if (gen_utils::bool_equals(true, tx->m_is_confirmed)) {
          if (header == nullptr) header = std::make_shared<monero_block>();
          header->m_timestamp = it->second.get_value<uint64_t>();
        }
      }
      else if (key == std::string("confirmations")) tx->m_num_confirmations = it->second.get_value<uint64_t>();
      else if (key == std::string("suggested_confirmations_threshold")) {
        if (*is_outgoing) {
          if (outgoing_transfer == nullptr)
            outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
          outgoing_transfer->m_tx = tx;
        }
        else {
          if (incoming_transfer == nullptr)
            incoming_transfer = std::make_shared<monero_incoming_transfer>();
          incoming_transfer->m_tx = tx;
          incoming_transfer->m_num_suggested_confirmations = it->second.get_value<uint64_t>();
        }
      }
      else if (key == std::string("amount")) {
        if (*is_outgoing) {
          if (outgoing_transfer == nullptr) {
            outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
            outgoing_transfer->m_tx = tx;
          }
          outgoing_transfer->m_amount = it->second.get_value<uint64_t>();
        }
        else {
          if (incoming_transfer == nullptr) incoming_transfer = std::make_shared<monero_incoming_transfer>();
          incoming_transfer->m_tx = tx;
          incoming_transfer->m_amount = it->second.get_value<uint64_t>();
        }
      }
      else if (key == std::string("address")) {
        if (!*is_outgoing) {
          if (incoming_transfer == nullptr) incoming_transfer = std::make_shared<monero_incoming_transfer>();
          incoming_transfer->m_tx = tx;
          incoming_transfer->m_address = it->second.data();
        }
      }
      else if (key == std::string("payment_id")) {
        std::string payment_id = it->second.data();
        if (payment_id != std::string("") && payment_id != monero_tx_wallet::DEFAULT_PAYMENT_ID) {
          tx->m_payment_id = payment_id;
        }
      }
      else if (key == std::string("subaddr_indices")) {
        if (*is_outgoing) {
          if (outgoing_transfer == nullptr) {
            outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
            outgoing_transfer->m_tx = tx;
          }
        }
        else {
          if (incoming_transfer == nullptr) incoming_transfer = std::make_shared<monero_incoming_transfer>();
          incoming_transfer->m_tx = tx;
        }

        bool first_major = true;
        bool first_minor = true;

        for(auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          for(auto it3 = it2->second.begin(); it3 != it2->second.end(); ++it3) {
            std::string index_key = it3->first;

            if (index_key == std::string("major") && first_major) {
              if (*is_outgoing) outgoing_transfer->m_account_index = it3->second.get_value<uint32_t>();
              else incoming_transfer->m_account_index = it3->second.get_value<uint32_t>();
              first_major = false;
            }
            else if (index_key == std::string("minor")) {
              if (*is_outgoing) {
                outgoing_transfer->m_subaddress_indices.push_back(it3->second.get_value<uint32_t>());
              }
              else if (first_minor) {
                incoming_transfer->m_subaddress_index = it3->second.get_value<uint32_t>();
                first_minor = false;
              }
              else throw monero_error("Expected 1 subaddress index for incoming transfer");
            }
          }
        }
      }
      else if (key == std::string("destinations") || key == std::string("recipients")) {
        if (!*is_outgoing) throw monero_error("Expected outgoing transaction");
        if (outgoing_transfer == nullptr) {
          outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
          outgoing_transfer->m_tx = tx;
        }
        auto node2 = it->second;
        outgoing_transfer->m_destinations.clear();

        for(auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto node3 = it2->second;
          auto dest = std::make_shared<monero_destination>();

          for(auto it3 = node3.begin(); it3 != node3.end(); ++it3) {
            std::string _key = it3->first;

            if (_key == std::string("address")) dest->m_address = it3->second.data();
            else if (_key == std::string("amount")) dest->m_amount = it3->second.get_value<uint64_t>();
            else throw monero_error(std::string("Unrecognized transaction destination field: ") + _key);
          }

          outgoing_transfer->m_destinations.push_back(dest);
        }
      }
      else if (key == std::string("amount_in")) tx->m_input_sum = it->second.get_value<uint64_t>();
      else if (key == std::string("amount_out")) tx->m_output_sum = it->second.get_value<uint64_t>();
      else if (key == std::string("change_address") && !it->second.data().empty()) tx->m_change_address = it->second.data();
      else if (key == std::string("change_amount")) tx->m_change_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("dummy_outputs")) tx->m_num_dummy_outputs = it->second.get_value<uint64_t>();
      else if (key == std::string("extra")) tx->m_extra_hex = it->second.data();
      else if (key == std::string("ring_size")) tx->m_ring_size = it->second.get_value<uint32_t>();
      else if (key == std::string("spent_key_images")) {
        auto node2 = it->second;

        for(auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          std::string _key = it2->first;

          if (_key == std::string("key_images")) {
            auto node3 = it2->second;
            if (tx->m_inputs.size() > 0) throw monero_error("inputs should be empty");

            for(auto it3 = node3.begin(); it3 != node3.end(); ++it3) {
              auto output = std::make_shared<monero_output_wallet>();
              auto key_image = std::make_shared<monero_key_image>();

              key_image->m_hex = it3->second.data();
              output->m_key_image = key_image;
              output->m_tx = tx;
              tx->m_inputs.push_back(output);
            }
          }
        }
      }
      else if (key == std::string("amounts_by_dest")) {
        if (!*is_outgoing) throw monero_error("Expected outgoing transaction");
        if (outgoing_transfer == nullptr) {
          outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
          outgoing_transfer->m_tx = tx;
        }
        auto node2 = it->second;
        std::vector<uint64_t> amounts_by_dest;

        for(auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          std::string _key = it2->first;

          if (_key == std::string("amounts")) {
            auto node3 = it2->second;

            for(auto it3 = node3.begin(); it3 != node3.end(); ++it3) {
              amounts_by_dest.push_back(it3->second.get_value<uint64_t>());
            }
          }
        }

        auto destinations = config.get_normalized_destinations();
        size_t num_destinations = destinations.size();
        if (num_destinations != amounts_by_dest.size()) throw monero_error("Expected destinations size equal to amounts by dest size");
        outgoing_transfer->m_destinations.clear();
        for(uint64_t i = 0; i < num_destinations; i++) {
          auto dest = std::make_shared<monero_destination>();
          dest->m_address = destinations[i]->m_address;
          dest->m_amount = amounts_by_dest[i];
          outgoing_transfer->m_destinations.push_back(dest);
        }
      }
    }

    // link block and tx
    if (header != nullptr) {
      auto block = std::make_shared<monero_block>();
      header->copy(header, block);
      block->m_txs.push_back(tx);
      tx->m_block = block;
    }

    if (*is_outgoing && outgoing_transfer != nullptr) {
      if (tx->m_is_confirmed == boost::none) tx->m_is_confirmed = false;
      if (gen_utils::bool_equals(false, outgoing_transfer->m_tx->m_is_confirmed)) tx->m_num_confirmations = 0;
      tx->m_is_outgoing = true;

      if (tx->m_outgoing_transfer != nullptr) {
        // overwrite to avoid reconcile error TODO: remove after >18.3.1 when amounts_by_dest supported
        if (!outgoing_transfer->m_destinations.empty()) {
          tx->m_outgoing_transfer->m_destinations.clear();
        }
        tx->m_outgoing_transfer->merge(tx->m_outgoing_transfer, outgoing_transfer);
      }
      else tx->m_outgoing_transfer = outgoing_transfer;
    }
    else if (is_outgoing != boost::none && *is_outgoing == false && incoming_transfer != nullptr) {
      if (tx->m_is_confirmed == boost::none) tx->m_is_confirmed = false;
      if (gen_utils::bool_equals(false, incoming_transfer->m_tx->m_is_confirmed)) tx->m_num_confirmations = 0;
      tx->m_is_incoming = true;
      tx->m_incoming_transfers.push_back(incoming_transfer);
    }

  }

  void deserialize_tx_with_transfer(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_wallet>& tx, boost::optional<bool> &is_outgoing) {
    monero_tx_config config;
    deserialize_tx_with_transfer(node, tx, is_outgoing, config);
  }

  void deserialize_tx_with_transfer(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_wallet>& tx) {
    boost::optional<bool> is_outgoing;
    deserialize_tx_with_transfer(node, tx, is_outgoing);
  }

  void deserialize_tx_with_output(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_wallet>& tx) {
    tx->m_is_confirmed = true;
    tx->m_is_relayed = true;
    tx->m_is_failed = false;
    tx->m_in_tx_pool = false;

    auto output = std::make_shared<monero_output_wallet>();
    output->m_tx = tx;

    for(auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("amount")) output->m_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("spent")) output->m_is_spent = it->second.get_value<bool>();
      else if (key == std::string("key_image") && !it->second.data().empty()) {
        auto key_image = std::make_shared<monero_key_image>();
        key_image->m_hex = it->second.data();
        output->m_key_image = key_image;
      }
      else if (key == std::string("global_index")) output->m_index = it->second.get_value<uint64_t>();
      else if (key == std::string("tx_hash")) tx->m_hash = it->second.data();
      else if (key == std::string("unlocked")) tx->m_is_locked = !it->second.get_value<bool>();
      else if (key == std::string("frozen")) output->m_is_frozen = it->second.get_value<bool>();
      else if (key == std::string("pubkey")) output->m_stealth_public_key = it->second.data();
      else if (key == std::string("subaddr_index")) {
        for(auto indices_it = it->second.begin(); indices_it != it->second.end(); ++indices_it) {
          std::string indices_key = indices_it->first;
          if (indices_key == std::string("major")) output->m_account_index = indices_it->second.get_value<uint32_t>();
          if (indices_key == std::string("minor")) output->m_subaddress_index = indices_it->second.get_value<uint32_t>();
        }
      }
      else if (key == std::string("block_height")) {
        auto block = std::make_shared<monero_block>();
        block->m_height = it->second.get_value<uint64_t>();
        block->m_txs.push_back(tx);
        tx->m_block = block;
      }
    }

    tx->m_outputs.push_back(output);
  }

  void deserialize_tx_with_output_and_merge(const boost::property_tree::ptree& node, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map) {
    for(auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("transfers")) {
        for(auto rpc_output_it = it->second.begin(); rpc_output_it != it->second.end(); ++rpc_output_it) {
          auto tx = std::make_shared<monero_tx_wallet>();
          deserialize_tx_with_output(rpc_output_it->second, tx);
          monero_utils::merge_tx(tx, tx_map, block_map);
        }
      }
    }
  }

  void deserialize_tx_with_transfer_and_merge(const boost::property_tree::ptree& node, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        auto tx = std::make_shared<monero_tx_wallet>();
        deserialize_tx_with_transfer(it2->second, tx);

        if (tx->m_is_confirmed != boost::none && *tx->m_is_confirmed == true) {
          if (tx->m_block == nullptr) throw monero_error("Confirmed tx has no block");
          auto& block_txs = tx->m_block->m_txs;
          if (std::find(block_txs.begin(), block_txs.end(), tx) == block_txs.end()) {
            throw monero_error("Tx not found in its block");
          }
        }

        // replace transfer amount with destination sum
        // TODO monero-wallet-rpc: confirmed tx from/to same account has amount 0 but cached transfers
        if (tx->m_outgoing_transfer != nullptr && gen_utils::bool_equals(true, tx->m_is_relayed) && !gen_utils::bool_equals(true, tx->m_is_failed) &&
            !tx->m_outgoing_transfer->m_destinations.empty() && tx->m_outgoing_transfer->m_amount.get() == 0) {
          auto outgoing_transfer = tx->m_outgoing_transfer;
          uint64_t transfer_total = 0;
          for(const auto& destination : outgoing_transfer->m_destinations) {
            transfer_total += destination->m_amount.get();
          }
          outgoing_transfer->m_amount = transfer_total;
        }

        // merge tx
        monero_utils::merge_tx(tx, tx_map, block_map);
      }
    }
  }

  void deserialize_tx_set(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_set>& set) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("multisig_txset") && !it->second.data().empty()) set->m_multisig_tx_hex = it->second.data();
      else if (key == std::string("unsigned_txset") && !it->second.data().empty()) set->m_unsigned_tx_hex = it->second.data();
      else if (key == std::string("signed_txset") && !it->second.data().empty()) set->m_signed_tx_hex = it->second.data();
    }
  }

  void deserialize_tx_set(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_set>& set, const std::shared_ptr<monero_tx_wallet> &tx, bool is_outgoing, const monero_tx_config &config) {
    deserialize_tx_set(node, set);
    boost::optional<bool> outgoing = is_outgoing;
    deserialize_tx_with_transfer(node, tx, outgoing, config);
    tx->m_tx_set = set;
    set->m_txs.push_back(tx);
  }

  void deserialize_sent_tx_set(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_set>& set) {
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    deserialize_sent_tx_set(node, set, txs, boost::none);
  }

  void deserialize_sent_tx_set(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_set>& set, std::vector<std::shared_ptr<monero_tx_wallet>> &txs, const boost::optional<monero_tx_config> &conf) {
    deserialize_tx_set(node, set);
    int num_txs = 0;
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("fee_list") && num_txs == 0) {
        auto fee_list_node = it->second;
        for (auto it2 = fee_list_node.begin(); it2 != fee_list_node.end(); ++it2) {
          num_txs++;
        }
      }
      else if (key == std::string("tx_hash_list") && num_txs == 0) {
        auto tx_hash_list_node = it->second;
        for (auto it2 = tx_hash_list_node.begin(); it2 != tx_hash_list_node.end(); ++it2) {
          num_txs++;
        }
      }
    }

    if (num_txs == 0) {
      if (txs.size() > 0) throw monero_error("txs should be empty");
      return;
    }

    if (txs.size() > 0) set->m_txs = txs;
    else {
      for(int i = 0; i < num_txs; i++) {
        auto tx = std::make_shared<monero_tx_wallet>();
        txs.push_back(tx);
      }
    }

    for(const auto &tx : txs) {
      tx->m_tx_set = set;
      tx->m_is_outgoing = true;
    }

    set->m_txs = txs;
    auto tx_at = [&txs](size_t i) -> const std::shared_ptr<monero_tx_wallet>& {
      if (i >= txs.size()) throw monero_error("Malformed sent tx set response: list has more entries than expected tx count (" + std::to_string(txs.size()) + ")");
      return txs[i];
    };

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tx_hash_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          tx->m_hash = it2->second.data();
          i++;
        }
      }
      else if (key == std::string("tx_key_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          tx->m_key = it2->second.data();
          i++;
        }
      }
      else if (key == std::string("tx_blob_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          tx->m_full_hex = it2->second.data();
          i++;
        }
      }
      else if (key == std::string("tx_metadata_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          tx->m_metadata = it2->second.data();
          i++;
        }
      }
      else if (key == std::string("fee_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          tx->m_fee = it2->second.get_value<uint64_t>();
          i++;
        }
      }
      else if (key == std::string("amount_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          if (tx->m_outgoing_transfer == nullptr) {
            auto outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
            outgoing_transfer->m_tx = tx;
            tx->m_outgoing_transfer = outgoing_transfer;
          }
          tx->m_outgoing_transfer->m_amount = it2->second.get_value<uint64_t>();
          i++;
        }
      }
      else if (key == std::string("weight_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          tx->m_weight = it2->second.get_value<uint64_t>();
          i++;
        }
      }
      else if (key == std::string("spent_key_images_list")) {
        auto node2 = it->second;
        int i = 0;
        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = tx_at(i);
          if (tx->m_inputs.size() > 0) throw monero_error("Expected no inputs in sent tx");

          auto node3 = it2->second;
          for (auto it3 = node3.begin(); it3 != node3.end(); ++it3) {
            std::string _key = it3->first;

            if (_key == std::string("key_images")) {
              auto node4 = it3->second;

              for (auto it4 = node4.begin(); it4 != node4.end(); ++it4) {
                auto output = std::make_shared<monero_output_wallet>();
                output->m_key_image = std::make_shared<monero_key_image>();
                output->m_key_image->m_hex = it4->second.data();
                output->m_tx = tx;
                tx->m_inputs.push_back(output);
              }
            }
          }

          i++;
        }
      }
      else if (key == std::string("amounts_by_dest_list")) {
        int i = 0;
        int destination_idx = 0;

        for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          auto tx = tx_at(i);

          for (auto it3 = it2->second.begin(); it3 != it2->second.end(); ++it3) {
            std::string amounts_by_dest_key = it3->first;

            if (amounts_by_dest_key == std::string("amounts")) {
              std::vector<uint64_t> amounts_by_dest;

              for(auto it4 = it3->second.begin(); it4 != it3->second.end(); ++it4) {
                amounts_by_dest.push_back(it4->second.get_value<uint64_t>());
              }

              if (tx->m_outgoing_transfer == nullptr) {
                auto outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
                outgoing_transfer->m_tx = tx;
                tx->m_outgoing_transfer = outgoing_transfer;
              }

              tx->m_outgoing_transfer->m_destinations.clear();

              for(const auto& amount : amounts_by_dest) {
                if (conf == boost::none) throw monero_error("Expected tx configuration");
                auto config = conf.get();
                if (config.get_normalized_destinations().size() == 1) {
                  // sweeping can create multiple withone address
                  auto dest = std::make_shared<monero_destination>();
                  dest->m_address = config.get_normalized_destinations()[0]->m_address;
                  dest->m_amount = amount;
                  tx->m_outgoing_transfer->m_destinations.push_back(dest);
                }
                else {
                  auto normalized_destinations = config.get_normalized_destinations();
                  if (destination_idx >= normalized_destinations.size()) throw monero_error("Malformed sent tx set response: amounts_by_dest_list has more entries than configured destinations");
                  auto dest = std::make_shared<monero_destination>();
                  dest->m_address = normalized_destinations[destination_idx]->m_address;
                  dest->m_amount = amount;
                  tx->m_outgoing_transfer->m_destinations.push_back(dest);
                  destination_idx++;
                }
              }
            }
          }

          i++;
        }
      }
    }
  }

  void deserialize_described_tx_set(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_set>& set) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("desc")) {
        auto node2 = it->second;

        for (auto it2 = node2.begin(); it2 != node2.end(); ++it2) {
          auto tx = std::make_shared<monero_tx_wallet>();
          boost::optional<bool> outgoing = true;
          deserialize_tx_with_transfer(it2->second, tx, outgoing);
          tx->m_tx_set = set;
          set->m_txs.push_back(tx);
        }
      }
    }
  }

  void deserialize_submitted_tx_hashes(const boost::property_tree::ptree& node, std::vector<std::string>& tx_hashes) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tx_hash_list")) {
        auto hashes_node = it->second;
        for (auto it2 = hashes_node.begin(); it2 != hashes_node.end(); ++it2) {
          tx_hashes.push_back(it2->second.data());
        }
      }
    }
  }

  void deserialize_relayed_tx_hash(const boost::property_tree::ptree& node, std::vector<std::string>& tx_hashes) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tx_hash")) tx_hashes.push_back(it->second.data());
    }
  }

  int deserialize_num_created_txs(const boost::property_tree::ptree& node, bool can_split) {
    int num_txs = 0;
    for(auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (can_split && key == std::string("fee_list")) {
        auto fee_list_node = it->second;
        for(auto it2 = fee_list_node.begin(); it2 != fee_list_node.end(); ++it2) {
          num_txs++;
        }
      }
      else if (!can_split && key == std::string("fee")) {
        num_txs = 1;
      }
    }
    return num_txs;
  }

  std::string deserialize_tx_key(const boost::property_tree::ptree& node) {
    std::string tx_key;

    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tx_key")) {
        tx_key = it->second.data();
        break;
      }
    }

    return tx_key;
  }

  void deserialize_tx_notes(const boost::property_tree::ptree& node, std::vector<std::string>& tx_notes) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("notes")) {
        auto notes_node = it->second;
        for (auto it2 = notes_node.begin(); it2 != notes_node.end(); ++it2) {
          tx_notes.push_back(it2->second.data());
        }
      }
    }
  }

  void deserialize_integrated_address(const boost::property_tree::ptree& node, monero_integrated_address& subaddress) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("integrated_address")) subaddress.m_integrated_address = it->second.data();
      else if (key == std::string("standard_address")) subaddress.m_standard_address = it->second.data();
      else if (key == std::string("payment_id")) subaddress.m_payment_id = it->second.data();
    }
  }

  void deserialize_key_image(const boost::property_tree::ptree& node, const std::shared_ptr<monero_key_image>& key_image) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("key_image")) key_image->m_hex = it->second.data();
      else if (key == std::string("signature")) key_image->m_signature = it->second.data();
    }
  }

  void deserialize_key_image_export_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_key_image_export_result>& result) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("offset")) result->m_offset = it->second.get_value<uint64_t>();
      else if (key == std::string("signed_key_images")) {
        auto key_images_node = it->second;

        for (auto it2 = key_images_node.begin(); it2 != key_images_node.end(); ++it2) {
          auto key_image = std::make_shared<monero_key_image>();
          deserialize_key_image(it2->second, key_image);
          result->m_key_images.push_back(key_image);
        }
      }
    }
  }

  void deserialize_key_image_import_result(const boost::property_tree::ptree& node, const std::shared_ptr<monero_key_image_import_result>& result) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("height")) result->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent")) result->m_spent_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("unspent")) result->m_unspent_amount = it->second.get_value<uint64_t>();
    }
  }

  void deserialize_message_signature_result(const boost::property_tree::ptree& node, monero_message_signature_result& result) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("good")) result.m_is_good = it->second.get_value<bool>();
      else if (key == std::string("old")) result.m_is_old = it->second.get_value<bool>();
      else if (key == std::string("signature_type")) {
        std::string sig_type = it->second.data();
        if (sig_type == std::string("view")) {
          result.m_signature_type = monero_message_signature_type::SIGN_WITH_VIEW_KEY;
        }
        else {
          result.m_signature_type = monero_message_signature_type::SIGN_WITH_SPEND_KEY;
        }
      }
      else if (key == std::string("version")) result.m_version = it->second.get_value<uint32_t>();
    }
  }

  void deserialize_check_tx(const boost::property_tree::ptree& node, const std::shared_ptr<monero_check_tx>& check) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("good")) check->m_is_good = it->second.get_value<bool>();
      if (key == std::string("in_pool")) check->m_in_tx_pool = it->second.get_value<bool>();
      else if (key == std::string("confirmations")) check->m_num_confirmations = it->second.get_value<uint64_t>();
      else if (key == std::string("received")) check->m_received_amount = it->second.get_value<uint64_t>();
    }

    if (!gen_utils::bool_equals(true, check->m_is_good)) {
      // normalize invalid tx proof
      check->m_in_tx_pool = boost::none;
      check->m_num_confirmations = boost::none;
      check->m_received_amount = boost::none;
    }
  }

  void deserialize_check_reserve(const boost::property_tree::ptree& node, const std::shared_ptr<monero_check_reserve>& check) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("good")) check->m_is_good = it->second.get_value<bool>();
      else if (key == std::string("total")) check->m_total_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("spent")) check->m_unconfirmed_spent_amount = it->second.get_value<uint64_t>();
    }

    if (!gen_utils::bool_equals(true, check->m_is_good)) {
      // normalize invalid check reserve
      check->m_total_amount = boost::none;
      check->m_unconfirmed_spent_amount = boost::none;
    }
  }

  void deserialize_multisig_info(const boost::property_tree::ptree& node, monero_multisig_info& info) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("multisig")) info.m_is_multisig = it->second.get_value<bool>();
      else if (key == std::string("ready")) info.m_is_ready = it->second.get_value<bool>();
      else if (key == std::string("threshold")) info.m_threshold = it->second.get_value<uint32_t>();
      else if (key == std::string("total")) info.m_num_participants = it->second.get_value<uint32_t>();
    }
  }

  void deserialize_multisig_init_result(const boost::property_tree::ptree& node, monero_multisig_init_result& info) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("address")) info.m_address = it->second.data();
      else if (key == std::string("multisig_info")) info.m_multisig_hex = it->second.data();
    }
  }

  void deserialize_multisig_sign_result(const boost::property_tree::ptree& node, monero_multisig_sign_result& res) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tx_data_hex")) res.m_signed_multisig_tx_hex = it->second.data();
      else if (key == std::string("tx_hash_list")) {
        auto node2 = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = node2.begin(); it2 != node2.end(); ++it2) {
          res.m_tx_hashes.push_back(it2->second.data());
        }
      }
    }
  }

  void deserialize_address_book_entry(const boost::property_tree::ptree& node, const std::shared_ptr<monero_address_book_entry>& entry) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("index")) entry->m_index = it->second.get_value<uint64_t>();
      else if (key == std::string("address")) entry->m_address = it->second.data();
      else if (key == std::string("description")) entry->m_description = it->second.data();
      else if (key == std::string("payment_id")) entry->m_payment_id = it->second.data();
    }
  }

  void deserialize_address_book_entries(const boost::property_tree::ptree& node, std::vector<monero_address_book_entry>& entries) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("entries")) {
        auto entries_node = it->second;
        for (auto it2 = entries_node.begin(); it2 != entries_node.end(); ++it2) {
          auto entry = std::make_shared<monero_address_book_entry>();
          deserialize_address_book_entry(it2->second, entry);
          entries.push_back(*entry);
        }
      }
    }
  }

  void deserialize_seed_languages(const boost::property_tree::ptree& node, std::vector<std::string>& languages) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("languages")) {
        auto languages_node = it->second;
        for (auto it2 = languages_node.begin(); it2 != languages_node.end(); ++it2) {
          languages.push_back(it2->second.data());
        }
      }
    }
  }

  uint64_t deserialize_address_book_index(const boost::property_tree::ptree& node) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("index")) {
        return it->second.get_value<uint64_t>();
      }
    }

    throw monero_error("Could not deserialize address book entry index");
  }

  void deserialize_account_tag(const boost::property_tree::ptree& node, const std::shared_ptr<monero_account_tag>& account_tag) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tag")) account_tag->m_tag = it->second.data();
      else if (key == std::string("label") && !it->second.data().empty()) account_tag->m_label = it->second.data();
      else if (key == std::string("accounts")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          account_tag->m_account_indices.push_back(it2->second.get_value<uint32_t>());
        }
      }
    }
  }

  void deserialize_account_tags(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_account_tag>>& account_tags) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("account_tags")) {
        for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          auto account_tag = std::make_shared<monero_account_tag>();
          deserialize_account_tag(it2->second, account_tag);
          account_tags.push_back(account_tag);
        }
      }
    }
  }

  std::string deserialize_signature(const boost::property_tree::ptree& node) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("signature")) return it->second.data();
    }

    throw monero_error("Invalid reserve proof response");
  }

  std::string deserialize_exported_outputs(const boost::property_tree::ptree& node) {
    std::string exported_outputs_hex;

    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("outputs_data_hex")) exported_outputs_hex = it->second.data();
    }

    return exported_outputs_hex;
  }

  int deserialize_num_imported_outputs(const boost::property_tree::ptree& node) {
    int num_imported = 0;

    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("num_imported")) {
        num_imported = it->second.get_value<int>();
        break;
      }
    }

    return num_imported;
  }

  bool deserialize_frozen_output_info(const boost::property_tree::ptree& node) {
    bool is_frozen = false;

    for(auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("frozen")) {
        is_frozen = it->second.get_value<bool>();
      }
    }

    return is_frozen;
  }

  monero_tx_priority deserialize_tx_priority(const boost::property_tree::ptree& node) {
    for(auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("priority")) {
        int priority = it->second.get_value<int>();
        if (priority == 0) return monero_tx_priority::DEFAULT;
        else if (priority == 1) return monero_tx_priority::UNIMPORTANT;
        else if (priority == 2) return monero_tx_priority::NORMAL;
        else if (priority == 3) return monero_tx_priority::ELEVATED;
      }
    }

    throw monero_error("Could not get default fee priority");
  }

  uint64_t deserialize_block_height(const boost::property_tree::ptree& node) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("height")) return it->second.get_value<uint64_t>();
    }
    throw monero_error("Invalid get_height response");
  }

  std::string deserialize_payment_uri(const boost::property_tree::ptree& node) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("uri")) return it->second.data();
    }
    throw monero_error("Could not deserialize payment uri");
  }

  void deserialize_payment_uri(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_config>& tx_config) {
    std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("uri")) {
        deserialize_payment_uri(it->second, tx_config);
        return;
      }
      if (key == std::string("address") && !it->second.data().empty()) destination->m_address = it->second.data();
      else if (key == std::string("amount")) destination->m_amount = it->second.get_value<uint64_t>();
      else if (key == std::string("payment_id") && !it->second.data().empty()) tx_config->m_payment_id = it->second.data();
      else if (key == std::string("recipient_name") && !it->second.data().empty()) tx_config->m_recipient_name = it->second.data();
      else if (key == std::string("tx_description") && !it->second.data().empty()) tx_config->m_note = it->second.data();
    }

    if (destination->m_address != boost::none || destination->m_amount != boost::none) tx_config->m_destinations.push_back(destination);
  }

  void deserialize_sync_result(const boost::property_tree::ptree& node, monero_sync_result& sync_result) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("blocks_fetched")) sync_result.m_num_blocks_fetched = it->second.get_value<uint64_t>();
      else if (key == std::string("received_money")) sync_result.m_received_money = it->second.get_value<bool>();
    }
  }
}
