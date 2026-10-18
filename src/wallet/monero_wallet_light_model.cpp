/**
 * Copyright (c) everoddaneven
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
 * Parts of this file are originally copyright (c) 2014-2019, MyMonero.com
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
#include "utils/monero_wallet_utils.h"

namespace monero {

  // --------------------------- MONERO DAEMON STATUS ---------------------------

  void monero_daemon_status::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_status>& status) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("outgoing_connections_count")) status->m_outgoing_connections_count = it->second.get_value<uint64_t>();
      else if (key == std::string("incoming_connections_count")) status->m_incoming_connections_count = it->second.get_value<uint64_t>();
      else if (key == std::string("height")) status->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("target_height")) status->m_target_height = it->second.get_value<uint64_t>();
      else if (key == std::string("state")) status->m_state = it->second.data();
      else if (key == std::string("network")) {
        std::string network_str = it->second.data();
        if (network_str == std::string("main") || network_str == std::string("fake")) status->m_network_type = monero_network_type::MAINNET;
        else if (network_str == std::string("test")) status->m_network_type = monero_network_type::TESTNET;
        else if (network_str == std::string("stage")) status->m_network_type = monero_network_type::STAGENET;
        else throw std::runtime_error("Cannot deserialize lws status: invalid network provided " + network_str);
      }
    }
  }

  // --------------------------- MONERO ADDRESS META ---------------------------

  void monero_address_meta::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_address_meta>& address_meta) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("maj_i")) address_meta->m_maj_i = boost::numeric_cast<uint32_t>(gen_utils::uint64_t_cast(it->second.data()));
      else if (key == std::string("min_i")) address_meta->m_min_i = boost::numeric_cast<uint32_t>(gen_utils::uint64_t_cast(it->second.data()));
    }
  }

  // --------------------------- MONERO OUTPUT LIGHT ---------------------------

  bool monero_output_light::is_key_image_known() const {
    return m_key_image != boost::none && !m_key_image->empty();
  }

  bool monero_output_light::is_rct() const {
    return m_rct != boost::none && !m_rct->empty();
  }

  bool monero_output_light::is_coinbase() const {
    return is_rct() && monero_wallet_utils::is_rct_hex_unblinded_coinbase(m_rct.get());
  }

  bool monero_output_light::is_spent() const {
    if (!is_key_image_known() || m_spend_key_images.empty()) return false;
    for(const auto& spend_key_image : m_spend_key_images) {
      if (spend_key_image == m_key_image.get()) return true;
    }
    return false;
  }

  void monero_output_light::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_light>& output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
      else if (key == std::string("amount")) output->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("index")) {
        uint64_t index = it->second.get_value<uint64_t>();
        if (index > 0xffff) throw std::runtime_error("Output index from server is out of bounds");
        output->m_index = index;
      }
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
        std::shared_ptr<monero_address_meta> recipient = std::make_shared<monero_address_meta>();
        monero_address_meta::from_property_tree(it->second, recipient);
        output->m_recipient = recipient;
      }
    }
  }

  // --------------------------- MONERO SPEND ---------------------------

  void monero_spend::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_spend>& spend) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("amount")) spend->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
      else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
      else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint64_t>();
      else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("sender")) {
        std::shared_ptr<monero_address_meta> sender = std::make_shared<monero_address_meta>();
        monero_address_meta::from_property_tree(it->second, sender);
        spend->m_sender = sender;
      }
    }
  }

  // --------------------------- MONERO TX LIGHT ---------------------------

  void monero_tx_light::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_light>& transaction) {
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
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_spend> out = std::make_shared<monero_spend>();
          monero_spend::from_property_tree(it2->second, out);
          if (out->m_sender == nullptr || out->m_amount == boost::none || out->m_tx_pub_key == boost::none || out->m_out_index == boost::none) {
            throw std::runtime_error("Light wallet server response is missing required spend fields");
          }
          transaction->m_spent_outputs.push_back(out);
        }
      }
      else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
      else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
      else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
      else if (key == std::string("mixin")) transaction->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("recipient")) {
        auto recipient = std::make_shared<monero_address_meta>();
        monero_address_meta::from_property_tree(it->second, recipient);
        transaction->m_recipient = recipient;
      }
    }
  }

  // --------------------------- MONERO RANDOM OUTPUTS ---------------------------

  void monero_random_outputs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_random_outputs>& random_outputs) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("amount")) random_outputs->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("outputs")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_output_light> out = std::make_shared<monero_output_light>();
          monero_output_light::from_property_tree(it2->second, out);
          if (out->m_public_key == boost::none || out->m_global_index == boost::none) {
            throw std::runtime_error("Light wallet server response is missing required decoy output fields");
          }
          random_outputs->m_outputs.push_back(out);
        }
      }
    }
  }

  // --------------------------- MONERO INDEX RANGE ---------------------------

  monero_index_range::monero_index_range(const uint32_t min_i, const uint32_t maj_i) {
    push_back(min_i);
    push_back(maj_i);
  }

  std::vector<uint32_t> monero_index_range::to_subaddress_indices() const {
    std::vector<uint32_t> indices;
    if (size() != 2) return indices;
    uint32_t min_i = at(0);
    uint32_t maj_i = at(1);
    for (uint64_t i = min_i; i <= maj_i; i++) indices.push_back(static_cast<uint32_t>(i));
    return indices;
  }

  void monero_index_range::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_index_range>& index_range) {
    int length = 0;
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      uint32_t value = it->second.get_value<uint32_t>();
      index_range->push_back(value);
      length++;
      if (length > 2) throw std::runtime_error("Invalid index range length");
    }
    if (length != 2) throw std::runtime_error("Invalid index range length");

    static const uint64_t MAX_INDEX_RANGE_SPAN = 1000000;
    uint32_t start = index_range->at(0);
    uint32_t end = index_range->at(1);
    if (start > end) throw std::runtime_error("Invalid index range from server: start > end");
    if (static_cast<uint64_t>(end) - start > MAX_INDEX_RANGE_SPAN) throw std::runtime_error("Index range from server is implausibly large");
  }

  // --------------------------- MONERO SUBADDRS ---------------------------

  std::vector<uint32_t> monero_subaddrs::get_subaddresses_indices(const uint32_t account_idx) const {
    std::vector<uint32_t> subaddress_idxs;
    auto it = find(account_idx);
    if (it != end()) {
      for (const auto& index_range : it->second) {
        const auto& idxs = index_range->to_subaddress_indices();
        subaddress_idxs.insert(subaddress_idxs.end(), idxs.begin(), idxs.end());
      }
    }
    return subaddress_idxs;
  }

  uint32_t monero_subaddrs::get_last_account_index() const {
    uint32_t last_account_idx = 0;
    for(const auto &kv : *this) {
      if (kv.first > last_account_idx) last_account_idx = kv.first;
    }
    return last_account_idx;
  }

  uint32_t monero_subaddrs::get_last_subaddress_index(const uint32_t account_idx) const {
    uint32_t last_subaddress_idx = 0;
    auto it = find(account_idx);
    if (it == end()) throw std::runtime_error("account not found");
    for (const auto& index_range : it->second) {
      if (index_range->at(1) > last_subaddress_idx) last_subaddress_idx = index_range->at(1);
    }
    return last_subaddress_idx;
  }

  void monero_subaddrs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_subaddrs>& subaddrs) {
    uint64_t account_count = 0;
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      if (++account_count > MAX_ACCOUNTS) throw std::runtime_error("Light wallet server reported an implausible number of accounts");
      boost::optional<uint32_t> _key;
      std::vector<std::shared_ptr<monero_index_range>> index_ranges;
      for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
        std::string key = it2->first;
        if (key == std::string("key")) _key = it2->second.get_value<uint32_t>();
        else if (key == std::string("value")) {
          for (boost::property_tree::ptree::const_iterator it3 = it2->second.begin(); it3 != it2->second.end(); ++it3) {
            std::shared_ptr<monero_index_range> ir = std::make_shared<monero_index_range>();
            monero_index_range::from_property_tree(it3->second, ir);
            index_ranges.push_back(ir);
          }
        }
      }

      if (_key == boost::none) throw std::runtime_error("Cannot deserialize subaddress: key 'key' not found.");
      if (_key.get() >= MAX_ACCOUNTS) throw std::runtime_error("Light wallet server reported an implausible account index " + std::to_string(_key.get()));

      static const uint64_t MAX_ACCOUNT_INDEX_RANGE_TOTAL_SPAN = 1000000;
      uint64_t total_span = 0;
      for (const auto& index_range : index_ranges) {
        if (index_range->size() != 2) continue; // already rejected above
        total_span += static_cast<uint64_t>(index_range->at(1)) - index_range->at(0) + 1;
        if (total_span > MAX_ACCOUNT_INDEX_RANGE_TOTAL_SPAN) throw std::runtime_error("Subaddress ranges from server are implausibly large in aggregate for account " + std::to_string(_key.get()));
      }

      subaddrs->emplace(_key.get(), index_ranges);
    }
  }

  rapidjson::Value monero_subaddrs::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kArrayType);

    // set sub-objects
    rapidjson::Value value_num(rapidjson::kNumberType);

    for(const auto& subaddr : *this) {
      rapidjson::Value obj_value(rapidjson::kObjectType);
      monero_utils::add_json_member("key", subaddr.first, allocator, obj_value, value_num);
      const auto& index_ranges = subaddr.second;
      rapidjson::Value obj_index_ranges(rapidjson::kArrayType);
      for (const auto& index_range : index_ranges) obj_index_ranges.PushBack(monero_utils::to_rapidjson_val(allocator, (std::vector<uint32_t>)*index_range), allocator);
      obj_value.AddMember("value", obj_index_ranges, allocator);
      root.PushBack(obj_value, allocator);
    }

    return root;
  }

  // --------------------------- MONERO OUTPUTS DECOYS TIE ---------------------------

  // combine newly requested mix outs returned from the server, with the already known decoys from prior tx construction attempts,
  // so that the same decoys will be re-used with the same outputs in all tx construction attempts. This ensures fee returned
  // by calculate_fee() will be correct in the final tx, and also reduces number of needed trips to the server during tx construction.
  // implementation based on mymonero-core-cpp's monero_transfer_utils::pre_step2_tie_unspent_outs_to_mix_outs_for_all_future_tx_attempts()
  monero_outputs_decoys_tie monero_outputs_decoys_tie::tie(const std::vector<std::shared_ptr<monero_output_light>>& outputs, std::vector<std::shared_ptr<monero_random_outputs>> decoys, const boost::optional<monero_output_map>& prior_tie_attempt) {
    monero_output_map tie_attempt;
    if (prior_tie_attempt != boost::none) tie_attempt = *prior_tie_attempt;

    std::vector<std::shared_ptr<monero_random_outputs>> mix_outs;
    mix_outs.reserve(outputs.size());

    for (size_t i = 0; i < outputs.size(); ++i) {
      // if we don't already know of a particular out's mix outs (from a prior attempt),
      // then tie out to a set of mix outs retrieved from the server
      auto& out = outputs[i];
      if (tie_attempt.find(out->m_public_key.get()) == tie_attempt.end()) {
        for (size_t j = 0; j < decoys.size(); ++j) {
          if ((out->is_rct() && decoys[j]->m_amount.get() != 0) ||
            (!out->is_rct() && decoys[j]->m_amount.get() != out->m_amount.get())) {
            continue;
          }

          // if we need to retry constructing tx, will remember to use same mix outs for this out on subsequent attempt(s)
          std::shared_ptr<monero_random_outputs> decoy_outputs = gen_utils::pop_index(decoys, j);
          tie_attempt[*out->m_public_key] = decoy_outputs->m_outputs;
          mix_outs.push_back(decoy_outputs);
          break;
        }
      } else {
        std::shared_ptr<monero_random_outputs> decoy_outputs = std::make_shared<monero_random_outputs>();
        decoy_outputs->m_outputs = tie_attempt[*out->m_public_key];
        decoy_outputs->m_amount = out->m_amount;
        mix_outs.push_back(decoy_outputs);
      }
    }

    // we expect to have a set of mix outs for every output in the tx
    if (mix_outs.size() != outputs.size()) throw std::runtime_error("not enough usable decoys found: " + std::to_string(mix_outs.size()));
    // we expect to use up all mix outs returned by the server
    if (!decoys.empty()) throw std::runtime_error("too many decoy remaining");

    monero_outputs_decoys_tie result;
    result.m_decoys = mix_outs;
    result.m_tie_attempt = std::move(tie_attempt);
    return result;
  }

  // --------------------------- MONERO OUTPUT SELECTION ---------------------------

  std::vector<size_t> monero_output_selection::get_output_indexes() const {
    std::vector<size_t> indexes;
    indexes.reserve(m_selected_outs.size());
    for (const auto &output : m_selected_outs) {
      if (output->m_cache_index == boost::none) throw std::runtime_error("output doesn't belong to the wallet");
      indexes.push_back(output->m_cache_index.get());
    }
    return indexes;
  }

  // --------------------------- MONERO WALLET PARAMS ---------------------------

  rapidjson::Value monero_wallet_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO GET RANDOM OUTS PARAMS ---------------------------

  rapidjson::Value monero_get_random_outs_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_count != boost::none) monero_utils::add_json_member("count", m_count.get(), allocator, root, value_num);

    // convert amounts to strings
    std::vector<std::string> amounts;
    for(const auto amount : m_amounts) amounts.push_back(std::to_string(amount));

    // set sub-arrays
    root.AddMember("amounts", monero_utils::to_rapidjson_val(allocator, amounts), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO IMPORT WALLET PARAMS ---------------------------

  rapidjson::Value monero_import_wallet_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_wallet_params::to_rapidjson_val(allocator);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_from_height != boost::none) monero_utils::add_json_member("from_height", m_from_height.get(), allocator, root, value_num);

    // return root
    return root;
  }

  // --------------------------- MONERO GET UNSPENT OUTS PARAMS ---------------------------

  rapidjson::Value monero_get_unspent_outs_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_wallet_params::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_amount != boost::none) monero_utils::add_json_member("amount", std::to_string(m_amount.get()), allocator, root, value_str);
    if (m_dust_threshold != boost::none) monero_utils::add_json_member("dust_threshold", std::to_string(m_dust_threshold.get()), allocator, root, value_str);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_mixin != boost::none) monero_utils::add_json_member("mixin", m_mixin.get(), allocator, root, value_num);

    // set bool values
    if (m_use_dust != boost::none) monero_utils::add_json_member("use_dust", m_use_dust.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO LOGIN PARAMS ---------------------------

  rapidjson::Value monero_login_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_wallet_params::to_rapidjson_val(allocator);

    // set bool values
    if (m_create_account != boost::none) monero_utils::add_json_member("create_account", m_create_account.get(), allocator, root);
    if (m_generated_locally != boost::none) monero_utils::add_json_member("generated_locally", m_generated_locally.get(), allocator, root);

    // return root
    return root;
  }

  // --------------------------- MONERO SUBMIT RAW TX PARAMS ---------------------------

  rapidjson::Value monero_submit_raw_tx_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_tx != boost::none) monero_utils::add_json_member("tx", m_tx.get(), allocator, root, value_str);

    // return root
    return root;
  }

  // --------------------------- MONERO UPSERT SUBADDRS PARAMS ---------------------------

  rapidjson::Value monero_upsert_subaddrs_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_wallet_params::to_rapidjson_val(allocator);

    // set bool values
    if (m_get_all != boost::none) monero_utils::add_json_member("get_all", m_get_all.get(), allocator, root);

    // set sub-objects
    if (m_subaddrs != boost::none) root.AddMember("subaddrs", m_subaddrs->to_rapidjson_val(allocator), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO GET ADDRESS INFO RESPONSE ---------------------------

  void monero_get_address_info_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_address_info_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("locked_funds")) response->m_locked_funds = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("total_received")) response->m_total_received = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("total_sent")) response->m_total_sent = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("scanned_height")) response->m_scanned_height = it->second.get_value<uint64_t>();
      else if (key == std::string("scanned_block_height")) response->m_scanned_block_height = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("start_height")) response->m_start_height = it->second.get_value<uint64_t>();
      else if (key == std::string("transaction_height")) response->m_transaction_height = it->second.get_value<uint64_t>();
      else if (key == std::string("blockchain_height")) response->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_spend> spent_output = std::make_shared<monero_spend>();
          monero_spend::from_property_tree(it2->second, spent_output);
          if (spent_output->m_sender == nullptr) throw std::runtime_error("Light wallet server response is missing spend sender info");
          response->m_spent_outputs.push_back(spent_output);
        }
      }
    }
  }

  // --------------------------- MONERO GET ADDRESS TXS RESPONSE ---------------------------

  void monero_get_address_txs_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_address_txs_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("total_received")) response->m_total_received = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("scanned_height")) response->m_scanned_height = it->second.get_value<uint64_t>();
      else if (key == std::string("scanned_block_height")) response->m_scanned_block_height = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("start_height")) response->m_start_height = it->second.get_value<uint64_t>();
      else if (key == std::string("blockchain_height")) response->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("transactions")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_tx_light> transaction = std::make_shared<monero_tx_light>();
          monero_tx_light::from_property_tree(it2->second, transaction);
          if (transaction->m_hash == boost::none || transaction->m_total_received == boost::none
              || transaction->m_total_sent == boost::none || transaction->m_mempool == boost::none
              || transaction->m_coinbase == boost::none || transaction->m_fee == boost::none
              || transaction->m_unlock_time == boost::none) {
            throw std::runtime_error("Light wallet server response is missing required transaction fields");
          }
          response->m_transactions.push_back(transaction);
        }
      }
    }
  }

  // --------------------------- MONERO GET RANDOM OUTS RESPONSE ---------------------------

  void monero_get_random_outs_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_random_outs_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("amount_outs")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_random_outputs> out = std::make_shared<monero_random_outputs>();
          monero_random_outputs::from_property_tree(it2->second, out);
          response->m_amount_outs.push_back(out);
        }
      }
    }
  }

  // --------------------------- MONERO GET UNSPENT OUTS RESPONSE ---------------------------

  void monero_get_unspent_outs_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_get_unspent_outs_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("per_byte_fee")) response->m_per_byte_fee = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("fee_mask")) response->m_fee_mask = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("amount")) response->m_amount = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("fees")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          response->m_fees.push_back(gen_utils::uint64_t_cast(it2->second.data()));
        }
      }
      else if (key == std::string("outputs")) {
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
          std::shared_ptr<monero_output_light> out = std::make_shared<monero_output_light>();
          monero_output_light::from_property_tree(it2->second, out);
          if (out->m_recipient == nullptr) throw std::runtime_error("Light wallet server response is missing output recipient info");
          if (out->m_tx_pub_key == boost::none || out->m_public_key == boost::none || out->m_global_index == boost::none
              || out->m_tx_hash == boost::none || out->m_amount == boost::none || out->m_index == boost::none) {
            throw std::runtime_error("Light wallet server response is missing required output fields");
          }
          response->m_outputs.push_back(out);
        }
      }
    }
  }

  // --------------------------- MONERO IMPORT WALLET RESPONSE ---------------------------

  void monero_import_wallet_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_import_wallet_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("payment_address")) response->m_payment_address = it->second.data();
      else if (key == std::string("payment_id")) response->m_payment_id = it->second.data();
      else if (key == std::string("import_fee")) response->m_import_fee = gen_utils::uint64_t_cast(it->second.data());
      else if (key == std::string("new_request")) response->m_new_request = it->second.get_value<bool>();
      else if (key == std::string("request_fulfilled")) response->m_request_fullfilled = it->second.get_value<bool>();
      else if (key == std::string("status")) response->m_status = it->second.data();
    }
  }

  // --------------------------- MONERO LOGIN RESPONSE ---------------------------

  void monero_login_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_login_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("new_address")) response->m_new_address = it->second.get_value<bool>();
      else if (key == std::string("generated_locally")) response->m_generated_locally = it->second.get_value<bool>();
      else if (key == std::string("start_height")) response->m_start_height = it->second.get_value<uint64_t>();
    }
  }

  // --------------------------- MONERO SUBMIT RAW TX RESPONSE ---------------------------

  void monero_submit_raw_tx_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_submit_raw_tx_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("status")) response->m_status = it->second.data();
    }
  }

  // --------------------------- MONERO SUBADDRS RESPONSE ---------------------------

  void monero_subaddrs_response::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_subaddrs_response>& response) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("new_subaddrs")) {
        std::shared_ptr<monero_subaddrs> new_subaddrs = std::make_shared<monero_subaddrs>();
        monero_subaddrs::from_property_tree(it->second, new_subaddrs);
        response->m_new_subaddrs = new_subaddrs;
      } else if (key == std::string("all_subaddrs")) {
        std::shared_ptr<monero_subaddrs> all_subaddrs = std::make_shared<monero_subaddrs>();
        monero_subaddrs::from_property_tree(it->second, all_subaddrs);
        response->m_all_subaddrs = all_subaddrs;
      }
    }
  }

  // --------------------------- MONERO LIGHT WALLET CACHE ---------------------------

  namespace {
    // flattens every subaddress bucket of a single account into one vector
    std::vector<std::shared_ptr<monero_output_light>> flatten_outputs(const serializable_unordered_map<uint32_t, std::vector<std::shared_ptr<monero_output_light>>>& subaddress_buckets) {
      std::vector<std::shared_ptr<monero_output_light>> result;
      for (const auto &kv : subaddress_buckets) result.insert(result.end(), kv.second.begin(), kv.second.end());
      return result;
    }

    uint64_t find_or_zero(const serializable_unordered_map<uint32_t, uint64_t>& m, uint32_t key) {
      auto it = m.find(key);
      return it == m.end() ? 0 : it->second;
    }

    uint64_t find_or_zero(const serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>>& m, uint32_t account_idx, uint32_t subaddress_idx) {
      auto it = m.find(account_idx);
      if (it == m.end()) return 0;
      auto it2 = it->second.find(subaddress_idx);
      return it2 == it->second.end() ? 0 : it2->second;
    }
  }

  monero_wallet_light_cache::monero_wallet_light_cache(const std::shared_ptr<monero_key_image_cache>& key_image_cache) : m_key_image_cache(key_image_cache), m_subaddrs(std::make_shared<monero_subaddrs_response>()) {
    m_subaddrs->m_all_subaddrs = std::make_shared<monero_subaddrs>();
  }

  monero_wallet_light_cache::~monero_wallet_light_cache() {
    MTRACE("monero_wallet_light_cache::~monero_wallet_light_cache()");
    for (auto& kv : m_self_constructed_txs) monero_utils::free(kv.second);
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_outputs(uint32_t account_idx) const {
    auto all = get_spent(account_idx);
    auto unspent = get_unspent(account_idx);
    all.insert(all.end(), unspent.begin(), unspent.end());
    return all;
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_outputs(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto all = get_spent(account_idx, subaddress_idx);
    auto unspent = get_unspent(account_idx, subaddress_idx);
    all.insert(all.end(), unspent.begin(), unspent.end());
    return all;
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_unspent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto account_it = m_unspent.find(account_idx);
    if (account_it == m_unspent.end()) return {};
    auto subaddr_it = account_it->second.find(subaddress_idx);
    return subaddr_it == account_it->second.end() ? std::vector<std::shared_ptr<monero_output_light>>() : subaddr_it->second;

  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_spent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto account_it = m_spent.find(account_idx);
    if (account_it == m_spent.end()) return {};
    auto subaddr_it = account_it->second.find(subaddress_idx);
    return subaddr_it == account_it->second.end() ? std::vector<std::shared_ptr<monero_output_light>>() : subaddr_it->second;
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_spent(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_spent.find(account_idx);
    return it == m_spent.end() ? std::vector<std::shared_ptr<monero_output_light>>() : flatten_outputs(it->second);
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_unspent(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_unspent.find(account_idx);
    return it == m_unspent.end() ? std::vector<std::shared_ptr<monero_output_light>>() : flatten_outputs(it->second);
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_spendable(uint32_t account_idx, const std::vector<uint32_t> &subaddresses_indices) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_unspent.find(account_idx);
    if (it == m_unspent.end()) {
      // account not found
      std::vector<std::shared_ptr<monero_output_light>> empty_result;
      return empty_result;
    }

    std::vector<std::shared_ptr<monero_output_light>> spendable;
    bool by_subaddress_idx = !subaddresses_indices.empty();
    const auto pool_key_images = get_pool_key_images();
    for(const auto& kv : it->second) {
      uint32_t subaddress_index = kv.first;
      if (by_subaddress_idx) {
        bool found = std::find(subaddresses_indices.begin(), subaddresses_indices.end(), subaddress_index) != subaddresses_indices.end();
        if (!found) continue;
      }

      for (const auto& output : kv.second) {
        if (output->m_frozen.value_or(false) || get_num_blocks_to_unlock(output->m_tx_hash.get()) > 0) continue;
        if (output->is_key_image_known() && pool_key_images.count(output->m_key_image.get())) continue;
        spendable.push_back(output);
      }
    }

    return spendable;
  }

  std::vector<std::shared_ptr<monero_output_light>> monero_wallet_light_cache::get_tx_outputs(const std::string& tx_hash, bool filter_spent) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_tx_hash_index.find(tx_hash);
    if (it == m_tx_hash_index.end()) return std::vector<std::shared_ptr<monero_output_light>>();
    if (!filter_spent) return it->second;
    std::vector<std::shared_ptr<monero_output_light>> outputs;
    for (const auto &output : it->second) if (!output->is_spent()) outputs.push_back(output);
    return outputs;
  }

  std::string monero_wallet_light_cache::get_tx_prefix_hash(const std::string& tx_hash) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto outputs = get_tx_outputs(tx_hash);
    if (outputs.empty()) return std::string("");
    auto& output = outputs[0];
    return output->m_tx_prefix_hash.get();
  }

  void monero_wallet_light_cache::resort_outputs_by_chain_order() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    std::sort(m_outputs.begin(), m_outputs.end(), [](const std::shared_ptr<monero_output_light>& a, const std::shared_ptr<monero_output_light>& b) {
      uint64_t a_h = a->m_height.value_or(0), b_h = b->m_height.value_or(0);
      if (a_h != b_h) return a_h < b_h;
      const std::string& a_tx_hash = a->m_tx_hash.value_or(std::string());
      const std::string& b_tx_hash = b->m_tx_hash.value_or(std::string());
      if (a_tx_hash != b_tx_hash) return a_tx_hash < b_tx_hash;
      return a->m_index.value_or(0) < b->m_index.value_or(0);
    });
  }

  static const uint64_t MAX_SANE_FEE_MASK = 1000000; // 100x today's real value
  static const uint64_t MAX_SANE_PER_BYTE_FEE = 100000000;

  void monero_wallet_light_cache::set_outputs(monero_get_unspent_outs_response& response) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    std::unordered_set<std::string> frozen_key_images;
    for (const auto& output : m_outputs) {
      if (output->m_frozen.value_or(false) && output->is_key_image_known()) frozen_key_images.insert(output->m_key_image.get());
    }

    m_per_byte_fee = response.m_per_byte_fee.value_or(0);
    m_fees = std::move(response.m_fees);
    m_fee_mask = std::min(response.m_fee_mask.value_or(0), MAX_SANE_FEE_MASK);
    m_amount = response.m_amount.value_or(0);
    m_outputs = std::move(response.m_outputs);
    resort_outputs_by_chain_order();

    if (!frozen_key_images.empty()) {
      for (auto& output : m_outputs) {
        if (output->is_key_image_known() && frozen_key_images.count(output->m_key_image.get())) output->m_frozen = true;
      }
    }

    reindex();
  }

  uint64_t monero_wallet_light_cache::get_per_byte_fee() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_per_byte_fee;
  }

  uint64_t monero_wallet_light_cache::get_base_fee(uint32_t priority) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    uint64_t fee_per_byte;
    if (!m_fees.empty()) {
      // mirrors wallet2::get_base_fee()'s 2021-scaling path: clamp to [1,4] and index directly.
      // These per-tier fees come straight from the daemon and aren't simple multiples of each other.
      const uint32_t clamped = priority == 0 ? 1 : std::min<uint32_t>(priority, 4);
      const uint32_t idx = clamped - 1;
      fee_per_byte = idx < m_fees.size() ? m_fees[idx] : m_per_byte_fee * monero_wallet_utils::get_fee_multiplier(priority);
    } else {
      // legacy fallback for servers that only ever returned a flat per_byte_fee
      fee_per_byte = m_per_byte_fee * monero_wallet_utils::get_fee_multiplier(priority);
    }
    // check the fully resolved rate
    if (fee_per_byte > MAX_SANE_PER_BYTE_FEE) {
      throw std::runtime_error("Light wallet server reported an implausible per-byte fee (" + std::to_string(fee_per_byte) + " piconero/byte)");
    }
    return fee_per_byte;
  }

  uint64_t monero_wallet_light_cache::get_fee_mask() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_fee_mask == 0 ? 1 : m_fee_mask;
  }

  uint64_t monero_wallet_light_cache::get_amount() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_amount;
  }

  // re-derives spent/unspent buckets and indices from the current m_outputs (e.g. after outputs already
  // in the cache had key images assigned in place, as import_key_images does), without a fresh response
  void monero_wallet_light_cache::reindex_outputs(uint64_t amount) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_amount = amount;
    reindex();
  }

  // (re)builds m_key_image_index/m_tx_hash_index/m_spent/m_unspent, and each output's m_cache_index,
  // from the current m_outputs
  void monero_wallet_light_cache::reindex() {
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      m_key_image_index.clear();
      m_tx_hash_index.clear();
      m_unspent.clear();
      m_spent.clear();
      clear_balance();
    }
    if (m_outputs.empty()) return;
    size_t index = 0;
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    const auto pool_key_images = get_pool_key_images();

    for (const auto &output : m_outputs) {
      output->m_cache_index = index;

      if (output->is_spent() || (output->is_key_image_known() && pool_key_images.count(output->m_key_image.get()))) {
        m_spent[output->m_recipient->m_maj_i][output->m_recipient->m_min_i].push_back(output);
      } else {
        m_unspent[output->m_recipient->m_maj_i][output->m_recipient->m_min_i].push_back(output);
      }

      if (output->is_key_image_known()) {
        std::string output_key_image = output->m_key_image.get();
        m_key_image_index[output_key_image] = index;
      }

      m_tx_hash_index[output->m_tx_hash.get()].push_back(output);
      index++;
    }
  }

  bool monero_wallet_light_cache::is_subaddress_used(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto unspent_account_it = m_unspent.find(account_idx);
    if (unspent_account_it != m_unspent.end()) {
      auto subaddr_it = unspent_account_it->second.find(subaddress_idx);
      if (subaddr_it != unspent_account_it->second.end() && !subaddr_it->second.empty()) return true;
    }
    auto spent_account_it = m_spent.find(account_idx);
    if (spent_account_it != m_spent.end()) {
      auto subaddr_it = spent_account_it->second.find(subaddress_idx);
      if (subaddr_it != spent_account_it->second.end() && !subaddr_it->second.empty()) return true;
    }
    return false;
  }

  uint64_t monero_wallet_light_cache::get_num_unspent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto account_it = m_unspent.find(account_idx);
    if (account_it == m_unspent.end()) return 0;
    auto subaddr_it = account_it->second.find(subaddress_idx);
    if (subaddr_it == account_it->second.end()) return 0;
    const auto pool_key_images = get_pool_key_images();
    uint64_t count = 0;
    for (const auto& output : subaddr_it->second) {
      if (output->is_key_image_known() && pool_key_images.count(output->m_key_image.get())) continue;
      count++;
    }
    return count;
  }

  void monero_wallet_light_cache::clear_balance() {
    m_account_balance.clear();
    m_account_unlocked_balance.clear();
    m_subaddress_balance.clear();
    m_subaddress_unlocked_balance.clear();
    m_balance = 0;
    m_unlocked_balance = 0;
  }

  void monero_wallet_light_cache::calculate_balance() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    clear_balance();
    const auto pool_key_images = get_pool_key_images();
    for (const auto &kv : m_unspent) {
      uint32_t account_idx = kv.first;
      uint64_t account_balance = 0;
      uint64_t account_unlocked_balance = 0;

      for (const auto &kv2 : kv.second) {
        uint32_t subaddress_idx = kv2.first;
        uint64_t subaddress_balance = 0;
        uint64_t subaddress_unlocked_balance = 0;

        for(const auto &output : kv2.second) {
          if (output->is_key_image_known() && pool_key_images.count(output->m_key_image.get())) continue;
          if (output->m_frozen.value_or(false)) continue;
          bool locked = get_num_blocks_to_unlock(output->m_tx_hash.get()) > 0;
          uint64_t amount = output->m_amount.get();
          subaddress_balance += amount;
          if (!locked) subaddress_unlocked_balance += amount;
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
    for_each_unconfirmed_tx([this](const std::string& hash, const std::shared_ptr<monero_tx_wallet>& tx) {
      if (tx->m_is_relayed != true || tx->m_is_failed == true) return;

      uint64_t change_amount = 0;
      if (tx->m_change_amount != boost::none) change_amount = tx->m_change_amount.get();

      uint32_t change_account_idx = 0;
      if (tx->m_outgoing_transfer != nullptr && tx->m_outgoing_transfer->m_account_index != boost::none) {
        change_account_idx = tx->m_outgoing_transfer->m_account_index.get();
      }

      m_balance += change_amount;
      m_account_balance[change_account_idx] += change_amount;
      m_subaddress_balance[change_account_idx][0] += change_amount;

      for (const std::shared_ptr<monero_output> &out : tx->m_outputs) {
        std::shared_ptr<monero_output_wallet> output = std::dynamic_pointer_cast<monero_output_wallet>(out);
        if (output == nullptr || output->m_account_index == boost::none || output->m_subaddress_index == boost::none) continue;
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
          if (subaddr_it == m_subaddress_balance[account_idx].end()) m_subaddress_balance[account_idx][subaddress_idx] = output_amount;
          else m_subaddress_balance[account_idx][subaddress_idx] += output_amount;
        }
        m_balance += output_amount;
      }
    });
  }

  uint64_t monero_wallet_light_cache::get_balance() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_balance;
  }

  uint64_t monero_wallet_light_cache::get_balance(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return find_or_zero(m_account_balance, account_idx);
  }

  uint64_t monero_wallet_light_cache::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return find_or_zero(m_subaddress_balance, account_idx, subaddress_idx);
  }

  uint64_t monero_wallet_light_cache::get_unlocked_balance() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_unlocked_balance;
  }

  uint64_t monero_wallet_light_cache::get_unlocked_balance(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return find_or_zero(m_account_unlocked_balance, account_idx);
  }

  uint64_t monero_wallet_light_cache::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return find_or_zero(m_subaddress_unlocked_balance, account_idx, subaddress_idx);
  }

  void validate_key_image(const std::string& key_image) {
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key image");
  }

  void monero_wallet_light_cache::set_key_image_frozen(const std::string& key_image, bool frozen) {
    if (key_image.empty()) throw std::runtime_error(std::string("Must specify key image to ") + (frozen ? "freeze" : "thaw"));
    validate_key_image(key_image);
    auto it = m_key_image_index.find(key_image);
    if (it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    m_outputs[it->second]->m_frozen = frozen;
  }

  bool monero_wallet_light_cache::is_key_image_frozen(const std::string& key_image) const {
    validate_key_image(key_image);
    auto it = m_key_image_index.find(key_image);
    if (it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    return m_outputs[it->second]->m_frozen.value_or(false);
  }

  std::shared_ptr<monero_output_light> monero_wallet_light_cache::get_output(const std::string& key_image) const {
    validate_key_image(key_image);
    auto it = m_key_image_index.find(key_image);
    if (it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    return m_outputs[it->second];
  }

  void monero_wallet_light_cache::set_key_image(const std::string& key_image, size_t index) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_key_image_index[key_image] = index;
  }

  // implementation based on monero-project's wallet2::export_outputs()
  monero_wallet_utils::wallet2_exported_outputs monero_wallet_light_cache::export_outputs(bool all, uint32_t start, uint32_t count) const {
    std::vector<tools::wallet2::exported_transfer_details> exported_transfers;

    // invalid cases
    if(count == 0) throw std::runtime_error("Nothing requested");
    if(!all && start > 0) throw std::runtime_error("Incremental mode is incompatible with non-zero start");

    // valid cases:
    // all: all outputs, subject to start/count
    // !all: incremental, subject to count
    // for convenience, start/count are allowed to go past the valid range, then nothing is returned
    const auto &unspent_outs = m_outputs;

    size_t offset = 0;
    if (!all) {
      while (offset < unspent_outs.size() && (unspent_outs[offset]->is_key_image_known() && !m_key_image_cache->request(unspent_outs[offset]->m_tx_pub_key.get(), unspent_outs[offset]->m_index.get(), unspent_outs[offset]->m_recipient->m_maj_i, unspent_outs[offset]->m_recipient->m_min_i)))
        ++offset;
    }
    else offset = start;

    exported_transfers.reserve(offset <= unspent_outs.size() ? unspent_outs.size() - offset : 0);
    for (size_t n = offset; n < unspent_outs.size() && n - offset < count; ++n) {
      const auto &out = unspent_outs[n];
      uint64_t out_amount = out->m_amount.get();
      auto internal_output_index = out->m_index.get();
      std::string tx_hash = out->m_tx_hash.get();
      uint64_t unlock_time = get_tx(tx_hash)->m_unlock_time.get();

      crypto::public_key public_key;
      crypto::public_key tx_pub_key;
      if (!epee::string_tools::hex_to_pod(out->m_public_key.get(), public_key)) throw std::runtime_error("failed to parse output public key");
      if (!epee::string_tools::hex_to_pod(out->m_tx_pub_key.get(), tx_pub_key)) throw std::runtime_error("failed to parse tx public key");

      cryptonote::transaction_prefix tx_prefix;
      add_tx_pub_key_to_extra(tx_prefix, tx_pub_key);

      cryptonote::tx_out txout;
      txout.target = cryptonote::txout_to_key(public_key);
      txout.amount = out_amount;
      tx_prefix.vout.resize(internal_output_index + 1);
      tx_prefix.vout[internal_output_index] = txout;
      tx_prefix.unlock_time = unlock_time;

      tools::wallet2::exported_transfer_details etd;
      etd.m_pubkey = public_key;
      etd.m_tx_pubkey = tx_pub_key; // pk_index?
      etd.m_internal_output_index = internal_output_index;
      etd.m_global_output_index = out->m_global_index.get();
      etd.m_flags.flags = 0;
      etd.m_flags.m_spent = out->is_spent();
      etd.m_flags.m_frozen = out->m_frozen.value_or(false);
      etd.m_flags.m_rct = out->is_rct();
      etd.m_flags.m_key_image_known = out->is_key_image_known();
      etd.m_flags.m_key_image_request = false; //td.m_key_image_request;
      etd.m_flags.m_key_image_partial = false;
      etd.m_amount = out_amount;
      etd.m_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx_prefix);
      etd.m_subaddr_index_major = out->m_recipient->m_maj_i;
      etd.m_subaddr_index_minor = out->m_recipient->m_min_i;

      exported_transfers.push_back(etd);
    }

    return std::make_tuple(offset, unspent_outs.size(), exported_transfers);
  }

  std::vector<std::shared_ptr<monero_tx_light>> monero_wallet_light_cache::get_txs() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_tx_list;
  }

  std::shared_ptr<monero_tx_light> monero_wallet_light_cache::get_tx(const std::string& hash) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_txs.find(hash);
    if (it == m_txs.end()) throw std::runtime_error("tx not found in store");
    return it->second;
  }

  void monero_wallet_light_cache::set_txs(monero_get_address_txs_response& response, const monero_get_address_info_response& addr_info_response) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_txs.clear();
    m_spent_key_images.clear();
    m_block_reward = 0;
    m_tx_list.clear();
    std::unordered_map<std::string, size_t> tx_list_index;

    for(auto &tx : response.m_transactions) {
      std::string tx_hash = tx->m_hash.get();
      bool confirmed = !tx->m_mempool.get();
      if (tx->m_coinbase.get()) {
        uint64_t amount = tx->m_total_received.get();
        if (m_block_reward == 0 || amount < m_block_reward) m_block_reward = amount;
      }

      auto tx_list_it = tx_list_index.find(tx_hash);
      if (tx_list_it == tx_list_index.end()) {
        tx_list_index[tx_hash] = m_tx_list.size();
        m_tx_list.push_back(tx);
      } else {
        m_tx_list[tx_list_it->second] = tx;
      }
      if (confirmed) {
        auto self_constructed_it = m_self_constructed_txs.find(tx_hash);
        if (self_constructed_it != m_self_constructed_txs.end() && self_constructed_it->second != nullptr) {
          const auto& self_tx = self_constructed_it->second;
          self_tx->m_is_confirmed = true;
          self_tx->m_in_tx_pool = false;
          self_tx->m_is_failed = false;
          if (tx->m_height != boost::none) {
            if (self_tx->m_block == nullptr) {
              auto block = std::make_shared<monero_block>();
              self_tx->m_block = block;
              block->m_txs.push_back(self_tx);
            }
            self_tx->m_block->m_height = tx->m_height;
          }
        }
      }
      m_txs[tx_hash] = std::move(tx);
    }

    const uint64_t now = static_cast<uint64_t>(time(NULL));

    for (auto& kv : m_self_constructed_txs) {
      const auto& self_tx = kv.second;
      if (self_tx == nullptr || self_tx->m_is_confirmed != true) continue;
      if (tx_list_index.find(kv.first) != tx_list_index.end()) continue;
      self_tx->m_is_confirmed = false;
      self_tx->m_in_tx_pool = true;
      self_tx->m_is_failed = false;
      self_tx->m_block = nullptr;
      m_self_constructed_tx_relay_times[kv.first] = now;
    }
    for (auto& kv : m_self_constructed_txs) {
      const auto& self_tx = kv.second;
      if (self_tx == nullptr || self_tx->m_is_confirmed == true || self_tx->m_is_failed == true) continue;
      if (self_tx->m_is_relayed != true) continue;
      auto relay_time_it = m_self_constructed_tx_relay_times.find(kv.first);
      if (relay_time_it == m_self_constructed_tx_relay_times.end()) continue; // no relay time on record (e.g. cache predates this fix) - can't judge, leave it alone
      if (now < relay_time_it->second + CRYPTONOTE_MEMPOOL_TX_LIVETIME) continue;
      self_tx->m_is_failed = true;
      self_tx->m_in_tx_pool = false;
    }

    if (m_block_reward == 0) m_block_reward = monero_wallet_utils::TAIL_EMISSION_REWARD;

    for (const auto &spend : addr_info_response.m_spent_outputs) {
      if (spend->m_key_image != boost::none) {
        m_spent_key_images[spend->m_key_image.get()] = true;
      }
    }
  }

  void monero_wallet_light_cache::refresh(monero_get_unspent_outs_response& unspent_outs, monero_get_address_txs_response& address_txs, const monero_get_address_info_response& address_info) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    set_txs(address_txs, address_info);
    set_outputs(unspent_outs);
    set_sync_status(address_info);
    calculate_balance();
  }

  uint64_t monero_wallet_light_cache::get_blockchain_height() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_blockchain_height;
  }

  uint64_t monero_wallet_light_cache::get_last_block_reward() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_block_reward > 1 ? m_block_reward - 2 : m_block_reward; // TODO why wallet full gives to 2 piconero less ?
  }

  uint64_t monero_wallet_light_cache::get_scanned_block_height() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_scanned_block_height;
  }

  uint64_t monero_wallet_light_cache::get_start_height() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_start_height;
  }

  void monero_wallet_light_cache::set_start_height(uint64_t height) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_start_height = height;
  }

  void monero_wallet_light_cache::set_sync_status(const monero_get_address_info_response& address_info) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_blockchain_height = address_info.m_blockchain_height.value_or(0);
    m_scanned_block_height = address_info.m_scanned_block_height.value_or(0);
    m_start_height = address_info.m_start_height.value_or(0);
  }

  boost::optional<std::string> monero_wallet_light_cache::get_change_pubkey(const std::string& tx_hash) const {
    auto it = m_self_constructed_txs.find(tx_hash);
    if (it == m_self_constructed_txs.end() || it->second == nullptr) return boost::none;
    for (const auto& out : it->second->m_outputs) {
      auto change_out = std::dynamic_pointer_cast<monero_output_wallet_light>(out);
      if (change_out != nullptr && change_out->m_is_change.value_or(false)) return change_out->m_stealth_public_key.value_or("");
    }
    return std::string("");
  }

  std::vector<std::shared_ptr<monero_destination>> monero_wallet_light_cache::get_tx_destinations(const std::string& tx_hash) const {
    auto it = m_self_constructed_txs.find(tx_hash);
    if (it == m_self_constructed_txs.end() || it->second == nullptr || it->second->m_outgoing_transfer == nullptr) return std::vector<std::shared_ptr<monero_destination>>();
    std::vector<std::shared_ptr<monero_destination>> destinations;
    for (const auto& destination : it->second->m_outgoing_transfer->m_destinations) {
      destinations.push_back(destination->copy(destination, std::make_shared<monero_destination>()));
    }
    return destinations;
  }

  std::shared_ptr<monero_tx_wallet> monero_wallet_light_cache::get_self_constructed_tx(const std::string& tx_hash) const {
    auto it = m_self_constructed_txs.find(tx_hash);
    if (it == m_self_constructed_txs.end()) return nullptr;
    return it->second;
  }

  void monero_wallet_light_cache::add_unconfirmed_tx(const std::shared_ptr<monero_tx_wallet>& tx, const std::string& change_pubkey) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    if (tx->m_hash == boost::none) throw std::runtime_error("Cannot set none unconfirmed tx hash");
    std::string tx_hash = tx->m_hash.get();
    if (tx_hash.empty()) throw std::runtime_error("Cannot set empty unconfirmed tx hash");
    if (!change_pubkey.empty()) {
      auto change_out = std::make_shared<monero_output_wallet_light>();
      change_out->m_tx = tx;
      change_out->m_is_change = true;
      change_out->m_stealth_public_key = change_pubkey;
      tx->m_outputs.push_back(change_out);
    }
    m_self_constructed_txs[tx_hash] = tx;
    if (tx->m_is_relayed.value_or(false)) m_self_constructed_tx_relay_times[tx_hash] = static_cast<uint64_t>(time(NULL));
  }

  void monero_wallet_light_cache::for_each_unconfirmed_tx(const std::function<void(const std::string&, const std::shared_ptr<monero_tx_wallet>&)>& visitor) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto& kv : m_self_constructed_txs) {
      if (kv.second != nullptr && !kv.second->m_is_confirmed.value_or(false)) visitor(kv.first, kv.second);
    }
  }

  uint64_t monero_wallet_light_cache::get_num_blocks_to_unlock(const std::string& tx_hash) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto tx_it = m_txs.find(tx_hash);
    if (tx_it == m_txs.end()) return CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    const auto& tx = tx_it->second;
    uint64_t current_height = get_scanned_block_height() + 1;
    uint64_t tx_height = tx->m_mempool.get() ? current_height : tx->m_height.get();
    uint64_t unlock_time = tx->m_unlock_time.get();
    uint64_t default_spendable_age = tx_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    uint64_t confirmations_needed = default_spendable_age > current_height ? default_spendable_age - current_height : 0;

    uint64_t num_blocks_to_unlock;
    if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER) {
      // unlock_time is a block height
      num_blocks_to_unlock = unlock_time <= current_height ? 0 : unlock_time - current_height;
    } else {
      // unlock_time is a unix timestamp; approximate remaining blocks assuming DIFFICULTY_TARGET_V2 seconds/block
      uint64_t now = static_cast<uint64_t>(time(NULL));
      num_blocks_to_unlock = unlock_time <= now ? 0 : (unlock_time - now) / DIFFICULTY_TARGET_V2;
    }

    return num_blocks_to_unlock > confirmations_needed ? num_blocks_to_unlock : confirmations_needed;
  }

  uint64_t monero_wallet_light_cache::get_num_blocks_to_unlock(const std::vector<std::shared_ptr<monero_output_light>>& outputs) const {
    uint64_t num_blocks = 0;
    for(const auto &output : outputs) {
      if (output->m_tx_hash == boost::none) continue;
      uint64_t blocks = get_num_blocks_to_unlock(output->m_tx_hash.get());
      if (blocks > num_blocks) num_blocks = blocks;
    }
    return num_blocks;
  }

  uint64_t monero_wallet_light_cache::get_num_blocks_to_unlock(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    uint64_t num_blocks = 0;
    auto spent_account_it = m_spent.find(account_idx);
    if (spent_account_it != m_spent.end()) {
      auto subaddr_it = spent_account_it->second.find(subaddress_idx);
      if (subaddr_it != spent_account_it->second.end()) num_blocks = std::max(num_blocks, get_num_blocks_to_unlock(subaddr_it->second));
    }
    auto unspent_account_it = m_unspent.find(account_idx);
    if (unspent_account_it != m_unspent.end()) {
      auto subaddr_it = unspent_account_it->second.find(subaddress_idx);
      if (subaddr_it != unspent_account_it->second.end()) num_blocks = std::max(num_blocks, get_num_blocks_to_unlock(subaddr_it->second));
    }
    return num_blocks;
  }

  bool monero_wallet_light_cache::is_key_image_in_pool(const std::string& key_image) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &kv : m_self_constructed_txs) {
      const auto& self_tx = kv.second;
      if (self_tx == nullptr || self_tx->m_is_relayed != true || self_tx->m_is_failed == true) continue;
      for (const auto &in : self_tx->m_inputs) {
        std::shared_ptr<monero_output_wallet> input = std::static_pointer_cast<monero_output_wallet>(in);
        if (input == nullptr || input->m_key_image == nullptr || input->m_key_image->m_hex == boost::none) continue;
        if (input->m_key_image->m_hex.get() == key_image) return true;
      }
    }
    return false;
  }

  std::unordered_set<std::string> monero_wallet_light_cache::get_pool_key_images() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    std::unordered_set<std::string> images;
    for (const auto &kv : m_self_constructed_txs) {
      const auto& self_tx = kv.second;
      if (self_tx == nullptr || self_tx->m_is_relayed != true || self_tx->m_is_failed == true) continue;
      for (const auto &in : self_tx->m_inputs) {
        std::shared_ptr<monero_output_wallet> input = std::static_pointer_cast<monero_output_wallet>(in);
        if (input == nullptr || input->m_key_image == nullptr || input->m_key_image->m_hex == boost::none) continue;
        images.insert(input->m_key_image->m_hex.get());
      }
    }
    return images;
  }

  bool monero_wallet_light_cache::is_key_image_spent(const std::string& key_image) const {
    if (is_key_image_in_pool(key_image)) return true;
    auto it = m_spent_key_images.find(key_image);
    if (it == m_spent_key_images.end()) return false;
    return it->second;
  }

  bool monero_wallet_light_cache::is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image) const {
    if (key_image == nullptr) throw std::runtime_error("key image is null");
    if (key_image->m_hex == boost::none) return false;
    return is_key_image_spent(key_image->m_hex.get());
  }

  bool monero_wallet_light_cache::is_key_image_spent(const std::string& key_image, const std::unordered_set<std::string>& pool_key_images) const {
    if (pool_key_images.count(key_image)) return true;
    auto it = m_spent_key_images.find(key_image);
    if (it == m_spent_key_images.end()) return false;
    return it->second;
  }

  bool monero_wallet_light_cache::is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image, const std::unordered_set<std::string>& pool_key_images) const {
    if (key_image == nullptr) throw std::runtime_error("key image is null");
    if (key_image->m_hex == boost::none) return false;
    return is_key_image_spent(key_image->m_hex.get(), pool_key_images);
  }

  void monero_wallet_light_cache::init_subaddress(monero_subaddress& subaddress) const {
    if (subaddress.m_account_index == boost::none) throw std::runtime_error("Cannot initialize subaddress: account index is none");
    if (subaddress.m_index == boost::none) throw std::runtime_error("Cannot initialize subaddress: subaddress index is none");
    uint32_t account_idx = subaddress.m_account_index.get();
    uint32_t subaddress_idx = subaddress.m_index.get();
    subaddress.m_balance = get_balance(account_idx, subaddress_idx);
    subaddress.m_unlocked_balance = get_unlocked_balance(account_idx, subaddress_idx);
    subaddress.m_num_unspent_outputs = get_num_unspent(account_idx, subaddress_idx);
    subaddress.m_is_used = is_subaddress_used(account_idx, subaddress_idx);
    subaddress.m_num_blocks_to_unlock = get_num_blocks_to_unlock(account_idx, subaddress_idx);
  }

  std::shared_ptr<monero_tx_wallet> monero_wallet_light_cache::init_tx_with_output(const std::shared_ptr<monero_output_light>& out, const std::unordered_set<std::string>& pool_key_images) const {
    // construct block
    std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
    block->m_height = out->m_height;

    // construct tx
    std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
    tx->m_block = block;
    block->m_txs.push_back(tx);
    tx->m_hash = out->m_tx_hash;
    tx->m_is_confirmed = true;
    tx->m_is_failed = false;
    tx->m_is_relayed = true;
    tx->m_in_tx_pool = false;
    tx->m_relay = true;
    tx->m_is_double_spend_seen = false;
    tx->m_is_locked = get_num_blocks_to_unlock(out->m_tx_hash.get()) > 0;

    // construct output
    std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
    output->m_tx = tx;
    tx->m_outputs.push_back(output);
    output->m_amount = out->m_amount;
    output->m_index = out->m_global_index;
    output->m_account_index = out->m_recipient->m_maj_i;
    output->m_subaddress_index = out->m_recipient->m_min_i;
    output->m_is_spent = out->is_spent();
    output->m_is_frozen = false;
    output->m_stealth_public_key = out->m_public_key;
    if (out->is_key_image_known()) {
      output->m_key_image = std::make_shared<monero_key_image>();
      output->m_key_image.get()->m_hex = out->m_key_image;
      output->m_is_frozen = out->m_frozen.value_or(false);
      if (!*output->m_is_spent) output->m_is_spent = is_key_image_spent(out->m_key_image.get(), pool_key_images);
    }

    // return pointer to new tx
    return tx;
  }


}