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

#include "daemon/monero_daemon_model.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include <map>

using namespace monero;

/**
 * Public library interface.
 */
namespace monero {

  /**
   * Configures a wallet to create.
   */
  struct monero_wallet_config : public serializable_struct {
    boost::optional<std::string> m_path;
    boost::optional<std::string> m_password;
    boost::optional<monero_network_type> m_network_type;
    boost::optional<monero_rpc_connection> m_server;
    boost::optional<std::string> m_seed;
    boost::optional<std::string> m_seed_offset;
    boost::optional<std::string> m_primary_address;
    boost::optional<std::string> m_private_view_key;
    boost::optional<std::string> m_private_spend_key;
    boost::optional<uint64_t> m_restore_height;
    boost::optional<std::string> m_language;
    boost::optional<bool> m_save_current;
    boost::optional<uint64_t> m_account_lookahead;
    boost::optional<uint64_t> m_subaddress_lookahead;
    boost::optional<bool> m_is_multisig;

    monero_wallet_config() {}
    monero_wallet_config(const monero_wallet_config& config);
    monero_wallet_config copy() const;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static std::shared_ptr<monero_wallet_config> deserialize(const std::string& config_json);
  };

  /**
   * Models a result of syncing a wallet.
   */
  struct monero_sync_result : public serializable_struct {
    uint64_t m_num_blocks_fetched;
    bool m_received_money;
    monero_sync_result() {}
    monero_sync_result(const uint64_t num_blocks_fetched, const bool received_money) : m_num_blocks_fetched(num_blocks_fetched), m_received_money(received_money) {}

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Models a Monero subaddress.
   */
  struct monero_subaddress : public serializable_struct {
    boost::optional<uint32_t> m_account_index;
    boost::optional<uint32_t> m_index;
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_label;
    boost::optional<uint64_t> m_balance;
    boost::optional<uint64_t> m_unlocked_balance;
    boost::optional<uint64_t> m_num_unspent_outputs;
    boost::optional<bool> m_is_used;
    boost::optional<uint64_t> m_num_blocks_to_unlock;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Models a Monero account.
   */
  struct monero_account : public serializable_struct {
    boost::optional<uint32_t> m_index;
    boost::optional<std::string> m_primary_address;
    boost::optional<uint64_t> m_balance;
    boost::optional<uint64_t> m_unlocked_balance;
    boost::optional<std::string> m_tag;
    std::vector<monero_subaddress> m_subaddresses;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Models an outgoing transfer destination.
   */
  struct monero_destination {
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_amount;

    monero_destination(boost::optional<std::string> address = boost::none, boost::optional<uint64_t> amount = boost::none) : m_address(address), m_amount(amount) {}
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_destination>& destination);
    std::shared_ptr<monero_destination> copy(const std::shared_ptr<monero_destination>& src, const std::shared_ptr<monero_destination>& tgt) const;
  };

  // forward declarations
  struct monero_tx_wallet;
  struct monero_tx_query;
  struct monero_tx_set;

  /**
   * Models a base transfer of funds to or from the wallet.
   *
   * TODO: m_is_incoming for api consistency
   */
  struct monero_transfer : serializable_struct {
    std::shared_ptr<monero_tx_wallet> m_tx;
    boost::optional<uint64_t> m_amount;
    boost::optional<uint32_t> m_account_index;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_transfer>& transfer);
    virtual boost::optional<bool> is_incoming() const = 0;  // derived class must implement
    std::shared_ptr<monero_transfer> copy(const std::shared_ptr<monero_transfer>& src, const std::shared_ptr<monero_transfer>& tgt) const;
    boost::optional<bool> is_outgoing() const {
			if (is_incoming() == boost::none) return boost::none;
      return !(*is_incoming());
    }
    void merge(const std::shared_ptr<monero_transfer>& self, const std::shared_ptr<monero_transfer>& other);
  };

  /**
   * Models an incoming transfer of funds to the wallet.
   */
  struct monero_incoming_transfer : public monero_transfer {
    boost::optional<uint32_t> m_subaddress_index;
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_num_suggested_confirmations;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<monero_incoming_transfer> copy(const std::shared_ptr<monero_transfer>& src, const std::shared_ptr<monero_transfer>& tgt) const;
    std::shared_ptr<monero_incoming_transfer> copy(const std::shared_ptr<monero_incoming_transfer>& src, const std::shared_ptr<monero_incoming_transfer>& tgt) const;
    boost::optional<bool> is_incoming() const;
    void merge(const std::shared_ptr<monero_transfer>& self, const std::shared_ptr<monero_transfer>& other);
    void merge(const std::shared_ptr<monero_incoming_transfer>& self, const std::shared_ptr<monero_incoming_transfer>& other);
  };

  /**
   * Models an outgoing transfer of funds from the wallet.
   */
  struct monero_outgoing_transfer : public monero_transfer {
    std::vector<uint32_t> m_subaddress_indices;
    std::vector<std::string> m_addresses;
    std::vector<std::shared_ptr<monero_destination>> m_destinations;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<monero_outgoing_transfer> copy(const std::shared_ptr<monero_transfer>& src, const std::shared_ptr<monero_transfer>& tgt) const;
    std::shared_ptr<monero_outgoing_transfer> copy(const std::shared_ptr<monero_outgoing_transfer>& src, const std::shared_ptr<monero_outgoing_transfer>& tgt) const;
    boost::optional<bool> is_incoming() const;
    void merge(const std::shared_ptr<monero_transfer>& self, const std::shared_ptr<monero_transfer>& other);
    void merge(const std::shared_ptr<monero_outgoing_transfer>& self, const std::shared_ptr<monero_outgoing_transfer>& other);
  };

  /**
   * Configures a query to retrieve transfers.
   *
   * All transfers are returned except those that do not meet the criteria defined in this query.
   */
  struct monero_transfer_query : public monero_transfer {
    boost::optional<bool> m_is_incoming;
    boost::optional<std::string> m_address;
    std::vector<std::string> m_addresses;
    boost::optional<uint32_t> m_subaddress_index;
    std::vector<uint32_t> m_subaddress_indices;
    std::vector<std::shared_ptr<monero_destination>> m_destinations;
    boost::optional<bool> m_has_destinations;
    boost::optional<std::shared_ptr<monero_tx_query>> m_tx_query;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_transfer_query>& transfer_query);
    static std::shared_ptr<monero_transfer_query> deserialize_from_block(const std::string& transfer_query_json);
    std::shared_ptr<monero_transfer_query> copy(const std::shared_ptr<monero_transfer>& src, const std::shared_ptr<monero_transfer>& tgt) const;
    std::shared_ptr<monero_transfer_query> copy(const std::shared_ptr<monero_transfer_query>& src, const std::shared_ptr<monero_transfer_query>& tgt) const;
    boost::optional<bool> is_incoming() const;
    bool meets_criteria(monero_transfer* transfer, bool query_parent = true) const;
  };

  /**
   * Models a Monero output with wallet extensions.
   */
  struct monero_output_wallet : public monero_output {
    boost::optional<uint32_t> m_account_index;
    boost::optional<uint32_t> m_subaddress_index;
    boost::optional<bool> m_is_spent;
    boost::optional<bool> m_is_frozen;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_wallet>& output_wallet);
    std::shared_ptr<monero_output_wallet> copy(const std::shared_ptr<monero_output>& src, const std::shared_ptr<monero_output>& tgt) const;
    std::shared_ptr<monero_output_wallet> copy(const std::shared_ptr<monero_output_wallet>& src, const std::shared_ptr<monero_output_wallet>& tgt) const;
    void merge(const std::shared_ptr<monero_output>& self, const std::shared_ptr<monero_output>& other);
    void merge(const std::shared_ptr<monero_output_wallet>& self, const std::shared_ptr<monero_output_wallet>& other);
  };

  /**
   * Configures a query to retrieve wallet outputs (i.e. outputs that the wallet has or had the
   * ability to spend).
   *
   * All outputs are returned except those that do not meet the criteria defined in this query.
   */
  struct monero_output_query : public monero_output_wallet {
    std::vector<uint32_t> m_subaddress_indices;
    boost::optional<uint64_t> m_min_amount;
    boost::optional<uint64_t> m_max_amount;
    boost::optional<std::shared_ptr<monero_tx_query>> m_tx_query;

    //boost::property_tree::ptree to_property_tree() const;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_query>& output_query);
    static std::shared_ptr<monero_output_query> deserialize_from_block(const std::string& output_query_json);
    std::shared_ptr<monero_output_query> copy(const std::shared_ptr<monero_output>& src, const std::shared_ptr<monero_output>& tgt) const;
    std::shared_ptr<monero_output_query> copy(const std::shared_ptr<monero_output_wallet>& src, const std::shared_ptr<monero_output_wallet>& tgt) const; // TODO: necessary to override all super classes?
    std::shared_ptr<monero_output_query> copy(const std::shared_ptr<monero_output_query>& src, const std::shared_ptr<monero_output_query>& tgt) const;
    bool meets_criteria(monero_output_wallet* output, bool query_parent = true) const;
  };

  /**
   * Models a Monero transaction in the context of a wallet.
   */
  struct monero_tx_wallet : public monero_tx {
    boost::optional<std::shared_ptr<monero_tx_set>> m_tx_set;
    boost::optional<bool> m_is_incoming;
    boost::optional<bool> m_is_outgoing;
    std::vector<std::shared_ptr<monero_incoming_transfer>> m_incoming_transfers;
    boost::optional<std::shared_ptr<monero_outgoing_transfer>> m_outgoing_transfer;
    boost::optional<std::string> m_note;
    boost::optional<bool> m_is_locked;
    boost::optional<uint64_t> m_input_sum;
    boost::optional<uint64_t> m_output_sum;
    boost::optional<std::string> m_change_address;
    boost::optional<uint64_t> m_change_amount;
    boost::optional<uint32_t> m_num_dummy_outputs;
    boost::optional<std::string> m_extra_hex;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_wallet>& tx_wallet);
    std::shared_ptr<monero_tx_wallet> copy(const std::shared_ptr<monero_tx>& src, const std::shared_ptr<monero_tx>& tgt) const;
    std::shared_ptr<monero_tx_wallet> copy(const std::shared_ptr<monero_tx_wallet>& src, const std::shared_ptr<monero_tx_wallet>& tgt) const;
    void merge(const std::shared_ptr<monero_tx>& self, const std::shared_ptr<monero_tx>& other);
    void merge(const std::shared_ptr<monero_tx_wallet>& self, const std::shared_ptr<monero_tx_wallet>& other);
    std::vector<std::shared_ptr<monero_transfer>> get_transfers() const;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers(const monero_transfer_query& query) const;
    std::vector<std::shared_ptr<monero_transfer>> filter_transfers(const monero_transfer_query& query);
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs_wallet() const;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs_wallet(const monero_output_query& query) const;
    std::vector<std::shared_ptr<monero_output_wallet>> filter_outputs_wallet(const monero_output_query& query);
  };

  /**
   * Configures a query to retrieve transactions.
   *
   * All transactions are returned except those that do not meet the criteria defined in this query.
   */
  struct monero_tx_query : public monero_tx_wallet {
    boost::optional<bool> m_is_outgoing;
    boost::optional<bool> m_is_incoming;
    std::vector<std::string> m_hashes;
    boost::optional<bool> m_has_payment_id;
    std::vector<std::string> m_payment_ids;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_min_height;
    boost::optional<uint64_t> m_max_height;
    boost::optional<uint64_t> m_include_outputs;
    boost::optional<std::shared_ptr<monero_transfer_query>> m_transfer_query;
    boost::optional<std::shared_ptr<monero_output_query>> m_input_query;
    boost::optional<std::shared_ptr<monero_output_query>> m_output_query;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_query>& tx_query);
    static std::shared_ptr<monero_tx_query> deserialize_from_block(const std::string& tx_query_json);
    std::shared_ptr<monero_tx_query> copy(const std::shared_ptr<monero_tx>& src, const std::shared_ptr<monero_tx>& tgt) const;
    std::shared_ptr<monero_tx_query> copy(const std::shared_ptr<monero_tx_wallet>& src, const std::shared_ptr<monero_tx_wallet>& tgt) const; // TODO: necessary to override all super classes?
    std::shared_ptr<monero_tx_query> copy(const std::shared_ptr<monero_tx_query>& src, const std::shared_ptr<monero_tx_query>& tgt) const;
    bool meets_criteria(monero_tx_wallet* tx, bool query_children = true) const;
  };

  /**
   * Groups transactions who share common hex data which is needed in order to
   * sign and submit the transactions.
   *
   * For example, multisig transactions created from create_txs() share a common
   * hex string which is needed in order to sign and submit the multisig
   * transactions.
   */
  struct monero_tx_set : public serializable_struct {
    std::vector<std::shared_ptr<monero_tx_wallet>> m_txs;
    boost::optional<std::string> m_signed_tx_hex;
    boost::optional<std::string> m_unsigned_tx_hex;
    boost::optional<std::string> m_multisig_tx_hex;

    //boost::property_tree::ptree to_property_tree() const;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static monero_tx_set deserialize(const std::string& tx_set_json);
  };

  /**
   * Monero integrated address model.
   */
  struct monero_integrated_address : public serializable_struct {
    std::string m_standard_address;
    std::string m_payment_id;
    std::string m_integrated_address;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Enumerates Monero network types.
   */
  enum monero_tx_priority : uint8_t {
    DEFAULT = 0,
    UNIMPORTANT,
    NORMAL,
    ELEVATED
  };

  /**
   * Configures a transaction to send, sweep, or create a payment URI.
   */
  struct monero_tx_config : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_amount;
    std::vector<std::shared_ptr<monero_destination>> m_destinations;
    std::vector<uint32_t> m_subtract_fee_from;
    boost::optional<std::string> m_payment_id;
    boost::optional<monero_tx_priority> m_priority;
    boost::optional<uint32_t> m_ring_size;
    boost::optional<uint64_t> m_fee;
    boost::optional<uint32_t> m_account_index;
    std::vector<uint32_t> m_subaddress_indices;
    boost::optional<bool> m_can_split;
    boost::optional<bool> m_relay;
    boost::optional<std::string> m_note;
    boost::optional<std::string> m_recipient_name;
    boost::optional<uint64_t> m_below_amount;
    boost::optional<bool> m_sweep_each_subaddress;
    boost::optional<std::string> m_key_image;

    monero_tx_config() {}
    monero_tx_config(const monero_tx_config& config);
    monero_tx_config copy() const;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static std::shared_ptr<monero_tx_config> deserialize(const std::string& config_json);
    std::vector<std::shared_ptr<monero_destination>> get_normalized_destinations() const;
  };

  /**
   * Models results from importing key images.
   */
  struct monero_key_image_import_result : public serializable_struct {
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_spent_amount;
    boost::optional<uint64_t> m_unspent_amount;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Enumerates message verification results.
   */
  enum monero_message_signature_type : uint8_t {
    SIGN_WITH_SPEND_KEY = 0,
    SIGN_WITH_VIEW_KEY
  };

  /**
   * Enumerates message verification results.
   */
  struct monero_message_signature_result : public serializable_struct {
    bool m_is_good;
    uint32_t m_version;
    bool m_is_old;
    monero_message_signature_type m_signature_type;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Base class for results from checking a transaction or reserve proof.
   */
  struct monero_check : public serializable_struct {
    bool m_is_good;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Results from checking a transaction key.
   */
  struct monero_check_tx : public monero_check {
    boost::optional<bool> m_in_tx_pool;
    boost::optional<uint64_t> m_num_confirmations;
    boost::optional<uint64_t> m_received_amount;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Results from checking a reserve proof.
   */
  struct monero_check_reserve : public monero_check  {
    boost::optional<uint64_t> m_total_amount;
    boost::optional<uint64_t> m_unconfirmed_spent_amount;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Models information about a multisig wallet.
   */
  struct monero_multisig_info : serializable_struct {
    bool m_is_multisig;
    bool m_is_ready;
    uint32_t m_threshold;
    uint32_t m_num_participants;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Models the result of initializing a multisig wallet which results in the
   * multisig wallet's address xor another multisig hex to share with
   * participants to create the wallet.
   */
  struct monero_multisig_init_result : serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_multisig_hex;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Models the result of signing multisig tx hex.
   */
  struct monero_multisig_sign_result : serializable_struct {
    boost::optional<std::string> m_signed_multisig_tx_hex;
    std::vector<std::string> m_tx_hashes;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  /**
   * Monero address book entry model.
   */
  struct monero_address_book_entry : serializable_struct {
    boost::optional<uint64_t> m_index;  // TODO: not boost::optional
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_description;
    boost::optional<std::string> m_payment_id;

    monero_address_book_entry() {}
    monero_address_book_entry(uint64_t index, const std::string& address, const std::string& description) : m_index(index), m_address(address), m_description(description) {}
    monero_address_book_entry(uint64_t index, const std::string& address, const std::string& description, const std::string& payment_id) : m_index(index), m_address(address), m_description(description), m_payment_id(payment_id) {}
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  // ------------------------------- LIGHT WALLET DATA STRUCTURES -------------------------------

  struct monero_light_address_meta {
    boost::optional<uint32_t> m_maj_i;
    boost::optional<uint32_t> m_min_i;

    static std::shared_ptr<monero_light_address_meta> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta);
  };

  struct monero_light_output {
    boost::optional<uint64_t> m_tx_id;
    boost::optional<std::string> m_amount;
    boost::optional<uint64_t> m_index;
    boost::optional<std::string> m_global_index;
    boost::optional<std::string> m_rct;
    boost::optional<std::string> m_tx_hash;
    boost::optional<std::string> m_tx_prefix_hash;
    boost::optional<std::string> m_public_key;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<std::vector<std::string>> m_spend_key_images;
    boost::optional<std::string> m_timestamp;
    boost::optional<uint64_t> m_height;
    boost::optional<monero_light_address_meta> m_recipient;

    static std::shared_ptr<monero_light_output> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output);
  };

  struct monero_light_rates {
    boost::optional<float> m_aud;
    boost::optional<float> m_brl;
    boost::optional<float> m_btc;
    boost::optional<float> m_cad;
    boost::optional<float> m_chf;
    boost::optional<float> m_cny;
    boost::optional<float> m_eur;
    boost::optional<float> m_gbp;
    boost::optional<float> m_hkd;
    boost::optional<float> m_inr;
    boost::optional<float> m_jpy;
    boost::optional<float> m_krw;
    boost::optional<float> m_mxn;
    boost::optional<float> m_nok;
    boost::optional<float> m_nzd;
    boost::optional<float> m_sek;
    boost::optional<float> m_sgd;
    boost::optional<float> m_try;
    boost::optional<float> m_usd;
    boost::optional<float> m_rub;
    boost::optional<float> m_zar;

    static std::shared_ptr<monero_light_rates> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_rates>& rates);
  };

  struct monero_light_spend {
    boost::optional<std::string> m_amount;
    boost::optional<std::string> m_key_image;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<uint64_t> m_out_index;
    boost::optional<uint32_t> m_mixin;
    boost::optional<monero_light_address_meta> m_sender;

    static std::shared_ptr<monero_light_spend> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend);
    std::shared_ptr<monero_light_spend> copy(const std::shared_ptr<monero_light_spend>& src, const std::shared_ptr<monero_light_spend>& tgt) const;
  };

  struct monero_light_transaction {
    boost::optional<uint64_t> m_id;
    boost::optional<std::string> m_hash;
    boost::optional<std::string> m_timestamp;
    boost::optional<std::string> m_total_received;
    boost::optional<std::string> m_total_sent;
    boost::optional<std::string> m_fee;
    boost::optional<uint64_t> m_unlock_time;
    boost::optional<uint64_t> m_height;
    boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
    boost::optional<std::string> m_payment_id;
    boost::optional<bool> m_coinbase;
    boost::optional<bool> m_mempool;
    boost::optional<uint32_t> m_mixin;
    boost::optional<monero_light_address_meta> m_recipient;

    static std::shared_ptr<monero_light_transaction> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_transaction>& transaction);
    std::shared_ptr<monero_light_transaction> copy(const std::shared_ptr<monero_light_transaction>& src, const std::shared_ptr<monero_light_transaction>& tgt, bool exclude_spend = false) const;
  };

  struct monero_light_random_output {
    boost::optional<std::string> m_global_index;
    boost::optional<std::string> m_public_key;
    boost::optional<std::string> m_rct;

    static std::shared_ptr<monero_light_random_output> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output);
  };

  struct monero_light_random_outputs {
    boost::optional<std::string> m_amount;
    boost::optional<std::vector<monero_light_random_output>> m_outputs;

    static std::shared_ptr<monero_light_random_outputs> deserialize(const std::string& config_json);
      
  };

  // ------------------------------- REQUEST/RESPONSE DATA STRUCTURES -------------------------------

  struct monero_light_get_address_info_request {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_address_info_response {
    boost::optional<std::string> m_locked_funds;
    boost::optional<std::string> m_total_received;
    boost::optional<std::string> m_total_sent;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_transaction_height;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
    boost::optional<monero_light_rates> m_rates;
    
    static std::shared_ptr<monero_light_get_address_info_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_address_txs_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_address_txs_response {
    boost::optional<std::string> m_total_received;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<std::vector<monero_light_transaction>> m_transactions;

    static std::shared_ptr<monero_light_get_address_txs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_random_outs_request : public serializable_struct {
    boost::optional<uint32_t> m_count;
    boost::optional<std::vector<std::string>> m_amounts;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_random_outs_response {
    boost::optional<std::vector<monero_light_random_output>> m_amount_outs;
      
    static std::shared_ptr<monero_light_get_random_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_unspent_outs_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;
    boost::optional<std::string> m_amount;
    boost::optional<uint32_t> m_mixin;
    boost::optional<bool> m_use_dust;
    boost::optional<std::string> m_dust_threshold;
    
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_unspent_outs_response {
    boost::optional<std::string> m_per_byte_fee;
    boost::optional<std::string> m_fee_mask;
    boost::optional<std::string> m_amount;
    boost::optional<std::vector<monero_light_output>> m_outputs;
    
    static std::shared_ptr<monero_light_get_unspent_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_import_request_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;
    
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_import_request_response {
    boost::optional<std::string> m_payment_address;
    boost::optional<std::string> m_payment_id;
    boost::optional<std::string> m_import_fee;
    boost::optional<bool> m_new_request;
    boost::optional<bool> m_request_fullfilled;
    boost::optional<std::string> m_status;
      
    static std::shared_ptr<monero_light_import_request_response> deserialize(const std::string& config_json);
  };

  struct monero_light_login_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;
    boost::optional<bool> m_create_account;
    boost::optional<bool> m_generated_locally;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_login_response {
    boost::optional<bool> m_new_address;
    boost::optional<bool> m_generated_locally;
    boost::optional<uint64_t> m_start_height;
      
    static std::shared_ptr<monero_light_login_response> deserialize(const std::string& config_json);
  };

  struct monero_light_submit_raw_tx_request : public serializable_struct {
    boost::optional<std::string> m_tx;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_submit_raw_tx_response {
    boost::optional<std::string> m_status;
    
    static std::shared_ptr<monero_light_submit_raw_tx_response> deserialize(const std::string& config_json);
  };

  struct monero_light_provision_subaddrs_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;
    boost::optional<uint32_t> m_maj_i;
    boost::optional<uint32_t> m_min_i;
    boost::optional<uint32_t> m_n_maj;
    boost::optional<uint32_t> m_n_min;
    boost::optional<bool> m_get_all;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;    
  };

  class monero_light_index_range : public std::vector<uint32_t> {
    public:
      monero_light_index_range() { 
        std::vector<uint32_t>();
      };

      monero_light_index_range(const uint32_t min_i, const uint32_t maj_i) {
        push_back(min_i);
        push_back(maj_i);
      };

      bool in_range(uint32_t subaddress_idx) {
        if (empty() || size() != 2) return false;
        return at(0) <= subaddress_idx && subaddress_idx <= at(1);
      };
      
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_index_range>& index_range);
  };

  class monero_light_subaddrs : public std::map<uint32_t, std::vector<monero_light_index_range>>, public serializable_struct {
    public:
      bool contains(const cryptonote::subaddress_index subaddress_index) const {
        return contains(subaddress_index.major, subaddress_index.minor);
      };
      bool contains(const uint32_t account_index, const uint32_t subaddress_index) const {
        for(auto kv : *this) {
          if (kv.first != account_index) continue;

          for (monero_light_index_range index_range : kv.second) {
            if (index_range.in_range(subaddress_index)) return true;
          }

          break;
        }

        return false;
      }
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
      static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_subaddrs>& subaddrs);
  };

  struct monero_light_provision_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_new_subaddrs;
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_provision_subaddrs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_upsert_subaddrs_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;
    boost::optional<monero_light_subaddrs> m_subaddrs;
    boost::optional<bool> m_get_all;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_upsert_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_new_subaddrs;
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_upsert_subaddrs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_subaddrs_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_get_subaddrs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_accept_requests_request : public serializable_struct {
    boost::optional<std::string> m_token;
    boost::optional<std::string> m_type;
    boost::optional<std::vector<std::string>> m_addresses;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_add_account_request : public serializable_struct {
    boost::optional<std::string> m_token;
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_list_accounts_request : public serializable_struct {
    boost::optional<std::string> m_token;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_account {
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_scan_height;
    boost::optional<uint64_t> m_access_time;

    static std::shared_ptr<monero_light_account> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_account>& account);
  };

  struct monero_light_list_accounts_response {
    boost::optional<std::vector<monero_light_account>> m_active;
    boost::optional<std::vector<monero_light_account>> m_inactive;
    boost::optional<std::vector<monero_light_account>> m_hidden;

    static std::shared_ptr<monero_light_list_accounts_response> deserialize(const std::string& config_json);
  };

  struct monero_light_list_requests_request : public serializable_struct {
    boost::optional<std::string> m_token;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_create_account_request {
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_start_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_create_account_request>& account);
  };

  struct monero_light_import_account_request {
    boost::optional<std::string> m_address;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_import_account_request>& account);
  };

  struct monero_light_list_requests_response {
    boost::optional<std::vector<monero_light_create_account_request>> m_create;
    boost::optional<std::vector<monero_light_import_account_request>> m_import;
    static std::shared_ptr<monero_light_list_requests_response> deserialize(const std::string& config_json);
  };

  struct monero_light_modify_account_status_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<std::string> m_status;
      boost::optional<std::vector<std::string>> m_addresses;

      monero_light_modify_account_status_request(std::string status, std::vector<std::string> addresses): m_status(status), m_addresses(addresses) {}
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_reject_requests_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<std::string> m_type;
      boost::optional<std::vector<std::string>> m_addresses;

      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_rescan_request : public serializable_struct {
      boost::optional<std::string> m_token;
      boost::optional<uint64_t> m_height;
      boost::optional<std::vector<std::string>> m_addresses;

      monero_light_rescan_request(uint64_t &height, std::vector<std::string> addresses): m_height(height), m_addresses(addresses) {}
      rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };


}
