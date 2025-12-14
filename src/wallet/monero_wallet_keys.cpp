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

#include "monero_wallet_keys.h"

#include "utils/monero_utils.h"
#include "monero_wallet_utils.h"
#include <chrono>
#include <iostream>
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "common/base58.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "string_tools.h"
#include "device/device.hpp"
#include "device/device_cold.hpp"

using namespace epee;
using namespace tools;
using namespace crypto;

/**
 * Public library interface.
 */
namespace monero {

  // ------------------------------- KEY IMAGE UTILS -------------------------------

  std::shared_ptr<monero_key_image> monero_key_image_cache::get(const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) {
    boost::lock_guard<boost::mutex> lock(m_mutex);
    auto it_pubkey = m_cache.find(tx_public_key);
    if (it_pubkey != m_cache.end()) {
        auto it_out_index = it_pubkey->second.find(out_index);
        if (it_out_index != it_pubkey->second.end()) {
            auto it_subaddr = it_out_index->second.find(received_subaddr);
            if (it_subaddr != it_out_index->second.end()) {
                return std::get<0>(it_subaddr->second);
            }
        }
    }
    return nullptr;
  }
  
  std::shared_ptr<monero_key_image> monero_key_image_cache::get(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx) {
    crypto::public_key _tx_public_key;
    string_tools::hex_to_pod(tx_public_key, _tx_public_key);
    return get(_tx_public_key, out_index, {account_idx, subaddress_idx});
  }

  void monero_key_image_cache::set(const std::shared_ptr<monero_key_image>& key_image, const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr, bool request) {
    boost::lock_guard<boost::mutex> lock(m_mutex);
    m_cache[tx_public_key][out_index][received_subaddr] = std::make_pair(key_image, request);
  }

  void monero_key_image_cache::set(const std::shared_ptr<monero_key_image>& key_image, const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx, bool request) {
    crypto::public_key _tx_public_key;
    string_tools::hex_to_pod(tx_public_key, _tx_public_key);
    set(key_image, _tx_public_key, out_index, {account_idx, subaddress_idx}, request);
  }

  bool monero_key_image_cache::request(const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) {
    boost::lock_guard<boost::mutex> lock(m_mutex);
    auto it_pubkey = m_cache.find(tx_public_key);
    if (it_pubkey != m_cache.end()) {
        auto it_out_index = it_pubkey->second.find(out_index);
        if (it_out_index != it_pubkey->second.end()) {
            auto it_subaddr = it_out_index->second.find(received_subaddr);
            if (it_subaddr != it_out_index->second.end()) {
                return std::get<1>(it_subaddr->second);
            }
        }
    }
    return false;
  }

  bool monero_key_image_cache::request(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx) {
    crypto::public_key _tx_public_key;
    string_tools::hex_to_pod(tx_public_key, _tx_public_key);
    return request(_tx_public_key, out_index, {account_idx, subaddress_idx});   
  }

  void monero_key_image_cache::set_request(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx, bool request) {
    auto key_image = get(tx_public_key, out_index, account_idx, subaddress_idx);
    if (key_image == nullptr) throw std::runtime_error("Key image not found in cache");
    set(key_image, tx_public_key, out_index, account_idx, subaddress_idx, request);
  }

  // Set up an address signature message hash
  // Hash data: domain separator, spend public key, view public key, mode identifier, payload data
  static crypto::hash get_message_hash(const std::string &data, const crypto::public_key &spend_key, const crypto::public_key &view_key, const uint8_t mode)
  {
    KECCAK_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, (const uint8_t*)config::HASH_KEY_MESSAGE_SIGNING, sizeof(config::HASH_KEY_MESSAGE_SIGNING)); // includes NUL
    keccak_update(&ctx, (const uint8_t*)&spend_key, sizeof(crypto::public_key));
    keccak_update(&ctx, (const uint8_t*)&view_key, sizeof(crypto::public_key));
    keccak_update(&ctx, (const uint8_t*)&mode, sizeof(uint8_t));
    char len_buf[(sizeof(size_t) * 8 + 6) / 7];
    char *ptr = len_buf;
    tools::write_varint(ptr, data.size());
    CHECK_AND_ASSERT_THROW_MES(ptr > len_buf && ptr <= len_buf + sizeof(len_buf), "Length overflow");
    keccak_update(&ctx, (const uint8_t*)len_buf, ptr - len_buf);
    keccak_update(&ctx, (const uint8_t*)data.data(), data.size());
    crypto::hash hash;
    keccak_finish(&ctx, (uint8_t*)&hash);
    return hash;
  }

  // ---------------------------- WALLET MANAGEMENT ---------------------------

  monero_wallet_keys* monero_wallet_keys::create_wallet_random(const monero_wallet_config& config) {

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config_normalized.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config_normalized.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

    // initialize random wallet account
    monero_wallet_keys* wallet = new monero_wallet_keys();
    crypto::secret_key spend_key_sk = wallet->m_account.generate();

    // initialize remaining wallet
    wallet->m_network_type = config_normalized.m_network_type.get();
    wallet->m_language = config_normalized.m_language.get();
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    wallet->init_common();

    return wallet;
  }

  monero_wallet_keys* monero_wallet_keys::create_wallet_from_seed(const monero_wallet_config& config) {

    // validate config
    if (config.m_is_multisig != boost::none && config.m_is_multisig.get()) throw std::runtime_error("Restoring from multisig seed not supported");
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config.m_seed == boost::none || config.m_seed.get().empty()) throw std::runtime_error("Must provide wallet seed");

    // validate mnemonic and get recovery key and language
    crypto::secret_key spend_key_sk;
    std::string language;
    bool is_valid = crypto::ElectrumWords::words_to_bytes(config.m_seed.get(), spend_key_sk, language);
    if (!is_valid) throw std::runtime_error("Invalid mnemonic");
    if (language == crypto::ElectrumWords::old_language_name) language = Language::English().get_language_name();

    // apply offset if given
    if (config.m_seed_offset != boost::none && !config.m_seed_offset.get().empty()) spend_key_sk = cryptonote::decrypt_key(spend_key_sk, config.m_seed_offset.get());

    // initialize wallet account
    monero_wallet_keys* wallet = new monero_wallet_keys();
    wallet->m_account = cryptonote::account_base{};
    crypto::secret_key spend_key_value = wallet->m_account.generate(spend_key_sk, true, false);

    // initialize remaining wallet
    wallet->m_network_type = config.m_network_type.get();
    wallet->m_language = language;
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_value, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    wallet->init_common();

    return wallet;
  }

  monero_wallet_keys* monero_wallet_keys::create_wallet_from_keys(const monero_wallet_config& config) {

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
    bool has_view_key = true;
    crypto::secret_key view_key_sk;
    if (config_normalized.m_private_view_key.get().empty()) {
      if (has_spend_key) has_view_key = false;
      else throw std::runtime_error("Neither spend key nor view key supplied");
    }
    if (has_view_key) {
      cryptonote::blobdata view_key_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(config_normalized.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("failed to parse secret view key");
      }
      view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());
    }

    // parse and validate address
    cryptonote::address_parse_info address_info;
    if (config_normalized.m_primary_address.get().empty()) {
      if (has_view_key) throw std::runtime_error("must provide address if providing private view key");
    } else {
      if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config_normalized.m_network_type.get()), config_normalized.m_primary_address.get())) throw std::runtime_error("failed to parse address");

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (has_spend_key) {
        if (!crypto::secret_key_to_public_key(spend_key_sk, pkey)) throw std::runtime_error("failed to verify secret spend key");
        if (address_info.address.m_spend_public_key != pkey) throw std::runtime_error("spend key does not match address");
      }
      if (has_view_key) {
        if (!crypto::secret_key_to_public_key(view_key_sk, pkey)) throw std::runtime_error("failed to verify secret view key");
        if (address_info.address.m_view_public_key != pkey) throw std::runtime_error("view key does not match address");
      }
    }

    // initialize wallet account
    monero_wallet_keys* wallet = new monero_wallet_keys();
    if (has_spend_key && has_view_key) {
      wallet->m_account.create_from_keys(address_info.address, spend_key_sk, view_key_sk);
    } else if (has_spend_key) {
      wallet->m_account.generate(spend_key_sk, true, false);
    } else {
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
    wallet->init_common();

    return wallet;
  }

  std::vector<std::string> monero_wallet_keys::get_seed_languages() {
    std::vector<std::string> languages;
    crypto::ElectrumWords::get_language_list(languages, true);  // TODO: support getting names in language
    return languages;
  }

  // ----------------------------- WALLET METHODS -----------------------------

  bool monero_wallet_keys::key_on_device() const {
    return m_account.get_device().get_type() != hw::device::device_type::SOFTWARE;
  }

  monero_wallet_keys::~monero_wallet_keys() {
    MTRACE("~monero_wallet_keys()");
    close();
  }

  monero_version monero_wallet_keys::get_version() const {
    monero_version version;
    version.m_number = 65552; // same as monero-wallet-rpc v0.15.0.1 release
    version.m_is_release = false; // TODO: could pull from MONERO_VERSION_IS_RELEASE in version.cpp
    return version;
  }

  std::string monero_wallet_keys::get_address(uint32_t account_idx, uint32_t subaddress_idx) const {
    hw::device &hwdev = m_account.get_device();
    cryptonote::subaddress_index index{account_idx, subaddress_idx};
    cryptonote::account_public_address address = hwdev.get_subaddress(m_account.get_keys(), index);
    return cryptonote::get_account_address_as_str(static_cast<cryptonote::network_type>(m_network_type), !index.is_zero(), address);
  }

  monero_integrated_address monero_wallet_keys::get_integrated_address(const std::string& standard_address, const std::string& payment_id) const {
    MTRACE("get_integrated_address()");

    // this logic is based on monero_wallet_full::get_integrated_address()
    
    // randomly generate payment id if not given, else validate
    crypto::hash8 payment_id_h8;
    if (payment_id.empty()) {
      payment_id_h8 = crypto::rand<crypto::hash8>();
    } else {
      if (!monero_utils::parse_short_payment_id(payment_id, payment_id_h8)) throw std::runtime_error("Invalid payment ID: " + payment_id);
    }

    // use primary address if standard address not given, else validate
    if (standard_address.empty()) {
      hw::device &hwdev = m_account.get_device();
      cryptonote::subaddress_index index{0, 0};
      cryptonote::account_public_address address = hwdev.get_subaddress(m_account.get_keys(), index);
      return decode_integrated_address(cryptonote::get_account_integrated_address_as_str(get_nettype(), address, payment_id_h8));
    } else {

      // validate standard address
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, get_nettype(), standard_address)) throw std::runtime_error("Invalid address");
      if (info.is_subaddress) throw std::runtime_error("Subaddress shouldn't be used");
      if (info.has_payment_id) throw std::runtime_error("Already integrated address");
      if (payment_id.empty()) throw std::runtime_error("Payment ID shouldn't be left unspecified");

      // create integrated address from given standard address
      return decode_integrated_address(cryptonote::get_account_integrated_address_as_str(get_nettype(), info.address, payment_id_h8));
    }
  }

  monero_integrated_address monero_wallet_keys::decode_integrated_address(const std::string& integrated_address) const {
    MTRACE("monero_wallet_keys::decode_integrated_address()");
    // TODO this logic is based on monero_wallet_full::decode_integrated_address(), refactory code?

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, get_nettype(), integrated_address)) throw std::runtime_error("Invalid address");
    if (!info.has_payment_id) throw std::runtime_error("Address is not an integrated address");

    cryptonote::account_public_address address = info.address;
    monero_integrated_address result;
    result.m_integrated_address = integrated_address;
    result.m_standard_address = cryptonote::get_account_address_as_str(get_nettype(), info.is_subaddress, address);
    result.m_payment_id = string_tools::pod_to_hex(info.payment_id);

    return result;
  }

  monero_account monero_wallet_keys::get_account(uint32_t account_idx, bool include_subaddresses) const {
    MTRACE("monero_wallet_keys::get_account()");

    if (include_subaddresses) {
      std::string err = "monero_wallet_keys::get_account(account_idx, include_subaddresses) include_subaddresses must be false";
      std::cout << err << std::endl;
      throw std::runtime_error(err);
    }

    // build and return account
    monero_account account;
    account.m_index = account_idx;
    account.m_primary_address = get_address(account_idx, 0);
    return account;
  }

  std::vector<monero_subaddress> monero_wallet_keys::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {

    // must provide subaddress indices
    if (subaddress_indices.empty()) {
      std::string err = "Keys-only wallet does not have enumerable set of subaddresses; specific specific subaddresses";
      std::cout << err << std::endl;
      throw std::runtime_error(err);
    }

    // initialize subaddresses at indices
    std::vector<monero_subaddress> subaddresses;
    for (uint32_t subaddressIndicesIdx = 0; subaddressIndicesIdx < subaddress_indices.size(); subaddressIndicesIdx++) {
      monero_subaddress subaddress;
      subaddress.m_account_index = account_idx;
      uint32_t subaddress_idx = subaddress_indices.at(subaddressIndicesIdx);
      subaddress.m_index = subaddress_idx;
      subaddress.m_address = get_address(account_idx, subaddress_idx);
      subaddresses.push_back(subaddress);
    }

    return subaddresses;
  }

  std::string monero_wallet_keys::sign_message(const std::string& msg, monero_message_signature_type signature_type, uint32_t account_idx, uint32_t subaddress_idx) const {
    MTRACE("monero_wallet_keys::sign_message()");
    
    cryptonote::subaddress_index index = {account_idx, subaddress_idx};

    const cryptonote::account_keys &keys = m_account.get_keys();
    crypto::signature signature;
    crypto::secret_key skey, m;
    crypto::secret_key skey_spend, skey_view;
    crypto::public_key pkey;
    crypto::public_key pkey_spend, pkey_view; // to include both in hash
    crypto::hash hash;
    uint8_t mode;

    // Use the base address
    if (index.is_zero())
    {
      switch (signature_type)
      {
        case monero_message_signature_type::SIGN_WITH_SPEND_KEY:
          skey = keys.m_spend_secret_key;
          pkey = keys.m_account_address.m_spend_public_key;
          mode = 0;
          break;
        case monero_message_signature_type::SIGN_WITH_VIEW_KEY:
          skey = keys.m_view_secret_key;
          pkey = keys.m_account_address.m_view_public_key;
          mode = 1;
          break;
        default: throw std::runtime_error("Invalid signature type requested");
      }
      hash = get_message_hash(msg,keys.m_account_address.m_spend_public_key,keys.m_account_address.m_view_public_key,mode);
    }
    // Use a subaddress
    else
    {
      skey_spend = keys.m_spend_secret_key;
      m = m_account.get_device().get_subaddress_secret_key(keys.m_view_secret_key, index);
      sc_add((unsigned char*)&skey_spend, (unsigned char*)&m, (unsigned char*)&skey_spend);
      secret_key_to_public_key(skey_spend,pkey_spend);
      sc_mul((unsigned char*)&skey_view, (unsigned char*)&keys.m_view_secret_key, (unsigned char*)&skey_spend);
      secret_key_to_public_key(skey_view,pkey_view);
      switch (signature_type)
      {
        case monero_message_signature_type::SIGN_WITH_SPEND_KEY:
          skey = skey_spend;
          pkey = pkey_spend;
          mode = 0;
          break;
        case monero_message_signature_type::SIGN_WITH_VIEW_KEY:
          skey = skey_view;
          pkey = pkey_view;
          mode = 1;
          break;
        default: CHECK_AND_ASSERT_THROW_MES(false, "Invalid signature type requested");
      }
      secret_key_to_public_key(skey, pkey);
      hash = get_message_hash(msg,pkey_spend,pkey_view,mode);
    }
    crypto::generate_signature(hash, pkey, skey, signature);
    return std::string("SigV2") + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
  }

  monero_message_signature_result monero_wallet_keys::verify_message(const std::string& msg, const std::string& address, const std::string& signature) const {
    MTRACE("monero_wallet_keys::verify_message()");

    // validate and parse address or url
    cryptonote::address_parse_info info;
    std::string err = "Invalid address";
    if (!get_account_address_from_str_or_url(info, get_nettype(), address,
      [&err](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid) {
          err = std::string("Invalid DNSSEC for ") + url;
          return {};
        }
        if (addresses.empty()) {
          err = std::string("No Monero address found at ") + url;
          return {};
        }
        return addresses[0];
      }))
    {
      throw std::runtime_error(err);
    }
    monero_message_signature_result result;
    result.m_is_good = false;
    result.m_is_old = false;

    static const size_t v1_header_len = strlen("SigV1");
    static const size_t v2_header_len = strlen("SigV2");
    const bool v1 = signature.size() >= v1_header_len && signature.substr(0, v1_header_len) == "SigV1";
    const bool v2 = signature.size() >= v2_header_len && signature.substr(0, v2_header_len) == "SigV2";
    if (!v1 && !v2)
    {
      std::cout << "Signature header check error" << std::endl;
      return result;
    }
    crypto::hash hash;
    if (v1)
    {
      crypto::cn_fast_hash(msg.data(), msg.size(), hash);
    }
    std::string decoded;
    if (!tools::base58::decode(signature.substr(v1 ? v1_header_len : v2_header_len), decoded)) {
      MWARNING("Signature decoding error");
      return result;
    }
    crypto::signature s;
    if (sizeof(s) != decoded.size()) {
      std::cout << "Signature decoding error" << std::endl;
      return result;
    }
    memcpy(&s, decoded.data(), sizeof(s));

    // Test each mode and return which mode, if either, succeeded
    if (v2)
        hash = get_message_hash(msg,info.address.m_spend_public_key,info.address.m_view_public_key,(uint8_t) 0);
    if (crypto::check_signature(hash, info.address.m_spend_public_key, s))
    {
      result.m_is_good = true;
      result.m_signature_type = monero_message_signature_type::SIGN_WITH_SPEND_KEY;
      result.m_is_old = !v2;
      result.m_version = v1 ? 1u : 2u;
      return result;
    }

    if (v2)
        hash = get_message_hash(msg,info.address.m_spend_public_key,info.address.m_view_public_key,(uint8_t) 1);
    if (crypto::check_signature(hash, info.address.m_view_public_key, s))
    {
      result.m_is_good = true;
      result.m_signature_type = monero_message_signature_type::SIGN_WITH_VIEW_KEY;
      result.m_is_old = !v2;
      result.m_version = v1 ? 1u : 2u;
      return result;
    }

    // Both modes failed
    return result;  
  }

  std::string monero_wallet_keys::get_payment_uri(const monero_tx_config& config) const {
    MTRACE("get_payment_uri()");

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

    // make uri using wallet2
    std::string error;
    std::string uri = monero_utils::make_uri(address, get_nettype(), payment_id, amount, note, m_recipient_name, error);
    if (uri.empty()) throw std::runtime_error("Cannot make URI from supplied parameters: " + error);
    return uri;
  }

  std::shared_ptr<monero_tx_config> monero_wallet_keys::parse_payment_uri(const std::string& uri) const {
    MTRACE("parse_payment_uri(" << uri << ")");

    // decode uri to parameters
    std::string address;
    std::string payment_id;
    uint64_t amount = 0;
    std::string note;
    std::string m_recipient_name;
    std::vector<std::string> unknown_parameters;
    std::string error;
    if (!monero_utils::parse_uri(uri, address, get_nettype(), payment_id, amount, note, m_recipient_name, unknown_parameters, error)) {
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
    if (!m_recipient_name.empty()) config->m_recipient_name = m_recipient_name;
    if (!unknown_parameters.empty()) MWARNING("WARNING in monero_wallet_full::parse_payment_uri: URI contains unknown parameters which are discarded"); // TODO: return unknown parameters?
    return config;
  }

  std::string monero_wallet_keys::get_tx_key(const std::string& tx_hash) const {
    MTRACE("monero_wallet_light::get_tx_key()");

    // validate and parse tx hash
    crypto::hash _tx_hash;
    if (!epee::string_tools::hex_to_pod(tx_hash, _tx_hash)) {
      throw std::runtime_error("TX hash has invalid format");
    }

    // get tx key and additional keys
    crypto::secret_key _tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    if (!get_tx_key(_tx_hash, _tx_key, additional_tx_keys)) {
      throw std::runtime_error("No tx secret key is stored for this tx");
    }

    // build and return tx key with additional keys
    epee::wipeable_string s;
    s += epee::to_hex::wipeable_string(_tx_key);
    for (uint64_t i = 0; i < additional_tx_keys.size(); ++i) {
      s += epee::to_hex::wipeable_string(additional_tx_keys[i]);
    }
    return std::string(s.data(), s.size());
  }

  void monero_wallet_keys::close(bool save) {
    if (save) throw std::runtime_error("MoneroWalletKeys does not support saving");
    // no pointers to destroy
  }

  // ------------------------------- PRIVATE HELPERS ----------------------------

  /**
    * Generates a key image for an output note (enote) in a simplified manner.
    * This function already assumes that we checked that the onetime address was addressed to `received_subaddr`.
    * 
    * @param ephem_pubkey is the tx main pubkey or an additional pubkey
    * @param tx_output_index is the index of the enote in the local output set of the tx
    * @param received_subaddr is the index of the recipient's subaddress
    * @param ack recipient's account keys, including 
    * @param hwdev Hardware device used for cryptographic operations
    */
  std::pair<crypto::key_image, crypto::signature> generate_ki(const crypto::public_key &ephem_pubkey, const size_t tx_output_index, const cryptonote::subaddress_index &received_subaddr, const cryptonote::account_keys &ack, hw::device &hwdev) {
    // notation:
    //   - R: ephem_pubkey
    //   - a: ack.m_view_secret_key [private viewkey]
    //   - b: ack.m_spend_secret_key [private spendkey]
    //   - idx: tx_output_index
    //   - index_major: received_subaddr.major
    //   - index_minor: received_subaddr.minor
    //   - Hs() [hash-to-scalar]
    //   - Hp() [hash-to-point]

    // 1. Diffie-Helman derived secret D = a R
    crypto::key_derivation recv_derivation;
    CHECK_AND_ASSERT_THROW_MES(hwdev.generate_key_derivation(ephem_pubkey, ack.m_view_secret_key, recv_derivation),
      "Failed to perform Diffie-Helman exchange against tx ephem pubkey");

    // 2. Non-address-extended onetime key secret u = Hs(D || idx) + b
    crypto::secret_key onetime_privkey_unextended;
    hwdev.derive_secret_key(recv_derivation, tx_output_index, ack.m_spend_secret_key, onetime_privkey_unextended);

    // 3. Subaddress key extension s = Hs(a || index_major || index_minor) if is subaddress, else s = 0
    const crypto::secret_key subaddr_ext{received_subaddr.is_zero() ?
      crypto::secret_key{} : hwdev.get_subaddress_secret_key(ack.m_view_secret_key, received_subaddr)};

    // 4. Onetime address private key x = u + s
    crypto::secret_key onetime_privkey;
    hwdev.sc_secret_add(onetime_privkey, onetime_privkey_unextended, subaddr_ext);

    // 5. Onetime address K = x G
    crypto::public_key onetime_pubkey;
    CHECK_AND_ASSERT_THROW_MES(hwdev.secret_key_to_public_key(onetime_privkey, onetime_pubkey),
      "Failed to make public key");

    // 6. Key image I = x Hp(K)
    crypto::key_image ki;
    hwdev.generate_key_image(onetime_pubkey, onetime_privkey, ki);

    // sign the key image with the output secret key
    crypto::signature signature;
    std::vector<const crypto::public_key*> key_ptrs;
    key_ptrs.push_back(&ephem_pubkey);

    crypto::generate_ring_signature((const crypto::hash&)ki, ki, key_ptrs, onetime_privkey, 0, &signature);

    return std::make_pair(ki, signature);
  }

  std::pair<crypto::key_image, crypto::signature> monero_wallet_keys::generate_key_image_for_enote(const crypto::public_key &ephem_pubkey, const size_t tx_output_index, const cryptonote::subaddress_index &received_subaddr) const {
    if (is_view_only()) throw std::runtime_error("cannot generate key image: wallet is view only");
    return generate_ki(ephem_pubkey, tx_output_index, received_subaddr, m_account.get_keys(), m_account.get_device());
  }

  monero_key_image monero_wallet_keys::generate_key_image(const std::string &tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const {
    crypto::public_key tx_pub_key;
    string_tools::hex_to_pod(tx_public_key, tx_pub_key);

    return generate_key_image(tx_pub_key, out_index, received_subaddr);
  }

  monero_key_image monero_wallet_keys::generate_key_image(const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const {
    monero_key_image result;

    auto found = m_generated_key_images.get(tx_public_key, out_index, received_subaddr);
    if (found != nullptr) return *found;

    std::pair<crypto::key_image, crypto::signature> key_image = generate_key_image_for_enote(tx_public_key, out_index, received_subaddr);
    result.m_hex = string_tools::pod_to_hex(key_image.first);
    result.m_signature = string_tools::pod_to_hex(key_image.second);
    m_generated_key_images.set(std::make_shared<monero_key_image>(result), tx_public_key, out_index, received_subaddr);

    return result;
  }

  bool monero_wallet_keys::key_image_is_ours(const crypto::key_image &key_image, const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const {
    std::string ki = string_tools::pod_to_hex(key_image);    
    auto found = m_generated_key_images.get(tx_public_key, out_index, received_subaddr);

    if (found != nullptr) {
      return found->m_hex.get() == ki;
    };

    if (is_view_only()) return false;

    monero_key_image enote_key_image = generate_key_image(tx_public_key, out_index, received_subaddr);
    std::string enote_ki = enote_key_image.m_hex.get();

    if (ki == enote_ki) {
      return true;
    }

    return false;
  }

  bool monero_wallet_keys::key_image_is_ours(const std::string &key_image, const std::string& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const {
    crypto::key_image ki;
    crypto::public_key tx_pub_key;

    string_tools::hex_to_pod(key_image, ki);
    string_tools::hex_to_pod(tx_public_key, tx_pub_key);

    return key_image_is_ours(ki, tx_pub_key, out_index, received_subaddr);
  }

  std::string encrypt(const std::string &plaintext_str, const crypto::secret_key &skey, bool authenticated = true) {
    const char *plaintext = plaintext_str.data();
    size_t len = plaintext_str.size();
    crypto::chacha_key key;
    crypto::generate_chacha_key(&skey, sizeof(skey), key, 1);
    std::string ciphertext;
    crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
    ciphertext.resize(len + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
    crypto::chacha20(plaintext, len, key, iv, &ciphertext[sizeof(iv)]);
    memcpy(&ciphertext[0], &iv, sizeof(iv));
    if (authenticated)
    {
      crypto::hash hash;
      crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(crypto::signature), hash);
      crypto::public_key pkey;
      crypto::secret_key_to_public_key(skey, pkey);
      crypto::signature &signature = *(crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
      crypto::generate_signature(hash, pkey, skey, signature);
    }
    return ciphertext;
  }

  std::string monero_wallet_keys::encrypt_with_private_view_key(const std::string &plaintext, bool authenticated) const {
    return encrypt(plaintext, m_account.get_keys().m_view_secret_key, authenticated);
  }

  template<typename T=std::string>
  T decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated = true)
  {
    const size_t prefix_size = sizeof(crypto::chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
    if(ciphertext.size() < prefix_size) throw std::runtime_error("Unexpected ciphertext size");
    uint64_t kdf_rounds = 1;
    crypto::chacha_key key;
    crypto::generate_chacha_key(&skey, sizeof(skey), key, kdf_rounds);
    const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
    if (authenticated)
    {
      crypto::hash hash;
      crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(crypto::signature), hash);
      crypto::public_key pkey;
      crypto::secret_key_to_public_key(skey, pkey);
      const crypto::signature &signature = *(const crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
      if(!crypto::check_signature(hash, pkey, signature)) throw std::runtime_error("Failed to authenticate ciphertext");
    }
    std::unique_ptr<char[]> buffer{new char[ciphertext.size() - prefix_size]};
    auto wiper = epee::misc_utils::create_scope_leave_handler([&]() { memwipe(buffer.get(), ciphertext.size() - prefix_size); });
    crypto::chacha20(ciphertext.data() + sizeof(iv), ciphertext.size() - prefix_size, key, iv, buffer.get());
    return T(buffer.get(), ciphertext.size() - prefix_size);
  }

  std::string monero_wallet_keys::decrypt_with_private_view_key(const std::string &ciphertext, bool authenticated) const {
    return decrypt(ciphertext, m_account.get_keys().m_view_secret_key, authenticated);
  }

  std::vector<tools::wallet2::pending_tx> monero_wallet_keys::parse_signed_tx(const std::string &signed_tx_st) const {
    std::string s = signed_tx_st;
    tools::wallet2::signed_tx_set signed_txs;

    const size_t magiclen = strlen(SIGNED_TX_PREFIX) - 1;
    if (strncmp(s.c_str(), SIGNED_TX_PREFIX, magiclen))
    {
      throw std::runtime_error("Bad magic from signed transaction");
    }
    s = s.substr(magiclen);
    const char version = s[0];
    s = s.substr(1);
    if (version == '\003' || version == '\004')
    {
      throw std::runtime_error("Not loading deprecated format");
    }
    else if (version == '\005')
    {
      try { s = decrypt_with_private_view_key(s); }
      catch (const std::exception &e) { throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what()); }
      try
      {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
        if (!::serialization::serialize(ar, signed_txs))
        {
          throw std::runtime_error("Failed to deserialize signed transaction");
        }
      }
      catch (const std::exception &e)
      {
        throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what());
      }
    }
    else
    {
      throw std::runtime_error("Unsupported version in signed transaction");
    }
    
    LOG_PRINT_L0("Loaded signed tx data from binary: " << signed_txs.ptx.size() << " transactions");
    for (auto &c_ptx: signed_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));

    return signed_txs.ptx;
  }

  tools::wallet2::unsigned_tx_set monero_wallet_keys::parse_unsigned_tx(const std::string &unsigned_tx_st) const {
    tools::wallet2::unsigned_tx_set exported_txs;

    std::string s = unsigned_tx_st;
    const size_t magiclen = strlen(UNSIGNED_TX_PREFIX) - 1;
    if (strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen))
    {
      throw std::runtime_error("Bad magic from unsigned tx");
    }
    s = s.substr(magiclen);
    const char version = s[0];
    s = s.substr(1);
    if (version == '\003' || version == '\004')
    {
      throw std::runtime_error("Not loading deprecated format");
    }
    else if (version == '\005')
    {
      try { s = decrypt_with_private_view_key(s); }
      catch(const std::exception &e) { 
        std::string msg = std::string("Failed to decrypt unsigned tx: ") + e.what();
        throw std::runtime_error(msg); 
      }
      try
      {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
        if (!::serialization::serialize(ar, exported_txs))
        {
          throw std::runtime_error("Failed to parse data from unsigned tx");
        }
      }
      catch (...)
      {
        throw std::runtime_error("Failed to parse data from unsigned tx");
      }
    }
    else
    {
      throw std::runtime_error("Unsupported version in unsigned tx");
    }

    LOG_PRINT_L1("Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions");
  
    return exported_txs;
  }

  std::string monero_wallet_keys::dump_pending_tx(tools::wallet2::tx_construction_data &construction_data, const boost::optional<std::string>& payment_id) const {
    tools::wallet2::unsigned_tx_set txs;
    if (payment_id != boost::none && !payment_id->empty()) {
      crypto::hash8 _payment_id;

      if (!monero_utils::parse_short_payment_id(payment_id.get(), _payment_id)) throw std::runtime_error("invalid short payment id: " + payment_id.get());
      cryptonote::remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
      std::string extra_nonce;
      cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, _payment_id);
      if(!cryptonote::add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce)) throw std::runtime_error("Failed to add decrypted payment id to tx extra");
      LOG_PRINT_L0("Successfully decrypted payment ID: " << payment_id.get());
    }
    else {
      LOG_PRINT_L0("Payment ID not set");
    }

    //txs.txes.push_back(get_construction_data_with_decrypted_short_payment_id(tx, m_account.get_device()));
    txs.txes.push_back(construction_data);
    
    txs.new_transfers = export_outputs(false, 0);
    // save as binary
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    try
    {
      if (!::serialization::serialize(ar, txs))
        return std::string();
    }
    catch (...)
    {
      return std::string();
    }
    
    LOG_PRINT_L0("Saving unsigned tx data: " << oss.str());
    
    std::string ciphertext = encrypt_with_private_view_key(oss.str());
    return epee::string_tools::buff_to_hex_nodelimer(std::string(UNSIGNED_TX_PREFIX) + ciphertext);
  }

  wallet2_exported_outputs monero_wallet_keys::export_outputs(bool all, uint32_t start, uint32_t count) const {
    throw std::runtime_error("monero_wallet_keys::export_outputs(): not supported");
  }

  bool monero_wallet_keys::get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const {
    additional_tx_keys.clear();
    const std::unordered_map<crypto::hash, crypto::secret_key>::const_iterator i = m_tx_keys.find(txid);
    if (i == m_tx_keys.end())
      return false;
    tx_key = i->second;
    if (tx_key == crypto::null_skey)
      return false;
    const auto j = m_additional_tx_keys.find(txid);
    if (j != m_additional_tx_keys.end())
      additional_tx_keys = j->second;
    return true;
  }
  
  bool monero_wallet_keys::get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const {
    bool r = get_tx_key_cached(txid, tx_key, additional_tx_keys);
    if (r)
    {
      MDEBUG("tx key cached for txid: " << txid);
      return true;
    }

    auto& hwdev = m_account.get_device();

    // So far only Cold protocol devices are supported.
    if (hwdev.device_protocol() != hw::device::PROTOCOL_COLD)
    {
      return false;
    }

    auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
    CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");
    if (!dev_cold->is_get_tx_key_supported())
    {
      MDEBUG("get_tx_key not supported by the device");
      return false;
    }

    hw::device_cold::tx_key_data_t tx_key_data;
    std::string tx_hash = epee::string_tools::pod_to_hex(txid);
    tx_key_data.tx_prefix_hash = get_tx_prefix_hash(tx_hash);

    if (tx_key_data.tx_prefix_hash.empty()) return false;

    std::vector<crypto::secret_key> tx_keys;
    dev_cold->get_tx_key(tx_keys, tx_key_data, m_account.get_keys().m_view_secret_key);
    if (tx_keys.empty())
    {
      MDEBUG("Empty tx keys for txid: " << txid);
      return false;
    }

    if (tx_keys[0] == crypto::null_skey) return false;

    tx_key = tx_keys[0];
    tx_keys.erase(tx_keys.begin());
    additional_tx_keys = tx_keys;
    return true;
  }

  // implementation based on monero-project wallet2::sign_tx()
  std::string monero_wallet_keys::sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes, std::vector<std::string>& signed_kis) {
    const auto& subaddresses = m_subaddresses;

    // sign the transactions
    for (size_t n = 0; n < exported_txs.txes.size(); ++n)
    {
      tools::wallet2::tx_construction_data &sd = exported_txs.txes[n];
      if(sd.sources.empty()) throw std::runtime_error("empty sources");
      if(sd.unlock_time) throw std::runtime_error("unlock time is non-zero");
      LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size());
      signed_txes.ptx.push_back(tools::wallet2::pending_tx());
      tools::wallet2::pending_tx &ptx = signed_txes.ptx.back();
      rct::RCTConfig rct_config = sd.rct_config;
      crypto::secret_key tx_key;
      std::vector<crypto::secret_key> additional_tx_keys;
      
      bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), subaddresses, sd.sources, sd.splitted_dsts, sd.change_dts.addr, sd.extra, ptx.tx, tx_key, additional_tx_keys, sd.use_rct, rct_config, sd.use_view_tags);
      if(!r) throw std::runtime_error("tx not constructed");
      // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
      // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
      // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
      // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

      // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
      // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
      // to see that info, so we save it here
      if (tx_key != crypto::null_skey)
      {
        const crypto::hash txid = get_transaction_hash(ptx.tx);
        m_tx_keys[txid] = tx_key;
        m_additional_tx_keys[txid] = additional_tx_keys;
      }

      std::string key_images;
      bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
      {
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
    const auto &keys = m_account.get_keys();
    hw::device &hwdev = m_account.get_device();
    for (size_t n = 0; n < exported_txs.txes.size(); ++n)
    {
      const cryptonote::transaction &tx = signed_txes.ptx[n].tx;

      crypto::key_derivation derivation;
      std::vector<crypto::key_derivation> additional_derivations;

      // compute public keys from out secret keys
      crypto::public_key tx_pub_key;
      crypto::secret_key_to_public_key(txs[n].tx_key, tx_pub_key);
      std::vector<crypto::public_key> additional_tx_pub_keys;
      for (const crypto::secret_key &skey: txs[n].additional_tx_keys)
      {
        additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
        crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
      }

      // compute derivations
      hwdev.set_mode(hw::device::TRANSACTION_PARSE);
      if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
      {
        MWARNING("Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
      }
      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        additional_derivations.push_back({});
        if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back()))
        {
          MWARNING("Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
          memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
        }
      }

      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        crypto::public_key output_public_key;
        if (!get_output_public_key(tx.vout[i], output_public_key))
          continue;

        // if this output is back to this wallet, we can calculate its key image already
        if (!is_out_to_acc_precomp(subaddresses, output_public_key, derivation, additional_derivations, i, hwdev, get_output_view_tag(tx.vout[i])))
          continue;
        crypto::key_image ki;
        cryptonote::keypair in_ephemeral;
        if (cryptonote::generate_key_image_helper(keys, subaddresses, output_public_key, tx_pub_key, additional_tx_pub_keys, i, in_ephemeral, ki, hwdev))
          signed_txes.tx_key_images[output_public_key] = ki;
        else
          MERROR("Failed to calculate key image");
      }
    }

    // add key images
    signed_txes.key_images.resize(signed_kis.size());

    for (size_t i = 0; i < signed_kis.size(); ++i)
    {
      std::string& signed_ki = signed_kis[i];
      crypto::key_image ski;
      
      if (signed_ki.empty())
        LOG_PRINT_L0("WARNING: key image not known in signing wallet at index " << i);
      else epee::string_tools::hex_to_pod(signed_ki, ski);

      signed_txes.key_images[i] = ski;
    }

    // save as binary
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    try
    {
      if (!::serialization::serialize(ar, signed_txes))
        return std::string();
    }
    catch(...)
    {
      return std::string();
    }
    LOG_PRINT_L3("Saving signed tx data (with encryption): " << oss.str());
    std::string ciphertext = encrypt_with_private_view_key(oss.str());
    return std::string(SIGNED_TX_PREFIX) + ciphertext;
  }

  void monero_wallet_keys::init_common() {
    m_primary_address = m_account.get_public_address_str(static_cast<cryptonote::network_type>(m_network_type));
    const cryptonote::account_keys& keys = m_account.get_keys();
    m_pub_view_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_view_public_key);
    m_prv_view_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_view_secret_key)));
    m_pub_spend_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_spend_public_key);
    m_prv_spend_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_spend_secret_key)));
    if (m_prv_spend_key == "0000000000000000000000000000000000000000000000000000000000000000") m_prv_spend_key = "";
  }
}

