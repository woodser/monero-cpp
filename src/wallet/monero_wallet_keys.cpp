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
#include "common/monero_error.h"
#include <chrono>
#include <iostream>
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "common/base58.h"
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

  // ------------------------------- MONERO KEY IMAGE CACHE -------------------------------

  std::shared_ptr<monero_key_image> monero_key_image_cache::get(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx) {
    crypto::public_key _tx_public_key;
    string_tools::hex_to_pod(tx_public_key, _tx_public_key);
    cryptonote::subaddress_index received_subaddr{account_idx, subaddress_idx};

    boost::lock_guard<boost::mutex> lock(m_mutex);
    auto it_pubkey = m_cache.find(_tx_public_key);
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

  void monero_key_image_cache::set(const std::shared_ptr<monero_key_image>& key_image, const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx, bool request) {
    crypto::public_key _tx_public_key;
    string_tools::hex_to_pod(tx_public_key, _tx_public_key);
    cryptonote::subaddress_index received_subaddr{account_idx, subaddress_idx};

    boost::lock_guard<boost::mutex> lock(m_mutex);
    m_cache[_tx_public_key][out_index][received_subaddr] = std::make_pair(key_image, request);
  }

  bool monero_key_image_cache::request(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx) {
    crypto::public_key _tx_public_key;
    string_tools::hex_to_pod(tx_public_key, _tx_public_key);
    cryptonote::subaddress_index received_subaddr{account_idx, subaddress_idx};

    boost::lock_guard<boost::mutex> lock(m_mutex);
    auto it_pubkey = m_cache.find(_tx_public_key);
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

  // ------------------------------- INTERNAL PRIVATE HELPERS ----------------------------

  /**
   * Setup an address signature message-hash.
   * Hash data: domain separator, spend public key, view public key, mode identifier, payload data.
   *
   * Based on wallet2's internal private helper get_message_hash.
   * @param data message data to hash
   * @param spend_key public spend key
   * @param view_key public view key
   * @param mode message hash mode
   * @return the address signature message-hash
   */
  static crypto::hash get_message_hash(const std::string &data, const crypto::public_key &spend_key, const crypto::public_key &view_key, const uint8_t mode) {
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

  std::string monero_wallet_keys::get_private_spend_key() const {
    MTRACE("monero_wallet_keys::get_private_spend_key()");
    assert_not_closed();
    if (is_view_only()) throw std::runtime_error("The wallet is watch-only. Cannot retrieve spend key.");

    std::string spend_key = epee::string_tools::pod_to_hex(unwrap(unwrap(m_account.get_keys().m_spend_secret_key)));
    if (spend_key == "0000000000000000000000000000000000000000000000000000000000000000") spend_key = "";
    return spend_key;
  }

  std::string monero_wallet_keys::get_seed() const {
    MTRACE("monero_wallet_keys::get_seed()");
    assert_not_closed();
    if (is_view_only()) throw std::runtime_error("The wallet is watch-only. Cannot retrieve seed.");
    return m_seed;
  }

  std::string monero_wallet_keys::get_seed_language() const {
    assert_not_closed();
    if (is_view_only()) throw std::runtime_error("The wallet is watch-only. Cannot retrieve seed language.");
    return m_language;
  }

  std::vector<std::string> monero_wallet_keys::get_seed_languages() {
    std::vector<std::string> languages;
    crypto::ElectrumWords::get_language_list(languages, true);  // TODO: support getting names in language
    return languages;
  }

  // ----------------------------- WALLET METHODS -----------------------------

  monero_wallet_keys::~monero_wallet_keys() {
    MTRACE("~monero_wallet_keys()");
    close();
  }

  monero_version monero_wallet_keys::get_version() const {
    assert_not_closed();
    monero_version version;
    version.m_number = 65552; // same as monero-wallet-rpc v0.15.0.1 release
    version.m_is_release = false; // TODO: could pull from MONERO_VERSION_IS_RELEASE in version.cpp
    return version;
  }

  std::string monero_wallet_keys::get_address(uint32_t account_idx, uint32_t subaddress_idx) const {
    assert_not_closed();
    hw::device &hwdev = m_account.get_device();
    cryptonote::subaddress_index index{account_idx, subaddress_idx};
    cryptonote::account_public_address address = hwdev.get_subaddress(m_account.get_keys(), index);
    return cryptonote::get_account_address_as_str(static_cast<cryptonote::network_type>(m_network_type), !index.is_zero(), address);
  }

  monero_integrated_address monero_wallet_keys::get_integrated_address(const std::string& standard_address, const std::string& payment_id) const {
    MTRACE("monero_wallet_keys::get_integrated_address()");
    assert_not_closed();

    // randomly generate payment id if not given, else validate
    crypto::hash8 payment_id_h8;
    if (payment_id.empty()) payment_id_h8 = crypto::rand<crypto::hash8>();
    else if (!monero_utils::parse_short_payment_id(payment_id, payment_id_h8)) throw std::runtime_error("Invalid payment ID: " + payment_id);

    // use primary address if standard address not given, else validate
    if (standard_address.empty()) {
      hw::device &hwdev = m_account.get_device();
      cryptonote::subaddress_index index{0, 0};
      cryptonote::account_public_address address = hwdev.get_subaddress(m_account.get_keys(), index);
      return decode_integrated_address(cryptonote::get_account_integrated_address_as_str(m_nettype, address, payment_id_h8));
    } else {
      // validate standard address
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, m_nettype, standard_address)) throw std::runtime_error("Invalid address");
      if (info.is_subaddress) throw std::runtime_error("Subaddress shouldn't be used");
      if (info.has_payment_id) throw std::runtime_error("Already integrated address");
      if (payment_id.empty()) throw std::runtime_error("Payment ID shouldn't be left unspecified");

      // create integrated address from given standard address
      return decode_integrated_address(cryptonote::get_account_integrated_address_as_str(m_nettype, info.address, payment_id_h8));
    }
  }

  // TODO this logic is based on monero_wallet_full::decode_integrated_address(), refactory code?
  monero_integrated_address monero_wallet_keys::decode_integrated_address(const std::string& integrated_address) const {
    MTRACE("monero_wallet_keys::decode_integrated_address()");
    assert_not_closed();

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, m_nettype, integrated_address)) throw std::runtime_error("Invalid address");
    if (!info.has_payment_id) throw std::runtime_error("Address is not an integrated address");

    cryptonote::account_public_address address = info.address;
    monero_integrated_address result;
    result.m_integrated_address = integrated_address;
    result.m_standard_address = cryptonote::get_account_address_as_str(m_nettype, info.is_subaddress, address);
    result.m_payment_id = string_tools::pod_to_hex(info.payment_id);

    return result;
  }

  monero_account monero_wallet_keys::get_account(uint32_t account_idx, bool include_subaddresses) const {
    MTRACE("monero_wallet_keys::get_account()");
    assert_not_closed();

    if (include_subaddresses) {
      std::string err = "monero_wallet_keys::get_account(account_idx, include_subaddresses) include_subaddresses must be false";
      MERROR(err);
      throw std::runtime_error(err);
    }

    // build and return account
    monero_account account;
    account.m_index = account_idx;
    account.m_primary_address = get_address(account_idx, 0);
    return account;
  }

  std::vector<monero_subaddress> monero_wallet_keys::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    assert_not_closed();

    // must provide subaddress indices
    if (subaddress_indices.empty()) {
      std::string err = "Keys-only wallet does not have enumerable set of subaddresses; specific specific subaddresses";
      MERROR(err);
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

  // implementation based on monero-project's wallet2::sign()
  std::string monero_wallet_keys::sign_message(const std::string& msg, monero_message_signature_type signature_type, uint32_t account_idx, uint32_t subaddress_idx) const {
    MTRACE("monero_wallet_keys::sign_message()");
    assert_not_closed();

    // Sign a message with a private key from either the base address or a subaddress
    // The signature is also bound to both keys and the signature mode (spend, view) to prevent unintended reuse
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
    if (index.is_zero()) {
      switch (signature_type) {
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
    else {
      // Use a subaddress
      skey_spend = keys.m_spend_secret_key;
      m = m_account.get_device().get_subaddress_secret_key(keys.m_view_secret_key, index);
      sc_add((unsigned char*)&skey_spend, (unsigned char*)&m, (unsigned char*)&skey_spend);
      secret_key_to_public_key(skey_spend,pkey_spend);
      sc_mul((unsigned char*)&skey_view, (unsigned char*)&keys.m_view_secret_key, (unsigned char*)&skey_spend);
      secret_key_to_public_key(skey_view,pkey_view);
      switch (signature_type) {
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

  // implementation based on monero-project's wallet2::verify()
  monero_message_signature_result monero_wallet_keys::verify_message(const std::string& msg, const std::string& address, const std::string& signature) const {
    MTRACE("monero_wallet_keys::verify_message()");
    assert_not_closed();

    // validate and parse address or url
    cryptonote::address_parse_info info;
    std::string err = "Invalid address";
    if (!get_account_address_from_str_or_url(info, m_nettype, address,
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
      })) {
      throw monero_error(err);
    }

    monero_message_signature_result result;
    result.m_is_good = false;
    result.m_is_old = false;
    result.m_version = 0;
    result.m_signature_type = monero_message_signature_type::SIGN_WITH_SPEND_KEY;

    static const size_t v1_header_len = strlen("SigV1");
    static const size_t v2_header_len = strlen("SigV2");
    const bool v1 = signature.size() >= v1_header_len && signature.substr(0, v1_header_len) == "SigV1";
    const bool v2 = signature.size() >= v2_header_len && signature.substr(0, v2_header_len) == "SigV2";
    if (!v1 && !v2) {
      MWARNING("Signature header check error");
      return result;
    }
    crypto::hash hash;
    if (v1) crypto::cn_fast_hash(msg.data(), msg.size(), hash);
    std::string decoded;
    if (!tools::base58::decode(signature.substr(v1 ? v1_header_len : v2_header_len), decoded)) {
      MWARNING("Signature decoding error");
      return result;
    }
    crypto::signature s;
    if (sizeof(s) != decoded.size()) {
      MWARNING("Signature decoding error");
      return result;
    }
    memcpy(&s, decoded.data(), sizeof(s));

    // Test each mode and return which mode, if either, succeeded
    if (v2) hash = get_message_hash(msg,info.address.m_spend_public_key,info.address.m_view_public_key,(uint8_t) 0);
    if (crypto::check_signature(hash, info.address.m_spend_public_key, s)) {
      result.m_is_good = true;
      result.m_signature_type = monero_message_signature_type::SIGN_WITH_SPEND_KEY;
      result.m_is_old = !v2;
      result.m_version = v1 ? 1u : 2u;
      return result;
    }

    if (v2) hash = get_message_hash(msg,info.address.m_spend_public_key,info.address.m_view_public_key,(uint8_t) 1);
    if (crypto::check_signature(hash, info.address.m_view_public_key, s)) {
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
    assert_not_closed();

    // validate config
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (destinations.size() != 1) throw std::runtime_error("Cannot make URI from supplied parameters: must provide exactly one destination to send funds");
    if (destinations.at(0)->m_address == boost::none) throw std::runtime_error("Cannot make URI from supplied parameters: must provide destination address");
    if (destinations.at(0)->m_amount == boost::none) throw std::runtime_error("Cannot make URI from supplied parameters: must provide destination amount");

    // prepare make uri params
    std::string address = destinations.at(0)->m_address.get();
    std::string payment_id = config.m_payment_id == boost::none ? "" : config.m_payment_id.get();
    uint64_t amount = destinations.at(0)->m_amount.get();
    std::string note = config.m_note == boost::none ? "" : config.m_note.get();
    std::string m_recipient_name = config.m_recipient_name == boost::none ? "" : config.m_recipient_name.get();

    // make uri using monero_utils
    try { return monero_utils::make_uri(address, m_network_type, payment_id, amount, note, m_recipient_name); }
    catch (const std::exception& ex) { throw std::runtime_error(std::string("Cannot make URI from supplied parameters: ") + ex.what()); }
  }

  std::shared_ptr<monero_tx_config> monero_wallet_keys::parse_payment_uri(const std::string& uri) const {
    MTRACE("parse_payment_uri(" << uri << ")");
    assert_not_closed();

    // decode uri to parameters
    std::string address;
    std::string payment_id;
    uint64_t amount = 0;
    std::string note;
    std::string m_recipient_name;
    std::vector<std::string> unknown_parameters;
    std::string error;
    if (!monero_utils::parse_uri(uri, address, m_network_type, payment_id, amount, note, m_recipient_name, unknown_parameters, error)) {
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

  void monero_wallet_keys::close(bool save) {
    if (save) throw std::runtime_error("MoneroWalletKeys does not support saving");
    // no pointers to destroy
    m_is_closed = true;
  }

  void monero_wallet_keys::assert_not_closed() const {
    if (is_closed()) throw std::runtime_error("Wallet is closed");
  }

  // ------------------------------- PRIVATE HELPERS ----------------------------

  std::shared_ptr<monero_key_image> monero_wallet_keys::generate_key_image(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx) const {
    auto found = m_key_image_cache->get(tx_public_key, out_index, account_idx, subaddress_idx);
    if (found != nullptr) return found;

    if (is_view_only()) throw std::runtime_error("Cannot generate key image: wallet is view only");
    crypto::public_key tx_pub_key;
    string_tools::hex_to_pod(tx_public_key, tx_pub_key);
    cryptonote::subaddress_index received_subaddr{account_idx, subaddress_idx};
    std::shared_ptr<monero_key_image> key_image = monero_utils::generate_key_image(tx_pub_key, out_index, received_subaddr, m_account);
    m_key_image_cache->set(key_image, tx_public_key, out_index, account_idx, subaddress_idx);
    return key_image;
  }

  bool monero_wallet_keys::is_key_image_ours(const std::string &key_image_hex, const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx) const {
    std::shared_ptr<monero_key_image> cached_key_image = m_key_image_cache->get(tx_public_key, out_index, account_idx, subaddress_idx);
    if (cached_key_image != nullptr) return cached_key_image->m_hex.get() == key_image_hex;
    if (is_view_only()) return false;
    std::shared_ptr<monero_key_image> key_image = generate_key_image(tx_public_key, out_index, account_idx, subaddress_idx);
    return key_image_hex == key_image->m_hex.get();
  }

  void monero_wallet_keys::init_common() {
    m_nettype = static_cast<cryptonote::network_type>(m_network_type);
    m_primary_address = m_account.get_public_address_str(m_nettype);
    const cryptonote::account_keys& keys = m_account.get_keys();
    m_pub_view_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_view_public_key);
    m_prv_view_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_view_secret_key)));
    m_pub_spend_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_spend_public_key);
    m_prv_spend_key = epee::string_tools::pod_to_hex(unwrap(unwrap(keys.m_spend_secret_key)));
    m_key_image_cache = std::make_shared<monero_key_image_cache>();
    if (m_prv_spend_key == "0000000000000000000000000000000000000000000000000000000000000000") m_prv_spend_key = "";
    m_is_closed = false;
  }
}
