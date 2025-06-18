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

#include "monero_wallet.h"
#include "cryptonote_basic/account.h"
#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>

using namespace monero;

/**
 * Public library interface.
 */
namespace monero {
  class monero_key_image_cache {
  public:
    //const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr
    std::shared_ptr<monero_key_image> get(const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr);
    std::shared_ptr<monero_key_image> get(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx = 0, uint32_t subaddress_idx = 0);

    void set(std::shared_ptr<monero_key_image> key_image, const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr, bool requested = false);
    void set(std::shared_ptr<monero_key_image> key_image, const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx = 0, uint32_t subaddress_idx = 0, bool requested = false);

    bool request(const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr);
    bool request(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx, uint32_t subaddress_idx);
    void set_request(const std::string& tx_public_key, uint64_t out_index, uint32_t account_idx = 0, uint32_t subaddress_idx = 0, bool request = true);

  private:
    serializable_unordered_map<crypto::public_key, serializable_unordered_map<uint64_t, serializable_unordered_map<cryptonote::subaddress_index, std::pair<std::shared_ptr<monero_key_image>, bool> >>> m_cache;
    mutable boost::mutex m_mutex;
  };
  
  /**
   * Implements a Monero wallet to provide basic key management.
   */
  class monero_wallet_keys : public monero_wallet {

  public:

    // --------------------------- STATIC WALLET UTILS --------------------------

    /**
     * Create a new wallet with a randomly generated seed.
     *
     * @param config is the wallet configuration (network type and language)
     */
    static monero_wallet_keys* create_wallet_random(const monero_wallet_config& config);

    /**
     * Create a wallet from an existing mnemonic phrase or seed.
     *
     * @param config is the wallet configuration (network type, seed, seed offset, isMultisig)
     */
    static monero_wallet_keys* create_wallet_from_seed(const monero_wallet_config& config);

    /**
     * Create a wallet from an address, view key, and spend key.
     * 
     * @param config is the wallet configuration (network type, address, view key, spend key, language)
     */
    static monero_wallet_keys* create_wallet_from_keys(const monero_wallet_config& config);

    /**
     * Get a list of available languages for the wallet's seed.
     *
     * @return the available languages for the wallet's seed
     */
    static std::vector<std::string> get_seed_languages();

    // ----------------------------- WALLET METHODS -----------------------------

    /**
     * Destruct the wallet.
     */
    ~monero_wallet_keys();

    /**
     * Supported wallet methods.
     */
    bool is_view_only() const override { return m_is_view_only; }
    monero_version get_version() const override;
    monero_network_type get_network_type() const override { return m_network_type; }
    std::string get_seed() const override { return m_seed; }
    std::string get_seed_language() const override { return m_language; }
    std::string get_private_view_key() const override { return m_prv_view_key; }
    std::string get_private_spend_key() const override { return m_prv_spend_key; }
    std::string get_public_view_key() const override { return m_pub_view_key; }
    std::string get_public_spend_key() const override { return m_pub_spend_key; }
    std::string get_primary_address() const override { return m_primary_address; }
    std::string get_address(const uint32_t account_idx, const uint32_t subaddress_idx) const override;
    monero_integrated_address get_integrated_address(const std::string& standard_address = "", const std::string& payment_id = "") const override;
    monero_integrated_address decode_integrated_address(const std::string& integrated_address) const override;
    monero_account get_account(const uint32_t account_idx, bool include_subaddresses) const override;
    std::vector<monero_subaddress> get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const override;
    std::string sign_message(const std::string& msg, monero_message_signature_type signature_type, uint32_t account_idx = 0, uint32_t subaddress_idx = 0) const override;
    monero_message_signature_result verify_message(const std::string& msg, const std::string& address, const std::string& signature) const override;
    void close(bool save = false) override;

    // --------------------------------- PRIVATE --------------------------------

  protected:
    bool m_is_view_only;
    monero_network_type m_network_type;
    cryptonote::account_base m_account;
    std::string m_seed;
    std::string m_language;
    std::string m_pub_view_key;
    std::string m_prv_view_key;
    std::string m_pub_spend_key;
    std::string m_prv_spend_key;
    std::string m_primary_address;
    mutable monero_key_image_cache m_generated_key_images;

    virtual void init_common();
    cryptonote::network_type get_nettype() const { return m_network_type == monero_network_type::TESTNET ? cryptonote::network_type::TESTNET : m_network_type == monero_network_type::STAGENET ? cryptonote::network_type::STAGENET : cryptonote::network_type::MAINNET; };

    bool key_on_device() const;

    monero_key_image generate_key_image(const std::string &tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const;
    monero_key_image generate_key_image(const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const;
    std::pair<crypto::key_image, crypto::signature> generate_key_image_for_enote(const crypto::public_key &ephem_pubkey, const size_t tx_output_index, const cryptonote::subaddress_index &received_subaddr) const;
    bool key_image_is_ours(crypto::key_image &key_image, const crypto::public_key& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const;
    bool key_image_is_ours(std::string &key_image, const std::string& tx_public_key, uint64_t out_index, const cryptonote::subaddress_index &received_subaddr) const;

    std::string encrypt(const char *plaintext, size_t len, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const std::string &plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt_with_private_view_key(const std::string &plaintext, bool authenticated = true) const;

    template<typename T=std::string> T decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string decrypt_with_private_view_key(const std::string &ciphertext, bool authenticated = true) const;

  };
}
