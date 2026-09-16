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

#pragma once

#ifndef monero_wallet_utils_h
#define monero_wallet_utils_h

#include "monero_utils.h"
#include "wallet/wallet2.h"
#include "wallet/monero_wallet.h"

/**
 * Collection of utilities for the Monero wallet.
 */
namespace monero_wallet_utils
{

  // ------------------------------ CONSTANTS ---------------------------------

  static const uint64_t TAIL_EMISSION_REWARD = 600000000000;

  // -------------------------------- UTILS -----------------------------------

  typedef std::tuple<uint64_t, uint64_t, std::vector<tools::wallet2::exported_transfer_details>> wallet2_exported_outputs;

  /**
   * Convert a wallet2::pending_tx to a transaction in this library's
   * native model.
   *
   * @param cn_tx is the wallet2 pending transaction to convert
   * @param nettype cryptonote's network type
   * @param monero_wallet wallet that created the pending transaction
   * @param out_change_pubkey if non-null, receives the change output's stealth public key (hex), or an
   *        empty string if there was no change output. The change output is otherwise stripped out of
   *        the returned tx's outputs, so this is the only way to identify it unambiguously afterward
   *        (its amount alone isn't a safe identifier: another output could coincidentally match it).
   * @return a wallet transaction in this library's native model
   */
  std::shared_ptr<monero_tx_wallet> ptx_to_tx(const tools::wallet2::pending_tx &ptx, cryptonote::network_type nettype, monero_wallet* wallet, std::string* out_change_pubkey = nullptr);

  /**
   * Parse signed tx hex to wallet2's internal data model signed_tx_set.
   *
   * Based on wallet2::parse_tx_from_str().
   *
   * @param unsigned_tx_st unsigned tx hex
   * @param view_secret_key private view key
   * @return signed tx set from wallet2's internal data model
   */
  tools::wallet2::signed_tx_set parse_signed_tx(const std::string &signed_tx_st, const crypto::secret_key &view_secret_key);

  /**
   * Parse unsigned tx hex to wallet2's internal data model unsigned_tx_set.
   *
   * Based on wallet2::parse_unsigned_tx_from_str().
   *
   * @param unsigned_tx_st unsigned tx hex
   * @param view_secret_key private view key
   * @return unsigned tx set from wallet2's internal data model
   */
  tools::wallet2::unsigned_tx_set parse_unsigned_tx(const std::string &unsigned_tx_st, const crypto::secret_key &view_secret_key);

  /**
   * Dump wallet2's tx construction data.
   *
   * Based on wallet2::dump_tx_to_str().
   *
   * @param construction_data
   * @param paymend_id
   * @param outputs
   * @param view_secret_key
   * @return unsigned tx hex
   */
  std::string dump_unsigned_tx(std::vector<tools::wallet2::tx_construction_data>& construction_data, const boost::optional<std::string>& payment_id, const wallet2_exported_outputs& outputs, const crypto::secret_key &view_secret_key);

  /**
   * Returns a copy of ptx's construction data with its encrypted short (integrated address)
   * payment id nonce decrypted back to plaintext, if it carries one.
   *
   * Based on wallet2.cpp's get_construction_data_with_decrypted_short_payment_id().
   *
   * @param ptx is the pending tx whose construction data should be exported
   * @param hwdev is the account's device abstraction, used to decrypt the payment id
   * @return a copy of ptx.construction_data with its payment id nonce decrypted, if it had one
   */
  tools::wallet2::tx_construction_data get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev);

  /**
   * Signs wallet2's unsigned tx set with wallet account.
   *
   * Based on wallet2::sign_tx().
   *
   * @param exported_txs
   * @param txs
   * @param signed_txs
   * @param signed_kis
   * @param account
   * @param subaddresses
   * @return signed tx hex (ciphertext)
   */
  std::string sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes, std::vector<std::string> &signed_kis, const cryptonote::account_base& account, const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& subaddresses);

  /**
   * Estimate the network fee for a transaction with the given shape (v8 fork rule).
   *
   * Based on monero-project's wallet2::estimate_fee().
   *
   * @param n_inputs is the number of inputs the tx will spend
   * @param mixin is the ring size minus one (number of decoys per input)
   * @param n_outputs is the number of outputs the tx will create
   * @param extra_size is the size in bytes of the tx's "extra" field (e.g. tx pub key, payment id)
   * @param base_fee is the daemon's per-byte base fee
   * @param fee_multiplier scales the fee according to priority, see get_fee_multiplier()
   * @param fee_quantization_mask rounds the fee up to a multiple of this mask, see calculate_fee_from_weight()
   * @return the estimated fee in atomic units
   */
  uint64_t estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask);

  /**
   * Estimate the serialized size in bytes of a RingCT transaction with the given shape (v8 fork rule).
   *
   * Based on monero-project's wallet2.cpp estimate_rct_tx_size().
   *
   * @param n_inputs is the number of inputs the tx will spend
   * @param mixin is the ring size minus one (number of decoys per input)
   * @param n_outputs is the number of outputs the tx will create
   * @param extra_size is the size in bytes of the tx's "extra" field
   * @return the estimated tx size in bytes
   */
  size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size);

  /**
   * Compute a tx fee from its weight, quantized so the fee doesn't reveal the tx's exact weight (v8 fork rule).
   *
   * Based on monero-project's wallet2.cpp calculate_fee_from_weight().
   *
   * @param base_fee is the daemon's per-byte base fee
   * @param weight is the tx weight in bytes, see estimate_tx_weight()
   * @param fee_multiplier scales the fee according to priority, see get_fee_multiplier()
   * @param fee_quantization_mask rounds the fee up to a multiple of this mask
   * @return the quantized fee in atomic units
   */
  uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask);

  /**
   * Estimate the weight of a RingCT transaction with the given shape (v8 fork rule).
   *
   * Based on monero-project's wallet2.cpp estimate_tx_weight() v8 enforced.
   *
   * @param n_inputs is the number of inputs the tx will spend
   * @param mixin is the ring size minus one (number of decoys per input)
   * @param n_outputs is the number of outputs the tx will create
   * @param extra_size is the size in bytes of the tx's "extra" field
   * @return the estimated tx weight in bytes
   */
  uint64_t estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size);

  /**
   * Get the maximum tx weight allowed to be relayed by the network (v8 fork rule).
   *
   * Based on monero-project's wallet2::get_upper_transaction_weight_limit().
   *
   * @param default_limit overrides the computed limit when non-zero (default 0, i.e. not overridden)
   * @return the tx weight limit in bytes
   */
  uint64_t get_tx_weight_limit(uint64_t default_limit = 0);

  /**
   * Get the fee multiplier applied to the base fee for a given tx priority (fee algorithm 3).
   *
   * Based on monero-project's wallet2::get_fee_multiplier().
   *
   * @param priority is the tx priority: 1 (or 0, which defaults to 1) is normal, 2 is elevated, 3 is priority, 4 is flash
   * @return the fee multiplier for the given priority
   */
  uint64_t get_fee_multiplier(uint32_t priority);

  /**
   * Validates a cryptonote::transaction.
   *
   * @param cn_tx is the transaction to validate
   */
  void validate_cn_tx(const cryptonote::transaction &cn_tx);

  /**
   * Encode a payment id into a tx's "extra" field.
   *
   * Based on mymonero-core-cpp's monero_transfer_utils.cpp
   * internal helper _add_pid_to_tx_extra().
   *
   * @param payment_id_string is the payment id to encode, as a 16 or 64 char hex string; a none or empty value is a no-op
   * @param extra is the tx's extra field to append the encoded payment id nonce to
   * @throws std::runtime_error if payment_id_string is neither a valid long nor short payment id, or if it could not be added to extra
   */
  void add_pid_to_tx_extra(const boost::optional<std::string>& payment_id_string, std::vector<uint8_t> &extra);

  /**
   * Decrypt an output's hex-econded RingCT commitment mask.
   *
   * Based on mymonero-core-cpp's monero_transfer_utils.cpp
   * internal helper _rct_hex_to_decrypted_mask().
   *
   * @param rct_str is the output's hex-encoded rct field
   * @param view_secret_key is the wallet's private view key, used to derive the shared secret with the tx
   * @param tx_pub_key is the transaction's public key
   * @param internal_output_index is the output's index within the transaction, used as the derivation index
   * @param decrypted_mask is set to the output's decrypted commitment mask
   * @return true if a mask was resolved (including the non-RCT and coinbase cases), false if rct_str is empty
   * @throws std::runtime_error if rct_str carries a malformed encrypted mask, or if the key derivation fails
   */
  bool rct_hex_to_decrypted_mask(const std::string &rct_str, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask);

  /**
   * Parse a hex-encoded RingCT commitment.
   *
   * Based on mymonero-core-cpp's monero_transfer_utils.cpp
   * internal helper _rct_hex_to_rct_commit().
   *
   * @param rct_str is the output's hex-encoded rct field
   * @param rct_commit is set to the output's parsed commitment
   * @return true if a commitment was parsed, false otherwise
   * @throws std::runtime_error if the commitment substring is not valid hex
   */
  bool rct_hex_to_rct_commit(const std::string &rct_str, rct::key &rct_commit);

  /**
   * Indicates if a hex-encoded rct field describes a coinbase output,
   * validating its commitment via rct::zeroCommit() rather than trusted.
   *
   * 1. "coinbase" (mymonero/openmonero-style).
   * 2. "<commitment><mask><amount>", where the commitment is left zeroed
   * and the mask is the identity element.
   *
   * @param rct_str is the output's hex-encoded rct field
   * @return true if rct_str describes an unblinded coinbase output under either convention
   */
  bool is_rct_hex_unblinded_coinbase(const std::string &rct_str);

  /**
   * Normalize an unconfirmed transaction by clearing its outputs and incoming transfers.
   *
   * @param tx is the unconfirmed transaction to normalize
   */
  void normalize_unconfirmed_tx(const std::shared_ptr<monero_tx_wallet>& tx);

  /**
   * Encrypt a string with chacha20, optionally signing the result so tampering can be detected on decryption.
   *
   * Based on monero-project's wallet2::encrypt().
   *
   * @param plaintext_str is the data to encrypt
   * @param skey is the secret key used to derive the chacha20 key and, if authenticated, to sign the ciphertext
   * @param authenticated specifies if a signature is appended to the ciphertext to allow monero_wallet_utils::decrypt() to verify its integrity (default true)
   * @return the ciphertext, prefixed with a random chacha20 IV and, if authenticated, suffixed with a signature
   */
  std::string encrypt(const std::string &plaintext_str, const crypto::secret_key &skey, bool authenticated = true);

  /**
   * Decrypt a string previously encrypted with monero_wallet_utils::encrypt().
   *
   * Based on wallet2::decrypt().
   *
   * @tparam T is the type to return the decrypted data as (e.g. std::string), constructed from a (const char*, size_t) buffer
   * @param ciphertext is the encrypted data to decrypt, as produced by monero_wallet_utils::encrypt()
   * @param skey is the secret key used to derive the chacha20 key and, if authenticated, to verify the ciphertext's signature
   * @param authenticated specifies if the ciphertext carries a signature that must be verified before decrypting (default true); must match the value used to encrypt
   * @return T the decrypted data
   * @throws std::runtime_error if the ciphertext is smaller than the expected prefix, or if authenticated and its signature fails to verify
   */
  template<typename T=std::string>
  T decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated = true) {
    const size_t prefix_size = sizeof(crypto::chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
    if(ciphertext.size() < prefix_size) throw std::runtime_error("Unexpected ciphertext size");
    uint64_t kdf_rounds = 1;
    crypto::chacha_key key;
    crypto::generate_chacha_key(&skey, sizeof(skey), key, kdf_rounds);
    const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
    if (authenticated) {
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
}

#endif
