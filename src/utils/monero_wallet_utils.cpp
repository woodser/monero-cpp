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

#include "monero_wallet_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "string_tools.h"
#include "byte_stream.h"
#include "gen_utils.h"

#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\005"
#define SIGNED_TX_PREFIX "Monero signed tx set\005"

std::shared_ptr<monero_tx_wallet> monero_wallet_utils::ptx_to_tx(const tools::wallet2::pending_tx &ptx, cryptonote::network_type nettype, monero_wallet* wallet, std::string* out_change_pubkey) {
  if (out_change_pubkey != nullptr) *out_change_pubkey = "";
  const auto &cn_tx = ptx.tx;
  const auto &cd = ptx.construction_data;
  std::shared_ptr<monero_tx_wallet> tx = std::dynamic_pointer_cast<monero_tx_wallet>(monero_utils::cn_tx_to_tx(cn_tx, true));
  tx->m_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(cn_tx));
  tx->m_relay = true;
  tx->m_is_relayed = true;
  tx->m_is_confirmed = false;
  tx->m_in_tx_pool = true;
  tx->m_is_miner_tx = false;
  tx->m_is_locked = true;
  tx->m_num_confirmations = 0;
  tx->m_is_failed = false;
  tx->m_ring_size = monero_utils::RING_SIZE;
  tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
  tx->m_is_double_spend_seen = false;
  try { tx->m_prunable_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_prunable_hash(cn_tx)); }
  catch (...) { tx->m_prunable_hash = boost::none; }
  tx->m_is_outgoing = false;
  tx->m_fee = ptx.fee;

  // dump wallet2 pending tx
  try {
    std::ostringstream oss;
    boost::archive::portable_binary_oarchive ar(oss);
    ar << ptx;
    tx->m_metadata = epee::string_tools::buff_to_hex_nodelimer(oss.str());
  } catch (...) {
    tx->m_metadata = "";
  }

  tx->m_weight = cryptonote::get_transaction_weight(cn_tx);
  tx->m_change_amount = cd.change_dts.amount;
  tx->m_change_address = cryptonote::get_account_address_as_str(nettype, cd.subaddr_account > 0, cd.change_dts.addr);

  uint32_t sender_account_idx = cd.subaddr_account;
  // cd.subaddr_indices is the deduplicated set of subaddresses used, not one entry per input, and
  // construct_tx_and_get_tx_key() reorders sources/tx.vin by key image, so position doesn't match
  // selection order either. Approximate with the smallest used index; callers with a real per-input
  // lookup (monero_wallet_light's create_txs()/sweep_account()) overwrite m_subaddress_index after.
  size_t i = 0;
  for (const auto& in : tx->m_inputs) {
    auto input = std::dynamic_pointer_cast<monero_output_wallet>(in);
    uint32_t subaddress_idx = cd.subaddr_indices.empty() ? 0 : *next(cd.subaddr_indices.begin(), std::min(i, cd.subaddr_indices.size() - 1));
    input->m_account_index = sender_account_idx;
    input->m_subaddress_index = subaddress_idx;
    input->m_is_spent = true;
    input->m_is_frozen = false;
    i++;
  }

  std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
  outgoing_transfer->m_tx = tx;
  tx->m_outgoing_transfer = outgoing_transfer;
  outgoing_transfer->m_account_index = sender_account_idx;
  outgoing_transfer->m_subaddress_indices = std::vector<uint32_t>(cd.subaddr_indices.begin(), cd.subaddr_indices.end());

  std::shared_ptr<monero_output_wallet> change_output = nullptr;
  std::vector<std::shared_ptr<monero_output_wallet>> external_outputs;

  uint64_t out_amount = 0;
  i = 0;

  std::map<uint32_t, std::map<uint32_t, std::vector<std::shared_ptr<monero_destination>>>> destination_index;
  std::vector<std::shared_ptr<monero_destination>> external_destinations;

  for (const auto& out : tx->m_outputs) {
    auto output = std::dynamic_pointer_cast<monero_output_wallet>(out);
    if (output == nullptr) {
      i++;
      continue;
    }

    if (i >= cd.splitted_dsts.size()) {
      out_amount += output->m_amount.get();
      external_outputs.push_back(output);
      i++;
      continue;
    }

    const auto &dest = cd.splitted_dsts[i];
    out->m_amount = dest.amount;
    out->m_index = i;

    crypto::hash payment_id = crypto::null_hash;
    std::string dest_address = dest.address(nettype, payment_id);

    try {
      monero_subaddress subaddress = wallet->get_address_index(dest_address);
      uint32_t receiver_account_idx = subaddress.m_account_index.get();
      uint32_t subaddress_idx = subaddress.m_index.get();
      output->m_account_index = receiver_account_idx;
      output->m_subaddress_index = subaddress_idx;
      output->m_is_spent = false;
      output->m_is_frozen = false;
      bool is_change = cd.change_dts.amount > 0 && dest.addr == cd.change_dts.addr && dest.amount == cd.change_dts.amount && change_output == nullptr;
      if (is_change) {
        change_output = output;
      }
      if (!is_change) {
        out_amount += output->m_amount.get();
        auto transfer = std::make_shared<monero_incoming_transfer>();
        transfer->m_tx = tx;
        transfer->m_amount = output->m_amount;
        transfer->m_address = dest_address;
        transfer->m_account_index = receiver_account_idx;
        transfer->m_subaddress_index = subaddress_idx;
        transfer->m_num_suggested_confirmations = 10;
        tx->m_incoming_transfers.push_back(transfer);
        auto destination = std::make_shared<monero_destination>();
        destination->m_amount = dest.amount;
        destination->m_address = dest_address;
        destination_index[receiver_account_idx][subaddress_idx].push_back(destination);
      }
    }
    catch (...) {
      // external output
      out_amount += output->m_amount.get();
      external_outputs.push_back(output);
      if (dest.amount > 0) {
        auto destination = std::make_shared<monero_destination>();
        destination->m_amount = dest.amount;
        destination->m_address = dest_address;
        external_destinations.push_back(destination);
      }
    }
    i++;
  }

  tx->m_is_incoming = !tx->m_incoming_transfers.empty();
  tx->m_is_outgoing = tx->m_outgoing_transfer != nullptr;

  if (change_output != nullptr) {
    if (out_change_pubkey != nullptr) *out_change_pubkey = change_output->m_stealth_public_key.value_or("");
    tx->m_outputs.erase(
      std::remove(tx->m_outputs.begin(), tx->m_outputs.end(), change_output),
      tx->m_outputs.end()
    );
  }

  for(const auto& ext_out : external_outputs) {
    tx->m_outputs.erase(
      std::remove(tx->m_outputs.begin(), tx->m_outputs.end(), ext_out),
      tx->m_outputs.end()
    );

    auto ext_output = std::make_shared<monero_output_wallet>();
    ext_output->m_tx = tx; // required by monero_utils::vout_before()/tx_height_less_than(), which assume every tx output has its tx set
    ext_output->m_stealth_public_key = ext_out->m_stealth_public_key;
    ext_output->m_index = ext_out->m_index;
    ext_output->m_amount = ext_out->m_amount;
    tx->m_outputs.push_back(ext_output);
  }

  outgoing_transfer->m_amount = out_amount;

  sort(tx->m_outputs.begin(), tx->m_outputs.end(), monero_utils::vout_before);
  sort(tx->m_incoming_transfers.begin(), tx->m_incoming_transfers.end(), monero_utils::incoming_transfer_before);

  // order destinations
  for(const auto &kv_index : destination_index) {
    for(const auto  &kv : kv_index.second) {
      for (const auto& destination : kv.second) outgoing_transfer->m_destinations.push_back(destination);
    }
  }
  for (const auto& destination : external_destinations) {
    outgoing_transfer->m_destinations.push_back(destination);
  }

  return tx;
}

tools::wallet2::signed_tx_set monero_wallet_utils::parse_signed_tx(const std::string &signed_tx_st, const crypto::secret_key &view_secret_key) {
  std::string s = signed_tx_st;
  tools::wallet2::signed_tx_set signed_txs;

  const size_t magiclen = strlen(SIGNED_TX_PREFIX) - 1;
  if (strncmp(s.c_str(), SIGNED_TX_PREFIX, magiclen)) throw std::runtime_error("Bad magic from signed transaction");
  s = s.substr(magiclen);
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003' || version == '\004') throw std::runtime_error("Not loading deprecated format");
  else if (version == '\005') {
    try {
      // decrypt with private view key
      s = monero_wallet_utils::decrypt(s, view_secret_key);
    }
    catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what());
    }
    try {
      binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
      if (!::serialization::serialize(ar, signed_txs)) throw std::runtime_error("Failed to deserialize signed transaction");
    }
    catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what());
    }
  }
  else throw std::runtime_error("Unsupported version in signed transaction");

  LOG_PRINT_L0("Loaded signed tx data from binary: " << signed_txs.ptx.size() << " transactions");
  for (auto &c_ptx: signed_txs.ptx) LOG_PRINT_L2(cryptonote::obj_to_json_str(c_ptx.tx));

  return signed_txs;
}

tools::wallet2::unsigned_tx_set monero_wallet_utils::parse_unsigned_tx(const std::string &unsigned_tx_st, const crypto::secret_key &view_secret_key) {
  tools::wallet2::unsigned_tx_set exported_txs;

  std::string s = unsigned_tx_st;
  const size_t magiclen = strlen(UNSIGNED_TX_PREFIX) - 1;
  if (strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen)) throw std::runtime_error("Bad magic from unsigned tx");
  s = s.substr(magiclen);
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003' || version == '\004') throw std::runtime_error("Not loading deprecated format");
  else if (version == '\005') {
    try {
      // decrypt with private view key
      s = monero_wallet_utils::decrypt(s, view_secret_key);
    }
    catch(const std::exception &e) {
      throw std::runtime_error(std::string("Failed to decrypt unsigned tx: ") + e.what());
    }
    try {
      binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
      if (!::serialization::serialize(ar, exported_txs)) throw std::runtime_error("Failed to parse data from unsigned tx");
    }
    catch (...) {
      throw std::runtime_error("Failed to parse data from unsigned tx");
    }
  }
  else throw std::runtime_error("Unsupported version in unsigned tx");

  LOG_PRINT_L1("Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions");

  return exported_txs;
}

std::string monero_wallet_utils::dump_unsigned_tx(std::vector<tools::wallet2::tx_construction_data>& construction_data, const boost::optional<std::string>& payment_id, const wallet2_exported_outputs& outputs, const crypto::secret_key &view_secret_key) {
  tools::wallet2::unsigned_tx_set txs;
  if (payment_id == boost::none || payment_id->empty()) LOG_PRINT_L0("Payment ID not set");

  txs.txes = construction_data;
  txs.new_transfers = outputs;

  // save as binary
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  try { if (!::serialization::serialize(ar, txs)) return std::string(); }
  catch (...) { return std::string(); }
  LOG_PRINT_L2("Saving unsigned tx data (" << static_cast<std::streamoff>(oss.tellp()) << " bytes)");

  // encrypt with private view key
  std::string ciphertext = monero_wallet_utils::encrypt(oss.str(), view_secret_key);
  return epee::string_tools::buff_to_hex_nodelimer(std::string(UNSIGNED_TX_PREFIX) + ciphertext);
}

tools::wallet2::tx_construction_data monero_wallet_utils::get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev) {
  tools::wallet2::tx_construction_data construction_data = ptx.construction_data;

  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  cryptonote::parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  cryptonote::tx_extra_nonce extra_nonce;
  if (cryptonote::find_tx_extra_field_by_type(tx_extra_fields, extra_nonce)) {
    crypto::hash8 payment_id = crypto::null_hash8;
    if (cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id)) {
      const crypto::public_key view_key_pub = cryptonote::get_destination_view_key_pub(construction_data.splitted_dsts, construction_data.change_dts.addr);
      if (view_key_pub == crypto::null_pkey) {
        MWARNING("Encrypted payment id found, but no unique destination public key, cannot decrypt");
      }
      else if (hwdev.decrypt_payment_id(payment_id, view_key_pub, ptx.tx_key)) {
        // remove encrypted
        cryptonote::remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
        // add decrypted
        std::string decrypted_extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(decrypted_extra_nonce, payment_id);
        if (!cryptonote::add_extra_nonce_to_tx_extra(construction_data.extra, decrypted_extra_nonce)) throw std::runtime_error("Failed to add decrypted payment id to tx extra");
        LOG_PRINT_L1("Decrypted payment ID: " << payment_id);
      }
    }
  }

  return construction_data;
}

std::string monero_wallet_utils::sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes, std::vector<std::string>& signed_kis, const cryptonote::account_base& account, const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& subaddresses) {
  // sign the transactions
  for (size_t n = 0; n < exported_txs.txes.size(); ++n) {
    tools::wallet2::tx_construction_data &sd = exported_txs.txes[n];
    if(sd.sources.empty()) throw std::runtime_error("empty sources");
    if(sd.unlock_time) throw std::runtime_error("unlock time is non-zero");
    LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size());
    signed_txes.ptx.push_back(tools::wallet2::pending_tx());
    tools::wallet2::pending_tx &ptx = signed_txes.ptx.back();
    rct::RCTConfig rct_config = sd.rct_config;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;

    bool r = cryptonote::construct_tx_and_get_tx_key(account.get_keys(), subaddresses, sd.sources, sd.splitted_dsts, sd.change_dts.addr, sd.extra, ptx.tx, tx_key, additional_tx_keys, sd.use_rct, rct_config, sd.use_view_tags);
    if(!r) throw std::runtime_error("tx not constructed");
    // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
    // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
    // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
    // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

    // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
    // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
    // to see that info, so we save it here

    std::string key_images;
    bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool {
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
  const auto &keys = account.get_keys();
  hw::device &hwdev = account.get_device();
  for (size_t n = 0; n < exported_txs.txes.size(); ++n) {
    const cryptonote::transaction &tx = signed_txes.ptx[n].tx;

    crypto::key_derivation derivation;
    std::vector<crypto::key_derivation> additional_derivations;

    // compute public keys from out secret keys
    crypto::public_key tx_pub_key;
    crypto::secret_key_to_public_key(txs[n].tx_key, tx_pub_key);
    std::vector<crypto::public_key> additional_tx_pub_keys;
    for (const crypto::secret_key &skey : txs[n].additional_tx_keys) {
      additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
      crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
    }

    // compute derivations
    hwdev.set_mode(hw::device::TRANSACTION_PARSE);
    if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation)) {
      MWARNING("Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
      static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
      memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
    }
    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i) {
      additional_derivations.push_back({});
      if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back())) {
        MWARNING("Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
        memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
      }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i) {
      crypto::public_key output_public_key;
      if (!get_output_public_key(tx.vout[i], output_public_key)) continue;
      // if this output is back to this wallet, we can calculate its key image already
      if (!is_out_to_acc_precomp(subaddresses, output_public_key, derivation, additional_derivations, i, hwdev, get_output_view_tag(tx.vout[i]))) continue;

      crypto::key_image ki;
      cryptonote::keypair in_ephemeral;
      if (cryptonote::generate_key_image_helper(keys, subaddresses, output_public_key, tx_pub_key, additional_tx_pub_keys, i, in_ephemeral, ki, hwdev)) signed_txes.tx_key_images[output_public_key] = ki;
      else MERROR("Failed to calculate key image");
    }
  }

  // add key images
  signed_txes.key_images.resize(signed_kis.size());
  for (size_t i = 0; i < signed_kis.size(); ++i) {
    std::string& signed_ki = signed_kis[i];
    crypto::key_image ski{};
    if (signed_ki.empty()) LOG_PRINT_L0("WARNING: key image not known in signing wallet at index " << i);
    else epee::string_tools::hex_to_pod(signed_ki, ski);
    signed_txes.key_images[i] = ski;
  }

  // save as binary
  std::ostringstream oss;
  binary_archive<true> ar(oss);
  try { if (!::serialization::serialize(ar, signed_txes)) return std::string(); }
  catch(...) { return std::string(); }
  LOG_PRINT_L3("Saving signed tx data (with encryption): " << oss.str());

  // encrypt with private view key
  std::string ciphertext = monero_wallet_utils::encrypt(oss.str(), keys.m_view_secret_key);
  return std::string(SIGNED_TX_PREFIX) + ciphertext;
}

uint64_t monero_wallet_utils::estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
  const size_t estimated_tx_weight = estimate_tx_weight(n_inputs, mixin, n_outputs, extra_size);
  return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
}

uint64_t monero_wallet_utils::get_fee_multiplier(uint32_t priority) {
  // v8 enforced fee algorithm 3
  if (priority == 2) return 5;
  if (priority == 3) return 25;
  if (priority == 4) return 1000;
  return 1;
}

size_t monero_wallet_utils::estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size) {
  size_t size = 1 + 6; // tx prefix first few bytes
  size += n_inputs * (1+6+(mixin+1)*2+32); // vin
  size += n_outputs * (6+32); // vuout
  size += extra_size; // extra
  size += 1; // rct signatures

  size_t log_padded_outputs = 0; // rangeSigs
  while ((1<<log_padded_outputs) < n_outputs) ++log_padded_outputs;
  size += (2 * (6 + log_padded_outputs) + 6) * 32 + 3;
  size += n_inputs * (32 * (mixin+1) + 64); // MGs/CLSAGs
  size += n_outputs * sizeof(crypto::view_tag); // View tags
  // size += 2 * 32 * (mixin+1) * n_inputs; // mixRing - not serialized, can be reconstructed
  size += 32 * n_inputs; // pseudoOuts
  size += 8 * n_outputs; // ecdhInfo
  size += 32 * n_outputs; // outPk - only commitment is saved
  size += 4; // txnFee

  return size;
}

uint64_t monero_wallet_utils::calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
  uint64_t fee = weight * base_fee * fee_multiplier;
  fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
  return fee;
}

uint64_t monero_wallet_utils::estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size) {
  size_t size = estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size);
  if (n_outputs > 2) {
    const uint64_t bp_base = (32 * (6 + 7 * 2)) / 2; // notional size of a 2-output bulletproof+ proof, normalized to 1 proof
    size_t log_padded_outputs = 2;
    while ((1<<log_padded_outputs) < n_outputs) ++log_padded_outputs;
    uint64_t nlr = 2 * (6 + log_padded_outputs);
    const uint64_t bp_size = 32 * (6 + nlr);
    const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
    MDEBUG("clawback on size " << size << ": " << bp_clawback);
    size += bp_clawback;
  }
  return size;
}

uint64_t monero_wallet_utils::get_tx_weight_limit(uint64_t default_limit) {
  if (default_limit > 0) return default_limit;
  return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE; // v8
}

void monero_wallet_utils::validate_cn_tx(const cryptonote::transaction &tx) {
  if (get_tx_weight_limit() <= cryptonote::get_transaction_weight(tx)) throw std::runtime_error("transaction is too big");
  if(tx.rct_signatures.p.bulletproofs_plus.empty()) throw std::runtime_error("Expected tx to use bulletproofs");
  auto tx_blob = cryptonote::t_serializable_object_to_blob(tx);
  size_t tx_blob_size = tx_blob.size();
  if(tx_blob_size <= 0) throw std::runtime_error("Expected tx blob byte length > 0");
}

void monero_wallet_utils::add_pid_to_tx_extra(const boost::optional<std::string>& payment_id_string, std::vector<uint8_t> &extra) {
  if (payment_id_string == boost::none || payment_id_string->size() == 0) return;

  // detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
  crypto::hash payment_id;
  if (monero_utils::parse_payment_id_long(*payment_id_string, payment_id)) {
    std::string extra_nonce;
    cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
    if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) throw std::runtime_error("Couldn't add pid nonce to tx extra");
  } else {
    crypto::hash8 payment_id8;
    // a PID has been specified by the user but the last resort in validating it fails; error
    if (!monero_utils::parse_payment_id_short(*payment_id_string, payment_id8)) throw std::runtime_error("Invalid pid");
    std::string extra_nonce;
    cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
    if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) throw std::runtime_error("Couldn't add pid nonce to tx extra");
  }
}

bool monero_wallet_utils::rct_hex_to_decrypted_mask(const std::string &rct_str, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask) {
  // rct string is empty if output is non RCT
  if (rct_str.empty()) return false;

  // rct_str is a magic value if output is RCT and coinbase
  if (rct_str == "coinbase") {
    decrypted_mask = rct::identity();
    return true;
  }

  auto make_key_derivation = [&]() {
    crypto::key_derivation derivation;
    if(!generate_key_derivation(tx_pub_key, view_secret_key, derivation)) throw std::runtime_error("Failed to generate key derivation");
    crypto::secret_key scalar;
    crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
    return rct::sk2rct(scalar);
  };

  rct::key encrypted_mask;
  // rct_str is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
  if (rct_str.size() < 64 * 2) {
    decrypted_mask = rct::genCommitmentMask(make_key_derivation());
    return true;
  }

  // rct_str is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  std::string encrypted_mask_str = rct_str.substr(64,64);
  if(!epee::string_tools::validate_hex(64, encrypted_mask_str)) throw std::runtime_error("Invalid rct mask: " + encrypted_mask_str);
  epee::string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);

  if (encrypted_mask == rct::identity()) {
    // backward compatibility; should no longer be needed after v11 mainnet fork
    decrypted_mask = encrypted_mask;
    return true;
  }

  // decrypt the mask
  sc_sub(decrypted_mask.bytes, encrypted_mask.bytes, rct::hash_to_scalar(make_key_derivation()).bytes);
  return true;
}

bool monero_wallet_utils::rct_hex_to_rct_commit(const std::string &rct_str, rct::key &rct_commit) {
  // rct string is empty if output is non RCT
  if (rct_str.empty()) return false;

  // rct_str is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  std::string rct_commit_str = rct_str.substr(0,64);
  if(!epee::string_tools::validate_hex(64, rct_commit_str)) throw std::runtime_error("Invalid rct commit hash: " + rct_commit_str);
  epee::string_tools::hex_to_pod(rct_commit_str, rct_commit);
  return true;
}

bool monero_wallet_utils::is_rct_hex_unblinded_coinbase(const std::string &rct_str) {
  if (rct_str == "coinbase") return true;
  if (rct_str.size() < 64 * 3) return false;

  std::string commit_str = rct_str.substr(0, 64);
  std::string mask_str = rct_str.substr(64, 64);
  if (!epee::string_tools::validate_hex(64, commit_str) || !epee::string_tools::validate_hex(64, mask_str)) return false;

  rct::key commit;
  rct::key mask;
  epee::string_tools::hex_to_pod(commit_str, commit);
  epee::string_tools::hex_to_pod(mask_str, mask);
  return commit == rct::zero() && mask == rct::identity();
}

void monero_wallet_utils::normalize_unconfirmed_tx(const std::shared_ptr<monero_tx_wallet> &tx) {
  tx->m_outputs.clear();
  tx->m_incoming_transfers.clear();
  tx->m_is_incoming = boost::none;

  tx->m_change_address = boost::none;
  tx->m_change_amount = boost::none;

  for(const auto &input : tx->m_inputs) {
    input->m_amount = boost::none;
  }
}

std::string monero_wallet_utils::encrypt(const std::string &plaintext_str, const crypto::secret_key &skey, bool authenticated) {
  const char *plaintext = plaintext_str.data();
  size_t len = plaintext_str.size();
  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, 1);
  std::string ciphertext;
  crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
  ciphertext.resize(len + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
  crypto::chacha20(plaintext, len, key, iv, &ciphertext[sizeof(iv)]);
  memcpy(&ciphertext[0], &iv, sizeof(iv));
  if (authenticated) {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(crypto::signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    crypto::signature &signature = *(crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, pkey, skey, signature);
  }
  return ciphertext;
}
