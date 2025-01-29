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

#include "monero_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "string_tools.h"
#include "byte_stream.h"

using namespace cryptonote;
using namespace monero_utils;

// ----------------------- WALLET HELPERS -----------------------

/**
 * Remove query criteria which require looking up other transfers/outputs to
 * fulfill query.
 *
 * @param query the query to decontextualize
 * @return a reference to the query for convenience
 */
std::shared_ptr<monero_tx_query> monero_utils::decontextualize(std::shared_ptr<monero_tx_query> query) {
  query->m_is_incoming = boost::none;
  query->m_is_outgoing = boost::none;
  query->m_transfer_query = boost::none;
  query->m_input_query = boost::none;
  query->m_output_query = boost::none;
  return query;
}

bool monero_utils::is_contextual(const monero_transfer_query& query) {
  if (query.m_tx_query == boost::none) return false;
  if (query.m_tx_query.get()->m_is_incoming != boost::none) return true;    // requires context of all transfers
  if (query.m_tx_query.get()->m_is_outgoing != boost::none) return true;
  if (query.m_tx_query.get()->m_input_query != boost::none) return true;    // requires context of inputs
  if (query.m_tx_query.get()->m_output_query != boost::none) return true;   // requires context of outputs
  return false;
}

bool monero_utils::is_contextual(const monero_output_query& query) {
  if (query.m_tx_query == boost::none) return false;
  if (query.m_tx_query.get()->m_is_incoming != boost::none) return true;    // requires context of all transfers
  if (query.m_tx_query.get()->m_is_outgoing != boost::none) return true;
  if (query.m_tx_query.get()->m_transfer_query != boost::none) return true; // requires context of transfers
  return false;
}

bool monero_utils::bool_equals(bool val, const boost::optional<bool>& opt_val) {
  return opt_val == boost::none ? false : val == *opt_val;
}

// compute m_num_confirmations TODO monero-project: this logic is based on wallet_rpc_server.cpp `set_confirmations` but it should be encapsulated in wallet2
void monero_utils::set_num_confirmations(std::shared_ptr<monero_tx_wallet>& tx, uint64_t blockchain_height) {
  std::shared_ptr<monero_block>& block = tx->m_block.get();
  if (block->m_height.get() >= blockchain_height || (block->m_height.get() == 0 && !tx->m_in_tx_pool.get())) tx->m_num_confirmations = 0;
  else tx->m_num_confirmations = blockchain_height - block->m_height.get();
}

// compute m_num_suggested_confirmations  TODO monero-project: this logic is based on wallet_rpc_server.cpp `set_confirmations` but it should be encapsulated in wallet2
void monero_utils::set_num_suggested_confirmations(std::shared_ptr<monero_incoming_transfer>& incoming_transfer, uint64_t blockchain_height, uint64_t block_reward, uint64_t unlock_time) {
  if (block_reward == 0) incoming_transfer->m_num_suggested_confirmations = 0;
  else incoming_transfer->m_num_suggested_confirmations = (incoming_transfer->m_amount.get() + block_reward - 1) / block_reward;
  if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER) {
    if (unlock_time > blockchain_height) incoming_transfer->m_num_suggested_confirmations = std::max(incoming_transfer->m_num_suggested_confirmations.get(), unlock_time - blockchain_height);
  } else {
    const uint64_t now = time(NULL);
    if (unlock_time > now) incoming_transfer->m_num_suggested_confirmations = std::max(incoming_transfer->m_num_suggested_confirmations.get(), (unlock_time - now + DIFFICULTY_TARGET_V2 - 1) / DIFFICULTY_TARGET_V2);
  }
}

std::shared_ptr<monero_tx_wallet> monero_utils::build_tx_with_incoming_transfer(tools::wallet2& m_w2, uint64_t height, const crypto::hash &payment_id, const tools::wallet2::payment_details &pd) {

  // construct block
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_height = pd.m_block_height;
  block->m_timestamp = pd.m_timestamp;

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_block = block;
  block->m_txs.push_back(tx);
  tx->m_hash = epee::string_tools::pod_to_hex(pd.m_tx_hash);
  tx->m_is_incoming = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_unlock_time;
  tx->m_is_locked = !m_w2.is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
  tx->m_fee = pd.m_fee;
  tx->m_note = m_w2.get_tx_note(pd.m_tx_hash);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = pd.m_coinbase ? true : false;
  tx->m_is_confirmed = true;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = false;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = false;
  set_num_confirmations(tx, height);

  // construct transfer
  std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();
  incoming_transfer->m_tx = tx;
  tx->m_incoming_transfers.push_back(incoming_transfer);
  incoming_transfer->m_amount = pd.m_amount;
  incoming_transfer->m_account_index = pd.m_subaddr_index.major;
  incoming_transfer->m_subaddress_index = pd.m_subaddr_index.minor;
  incoming_transfer->m_address = m_w2.get_subaddress_as_str(pd.m_subaddr_index);
  set_num_suggested_confirmations(incoming_transfer, height, m_w2.get_last_block_reward(), pd.m_unlock_time);

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> monero_utils::build_tx_with_outgoing_transfer(tools::wallet2& m_w2, uint64_t height, const crypto::hash &txid, const tools::wallet2::confirmed_transfer_details &pd) {

  // construct block
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_height = pd.m_block_height;
  block->m_timestamp = pd.m_timestamp;

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_block = block;
  block->m_txs.push_back(tx);
  tx->m_hash = epee::string_tools::pod_to_hex(txid);
  tx->m_is_outgoing = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(pd.m_payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_unlock_time;
  tx->m_is_locked = !m_w2.is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
  tx->m_fee = pd.m_amount_in - pd.m_amount_out;
  tx->m_note = m_w2.get_tx_note(txid);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = false;
  tx->m_is_confirmed = true;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = false;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = false;
  set_num_confirmations(tx, height);

  // construct transfer
  std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
  outgoing_transfer->m_tx = tx;
  tx->m_outgoing_transfer = outgoing_transfer;
  uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
  outgoing_transfer->m_amount = pd.m_amount_in - change - *tx->m_fee;
  
  if (pd.m_subaddr_account != 4294967295) outgoing_transfer->m_account_index = pd.m_subaddr_account;
  else outgoing_transfer->m_account_index = 2147483647;
  std::vector<uint32_t> subaddress_indices;
  std::vector<std::string> addresses;
  for (uint32_t i: pd.m_subaddr_indices) {
    subaddress_indices.push_back(i);
    addresses.push_back(m_w2.get_subaddress_as_str({pd.m_subaddr_account, i}));
  }
  outgoing_transfer->m_subaddress_indices = subaddress_indices;
  outgoing_transfer->m_addresses = addresses;

  // initialize destinations
  for (const auto &d: pd.m_dests) {
    std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
    destination->m_amount = d.amount;
    destination->m_address = d.address(m_w2.nettype(), pd.m_payment_id);
    outgoing_transfer->m_destinations.push_back(destination);
  }

  // replace transfer amount with destination sum
  // TODO monero-project: confirmed tx from/to same account has amount 0 but cached transfer destinations
  if (*outgoing_transfer->m_amount == 0 && !outgoing_transfer->m_destinations.empty()) {
    uint64_t amount = 0;
    for (const std::shared_ptr<monero_destination>& destination : outgoing_transfer->m_destinations) amount += *destination->m_amount;
    outgoing_transfer->m_amount = amount;
  }

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> monero_utils::build_tx_with_incoming_transfer_unconfirmed(const tools::wallet2& m_w2, uint64_t height, const crypto::hash &payment_id, const tools::wallet2::pool_payment_details &ppd) {

  // construct tx
  const tools::wallet2::payment_details &pd = ppd.m_pd;
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_hash = epee::string_tools::pod_to_hex(pd.m_tx_hash);
  tx->m_is_incoming = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_unlock_time;
  tx->m_is_locked = true;
  tx->m_fee = pd.m_fee;
  tx->m_note = m_w2.get_tx_note(pd.m_tx_hash);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = false;
  tx->m_is_confirmed = false;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = true;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = ppd.m_double_spend_seen;
  tx->m_num_confirmations = 0;

  // construct transfer
  std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();
  incoming_transfer->m_tx = tx;
  tx->m_incoming_transfers.push_back(incoming_transfer);
  incoming_transfer->m_amount = pd.m_amount;
  incoming_transfer->m_account_index = pd.m_subaddr_index.major;
  incoming_transfer->m_subaddress_index = pd.m_subaddr_index.minor;
  incoming_transfer->m_address = m_w2.get_subaddress_as_str(pd.m_subaddr_index);
  set_num_suggested_confirmations(incoming_transfer, height, m_w2.get_last_block_reward(), pd.m_unlock_time);

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> monero_utils::build_tx_with_outgoing_transfer_unconfirmed(const tools::wallet2& m_w2, const crypto::hash &txid, const tools::wallet2::unconfirmed_transfer_details &pd) {

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
  tx->m_hash = epee::string_tools::pod_to_hex(txid);
  tx->m_is_outgoing = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(pd.m_payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_tx.unlock_time;
  tx->m_is_locked = true;
  tx->m_fee = pd.m_amount_in - pd.m_amount_out;
  tx->m_note = m_w2.get_tx_note(txid);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = false;
  tx->m_is_confirmed = false;
  tx->m_is_relayed = !tx->m_is_failed.get();
  tx->m_in_tx_pool = !tx->m_is_failed.get();
  tx->m_relay = true;
  if (!tx->m_is_failed.get() && tx->m_is_relayed.get()) tx->m_is_double_spend_seen = false;  // TODO: test and handle if true
  tx->m_num_confirmations = 0;

  // construct transfer
  std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
  outgoing_transfer->m_tx = tx;
  tx->m_outgoing_transfer = outgoing_transfer;
  outgoing_transfer->m_amount = pd.m_amount_in - pd.m_change - tx->m_fee.get();
  if (pd.m_subaddr_account != 4294967295) outgoing_transfer->m_account_index = pd.m_subaddr_account;
  else outgoing_transfer->m_account_index = 2147483647;

  std::vector<uint32_t> subaddress_indices;
  std::vector<std::string> addresses;
  for (uint32_t i: pd.m_subaddr_indices) {
    subaddress_indices.push_back(i);
    addresses.push_back(m_w2.get_subaddress_as_str({pd.m_subaddr_account, i}));
  }
  outgoing_transfer->m_subaddress_indices = subaddress_indices;
  outgoing_transfer->m_addresses = addresses;

  // initialize destinations
  for (const auto &d: pd.m_dests) {
    std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
    destination->m_amount = d.amount;
    destination->m_address = d.address(m_w2.nettype(), pd.m_payment_id);
    outgoing_transfer->m_destinations.push_back(destination);
  }

  // replace transfer amount with destination sum
  // TODO monero-project: confirmed tx from/to same account has amount 0 but cached transfer destinations
  if (*outgoing_transfer->m_amount == 0 && !outgoing_transfer->m_destinations.empty()) {
    uint64_t amount = 0;
    for (const std::shared_ptr<monero_destination>& destination : outgoing_transfer->m_destinations) amount += *destination->m_amount;
    outgoing_transfer->m_amount = amount;
  }

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> monero_utils::build_tx_with_vout(tools::wallet2& m_w2, const tools::wallet2::transfer_details& td) {

  // construct block
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_height = td.m_block_height;

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_block = block;
  block->m_txs.push_back(tx);
  tx->m_hash = epee::string_tools::pod_to_hex(td.m_txid);
  tx->m_is_confirmed = true;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = false;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = false;
  tx->m_is_locked = !m_w2.is_transfer_unlocked(td);

  // construct output
  std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
  output->m_tx = tx;
  tx->m_outputs.push_back(output);
  output->m_amount = td.amount();
  output->m_index = td.m_global_output_index;
  output->m_account_index = td.m_subaddr_index.major;
  output->m_subaddress_index = td.m_subaddr_index.minor;
  output->m_is_spent = td.m_spent;
  output->m_is_frozen = td.m_frozen;
  output->m_stealth_public_key = epee::string_tools::pod_to_hex(td.get_public_key());
  if (td.m_key_image_known) {
    output->m_key_image = std::make_shared<monero_key_image>();
    output->m_key_image.get()->m_hex = epee::string_tools::pod_to_hex(td.m_key_image);
  }

  // return pointer to new tx
  return tx;
}

/**
 * Merges a transaction into a unique set of transactions.
 *
 * @param tx is the transaction to merge into the existing txs
 * @param tx_map maps tx hashes to txs
 * @param block_map maps block heights to blocks
 */
void monero_utils::merge_tx(const std::shared_ptr<monero_tx_wallet>& tx, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map) {
  if (tx->m_hash == boost::none) throw std::runtime_error("Tx hash is not initialized");

  // merge tx
  std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.find(*tx->m_hash);
  if (tx_iter == tx_map.end()) {
    tx_map[*tx->m_hash] = tx; // cache new tx
  } else {
    std::shared_ptr<monero_tx_wallet>& a_tx = tx_map[*tx->m_hash];
    a_tx->merge(a_tx, tx); // merge with existing tx
  }

  // merge tx's block if confirmed
  if (tx->get_height() != boost::none) {
    std::map<uint64_t, std::shared_ptr<monero_block>>::const_iterator block_iter = block_map.find(tx->get_height().get());
    if (block_iter == block_map.end()) {
      block_map[tx->get_height().get()] = tx->m_block.get(); // cache new block
    } else {
      std::shared_ptr<monero_block>& a_block = block_map[tx->get_height().get()];
      a_block->merge(a_block, tx->m_block.get()); // merge with existing block
    }
  }
}

/**
 * Returns true iff tx1's height is known to be less than tx2's height for sorting.
 */
bool monero_utils::tx_height_less_than(const std::shared_ptr<monero_tx>& tx1, const std::shared_ptr<monero_tx>& tx2) {
  if (tx1->m_block != boost::none && tx2->m_block != boost::none) return tx1->get_height() < tx2->get_height();
  else if (tx1->m_block == boost::none) return false;
  else return true;
}

/**
 * Returns true iff transfer1 is ordered before transfer2 by ascending account and subaddress indices.
 */
bool monero_utils::incoming_transfer_before(const std::shared_ptr<monero_incoming_transfer>& transfer1, const std::shared_ptr<monero_incoming_transfer>& transfer2) {

  // compare by height
  if (tx_height_less_than(transfer1->m_tx, transfer2->m_tx)) return true;

  // compare by account and subaddress index
  if (transfer1->m_account_index.get() < transfer2->m_account_index.get()) return true;
  else if (transfer1->m_account_index.get() == transfer2->m_account_index.get()) return transfer1->m_subaddress_index.get() < transfer2->m_subaddress_index.get();
  else return false;
}

/**
 * Returns true iff wallet vout1 is ordered before vout2 by ascending account and subaddress indices then index.
 */
bool monero_utils::vout_before(const std::shared_ptr<monero_output>& o1, const std::shared_ptr<monero_output>& o2) {
  if (o1 == o2) return false; // ignore equal references
  std::shared_ptr<monero_output_wallet> ow1 = std::static_pointer_cast<monero_output_wallet>(o1);
  std::shared_ptr<monero_output_wallet> ow2 = std::static_pointer_cast<monero_output_wallet>(o2);

  // compare by height
  if (tx_height_less_than(ow1->m_tx, ow2->m_tx)) return true;

  // compare by account index, subaddress index, output index, then key image hex
  if (ow1->m_account_index.get() < ow2->m_account_index.get()) return true;
  if (ow1->m_account_index.get() == ow2->m_account_index.get()) {
    if (ow1->m_subaddress_index.get() < ow2->m_subaddress_index.get()) return true;
    if (ow1->m_subaddress_index.get() == ow2->m_subaddress_index.get()) {
      if (ow1->m_index.get() < ow2->m_index.get()) return true;
      if (ow1->m_index.get() == ow2->m_index.get()) throw std::runtime_error("Should never sort outputs with duplicate indices");
    }
  }
  return false;
}

std::string monero_utils::get_default_ringdb_path(cryptonote::network_type nettype)
{
  boost::filesystem::path dir = tools::get_default_data_dir();
  // remove .bitmonero, replace with .shared-ringdb
  dir = dir.remove_filename();
  dir /= ".shared-ringdb";
  if (nettype == cryptonote::TESTNET)
    dir /= "testnet";
  else if (nettype == cryptonote::STAGENET)
    dir /= "stagenet";
  return dir.string();
}

/**
 * ---------------- DUPLICATED WALLET RPC TRANSFER CODE ---------------------
 *
 * These functions are duplicated from private functions in wallet rpc
 * on_transfer/on_transfer_split, with minor modifications to not be class members.
 *
 * This code is used to generate and send transactions with equivalent functionality as
 * wallet rpc.
 *
 * Duplicated code is not ideal.  Solutions considered:
 *
 * (1) Duplicate wallet rpc code as done here.
 * (2) Modify monero-wallet-rpc on_transfer() / on_transfer_split() to be public.
 * (3) Modify monero-wallet-rpc to make this class a friend.
 * (4) Move all logic in monero-wallet-rpc to wallet2 so all users can access.
 *
 * Options 2-4 require modification of monero-project C++.  Of those, (4) is probably ideal.
 * TODO: open patch on monero-project which moves common wallet rpc logic (e.g. on_transfer, on_transfer_split) to m_w2.
 *
 * Until then, option (1) is used because it allows monero-project binaries to be used without modification, it's easy, and
 * anything other than (4) is temporary.
 */
//------------------------------------------------------------------------------------------------------------------------------
bool monero_utils::validate_transfer(tools::wallet2* m_w2, const std::list<tools::wallet_rpc::transfer_destination>& destinations, const std::string& payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, bool at_least_one_destination, epee::json_rpc::error& er)
{
  crypto::hash8 integrated_payment_id = crypto::null_hash8;
  std::string extra_nonce;
  for (auto it = destinations.begin(); it != destinations.end(); it++)
  {
    cryptonote::address_parse_info info;
    cryptonote::tx_destination_entry de;
    er.message = "";
    if(!get_account_address_from_str_or_url(info, m_w2->nettype(), it->address,
      [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid)
        {
          er.message = std::string("Invalid DNSSEC for ") + url;
          return {};
        }
        if (addresses.empty())
        {
          er.message = std::string("No Monero address found at ") + url;
          return {};
        }
        return addresses[0];
      }))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      if (er.message.empty())
        er.message = std::string("Invalid destination address");
      return false;
    }

    de.original = it->address;
    de.addr = info.address;
    de.is_subaddress = info.is_subaddress;
    de.amount = it->amount;
    de.is_integrated = info.has_payment_id;
    dsts.push_back(de);

    if (info.has_payment_id)
    {
      if (!payment_id.empty() || integrated_payment_id != crypto::null_hash8)
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "A single payment id is allowed per transaction";
        return false;
      }
      integrated_payment_id = info.payment_id;
      cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, integrated_payment_id);

      /* Append Payment ID data into extra */
      if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Something went wrong with integrated payment_id.";
        return false;
      }
    }
  }

  if (at_least_one_destination && dsts.empty())
  {
    er.code = WALLET_RPC_ERROR_CODE_ZERO_DESTINATION;
    er.message = "No destinations for this transfer";
    return false;
  }

  if (!payment_id.empty())
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
    er.message = "Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead";
    return false;
  }
  return true;
}
//------------------------------------------------------------------------------------------------------------------------------
std::string monero_utils::ptx_to_string(const tools::wallet2::pending_tx &ptx)
{
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try
  {
    ar << ptx;
  }
  catch (...)
  {
    return "";
  }
  return epee::string_tools::buff_to_hex_nodelimer(oss.str());
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t monero_utils::total_amount(const tools::wallet2::pending_tx &ptx)
{
  uint64_t amount = 0;
  for (const auto &dest: ptx.dests) amount += dest.amount;
  return amount;
}

std::string monero_utils::tx_hex_to_hash(std::string hex) {
  cryptonote::blobdata blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(hex, blob))
  {
    throw std::runtime_error("Failed to parse hex.");
  }

  bool loaded = false;
  tools::wallet2::pending_tx ptx;

  try
  {
    binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
    if (::serialization::serialize(ar, ptx))
      loaded = true;
  }
  catch(...) {}

  if (!loaded)
  {
    try
    {
      std::istringstream iss(blob);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> ptx;
    }
    catch (...) {
      throw std::runtime_error("Failed to parse tx metadata.");
    }
  }

  return epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
}

bool monero_utils::is_error_value(const std::string &s) { return s.empty(); }

// --------------------------- LOG UTILS -------------------------------

void monero_utils::set_log_level(int level) {
  mlog_set_log_level(level);
}

void monero_utils::configure_logging(const std::string& path, bool console) {
  mlog_configure(path, console);
}

// --------------------------- VALIDATION UTILS -------------------------------

monero_integrated_address monero_utils::get_integrated_address(monero_network_type network_type, const std::string& standard_address, const std::string& payment_id) {

  // parse and validate address
  cryptonote::address_parse_info address_info;
  if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(network_type), standard_address)) throw std::runtime_error("Invalid address");
  if (address_info.has_payment_id) throw std::runtime_error("The given address already has a payment id");

  // randomly generate payment id if not given, else validate
  crypto::hash8 payment_id_h8;
  if (payment_id.empty()) {
    payment_id_h8 = crypto::rand<crypto::hash8>();
  } else {
    cryptonote::blobdata payment_id_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id, payment_id_data) || sizeof(crypto::hash8) != payment_id_data.size()) throw std::runtime_error("Invalid payment id");
    payment_id_h8 = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  }

  // build integrated address
  monero_integrated_address integrated_address;
  integrated_address.m_integrated_address = cryptonote::get_account_integrated_address_as_str(static_cast<cryptonote::network_type>(network_type), address_info.address, payment_id_h8);
  integrated_address.m_standard_address = standard_address;
  integrated_address.m_payment_id = epee::string_tools::pod_to_hex(payment_id_h8);
  return integrated_address;
}

bool monero_utils::is_valid_address(const std::string& address, monero_network_type network_type) {
  try {
    validate_address(address, network_type);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_private_view_key(const std::string& private_view_key) {
  try {
    validate_private_view_key(private_view_key);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_private_spend_key(const std::string& private_spend_key) {
  try {
    validate_private_spend_key(private_spend_key);
    return true;
  } catch (...) {
    return false;
  }
}

void monero_utils::validate_address(const std::string& address, monero_network_type network_type) {
  cryptonote::address_parse_info info;
  if (!get_account_address_from_str(info, static_cast<cryptonote::network_type>(network_type), address)) throw std::runtime_error("Invalid address");
}

void monero_utils::validate_private_view_key(const std::string& private_view_key) {
  if (private_view_key.length() != 64) throw std::runtime_error("private view key expected to be 64 hex characters");
  cryptonote::blobdata private_view_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(private_view_key, private_view_key_data) || private_view_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("private view key expected to be 64 hex characters");
  }
}

void monero_utils::validate_private_spend_key(const std::string& private_spend_key) {
  if (private_spend_key.length() != 64) throw std::runtime_error("private spend key expected to be 64 hex characters");
  cryptonote::blobdata private_spend_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(private_spend_key, private_spend_key_data) || private_spend_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("private spend key expected to be 64 hex characters");
  }
}

// -------------------------- BINARY SERIALIZATION ----------------------------

void monero_utils::json_to_binary(const std::string &json, std::string &bin) {
  epee::serialization::portable_storage ps;
  ps.load_from_json(json);
  epee::byte_stream bs;
  ps.store_to_binary(bs);
  bin = std::string((char*) bs.data(), bs.size());
}

void monero_utils::binary_to_json(const std::string &bin, std::string &json) {
  epee::serialization::portable_storage ps;
  ps.load_from_binary(bin);
  ps.dump_as_json(json);
}

void monero_utils::binary_blocks_to_json(const std::string &bin, std::string &json) {

  // load binary rpc response to struct
  cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response resp_struct;
  epee::serialization::load_t_from_binary(resp_struct, bin);

  // build property tree from deserialized blocks and transactions
  boost::property_tree::ptree root;
  boost::property_tree::ptree blocksNode; // array of block strings
  boost::property_tree::ptree txsNodes;   // array of txs per block (array of array)
  for (int blockIdx = 0; blockIdx < resp_struct.blocks.size(); blockIdx++) {

    // parse and validate block
    cryptonote::block block;
    if (cryptonote::parse_and_validate_block_from_blob(resp_struct.blocks[blockIdx].block, block)) {

      // add block node to blocks node
      boost::property_tree::ptree blockNode;
      blockNode.put("", cryptonote::obj_to_json_str(block));  // TODO: no pretty print
      blocksNode.push_back(std::make_pair("", blockNode));
    } else {
      throw std::runtime_error("failed to parse block blob at index " + std::to_string(blockIdx));
    }

    // parse and validate txs
    boost::property_tree::ptree txs_node;
    for (int txIdx = 0; txIdx < resp_struct.blocks[blockIdx].txs.size(); txIdx++) {
      cryptonote::transaction tx;
      if (cryptonote::parse_and_validate_tx_from_blob(resp_struct.blocks[blockIdx].txs[txIdx].blob, tx)) {

        // add tx node to txs node
        boost::property_tree::ptree txNode;
        //MTRACE("PRUNED:\n" << monero_utils::get_pruned_tx_json(tx));
        txNode.put("", monero_utils::get_pruned_tx_json(tx)); // TODO: no pretty print
        txs_node.push_back(std::make_pair("", txNode));
      } else {
        throw std::runtime_error("failed to parse tx blob at index " + std::to_string(txIdx));
      }
    }
    txsNodes.push_back(std::make_pair("", txs_node)); // array of array of transactions, one array per block
  }
  root.add_child("blocks", blocksNode);
  root.add_child("txs", txsNodes);
  root.put("status", resp_struct.status);
  root.put("untrusted", resp_struct.untrusted); // TODO: loss of ints and bools

  // convert root to string // TODO: common utility with serial_bridge
  std::stringstream ss;
  boost::property_tree::write_json(ss, root, false/*pretty*/);
  json = ss.str();
}

// ------------------------------- RAPIDJSON ----------------------------------

std::string monero_utils::serialize(const rapidjson::Document& doc) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  return buffer.GetString();
}

void monero_utils::add_json_member(std::string key, std::string val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field) {
  rapidjson::Value field_key(key.c_str(), key.size(), allocator);
  field.SetString(val.c_str(), val.size(), allocator);
  root.AddMember(field_key, field, allocator);
}

void monero_utils::add_json_member(std::string key, bool val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root) {
  rapidjson::Value field_key(key.c_str(), key.size(), allocator);
  if (val) {
    rapidjson::Value field_val(rapidjson::kTrueType);
    root.AddMember(field_key, field_val, allocator);
  } else {
    rapidjson::Value field_val(rapidjson::kFalseType);
    root.AddMember(field_key, field_val, allocator);
  }
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::string>& strs) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_str(rapidjson::kStringType);
  for (const std::string& str : strs) {
    value_str.SetString(str.c_str(), str.size(), allocator);
    value_arr.PushBack(value_str, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint8_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetInt(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

// TODO: remove these redundant implementations for different sizes?
rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint32_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetUint64(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint64_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetUint64(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

// ------------------------ PROPERTY TREES ---------------------------

std::string monero_utils::serialize(const boost::property_tree::ptree& node) {
  std::stringstream ss;
  boost::property_tree::write_json(ss, node, false);
  std::string str = ss.str();
  return str.substr(0, str.size() - 1); // strip newline
}

void monero_utils::deserialize(const std::string& json, boost::property_tree::ptree& root) {
  std::istringstream iss = json.empty() ? std::istringstream() : std::istringstream(json);
  try {
    boost::property_tree::read_json(iss, root);
  } catch (std::exception const& e) {
    throw std::runtime_error("Invalid JSON");
  }
}

// ----------------------------------------------------------------------------

bool monero_utils::is_valid_language(const std::string& language) {
  std::vector<std::string> languages;
  crypto::ElectrumWords::get_language_list(languages, false);
  std::vector<std::string>::iterator it = std::find(languages.begin(), languages.end(), language);
  if (it == languages.end()) {
    crypto::ElectrumWords::get_language_list(languages, true);
    it = std::find(languages.begin(), languages.end(), language);
  }
  if (it == languages.end()) return false;
  return true;
}

// TODO: this is unused
std::shared_ptr<monero_block> monero_utils::cn_block_to_block(const cryptonote::block& cn_block) {
  cryptonote::block temp = cn_block;
  std::cout << cryptonote::obj_to_json_str(temp) << std::endl;
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_major_version = cn_block.major_version;
  block->m_minor_version = cn_block.minor_version;
  block->m_timestamp = cn_block.timestamp;
  block->m_prev_hash = epee::string_tools::pod_to_hex(cn_block.prev_id);
  block->m_nonce = cn_block.nonce;
  block->m_miner_tx = monero_utils::cn_tx_to_tx(cn_block.miner_tx);
  for (const crypto::hash& tx_hash : cn_block.tx_hashes) {
    block->m_tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
  }
  return block;
}

std::shared_ptr<monero_tx> monero_utils::cn_tx_to_tx(const cryptonote::transaction& cn_tx, bool init_as_tx_wallet) {
  std::shared_ptr<monero_tx> tx = init_as_tx_wallet ? std::make_shared<monero_tx_wallet>() : std::make_shared<monero_tx>();
  tx->m_version = cn_tx.version;
  tx->m_unlock_time = cn_tx.unlock_time;
  tx->m_hash = epee::string_tools::pod_to_hex(cn_tx.hash);
  tx->m_extra = cn_tx.extra;

  // init inputs
  for (const txin_v& cnVin : cn_tx.vin) {
    if (cnVin.which() != 0 && cnVin.which() != 3) throw std::runtime_error("Unsupported variant type");
    if (tx->m_is_miner_tx == boost::none) tx->m_is_miner_tx = cnVin.which() == 0;
    if (cnVin.which() != 3) continue; // only process txin_to_key of variant  TODO: support other types, like 0 "gen" which is miner tx?
    std::shared_ptr<monero_output> input = init_as_tx_wallet ? std::make_shared<monero_output_wallet>() : std::make_shared<monero_output>();
    input->m_tx = tx;
    tx->m_inputs.push_back(input);
    const txin_to_key& txin = boost::get<txin_to_key>(cnVin);
    input->m_amount = txin.amount;
    input->m_ring_output_indices = txin.key_offsets;
    crypto::key_image cnKeyImage = txin.k_image;
    input->m_key_image = std::make_shared<monero_key_image>();
    input->m_key_image.get()->m_hex = epee::string_tools::pod_to_hex(cnKeyImage);
  }

  // init outputs
  for (const tx_out& cnVout : cn_tx.vout) {
    std::shared_ptr<monero_output> output = init_as_tx_wallet ? std::make_shared<monero_output_wallet>() : std::make_shared<monero_output>();
    output->m_tx = tx;
    tx->m_outputs.push_back(output);
    output->m_amount = cnVout.amount;

    // before HF_VERSION_VIEW_TAGS, outputs with public keys are of type txout_to_key
    // after HF_VERSION_VIEW_TAGS, outputs with public keys are of type txout_to_tagged_key
    crypto::public_key cnStealthPublicKey;
    if (cnVout.target.type() == typeid(txout_to_key))
      cnStealthPublicKey = boost::get<txout_to_key>(cnVout.target).key;
    else if (cnVout.target.type() == typeid(txout_to_tagged_key))
      cnStealthPublicKey = boost::get<txout_to_tagged_key>(cnVout.target).key;
    else
      throw std::runtime_error(std::string("Unexpected output target type found: ") + std::string(cnVout.target.type().name()));
    output->m_stealth_public_key = epee::string_tools::pod_to_hex(cnStealthPublicKey);
  }

  return tx;

  // TODO: finish this, cryptonote::transaction has:
//  std::vector<std::vector<crypto::signature> > m_signatures;
//  rct::rctSig m_rct_signatures;
//  mutable size_t blob_size;
}
