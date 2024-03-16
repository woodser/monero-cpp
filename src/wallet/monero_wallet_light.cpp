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

#include "wallet/wallet_rpc_server_commands_defs.h"
#include "monero_wallet_light.h"
#include "utils/monero_utils.h"
#include <thread>
#include <chrono>
#include <iostream>
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "string_tools.h"
#include "device/device.hpp"
#include "common/threadpool.h"

using namespace epee;
using namespace tools;
using namespace crypto;

/**
 * Public library interface.
 */
namespace monero {

namespace light {
    // ----------------------- INTERNAL PRIVATE HELPERS -----------------------

  struct key_image_list
  {
    std::list<std::string> key_images;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(key_images)
    END_KV_SERIALIZE_MAP()
  };

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
  bool validate_transfer(wallet2* m_w2, const std::list<wallet_rpc::transfer_destination>& destinations, const std::string& payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, bool at_least_one_destination, epee::json_rpc::error& er)
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
  static std::string ptx_to_string(const tools::wallet2::pending_tx &ptx)
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
  template<typename T> static bool is_error_value(const T &val) { return false; }
  static bool is_error_value(const std::string &s) { return s.empty(); }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  static bool fill(T &where, V s)
  {
    if (is_error_value(s)) return false;
    where = std::move(s);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  static bool fill(std::list<T> &where, V s)
  {
    if (is_error_value(s)) return false;
    where.emplace_back(std::move(s));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static uint64_t total_amount(const tools::wallet2::pending_tx &ptx)
  {
    uint64_t amount = 0;
    for (const auto &dest: ptx.dests) amount += dest.amount;
    return amount;
  }
  
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename Ts, typename Tu, typename Tk, typename Ta>
  bool fill_response(wallet2* m_w2, std::vector<tools::wallet2::pending_tx> &ptx_vector,
      bool get_tx_key, Ts& tx_key, Tu &amount, Ta &amounts_by_dest, Tu &fee, Tu &weight, std::string &multisig_txset, std::string &unsigned_txset, bool do_not_relay,
      Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata, Tk &spent_key_images, epee::json_rpc::error &er)
  {
    for (const auto & ptx : ptx_vector)
    {
      if (get_tx_key)
      {
        epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
          s += epee::to_hex::wipeable_string(additional_tx_key);
        fill(tx_key, std::string(s.data(), s.size()));
      }
      // Compute amount leaving wallet in tx. By convention dests does not include change outputs
      fill(amount, total_amount(ptx));
      fill(fee, ptx.fee);
      fill(weight, cryptonote::get_transaction_weight(ptx.tx));

      // add amounts by destination
      tools::wallet_rpc::amounts_list abd;
      for (const auto& dst : ptx.dests)
        abd.amounts.push_back(dst.amount);
      fill(amounts_by_dest, abd);

      // add spent key images
      key_image_list key_image_list;
      bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
      {
        CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
        key_image_list.key_images.push_back(epee::string_tools::pod_to_hex(in.k_image));
        return true;
      });
      THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, ptx.tx);
      fill(spent_key_images, key_image_list);
    }

    if (m_w2->multisig())
    {
      multisig_txset = epee::string_tools::buff_to_hex_nodelimer(m_w2->save_multisig_tx(ptx_vector));
      if (multisig_txset.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to save multisig tx set after creation";
        return false;
      }
    }
    else
    {
      if (m_w2->watch_only()){
        unsigned_txset = epee::string_tools::buff_to_hex_nodelimer(m_w2->dump_tx_to_str(ptx_vector));
        if (unsigned_txset.empty())
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to save unsigned tx set after creation";
          return false;
        }
      }
      else if (!do_not_relay)
        m_w2->commit_tx(ptx_vector);

      // populate response with tx hashes
      for (auto & ptx : ptx_vector)
      {
        bool r = fill(tx_hash, epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
        r = r && (!get_tx_hex || fill(tx_blob, epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx))));
        r = r && (!get_tx_metadata || fill(tx_metadata, ptx_to_string(ptx)));
        if (!r)
        {
          er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
          er.message = "Failed to save tx info";
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Listens to wallet2 notifications in order to notify external wallet listeners.
   */
  struct wallet2_listener : public tools::i_wallet2_callback {

  public:

    /**
     * Constructs the listener.
     *
     * @param wallet provides context to notify external listeners
     * @param wallet2 provides source notifications which this listener propagates to external listeners
     */
    wallet2_listener(monero_wallet_light& wallet, tools::wallet2& wallet2) : m_wallet(wallet), m_w2(wallet2) {
      this->m_sync_start_height = boost::none;
      this->m_sync_end_height = boost::none;
      m_prev_balance = wallet.get_balance();
      m_prev_unlocked_balance = wallet.get_unlocked_balance();
      m_notification_pool = std::unique_ptr<tools::threadpool>(tools::threadpool::getNewForUnitTests(1));  // TODO (monero-project): utility can be for general use
    }

    ~wallet2_listener() {
      MTRACE("~wallet2_listener()");
      m_w2.callback(nullptr);
      m_notification_pool->recycle();
    }

    void update_listening() {
      boost::lock_guard<boost::mutex> guarg(m_listener_mutex);

      // if starting to listen, cache locked txs for later comparison
      if (!m_wallet.get_listeners().empty() && m_w2.callback() == nullptr) check_for_changed_unlocked_txs();

      // update callback
      m_w2.callback(m_wallet.get_listeners().empty() ? nullptr : this);
    }

    void on_sync_start(uint64_t start_height) {
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, start_height]() {
        if (m_sync_start_height != boost::none || m_sync_end_height != boost::none) throw std::runtime_error("Sync start or end height should not already be allocated, is previous sync in progress?");
        m_sync_start_height = start_height;
        m_sync_end_height = m_wallet.get_daemon_height();
      });
      waiter.wait(); // TODO: this processes notification on thread, process off thread
    }

    void on_sync_end() {
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this]() {
        check_for_changed_balances();
        if (m_prev_locked_tx_hashes.size() > 0) check_for_changed_unlocked_txs();
        m_sync_start_height = boost::none;
        m_sync_end_height = boost::none;
      });
      m_notification_pool->recycle();
      waiter.wait();
    }

    void on_new_block(uint64_t height, const cryptonote::block& cn_block) override {
      if (m_wallet.get_listeners().empty()) return;

      // ignore notifications before sync start height, irrelevant to clients
      if (m_sync_start_height == boost::none || height < *m_sync_start_height) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height]() {

        // notify listeners of new block
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_new_block(height);
        }

        // notify listeners of sync progress
        if (height >= *m_sync_end_height) m_sync_end_height = height + 1; // increase end height if necessary
        double percent_done = (double) (height - *m_sync_start_height + 1) / (double) (*m_sync_end_height - *m_sync_start_height);
        std::string message = std::string("Synchronizing");
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_sync_progress(height, *m_sync_start_height, *m_sync_end_height, percent_done, message);
        }

        // notify if balances change
        bool balances_changed = check_for_changed_balances();

        // notify when txs unlock after wallet is synced
        if (balances_changed && m_wallet.is_synced()) check_for_changed_unlocked_txs();
      });
      waiter.wait();
    }

    void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& cn_tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) override {
      if (m_wallet.get_listeners().empty()) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height, txid, cn_tx, amount, subaddr_index]() {
        try {

          // create library tx
          std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(monero_utils::cn_tx_to_tx(cn_tx, true));
          tx->m_hash = epee::string_tools::pod_to_hex(txid);
          tx->m_is_confirmed = false;
          tx->m_is_locked = true;
          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
          tx->m_outputs.push_back(output);
          output->m_tx = tx;
          output->m_amount = amount;
          output->m_account_index = subaddr_index.major;
          output->m_subaddress_index = subaddr_index.minor;

          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_received(*output);
          }

          // notify if balances changed
          check_for_changed_balances();

          // watch for unlock
          m_prev_locked_tx_hashes.insert(tx->m_hash.get());

          // free memory
          monero_utils::free(tx);
        } catch (std::exception& e) {
          std::cout << "Error processing unconfirmed output received: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    }

    void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& cn_tx, uint64_t amount, uint64_t burnt, const cryptonote::subaddress_index& subaddr_index, bool is_change, uint64_t unlock_time) override {
      if (m_wallet.get_listeners().empty()) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height, txid, cn_tx, amount, burnt, subaddr_index, is_change, unlock_time]() {
        try {

          // create native library tx
          std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
          block->m_height = height;
          std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(monero_utils::cn_tx_to_tx(cn_tx, true));
          block->m_txs.push_back(tx);
          tx->m_block = block;
          tx->m_hash = epee::string_tools::pod_to_hex(txid);
          tx->m_is_confirmed = true;
          tx->m_is_locked = true;
          tx->m_unlock_time = unlock_time;
          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
          tx->m_outputs.push_back(output);
          output->m_tx = tx;
          output->m_amount = amount - burnt;
          output->m_account_index = subaddr_index.major;
          output->m_subaddress_index = subaddr_index.minor;

          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_received(*output);
          }

          // watch for unlock
          m_prev_locked_tx_hashes.insert(tx->m_hash.get());

          // free memory
          monero_utils::free(block);
        } catch (std::exception& e) {
          std::cout << "Error processing confirmed output received: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    }

    void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& cn_tx_in, uint64_t amount, const cryptonote::transaction& cn_tx_out, const cryptonote::subaddress_index& subaddr_index) override {
      if (m_wallet.get_listeners().empty()) return;
      if (&cn_tx_in != &cn_tx_out) throw std::runtime_error("on_money_spent() in tx is different than out tx");

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height, txid, cn_tx_in, amount, cn_tx_out, subaddr_index]() {
        try {

          // create native library tx
          std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
          block->m_height = height;
          std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(monero_utils::cn_tx_to_tx(cn_tx_in, true));
          block->m_txs.push_back(tx);
          tx->m_block = block;
          tx->m_hash = epee::string_tools::pod_to_hex(txid);
          tx->m_is_confirmed = true;
          tx->m_is_locked = true;
          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
          tx->m_inputs.push_back(output);
          output->m_tx = tx;
          output->m_amount = amount;
          output->m_account_index = subaddr_index.major;
          output->m_subaddress_index = subaddr_index.minor;

          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_spent(*output);
          }

          // watch for unlock
          m_prev_locked_tx_hashes.insert(tx->m_hash.get());

          // free memory
          monero_utils::free(block);
        } catch (std::exception& e) {
          std::cout << "Error processing confirmed output spent: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    }

    void on_spend_tx_hashes(const std::vector<std::string>& tx_hashes) {
      if (m_wallet.get_listeners().empty()) return;
      monero_tx_query tx_query;
      tx_query.m_hashes = tx_hashes;
      tx_query.m_include_outputs = true;
      tx_query.m_is_locked = true;
      on_spend_txs(m_wallet.get_txs(tx_query));
    }

    void on_spend_txs(const std::vector<std::shared_ptr<monero_tx_wallet>>& txs) {
      if (m_wallet.get_listeners().empty()) return;
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, txs]() {
        check_for_changed_balances();
        for (const std::shared_ptr<monero_tx_wallet>& tx : txs) notify_outputs(tx);
      });
      waiter.wait();
    }

  private:
    monero_wallet& m_wallet; // wallet to provide context for notifications
    tools::wallet2& m_w2;         // internal wallet implementation to listen to
    boost::optional<uint64_t> m_sync_start_height;
    boost::optional<uint64_t> m_sync_end_height;
    boost::mutex m_listener_mutex;
    uint64_t m_prev_balance;
    uint64_t m_prev_unlocked_balance;
    std::set<std::string> m_prev_locked_tx_hashes;
    std::unique_ptr<tools::threadpool> m_notification_pool;  // threadpool of size 1 to queue notifications for external announcement

    bool check_for_changed_balances() {
      uint64_t balance = m_wallet.get_balance();
      uint64_t unlocked_balance = m_wallet.get_unlocked_balance();
      if (balance != m_prev_balance || unlocked_balance != m_prev_unlocked_balance) {
        m_prev_balance = balance;
        m_prev_unlocked_balance = unlocked_balance;
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_balances_changed(balance, unlocked_balance);
        }
        return true;
      }
      return false;
    }

    // TODO: this can probably be optimized using e.g. wallet2.get_num_rct_outputs() or wallet2.get_num_transfer_details(), or by retaining confirmed block height and only checking on or after unlock height, etc
    void check_for_changed_unlocked_txs() {

      // get confirmed and locked txs
      monero_tx_query query = monero_tx_query();
      query.m_is_locked = true;
      query.m_is_confirmed = true;
      query.m_min_height = m_wallet.get_height() - 70; // only monitor recent txs
      std::vector<std::shared_ptr<monero_tx_wallet>> locked_txs = m_wallet.get_txs(query);

      // collect hashes of txs no longer locked
      std::vector<std::string> tx_hashes_no_longer_locked;
      for (const std::string prev_locked_tx_hash : m_prev_locked_tx_hashes) {
        bool found = false;
        for (const std::shared_ptr<monero_tx_wallet>& locked_tx : locked_txs) {
          if (locked_tx->m_hash.get() == prev_locked_tx_hash) {
            found = true;
            break;
          }
        }
        if (!found) tx_hashes_no_longer_locked.push_back(prev_locked_tx_hash);
      }

      // fetch txs that are no longer locked
      std::vector<std::shared_ptr<monero_tx_wallet>> txs_no_longer_locked;
      if (!tx_hashes_no_longer_locked.empty()) {
        query.m_hashes = tx_hashes_no_longer_locked;
        query.m_is_locked = false;
        query.m_include_outputs = true;
        txs_no_longer_locked = m_wallet.get_txs(query);
      }

      // notify listeners of newly unlocked inputs and outputs
      for (const std::shared_ptr<monero_tx_wallet>& unlocked_tx : txs_no_longer_locked) {
        notify_outputs(unlocked_tx);
      }

      // re-assign currently locked tx hashes // TODO: needs mutex for thread safety?
      m_prev_locked_tx_hashes.clear();
      for (const std::shared_ptr<monero_tx_wallet>& locked_tx : locked_txs) {
        m_prev_locked_tx_hashes.insert(locked_tx->m_hash.get());
      }

      // free memory
      monero_utils::free(locked_txs);
      monero_utils::free(txs_no_longer_locked);
    }

    void notify_outputs(const std::shared_ptr<monero_tx_wallet>& tx) {

      // notify spent outputs
      if (tx->m_outgoing_transfer != boost::none) {
        
        // build dummy input for notification // TODO: this provides one input with outgoing amount like monero-wallet-rpc client, use real inputs instead
        std::shared_ptr<monero_output_wallet> input = std::make_shared<monero_output_wallet>();
        input->m_amount = tx->m_outgoing_transfer.get()->m_amount.get() + tx->m_fee.get();
        input->m_account_index = tx->m_outgoing_transfer.get()->m_account_index;
        if (tx->m_outgoing_transfer.get()->m_subaddress_indices.size() == 1) input->m_subaddress_index = tx->m_outgoing_transfer.get()->m_subaddress_indices[0]; // initialize if transfer sourced from single subaddress
        std::shared_ptr<monero_tx_wallet> tx_notify = std::make_shared<monero_tx_wallet>();
        input->m_tx = tx_notify;
        tx_notify->m_inputs.push_back(input);
        tx_notify->m_hash = tx->m_hash;
        tx_notify->m_is_locked = tx->m_is_locked;
        tx_notify->m_unlock_time = tx->m_unlock_time;
        if (tx->m_block != boost::none) {
          std::shared_ptr<monero_block> block_notify = std::make_shared<monero_block>();
          tx_notify->m_block = block_notify;
          block_notify->m_height = tx->get_height();
          block_notify->m_txs.push_back(tx_notify);
        }
        
        // notify listeners and free memory
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) listener->on_output_spent(*input);
        monero_utils::free(tx_notify);
      }

      // notify received outputs
      if (!tx->m_incoming_transfers.empty()) {
        for (const std::shared_ptr<monero_output_wallet>& output : tx->get_outputs_wallet()) {
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) listener->on_output_received(*output);
        }
      }
    }
  };

}

  // ------------------------------- UTILS -------------------------------

  bool monero_wallet_light_utils::is_uint64_t(const std::string& str) {
    try {
      uint64_t sz;
      std::stol(str, &sz);
      return sz == str.size();
    } 
    catch (const std::invalid_argument&) {
      // if no conversion could be performed.
      return false;   
    } 
    catch (const std::out_of_range&) {
      //  if the converted value would fall out of the range of the result type.
      return false;
    }
  }

  uint64_t monero_wallet_light_utils::uint64_t_cast(const std::string& str) {
    if (!is_uint64_t(str)) {
      throw std::out_of_range("String provided is not a valid uint64_t");
    }

    uint64_t value;
    
    std::istringstream itr(str);

    itr >> value;

    return value;
  }

  std::string monero_wallet_light_utils::tx_hex_to_hash(std::string hex) {
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

  // ------------------------------- DESERIALIZE UTILS -------------------------------

  std::shared_ptr<monero_light_output> monero_light_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
        else if (key == std::string("amount")) output->m_amount = it->second.data();
        else if (key == std::string("index")) output->m_index = it->second.get_value<uint16_t>();
        else if (key == std::string("global_index")) output->m_global_index = it->second.data();
        else if (key == std::string("rct")) output->m_rct = it->second.data();
        else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
        else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
        else if (key == std::string("public_key")) output->m_public_key = it->second.data();
        else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
        else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
        else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
        else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
    }

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
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) spend->m_amount = it->second.data();
        else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
        else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
        else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint16_t>();
        else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
    }

    return spend;
  }

  std::shared_ptr<monero_light_transaction> monero_light_transaction::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_transaction> transaction = std::make_shared<monero_light_transaction>();
    
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
          
          transaction->m_spent_outputs = std::vector<monero_light_spend>();

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
        else if (key == std::string("mixin")) transaction->m_height = it->second.get_value<uint32_t>();
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
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount")) random_outputs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            random_outputs->m_outputs = std::vector<monero_light_random_output>();

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
    MINFO("monero_light_get_address_info_response::deserialize()");
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_address_info_response> address_info = std::make_shared<monero_light_get_address_info_response>();
    
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
          address_info->m_spent_outputs = std::vector<monero_light_spend>();
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
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("total_received")) address_txs->m_total_received = it->second.data();
        else if (key == std::string("scanned_height")) address_txs->m_scanned_height = it->second.get_value<uint64_t>();
        else if (key == std::string("scanned_block_height")) address_txs->m_scanned_block_height = it->second.get_value<uint64_t>();
        else if (key == std::string("start_height")) address_txs->m_start_height = it->second.get_value<uint64_t>();
        else if (key == std::string("blockchain_height")) address_txs->m_blockchain_height = it->second.get_value<uint64_t>();
        else if (key == std::string("transactions")) {
          address_txs->m_transactions = std::vector<monero_light_transaction>();

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
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("amount_outs")) {
          random_outs->m_amount_outs = std::vector<monero_light_random_output>();
          boost::property_tree::ptree outs_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
            std::shared_ptr<monero_light_random_output> out = std::make_shared<monero_light_random_output>();
            monero_light_random_output::from_property_tree(it2->second, out);
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
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("per_byte_fee")) unspent_outs->m_per_byte_fee = it->second.data();
        else if (key == std::string("fee_mask")) unspent_outs->m_fee_mask = it->second.data();
        else if (key == std::string("amount")) unspent_outs->m_amount = it->second.data();
        else if (key == std::string("outputs")) {
            unspent_outs->m_outputs = std::vector<monero_light_output>();

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
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("active")) {
            accounts->m_active = std::vector<monero_light_account>();
            
            boost::property_tree::ptree accounts_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
              std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
              monero_light_account::from_property_tree(it2->second, account);
              accounts->m_active->push_back(*account);
            }
        }
        else if (key == std::string("inactive")) {
            accounts->m_inactive = std::vector<monero_light_account>();

            boost::property_tree::ptree accounts_node = it->second;
            for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
              std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
              monero_light_account::from_property_tree(it2->second, account);
              accounts->m_inactive->push_back(*account);
            }
        }
        else if (key == std::string("hidden")) {
            accounts->m_hidden = std::vector<monero_light_account>();

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

  monero_lws_connection monero_lws_connection::from_property_tree(const boost::property_tree::ptree& node) {
    monero_lws_connection *connection = new monero_lws_connection();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("uri")) connection->m_uri = it->second.data();
        else if (key == std::string("port")) connection->m_port = it->second.data();
    }

    return *connection;
  }

  monero_lws_admin_connection monero_lws_admin_connection::from_property_tree(const boost::property_tree::ptree& node) {
    monero_lws_admin_connection *connection = new monero_lws_admin_connection();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("uri")) connection->m_uri = it->second.data();
        else if (key == std::string("port")) connection->m_port = it->second.data();
        else if (key == std::string("admin_uri")) connection->m_admin_uri = it->second.data();
        else if (key == std::string("admin_port")) connection->m_admin_port = it->second.data();
        else if (key == std::string("token")) connection->m_token = it->second.data();
    }

    return *connection;
  }

  void monero_light_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
        else if (key == std::string("amount")) output->m_amount = it->second.data();
        else if (key == std::string("index")) output->m_index = it->second.get_value<uint16_t>();
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
        else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint16_t>();
        else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
    }
  }

  void monero_light_transaction::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_transaction>& transaction) {
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
            
            transaction->m_spent_outputs = std::vector<monero_light_spend>();
            
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
        else if (key == std::string("mixin")) transaction->m_height = it->second.get_value<uint32_t>();
    }
  }

  void monero_light_random_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first;

        if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
        else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
        else if (key == std::string("rct")) random_output->m_rct = it->second.data();
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

  rapidjson::Value monero_lws_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
    if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_str);

    
    // return root
    return root;
  }

  rapidjson::Value monero_lws_admin_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
    if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_str);
    if (m_admin_uri != boost::none) monero_utils::add_json_member("admin_uri", m_admin_uri.get(), allocator, root, value_str);
    if (m_admin_port != boost::none) monero_utils::add_json_member("admin_port", m_admin_port.get(), allocator, root, value_str);
    if (m_token != boost::none) monero_utils::add_json_member("token", m_token.get(), allocator, root, value_str);
    
    // return root
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

    if (exclude_spend) {
      return tgt;
    }

    if (!src->m_spent_outputs.get().empty()) {
      tgt->m_spent_outputs = std::vector<monero_light_spend>();
      for (const monero_light_spend& spent_output : src->m_spent_outputs.get()) {
        std::shared_ptr<monero_light_spend> spent_output_ptr = std::make_shared<monero_light_spend>(spent_output);
        std::shared_ptr<monero_light_spend> spent_output_copy = spent_output_ptr->copy(spent_output_ptr, std::make_shared<monero_light_spend>());
        tgt->m_spent_outputs.get().push_back(*spent_output_copy);
      }
    }

    return tgt;
  }

  // ---------------------------- WALLET MANAGEMENT ---------------------------

  monero_wallet_light* monero_wallet_light::create_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet(config)");

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config.m_path == boost::none) config_normalized.m_path = std::string("");
    if (config.m_password == boost::none) config_normalized.m_password = std::string("");
    if (config.m_language == boost::none) config_normalized.m_language = std::string("");
    if (config.m_seed == boost::none) config_normalized.m_seed = std::string("");
    if (config.m_primary_address == boost::none) config_normalized.m_primary_address = std::string("");
    if (config.m_private_spend_key == boost::none) config_normalized.m_private_spend_key = std::string("");
    if (config.m_private_view_key == boost::none) config_normalized.m_private_view_key = std::string("");
    if (config.m_seed_offset == boost::none) config_normalized.m_seed_offset = std::string("");
    if (config.m_is_multisig == boost::none) config_normalized.m_is_multisig = false;
    if (config.m_account_lookahead != boost::none && config.m_subaddress_lookahead == boost::none) throw std::runtime_error("No subaddress lookahead provided with account lookahead");
    if (config.m_account_lookahead == boost::none && config.m_subaddress_lookahead != boost::none) throw std::runtime_error("No account lookahead provided with subaddress lookahead");
    if (config_normalized.m_language.get().empty()) config_normalized.m_language = std::string("English");
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");

    // create wallet
    if (!config_normalized.m_primary_address.get().empty() && !config_normalized.m_private_view_key.get().empty()) {
      return create_wallet_from_keys(config_normalized, std::move(http_client_factory));
    } else {
      throw std::runtime_error("Configuration must have primary address and private view key.");
    }
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
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
    crypto::secret_key view_key_sk;
    if (config_normalized.m_private_view_key.get().empty()) {
      throw std::runtime_error("Must provide view key");
    }

    cryptonote::blobdata view_key_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(config_normalized.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("failed to parse secret view key");
    }
    view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());

    // parse and validate address
    cryptonote::address_parse_info address_info;
    if (config_normalized.m_primary_address.get().empty()) {
      throw std::runtime_error("must provide primary address");
    } else {
      if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config_normalized.m_network_type.get()), config_normalized.m_primary_address.get())) throw std::runtime_error("failed to parse address");

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(view_key_sk, pkey)) throw std::runtime_error("failed to verify secret view key");
      if (address_info.address.m_view_public_key != pkey) throw std::runtime_error("view key does not match address");
    }

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light();
    if (has_spend_key) {
      wallet->m_account.create_from_keys(address_info.address, spend_key_sk, view_key_sk);
    }
    else {
      wallet->m_account.create_from_viewkey(address_info.address, view_key_sk);
    }

    // initialize remaining wallet
    wallet->m_network_type = config_normalized.m_network_type.get();

    wallet->m_http_client = http_client_factory != nullptr ? http_client_factory->create() : net::http::client_factory().create();
    wallet->m_http_admin_client = http_client_factory != nullptr ? http_client_factory->create() : net::http::client_factory().create();
    if (http_client_factory == nullptr) wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true));
    else wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true, std::move(http_client_factory)));
    if (config.m_account_lookahead != boost::none) wallet->m_w2->set_subaddress_lookahead(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
    if (has_spend_key) wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), address_info.address, spend_key_sk, view_key_sk);
    else if (has_spend_key) wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), spend_key_sk, true, false);
    else wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), address_info.address, view_key_sk);
    if (config_normalized.m_server != boost::none) wallet->set_daemon_connection(config_normalized.m_server.get());
    
    wallet->init_common();

    return wallet;
  }

  std::vector<std::string> monero_wallet_light::get_seed_languages() {
    std::vector<std::string> languages;
    crypto::ElectrumWords::get_language_list(languages, true);
    return languages;
  }

  // ----------------------------- WALLET METHODS -----------------------------

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close();
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_rpc_connection>& connection) {
    if (connection == boost::none) {
      set_daemon_connection("");
      return;
    }

    m_lws_uri = connection.get().m_uri.get();
  }

  void monero_wallet_light::set_daemon_connection(std::string host, std::string port, std::string admin_uri, std::string admin_port, std::string token) {
    m_host = host;
    m_port = port;
    m_lws_uri = host + ":" + port;
    m_admin_uri = admin_uri;
    m_admin_port = admin_port;
    m_lws_admin_uri = admin_uri + ":" + admin_port;
    m_token = token;

    if (m_http_client != nullptr) {
      if (m_http_client->is_connected()) m_http_client->disconnect();

      if (!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Could not server: " + host);
      if (!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to server: " + host);
    }
  }

  void monero_wallet_light::set_daemon_proxy(const std::string& uri) {
    if (m_http_client == nullptr) throw std::runtime_error("Cannot set daemon proxy");
    m_http_client->set_proxy(uri);
    m_http_admin_client->set_proxy(uri);
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    if (m_http_client == nullptr) return false;

    return m_http_client->is_connected();
  }

  bool monero_wallet_light::is_connected_to_admin_daemon() const {
    if (m_http_admin_client == nullptr) return false;
    return m_http_admin_client->is_connected();
  }

  bool monero_wallet_light::is_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_blockchain_height.get() == m_scanned_block_height;
  }

  bool monero_wallet_light::is_daemon_synced() const {
    monero_light_get_address_info_response address_info = get_address_info();

    return address_info.m_blockchain_height.get() == address_info.m_scanned_height.get();
  }

  monero_version monero_wallet_light::get_version() const {
    monero_version version;
    version.m_number = 65552; // same as monero-wallet-rpc v0.15.0.1 release
    version.m_is_release = false; // TODO: could pull from MONERO_VERSION_IS_RELEASE in version.cpp
    return version;
  }

  void monero_wallet_light::set_restore_height(uint64_t restore_height) {
    if (!is_connected_to_admin_daemon()) throw std::runtime_error("Wallet is not connected to admin daemon");
    rescan(restore_height);
  }

  monero_sync_result monero_wallet_light::sync_aux() {
    MTRACE("sync_aux()");
    if (!is_connected_to_daemon()) throw std::runtime_error("sync_aux(): Wallet is not connected to daemon");
    
    monero_sync_result result(0, false);
    MTRACE("sync_aux(): get_address_txs()");
    monero_light_get_address_txs_response response = get_address_txs();
    MTRACE("sync_aux(): txs " << response.m_transactions.get().size());
    uint64_t old_scanned_height = m_scanned_block_height;

    m_start_height = response.m_start_height.get();
    m_scanned_block_height = response.m_scanned_block_height.get();
    m_blockchain_height = response.m_blockchain_height.get();

    m_raw_transactions = response.m_transactions.get();
    m_transactions = std::vector<monero_light_transaction>();
    MTRACE("sync_aux(): before for");
    for (const monero_light_transaction& raw_transaction : m_raw_transactions) {
      MTRACE("sync_aux(): processing raw_transaction: " << raw_transaction.m_id.get());
      std::shared_ptr<monero_light_transaction> transaction_ptr = std::make_shared<monero_light_transaction>(raw_transaction);
      std::shared_ptr<monero_light_transaction> transaction = transaction_ptr->copy(transaction_ptr, std::make_shared<monero_light_transaction>(),true);
      uint64_t total_received = monero_wallet_light_utils::uint64_t_cast(transaction->m_total_received.get());
      MTRACE("sync_aux(): B");
      if (!result.m_received_money) result.m_received_money = total_received > 0;

      if (!has_imported_key_images()) {
        if (total_received == 0) continue;
        MTRACE("sync_aux(): appending transaction: " << transaction->m_hash.get());
        m_transactions.push_back(*transaction);
        continue;
      }
      MTRACE("sync_aux(): C");
      for(monero_light_spend spent_output : raw_transaction.m_spent_outputs.get()) {
        bool is_spent = is_output_spent(spent_output.m_key_image.get());
        if (is_spent) transaction->m_spent_outputs.get().push_back(spent_output);
        else {
          uint64_t total_sent = monero_wallet_light_utils::uint64_t_cast(transaction->m_total_sent.get());
          uint64_t spent_amount = monero_wallet_light_utils::uint64_t_cast(spent_output.m_amount.get());
          uint64_t recalc_sent = total_sent - spent_amount;
          transaction->m_total_sent = boost::lexical_cast<std::string>(recalc_sent);
        }
      
        uint64_t final_sent = monero_wallet_light_utils::uint64_t_cast(transaction->m_total_sent.get());
        m_transactions.push_back(*transaction);
      }
      MTRACE("sync_aux(): E");
    }
  
    MTRACE("sync_aux(): G");

    calculate_balances();
    MTRACE("sync_aux(): calculate_balances() done");

    result.m_num_blocks_fetched = m_scanned_block_height - old_scanned_height;
    result.m_received_money = false; // to do

    
    MINFO("sync_aux(): starting wallet2 sync");
    // attempt to refresh wallet2 which may throw exception
    try {
      m_w2->refresh(m_w2->is_trusted_daemon(), m_start_height, result.m_num_blocks_fetched, result.m_received_money, true);
      MINFO("sync_aux(): wallet2 synced");
      // find and save rings
      m_w2->find_and_save_rings(false);
      MINFO("sync_aux(): fixed and saved rings");
    } catch (...) {
      MINFO("Error occurred while w2 refresh");
    }
    
    MINFO("sync_aux(): end");
    return result;
  }

  monero_sync_result monero_wallet_light::sync() {
    MTRACE("sync()");
    if(!is_connected_to_daemon()) throw std::runtime_error("sync(): Wallet is not connected to daemon");

    monero_sync_result result = sync_aux();
    monero_sync_result last_sync(0, false);

    uint64_t last_scanned_height = m_scanned_block_height;

    while(!is_synced()) {
      last_sync = sync_aux();
      result.m_num_blocks_fetched += last_sync.m_num_blocks_fetched;
      if (last_sync.m_received_money) result.m_received_money = true;
    }
    
    return result;
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
    MTRACE("sync(" << start_height << ")");
    if (!is_connected_to_daemon()) throw std::runtime_error("sync(uint64_t): Wallet is not connected to daemon");
    if (start_height < m_start_height) {
      if (!is_connected_to_admin_daemon()) throw std::runtime_error("Wallet is not connected to admin daemon");
      rescan(start_height, m_primary_address);
    }

    monero_sync_result last_sync = sync_aux();

    while(!is_synced()) {
      std::this_thread::sleep_for(std::chrono::seconds(120));
      last_sync = sync_aux();
    }

    monero_sync_result result;
    uint64_t height = get_height();

    result.m_num_blocks_fetched = (start_height > height) ? 0 : height - start_height;
    result.m_received_money = last_sync.m_received_money;

    return result;
  }

  monero_sync_result monero_wallet_light::sync(monero_wallet_listener& listener) {
    MTRACE("sync(listener)");
    if (!is_connected_to_daemon()) throw std::runtime_error("sync(monero_wallet_listener&): Wallet is not connected to daemon");
    uint64_t last_scanned_block_height = m_scanned_block_height;
    monero_sync_result last_sync = sync_aux();
    
    while(!is_synced()) {
      
      uint64_t last_balance = m_balance;
      uint64_t last_unlocked_balance = m_balance_unlocked;

      std::this_thread::sleep_for(std::chrono::seconds(120));
      last_sync = sync_aux();
      std::string message = "Sync progress (" + boost::lexical_cast<std::string>(m_scanned_block_height) + "/" + boost::lexical_cast<std::string>(m_blockchain_height) + ")";
      double percentage = m_scanned_block_height / m_blockchain_height;
      listener.on_sync_progress(m_scanned_block_height, m_start_height, m_blockchain_height, percentage, message);

      if (m_balance != last_balance || last_unlocked_balance != m_balance_unlocked) listener.on_balances_changed(m_balance, m_balance_unlocked);
      listener.on_new_block(m_scanned_block_height);
      
      // to do on_output_spent, on_output_received between last_scanned_block_height and m_scanned_block_height

      last_scanned_block_height = m_scanned_block_height;
    }

    monero_sync_result result;

    result.m_num_blocks_fetched = m_scanned_block_height - last_scanned_block_height;
    result.m_received_money = last_sync.m_received_money;

    return result;
  }

  void monero_wallet_light::start_syncing(uint64_t sync_period_in_ms) {
    sync();
  }

  void monero_wallet_light::rescan_blockchain() {       
    if (is_connected_to_admin_daemon())
    {
      rescan();
      return;
    }
    else if(!is_connected_to_daemon()) throw std::runtime_error("rescan_blockchain(): Wallet is not connected to daemon");
    monero_light_import_request_response response = import_request();

    if (response.m_import_fee != boost::none) {
      uint64_t import_fee = monero_wallet_light_utils::uint64_t_cast(response.m_import_fee.get());

      if (import_fee > 0) throw std::runtime_error("Could not rescan blockhain beacuse current lws server requires an import fee.");
    }
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs()  const {
    monero_tx_query query;

    return get_txs(query);
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs(const monero_tx_query& query) const {
    MINFO("monero_wallet_light::get_txs(monero_tx_query)");
    bool has_ki = has_imported_key_images();
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();

    if (m_transactions.empty()) {
      MINFO("Empty txs!");
    }

    for (monero_light_transaction light_tx : m_transactions) {
      MINFO("Processing light_tx: " << light_tx.m_hash.get());
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
      MINFO("A");
      if (tx_wallet->m_block == boost::none) tx_wallet->m_block = std::make_shared<monero_block>();
      tx_wallet->m_block.get()->m_height = light_tx.m_height;
      MINFO("B");
      tx_wallet->m_hash = light_tx.m_hash;
      MINFO("C");
      tx_wallet->m_is_relayed = true;
      MINFO("D");
      uint64_t total_sent;
      uint64_t total_received;

      std::istringstream tss(light_tx.m_total_sent.get());
      std::istringstream trs(light_tx.m_total_received.get());
      MINFO("E");
      tss >> total_sent;
      trs >> total_received;
      MINFO("F");

      if (total_sent == 0 && total_received > 0) {
        tx_wallet->m_is_incoming = true;
        tx_wallet->m_is_outgoing = false;
      } else if (total_received == 0 && total_sent > 0) {
        tx_wallet->m_is_outgoing = true;
        tx_wallet->m_is_incoming = false;
      } else if (light_tx.m_coinbase.get()) {
        tx_wallet->m_is_incoming = true;
        tx_wallet->m_is_outgoing = false;
      }
      MINFO("G");
      if(tx_wallet->m_is_outgoing != boost::none && tx_wallet->m_is_outgoing.get() && !has_ki) {
        MINFO("Not appending light_tx: " << light_tx.m_hash.get());
        continue;
      }
      MINFO("H");
    
      tx_wallet->m_unlock_time = light_tx.m_unlock_time;
      tx_wallet->m_payment_id = light_tx.m_payment_id;
      tx_wallet->m_in_tx_pool = light_tx.m_mempool;
      tx_wallet->m_is_miner_tx = light_tx.m_coinbase;
      tx_wallet->m_is_locked = light_tx.m_unlock_time.get() != 0;
      uint64_t num_confirmations = m_blockchain_height - light_tx.m_height.get();
      tx_wallet->m_num_confirmations = num_confirmations;
      tx_wallet->m_is_confirmed = num_confirmations > 0;
      MINFO("I");
      tx_wallet->m_fee = monero_wallet_light_utils::uint64_t_cast(light_tx.m_fee.get());
      tx_wallet->m_is_failed = false;
      
      MINFO("Appending light_tx: " << light_tx.m_hash.get());
      txs.push_back(tx_wallet);
    }

    return txs;
  }

  /**
   * Get incoming and outgoing transfers to and from this wallet.  An outgoing
   * transfer represents a total amount sent from primary address to
   * individual destination addresses, each with their own amount.
   * An incoming transfer represents a total amount received into
   * primary address account. Transfers belong to transactions which
   * are stored on the blockchain.
   *
   * Query results can be filtered by passing in a monero_transfer_query.
   * Transfers must meet every criteria defined in the query in order to be
   * returned.  All filtering is optional and no filtering is applied when not
   * defined.
   *
   * @param query filters query results (optional)
   * @return wallet transfers per the query (free memory using monero_utils::free)
   */
  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers(const monero_transfer_query& query) const {
    MINFO("monero_wallet_light::get_transfers(monero_transfer_query&)");
    std::vector<std::shared_ptr<monero_transfer>> transfers = std::vector<std::shared_ptr<monero_transfer>>();

    for (monero_light_transaction light_tx : m_transactions) {
      MINFO("monero_wallet_light::get_transfers(): processing light_tx " << light_tx.m_hash.get());
      std::shared_ptr<monero_transfer> transfer;

      if (is_view_only()) {
        transfer = std::make_shared<monero_incoming_transfer>();
      } else {
        uint64_t total_received = monero_wallet_light_utils::uint64_t_cast(light_tx.m_total_received.get());
        uint64_t total_sent = monero_wallet_light_utils::uint64_t_cast(light_tx.m_total_sent.get());

        if (total_received > 0) {
          transfer = std::make_shared<monero_incoming_transfer>();
        } else if (total_sent > 0) {
          transfer = std::make_shared<monero_outgoing_transfer>();
        } else {
          continue;
        }
      }

      transfer->m_amount = monero_wallet_light_utils::uint64_t_cast(light_tx.m_total_received.get());
      transfer->m_account_index = 0;
      transfer->m_tx = std::make_shared<monero_tx_wallet>();
      transfer->m_tx->m_is_incoming = true;
      if (transfer->m_tx->m_block == boost::none) transfer->m_tx->m_block = std::make_shared<monero_block>();
      transfer->m_tx->m_block.get()->m_height = light_tx.m_height;
      transfer->m_tx->m_hash = light_tx.m_hash;
      transfer->m_tx->m_is_relayed = true;
      transfer->m_tx->m_unlock_time = light_tx.m_unlock_time;
      transfer->m_tx->m_payment_id = light_tx.m_payment_id;
      transfer->m_tx->m_in_tx_pool = light_tx.m_mempool;
      transfer->m_tx->m_is_miner_tx = light_tx.m_coinbase;
      transfer->m_tx->m_is_locked = light_tx.m_unlock_time.get() != 0;
      uint64_t num_confirmations = m_blockchain_height - light_tx.m_height.get();
      transfer->m_tx->m_num_confirmations = num_confirmations;
      transfer->m_tx->m_is_confirmed = num_confirmations > 0;
      transfer->m_tx->m_fee = monero_wallet_light_utils::uint64_t_cast(light_tx.m_fee.get());
      transfer->m_tx->m_is_failed = false;

      transfers.push_back(transfer);
    }

    return transfers;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs() const {
    const monero_output_query query;
    
    return get_outputs(query);
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
    MINFO("monero_wallet_light::get_outputs()");
    monero_light_get_unspent_outs_response response = get_unspent_outs();

    std::vector<std::shared_ptr<monero_output_wallet>> outputs = std::vector<std::shared_ptr<monero_output_wallet>>();
    //bool view_only = is_view_only();
    bool has_imported_key_images =  m_imported_key_images.size() > 0;

    if (response.m_outputs == boost::none || response.m_outputs.get().empty()) {
      MINFO("monero_wallet_light::get_outputs: response outputs is empty");
      return outputs;
    }

    for(monero_light_output light_output : response.m_outputs.get()) {
      MINFO("Processing output: " << light_output.m_public_key.get());
      std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
      output->m_account_index = 0;
      output->m_index = light_output.m_index;
      output->m_amount = monero_wallet_light_utils::uint64_t_cast(light_output.m_amount.get());
      output->m_stealth_public_key = light_output.m_public_key;
      output->m_key_image = std::make_shared<monero_key_image>();
      output->m_key_image.get()->m_hex = "0100000000000000000000000000000000000000000000000000000000000000";
      output->m_is_spent = false;
      
      if (has_imported_key_images && light_output.m_spend_key_images != boost::none) {
        for (std::string light_spend_key_image : light_output.m_spend_key_images.get()){
          if(is_output_spent(light_spend_key_image)) {
            output->m_key_image.get()->m_hex = light_spend_key_image;
            output->m_is_spent = true;
            
            break;
          }
        }
      }

      output->m_tx = std::make_shared<monero_tx>();
      output->m_tx->m_block = std::make_shared<monero_block>();
      output->m_tx->m_block.get()->m_height = light_output.m_height.get();
      output->m_tx->m_hash = light_output.m_tx_hash;
      output->m_tx->m_key = light_output.m_tx_pub_key;
      output->m_tx->m_rct_signatures = light_output.m_rct;
      
      outputs.push_back(output);
    }

    return outputs;
  }

  std::string monero_wallet_light::export_outputs(bool all) const {
    if (m_w2 == nullptr) throw std::runtime_error("Wallet is not initialized");
    if (!m_w2->light_wallet()) throw std::runtime_error("Wallet light is not initiliazed");
    return epee::string_tools::buff_to_hex_nodelimer(m_w2->export_outputs_to_str(all));
  }

  std::vector<std::shared_ptr<monero_key_image>> monero_wallet_light::export_key_images(bool all) const {
    if (all) {
      //m_exported_key_images = m_imported_key_images;
      return m_imported_key_images;
    }

    std::vector<std::shared_ptr<monero_key_image>> result = std::vector<std::shared_ptr<monero_key_image>>();

    for(std::shared_ptr<monero_key_image> imported_key_image : m_imported_key_images) {
      bool append = true;

      for (std::shared_ptr<monero_key_image> exported_key_image : m_exported_key_images) {
        if (imported_key_image->m_hex == exported_key_image->m_hex) {
          append = false;
          break;
        }
      }

      if (append) {
        result.push_back(imported_key_image);
      }
    }

    //for (std::shared_ptr<monero_key_image> exported_key_image : result) {
      
      //m_exported_key_images.push_back(exported_key_image);
    //}

    return result;
  }

  std::shared_ptr<monero_key_image_import_result> monero_wallet_light::import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) {
    bool append_key_image = true;
    bool has_changes = false;

    for (std::shared_ptr<monero_key_image> key_image : key_images) {
      append_key_image = true;

      for (std::shared_ptr<monero_key_image> imported_key_image : m_imported_key_images) {
        if (imported_key_image->m_hex == key_image->m_hex) {
          append_key_image = false;
          break;
        }
      }

      if (append_key_image) {
        m_imported_key_images.push_back(key_image);
        has_changes = true;
      }
    }

    // validate and prepare key images for wallet2
    std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
    ski.resize(key_images.size());
    for (uint64_t n = 0; n < ski.size(); ++n) {
      if (!epee::string_tools::hex_to_pod(key_images[n]->m_hex.get(), ski[n].first)) {
        throw std::runtime_error("failed to parse key image");
      }
      if (!epee::string_tools::hex_to_pod(key_images[n]->m_signature.get(), ski[n].second)) {
        throw std::runtime_error("failed to parse signature");
      }
    }

    // import key images
    uint64_t spent = 0, unspent = 0;
    uint64_t height = m_w2->import_key_images(ski, 0, spent, unspent, is_connected_to_daemon()); // TODO: use offset? refer to wallet_rpc_server::on_import_key_images() req.offset

    // translate results
    std::shared_ptr<monero_key_image_import_result> result = std::make_shared<monero_key_image_import_result>();
    result->m_height = height;
    result->m_spent_amount = spent;
    result->m_unspent_amount = unspent;
    return result;
  };

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::create_txs(const monero_tx_config& config) {
    MTRACE("monero_wallet_light::create_txs");
    //std::cout << "monero_tx_config: " << config.serialize()  << std::endl;

    // validate config
    if (config.m_account_index == boost::none) throw std::runtime_error("Must specify account index to send from");
    if (config.m_account_index.get() != 0) throw std::runtime_error("Must specify exactly account index 0 to send from");

    // prepare parameters for wallet rpc's validate_transfer()
    std::string payment_id = config.m_payment_id == boost::none ? std::string("") : config.m_payment_id.get();
    std::list<tools::wallet_rpc::transfer_destination> tr_destinations;
    for (const std::shared_ptr<monero_destination>& destination : config.get_normalized_destinations()) {
      tools::wallet_rpc::transfer_destination tr_destination;
      if (destination->m_amount == boost::none) throw std::runtime_error("Destination amount not defined");
      if (destination->m_address == boost::none) throw std::runtime_error("Destination address not defined");
      tr_destination.amount = destination->m_amount.get();
      tr_destination.address = destination->m_address.get();
      tr_destinations.push_back(tr_destination);
    }

    // validate the requested txs and populate dsts & extra
    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;
    epee::json_rpc::error err;
    if (!light::validate_transfer(m_w2.get(), tr_destinations, payment_id, dsts, extra, true, err)) {
      throw std::runtime_error(err.message);
    }

    // prepare parameters for wallet2's create_transactions_2()
    uint64_t mixin = m_w2->adjust_mixin(0); // get mixin for call to 'create_transactions_2'
    uint32_t priority = m_w2->adjust_priority(config.m_priority == boost::none ? 0 : config.m_priority.get());
    uint64_t unlock_time = config.m_unlock_time == boost::none ? 0 : config.m_unlock_time.get();
    uint32_t account_index = config.m_account_index.get();
    std::set<uint32_t> subaddress_indices;
    for (const uint32_t& subaddress_idx : config.m_subaddress_indices) subaddress_indices.insert(subaddress_idx);
    std::set<uint32_t> subtract_fee_from;
    for (const uint32_t& subtract_fee_from_idx : config.m_subtract_fee_from) subtract_fee_from.insert(subtract_fee_from_idx);

    // prepare transactions
    std::vector<wallet2::pending_tx> ptx_vector = m_w2->create_transactions_2(dsts, mixin, unlock_time, priority, extra, account_index, subaddress_indices, subtract_fee_from);
    if (ptx_vector.empty()) throw std::runtime_error("No transaction created");

    // check if request cannot be fulfilled due to splitting
    if (ptx_vector.size() > 1) {
      if (config.m_can_split != boost::none && !config.m_can_split.get()) {
        throw std::runtime_error("Transaction would be too large.  Try create_txs()");
      }
      if (subtract_fee_from.size() > 0 && config.m_can_split != boost::none && config.m_can_split.get()) {
        throw std::runtime_error("subtractfeefrom transfers cannot be split over multiple transactions yet");
      }
    }

    // config for fill_response()
    bool get_tx_keys = true;
    bool get_tx_hex = true;
    bool get_tx_metadata = true;
    bool relay = config.m_relay != boost::none && config.m_relay.get();
    if (config.m_relay != boost::none && config.m_relay.get() == true && is_multisig()) throw std::runtime_error("Cannot relay multisig transaction until co-signed");

    // commit txs (if relaying) and get response using wallet rpc's fill_response()
    std::list<std::string> tx_keys;
    std::list<uint64_t> tx_amounts;
    std::list<tools::wallet_rpc::amounts_list> tx_amounts_by_dest;
    std::list<uint64_t> tx_fees;
    std::list<uint64_t> tx_weights;
    std::string multisig_tx_hex;
    std::string unsigned_tx_hex;
    std::list<std::string> tx_hashes;
    std::list<std::string> tx_blobs;
    std::list<std::string> tx_metadatas;
    std::list<light::key_image_list> input_key_images_list;
    if (!light::fill_response(m_w2.get(), ptx_vector, get_tx_keys, tx_keys, tx_amounts, tx_amounts_by_dest, tx_fees, tx_weights, multisig_tx_hex, unsigned_tx_hex, !relay, tx_hashes, get_tx_hex, tx_blobs, get_tx_metadata, tx_metadatas, input_key_images_list, err)) {
      throw std::runtime_error("need to handle error filling response!");  // TODO
    }

    // build sent txs from results  // TODO: break this into separate utility function
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    auto tx_hashes_iter = tx_hashes.begin();
    auto tx_keys_iter = tx_keys.begin();
    auto tx_amounts_iter = tx_amounts.begin();
    auto tx_amounts_by_dest_iter = tx_amounts_by_dest.begin();
    auto tx_fees_iter = tx_fees.begin();
    auto tx_weights_iter = tx_weights.begin();
    auto tx_blobs_iter = tx_blobs.begin();
    auto tx_metadatas_iter = tx_metadatas.begin();
    auto input_key_images_list_iter = input_key_images_list.begin();
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    auto destinations_iter = destinations.begin();
    while (tx_fees_iter != tx_fees.end()) {

      // init tx with outgoing transfer from filled values
      std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
      txs.push_back(tx);
      tx->m_hash = *tx_hashes_iter;
      tx->m_key = *tx_keys_iter;
      tx->m_fee = *tx_fees_iter;
      tx->m_weight = *tx_weights_iter;
      tx->m_full_hex = *tx_blobs_iter;
      tx->m_metadata = *tx_metadatas_iter;
      std::shared_ptr<monero_outgoing_transfer> out_transfer = std::make_shared<monero_outgoing_transfer>();
      tx->m_outgoing_transfer = out_transfer;
      out_transfer->m_amount = *tx_amounts_iter;

      // init inputs with key images
      std::list<std::string> input_key_images = (*input_key_images_list_iter).key_images;
      for (const std::string& input_key_image : input_key_images) {
        std::shared_ptr<monero_output_wallet> input = std::make_shared<monero_output_wallet>();
        input->m_tx = tx;
        tx->m_inputs.push_back(input);
        input->m_key_image = std::make_shared<monero_key_image>();
        input->m_key_image.get()->m_hex = input_key_image;
      }

      // init destinations
      for (const uint64_t tx_amount_by_dest : (*tx_amounts_by_dest_iter).amounts) {
        std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
        destination->m_address = (*destinations_iter)->m_address;
        destination->m_amount = tx_amount_by_dest;
        tx->m_outgoing_transfer.get()->m_destinations.push_back(destination);
        destinations_iter++;
      }

      // init other known fields
      tx->m_is_outgoing = true;
      tx->m_payment_id = config.m_payment_id;
      tx->m_is_confirmed = false;
      tx->m_is_miner_tx = false;
      tx->m_is_failed = false;   // TODO: test and handle if true
      tx->m_relay = config.m_relay != boost::none && config.m_relay.get();
      tx->m_is_relayed = tx->m_relay.get();
      tx->m_in_tx_pool = tx->m_relay.get();
      if (!tx->m_is_failed.get() && tx->m_is_relayed.get()) tx->m_is_double_spend_seen = false;  // TODO: test and handle if true
      tx->m_num_confirmations = 0;
      tx->m_ring_size = monero_utils::RING_SIZE;
      tx->m_unlock_time = config.m_unlock_time == boost::none ? 0 : config.m_unlock_time.get();
      tx->m_is_locked = true;
      if (tx->m_is_relayed.get()) tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));  // set last relayed timestamp to current time iff relayed  // TODO monero-project: this should be encapsulated in wallet2
      out_transfer->m_account_index = config.m_account_index;
      if (config.m_subaddress_indices.size() == 1) out_transfer->m_subaddress_indices.push_back(config.m_subaddress_indices[0]);  // subaddress index is known iff 1 requested  // TODO: get all known subaddress indices here

      // iterate to next element
      tx_keys_iter++;
      tx_amounts_iter++;
      tx_amounts_by_dest_iter++;
      tx_fees_iter++;
      tx_hashes_iter++;
      tx_blobs_iter++;
      tx_metadatas_iter++;
      input_key_images_list_iter++;
    }

    // build tx set
    std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
    tx_set->m_txs = txs;
    for (int i = 0; i < txs.size(); i++) txs[i]->m_tx_set = tx_set;
    if (!multisig_tx_hex.empty()) tx_set->m_multisig_tx_hex = multisig_tx_hex;
    if (!unsigned_tx_hex.empty()) tx_set->m_unsigned_tx_hex = unsigned_tx_hex;

    // notify listeners of spent funds
    //if (relay) m_w2_listener->on_spend_txs(txs);
    return txs;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    std::vector<std::string> result = std::vector<std::string>();
    
    for (std::string tx_metadata : tx_metadatas) {
      monero_light_submit_raw_tx_response response = submit_raw_tx(tx_metadata);

      std::string status = response.m_status.get();

      if (status != std::string("success")) {
        throw std::runtime_error("Invalid tx metadata.");
      }

      std::string tx_hash = monero_wallet_light_utils::tx_hex_to_hash(tx_metadata);
      result.push_back(tx_hash);
    }

    return result;
  }

  uint64_t monero_wallet_light::wait_for_next_block() {
    uint64_t last_block = get_daemon_height();
        
    while(true) {
      uint64_t current_block = get_daemon_height();

      if (current_block > last_block) {
        last_block = current_block;
        break;
      }

      std::this_thread::sleep_for(std::chrono::seconds(120));
    }

    return last_block;
  }

  monero_account monero_wallet_light::get_account(const uint32_t account_idx, bool include_subaddresses) const {
    if (account_idx > 0) throw std::runtime_error("Can only get primary account");

    monero_account account;
    account.m_index = 0;
    account.m_primary_address = m_primary_address;
    account.m_balance = m_balance;;
    account.m_unlocked_balance = m_balance_unlocked;

    return account;
  }

  std::vector<monero_account> monero_wallet_light::get_accounts(bool include_subaddresses, const std::string& tag) const {
    MTRACE("get_accounts(" << include_subaddresses << ", " << tag << ")");

    std::vector<monero_account> accounts;

    accounts.push_back(get_account());

    return accounts;
  }

  void monero_wallet_light::close(bool save) {
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    if (m_http_client != nullptr && m_http_client->is_connected()) {
      m_http_client->disconnect();
      epee::net_utils::http::abstract_http_client *release_client = m_http_client.release();
      delete release_client;
    }

    if (m_http_admin_client != nullptr && m_http_admin_client->is_connected()) {
      m_http_admin_client->disconnect();
      epee::net_utils::http::abstract_http_client *release_admin_client = m_http_admin_client.release();
      delete release_admin_client;
    }

    if (m_http_client != nullptr) {
      epee::net_utils::http::abstract_http_client *release_client = m_http_client.release();
      delete release_client;
    }

    if (m_http_admin_client != nullptr) {
      epee::net_utils::http::abstract_http_client *release_admin_client = m_http_admin_client.release();
      delete release_admin_client;
    }
    // no pointers to destroy
  }

  // ------------------------------- PROTECTED HELPERS ----------------------------

  void monero_wallet_light::init_common() {
    MINFO("monero_wallet_light::init_common()");
    m_w2->set_light_wallet(true);
    MINFO("Creating default listener");
    light::wallet2_listener *default_listener = new light::wallet2_listener(*this, *m_w2);
    MINFO("Default listener created");
    m_w2->callback(default_listener);
    MINFO("Default listener set to w2");
    m_primary_address = m_account.get_public_address_str(static_cast<cryptonote::network_type>(m_network_type));
    const cryptonote::account_keys& keys = m_account.get_keys();
    m_pub_spend_key = epee::string_tools::pod_to_hex(keys.m_account_address.m_spend_public_key);
    m_prv_view_key = epee::string_tools::pod_to_hex(keys.m_view_secret_key);

    m_request_pending = false;
    m_request_accepted = false;

    if (m_lws_uri != "") {
      epee::net_utils::ssl_support_t ssl = m_lws_uri.rfind("https", 0) == 0 ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;

      if(!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Invalid lws address");
      MINFO("successfully set lw server: " << m_lws_uri);
      if(!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to lws");
      MINFO("successfully connected to lw server: " << m_lws_uri);
      if(!m_w2->init(m_lws_uri, boost::none, {}, 0, false, ssl)) throw std::runtime_error("Failed to initialize light wallet with daemon connection");
      MINFO("successfully initialized wallet2");
      login();
      MINFO("Done login");
    } else {
      throw std::runtime_error("Must provide a lws address");
    }

    if (m_lws_admin_uri != "") {
      if (!m_http_admin_client->set_server(m_lws_admin_uri, boost::none)) throw std::runtime_error("Invalid admin lws address");
      if (!m_http_admin_client->connect(m_timeout)) throw std::runtime_error("Could not connect to admin lws");
    } else {
      m_http_admin_client = nullptr;
    }
    
    MINFO("monero_wallet_light::init_common() end");

  }

  void monero_wallet_light::calculate_balances() {
   uint64_t total_received = 0;
   uint64_t total_sent = 0;
   uint64_t total_pending_received = 0;

   uint64_t total_pending_sent = 0;
   uint64_t total_locked_received = 0;
   uint64_t total_locked_sent = 0;

   for (monero_light_transaction transaction : m_transactions) {
    if (transaction.m_mempool != boost::none && transaction.m_mempool.get()) {
      total_pending_sent += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_sent.get());
      total_pending_received += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_received.get());
    } else {
      // transaction has confirmations
      uint64_t tx_confirmations = m_scanned_block_height - transaction.m_height.get();
      if (tx_confirmations < 10) {
        if (!is_view_only()) total_locked_sent += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_sent.get());
        total_locked_received += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_received.get());
      }

      total_received += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_received.get());
      if (!is_view_only()) total_sent += monero_wallet_light_utils::uint64_t_cast(transaction.m_total_sent.get());
    }
   }

   m_balance = total_received - total_sent;
   m_balance_pending = total_pending_received - total_pending_sent;
   m_balance_unlocked = m_balance - total_locked_received - total_locked_sent;
  }

  bool monero_wallet_light::is_output_spent(std::string key_image) const {
    for (std::shared_ptr<monero_key_image> imported_key_image : m_imported_key_images) {
      if (imported_key_image->m_hex == key_image) return true;
    } 

    return false;
  }

  // ------------------------------- PROTECTED LWS HELPERS ----------------------------

  const epee::net_utils::http::http_response_info* monero_wallet_light::post(std::string method, std::string &body, bool admin) const {
    const epee::net_utils::http::http_response_info *response = nullptr;
    
    if (admin) {
      if (m_http_admin_client == nullptr || m_admin_uri == "") {
        throw std::runtime_error("Must set admin lws address before calling admin methods");
      }
      if (!m_http_admin_client->invoke_post(method, body, m_timeout, &response)) {
        throw std::runtime_error("Network error");
      }    
    }
    else {
      if (!m_http_client->invoke_post(method, body, m_timeout, &response)) {
        throw std::runtime_error("Network error");
      }
    }

    return response;
  }

  monero_light_get_address_info_response monero_wallet_light::get_address_info(monero_light_get_address_info_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_address_info", body);
    int status_code = response->m_response_code;

    if (status_code == 403) {
      if (m_request_pending) {
        throw std::runtime_error("Authorization request is pending");
      }

      throw std::runtime_error("Not authorized");
    }

    else if (status_code == 200) {
      return *monero_light_get_address_info_response::deserialize(response->m_body);
    }

    throw std::runtime_error("Unknown error");
  }

  monero_light_get_address_txs_response monero_wallet_light::get_address_txs(monero_light_get_address_txs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_address_txs", body);
    int status_code = response->m_response_code;

    if (status_code == 403) {
      if (m_request_pending) {
        throw std::runtime_error("Authorization request is pending");
      }

      throw std::runtime_error("Not authorized");
    }

    else if (status_code == 200) {
      return *monero_light_get_address_txs_response::deserialize(response->m_body);
    }

    throw std::runtime_error("Unknown error");
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(monero_light_get_random_outs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_random_outs", body);
    int status_code = response->m_response_code;
    if (status_code == 200) {
      return *monero_light_get_random_outs_response::deserialize(response->m_body);
    }

    throw std::runtime_error("Unknown error");
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(monero_light_get_unspent_outs_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/get_unspent_outs", body);
    int status_code = response->m_response_code;
    if (status_code == 403) {
      if (m_request_pending) {
        throw std::runtime_error("Authorization request is pending");
      }

      throw std::runtime_error("Not authorized");
    }
    else if (status_code == 400) {
      throw std::runtime_error("Outputs are less than amount");
    }
    else if (status_code == 200) {
      return *monero_light_get_unspent_outs_response::deserialize(response->m_body);
    }

    throw std::runtime_error("Unknown error");
  }

  monero_light_import_request_response monero_wallet_light::import_request(monero_light_import_request_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/import_request", body);
    int status_code = response->m_response_code;

    if (status_code != 200) {
      throw std::runtime_error("Unknown error");
    }

    return *monero_light_import_request_response::deserialize(response->m_body);
  }

  monero_light_submit_raw_tx_response monero_wallet_light::submit_raw_tx(monero_light_submit_raw_tx_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/submit_raw_tx", body);
    int status_code = response->m_response_code;
    
    if (status_code != 200) {
      throw std::runtime_error("Unknown error");
    }

    return *monero_light_submit_raw_tx_response::deserialize(response->m_body);
  }

  monero_light_login_response monero_wallet_light::login(monero_light_login_request request) {
    MINFO("monero_wallet_light::login()");

    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();
    const epee::net_utils::http::http_response_info *response = post("/login", body);
    int status_code = response->m_response_code;

    if (status_code == 501) {
      throw std::runtime_error("Server does not allow account creations");
    }
    else if (status_code == 403) {
      m_request_pending = true;
      m_request_accepted = false;
      throw std::runtime_error("Authorization request is pending");
    } else if (status_code != 200) {
      throw std::runtime_error("Unknown error");
    }

    if(m_request_pending) {
      m_request_pending = false;
      m_request_accepted = true;
    } else if (!m_request_pending && !m_request_accepted) {
      // first time?
      const epee::net_utils::http::http_response_info *info = post("/login", body);
      int status_code_info = info->m_response_code;

      if (status_code_info == 403) {
        m_request_pending = true;
        m_request_accepted = false;
      } else if (status_code_info == 200) {
        m_request_pending = false;
        m_request_accepted = true;
      } else {
        throw std::runtime_error("Unknown error while checking login request");
      }
    }

    return *monero_light_login_response::deserialize(response->m_body);
  }

  // ------------------------------- PROTECTED LWS ADMIN HELPERS ----------------------------

  void monero_wallet_light::accept_requests(monero_light_accept_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/accept_requests", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");
  }

  void monero_wallet_light::reject_requests(monero_light_reject_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/reject_requests", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");
  }
  
  void monero_wallet_light::add_account(monero_light_add_account_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/add_account", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");
  }
  
  monero_light_list_accounts_response monero_wallet_light::list_accounts(monero_light_list_accounts_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/list_accounts", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");

    return *monero_light_list_accounts_response::deserialize(response->m_body);
  }
  
  monero_light_list_requests_response monero_wallet_light::list_requests(monero_light_list_requests_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/list_requests", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");

    return *monero_light_list_requests_response::deserialize(response->m_body);
  }
  
  void monero_wallet_light::modify_account_status(monero_light_modify_account_status_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/modify_account_status", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");
  }
  
  void monero_wallet_light::rescan(monero_light_rescan_request request) const {
    rapidjson::Document document(rapidjson::Type::kObjectType);
    rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    req.Accept(writer);
    std::string body = sb.GetString();

    const epee::net_utils::http::http_response_info *response = post("/rescan", body, true);
    int status_code = response->m_response_code;

    if (status_code == 403) throw std::runtime_error("Not authorized");
    if (status_code != 200) throw std::runtime_error("Unknown error");
  }

}