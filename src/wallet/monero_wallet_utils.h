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

#ifndef monero_wallet_utils_h
#define monero_wallet_utils_h

#include "utils/monero_utils.h"
#include "wallet/monero_wallet_model.h"
#include "wallet/monero_wallet.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "wallet/wallet2.h"
#include "serialization/keyvalue_serialization.h" // TODO: consolidate with other binary deps?
#include "storages/portable_storage.h"
#include "common/threadpool.h"

/**
 * Collection of wallet utilities.
 */
namespace monero_wallet_utils
{

  // ----------------------------- WALLET LISTENER ----------------------------

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
    wallet2_listener(monero_wallet& wallet, boost::optional<tools::wallet2&> wallet2 = boost::none) : m_wallet(wallet) {
      this->m_sync_start_height = boost::none;
      this->m_sync_end_height = boost::none;
      if (wallet2 != boost::none) m_w2 = wallet2.get();
      m_prev_balance = wallet.get_balance();
      m_prev_unlocked_balance = wallet.get_unlocked_balance();
      m_notification_pool = std::unique_ptr<tools::threadpool>(tools::threadpool::getNewForUnitTests(1));  // TODO (monero-project): utility can be for general use
    }

    ~wallet2_listener() {
      MTRACE("~wallet2_listener()");
      if (m_w2 != boost::none)
        m_w2->callback(nullptr);
      m_notification_pool->recycle();
    }

    void update_listening() {
      boost::lock_guard<boost::mutex> guarg(m_listener_mutex);

      // update callback
      if (m_w2 != boost::none) m_w2->callback(m_wallet.get_listeners().empty() ? nullptr : this);

      // if starting to listen, cache locked txs for later comparison
      if (!m_wallet.get_listeners().empty()) {
        if (m_w2 != boost::none && m_w2->callback() != nullptr) return;
        tools::threadpool::waiter waiter(*m_notification_pool);
        m_notification_pool->submit(&waiter, [this]() {
          check_for_changed_unlocked_txs();
        });
        waiter.wait();
      }
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

  protected:
    monero_wallet& m_wallet; // wallet to provide context for notifications
    boost::optional<tools::wallet2&> m_w2;         // internal wallet implementation to listen to
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

#endif /* monero_wallet_utils_h */
