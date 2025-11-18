#include "monero_wallet_light.h"
#include "utils/gen_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "common/threadpool.h"
#include "net/jsonrpc_structs.h"
#include "string_tools.h"
#include "serialization/serialization.h"
#include "device/device_cold.hpp"

#define APPROXIMATE_INPUT_BYTES 80
#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\004"
#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\005"
#define SIGNED_TX_PREFIX "Monero signed tx set\005"
#define MULTISIG_UNSIGNED_TX_PREFIX "Monero multisig unsigned tx set\001"
#define TAIL_EMISSION_REWARD 600000000000
#define TAIL_EMISSION_HEIGHT 2641623

namespace
{
	template<typename T>
	T pop_index(std::vector<T>& vec, size_t idx)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

		T res = std::move(vec[idx]);
		if (idx + 1 != vec.size()) {
			vec[idx] = std::move(vec.back());
		}
		vec.resize(vec.size() - 1);
		
		return res;
	}
	//
	template<typename T>
	T pop_random_value(std::vector<T>& vec)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		
		size_t idx = crypto::rand<size_t>() % vec.size();
		return pop_index (vec, idx);
	}
}

namespace monero {

  struct wallet_light_listener : public monero_wallet_listener {

  public:

    wallet_light_listener(monero_wallet_light &wallet): m_wallet(wallet) {
      this->m_sync_start_height = boost::none;
      this->m_sync_end_height = boost::none;
      m_prev_balance = wallet.get_balance();
      m_prev_unlocked_balance = wallet.get_unlocked_balance();
      m_notification_pool = std::unique_ptr<tools::threadpool>(tools::threadpool::getNewForUnitTests(1));  // TODO (monero-project): utility can be for general use
    }

    ~wallet_light_listener() {
      MTRACE("~wallet_light_listener()");
      m_notification_pool->recycle();
    }

    void update_listening() {
      boost::lock_guard<boost::mutex> guarg(m_listener_mutex);

      // if starting to listen, cache locked txs for later comparison
      if (!m_wallet.get_listeners().empty()) check_for_changed_unlocked_txs();
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
    // override wallet2
    /**
      * Invoked when a new block is processed.
      *
      * @param block - the newly processed block
      */
    void on_new_block(uint64_t height) {
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
    };

    void on_unconfirmed_money_received(const monero_light_output& output) {
      if (m_wallet.get_listeners().empty()) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          //height, txid, cn_tx, amount, subaddr_index
          uint64_t height = *output.m_height;
          uint64_t amount = gen_utils::uint64_t_cast(*output.m_amount);
          cryptonote::subaddress_index subaddr_index = {*output.m_recipient->m_maj_i, *output.m_recipient->m_min_i};

          // create library tx
          std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();

          tx->m_hash = output.m_tx_hash;
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

    void on_money_received(const monero_light_output& output) {
      if (m_wallet.get_listeners().empty()) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          uint64_t height = *output.m_height;
          uint64_t amount = gen_utils::uint64_t_cast(*output.m_amount);
          cryptonote::subaddress_index subaddr_index = {*output.m_recipient->m_maj_i, *output.m_recipient->m_min_i};

          // create native library tx
          std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
          block->m_height = height;
          std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
          block->m_txs.push_back(tx);
          tx->m_block = block;
          tx->m_hash = output.m_tx_hash;
          tx->m_is_confirmed = true;
          tx->m_is_locked = true;
          //tx->m_unlock_time = unlock_time;
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

    void on_money_spent(const monero_light_output& output) {
      if (m_wallet.get_listeners().empty()) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          //txid, cn_tx_in, cn_tx_out
          uint64_t height = *output.m_height;
          uint64_t amount = gen_utils::uint64_t_cast(*output.m_amount);
          cryptonote::subaddress_index subaddr_index = {*output.m_recipient->m_maj_i, *output.m_recipient->m_min_i};

          // create native library tx
          std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
          block->m_height = height;
          std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
          block->m_txs.push_back(tx);
          tx->m_block = block;
          tx->m_hash = output.m_tx_hash;
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
    // end override wallet2
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

    /**
      * Invoked when sync progress is made.
      *
      * @param height - height of the synced block
      * @param start_height - starting height of the sync request
      * @param end_height - ending height of the sync request
      * @param percent_done - sync progress as a percentage
      * @param message - human-readable description of the current progress
      */
    void on_sync_progress(uint64_t height, uint64_t start_height, uint64_t end_height, double percent_done, const std::string& message) { }

    /**
      * Invoked when the wallet's balances change.
      *
      * @param new_balance - new balance
      * @param new_unlocked_balance - new unlocked balance
      */
    void on_balances_changed(uint64_t new_balance, uint64_t new_unlocked_balance) {
      if (m_wallet.get_listeners().empty()) return;
      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, new_balance, new_unlocked_balance]() {
        try {
          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_balances_changed(new_balance, new_unlocked_balance);
          }
        } catch (std::exception& e) {
          std::cout << "Error processing balance change: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    };

    /**
      * Invoked when the wallet receives an output.
      *
      * @param output - the received output
      */
    void on_output_received(const monero_output_wallet& output) {
      if (m_wallet.get_listeners().empty()) return;
      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_received(output);
          }

          // watch for unlock
          //m_prev_locked_tx_hashes.insert(tx->m_hash.get());

          // free memory
        } catch (std::exception& e) {
          std::cout << "Error processing confirmed output received: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    };

    /**
      * Invoked when the wallet spends an output.
      *
      * @param output - the spent output
      */
    void on_output_spent(const monero_output_wallet& output) {
      if (m_wallet.get_listeners().empty()) return;
      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_spent(output);
          }
        } catch (std::exception& e) {
          std::cout << "Error processing spent output: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    };

  private:
    monero_wallet_light& m_wallet;
    boost::optional<uint64_t> m_sync_start_height;
    boost::optional<uint64_t> m_sync_end_height;
    boost::mutex m_listener_mutex;
    uint64_t m_prev_balance;
    uint64_t m_prev_unlocked_balance;
    std::set<std::string> m_prev_locked_tx_hashes;
    std::unique_ptr<tools::threadpool> m_notification_pool;

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

  static std::string dump_ptx(const tools::wallet2::pending_tx &ptx) {
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

  bool _rct_hex_to_rct_commit(const std::string &rct_string, rct::key &rct_commit) {
    // rct string is empty if output is non RCT
    if (rct_string.empty()) {
      return false;
    }
    // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
    std::string rct_commit_str = rct_string.substr(0,64);
    if(!epee::string_tools::validate_hex(64, rct_commit_str)) throw std::runtime_error("Invalid rct commit hash: " + rct_commit_str);
    epee::string_tools::hex_to_pod(rct_commit_str, rct_commit);
    return true;
  }

  bool _rct_hex_to_decrypted_mask(const std::string &rct_string, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask) {
    // rct string is empty if output is non RCT
    if (rct_string.empty()) {
      return false;
    }
    // rct_string is a magic value if output is RCT and coinbase
    if (rct_string == "coinbase") {
      decrypted_mask = rct::identity();
      return true;
    }
    auto make_key_derivation = [&]() {
      crypto::key_derivation derivation;
      bool r = generate_key_derivation(tx_pub_key, view_secret_key, derivation);
      if(!r) throw std::runtime_error("Failed to generate key derivation");
      crypto::secret_key scalar;
      crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
      return rct::sk2rct(scalar);
    };
    rct::key encrypted_mask;
    // rct_string is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
    if (rct_string.size() < 64 * 2) {
      decrypted_mask = rct::genCommitmentMask(make_key_derivation());
      return true;
    }
    // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
    std::string encrypted_mask_str = rct_string.substr(64,64);
    if(!epee::string_tools::validate_hex(64, encrypted_mask_str)) throw std::runtime_error("Invalid rct mask: " + encrypted_mask_str);
    epee::string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
    //
    if (encrypted_mask == rct::identity()) {
      // backward compatibility; should no longer be needed after v11 mainnet fork
      decrypted_mask = encrypted_mask;
      return true;
    }
    //
    // Decrypt the mask
    sc_sub(decrypted_mask.bytes,
      encrypted_mask.bytes,
      rct::hash_to_scalar(make_key_derivation()).bytes);
    
    return true;
  }

  void _add_pid_to_tx_extra(const boost::optional<std::string>& payment_id_string, std::vector<uint8_t> &extra) { // Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
    bool r = false;
    if (payment_id_string != boost::none && payment_id_string->size() > 0) {
      crypto::hash payment_id;
      r = monero_utils::parse_long_payment_id(*payment_id_string, payment_id);
      if (r) {
        std::string extra_nonce;
        cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
        r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r) {
          throw std::runtime_error("Couldn't add pid nonce to tx extra");
        }
      } else {
        crypto::hash8 payment_id8;
        r = monero_utils::parse_short_payment_id(*payment_id_string, payment_id8);
        if (!r) { // a PID has been specified by the user but the last resort in validating it fails; error
          throw std::runtime_error("Invalid pid");
        }
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
        r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r) {
          throw std::runtime_error("Couldn't add pid nonce to tx extra");
        }
      }
    }
  }

  monero_light_get_random_outs_params monero_wallet_light::prepare_get_random_outs_params(const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, bool is_sweeping, uint32_t simple_priority, const std::vector<monero_light_output> &unspent_outs, uint64_t fee_per_b, uint64_t fee_quantization_mask, boost::optional<uint64_t> prior_attempt_size_calcd_fee, boost::optional<monero_light_spendable_random_outputs> prior_attempt_unspent_outs_to_mix_outs) {
    monero_light_get_random_outs_params params;

    if (!is_sweeping) {
      for (uint64_t sending_amount : sending_amounts) {
        if (sending_amount == 0) {
          throw std::runtime_error("entered amount is too low");
        }
      }
    }
    
    uint32_t fake_outs_count = get_mixin_size();
    params.m_mixin = fake_outs_count;

    bool use_rct = true;
    bool bulletproof = true;
    bool clsag = true;
    
    std::vector<uint8_t> extra;
    _add_pid_to_tx_extra(payment_id_string, extra);

    const uint64_t base_fee = get_base_fee(fee_per_b); // in other words, fee_per_b
    const uint64_t fee_multiplier = get_fee_multiplier(simple_priority, get_default_priority(), get_fee_algorithm());
    
    uint64_t attempt_at_min_fee;
    if (prior_attempt_size_calcd_fee == boost::none) {
      attempt_at_min_fee = estimate_fee(true/*use_per_byte_fee*/, true/*use_rct*/, 1/*est num inputs*/, fake_outs_count, 2, extra.size(), bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask);
      // use a minimum viable estimate_fee() with 1 input. It would be better to under-shoot this estimate, and then need to use a higher fee  from calculate_fee() because the estimate is too low,
      // versus the worse alternative of over-estimating here and getting stuck using too high of a fee that leads to fingerprinting
    } else {
      attempt_at_min_fee = *prior_attempt_size_calcd_fee;
    }
    // fee may get changed as follows…
    uint64_t sum_sending_amounts;
    uint64_t potential_total; // aka balance_required

    if (is_sweeping) {
      potential_total = sum_sending_amounts = UINT64_MAX; // balance required: all
    } else {
      sum_sending_amounts = 0;
      for (uint64_t amount : sending_amounts) {
        sum_sending_amounts += amount;
      }
      potential_total = sum_sending_amounts + attempt_at_min_fee;
    }
    //
    // Gather outputs and amount to use for getting decoy outputs…
    uint64_t using_outs_amount = 0;
    std::vector<monero_light_output>  remaining_unusedOuts = unspent_outs; // take copy so not to modify original

    // start by using all the passed in outs that were selected in a prior tx construction attempt
    if (prior_attempt_unspent_outs_to_mix_outs != boost::none) {
      for (size_t i = 0; i < remaining_unusedOuts.size(); ++i) {
        monero_light_output &out = remaining_unusedOuts[i];

        // search for out by public key to see if it should be re-used in an attempt
        if (prior_attempt_unspent_outs_to_mix_outs->find(*out.m_public_key) != prior_attempt_unspent_outs_to_mix_outs->end()) {
          using_outs_amount += gen_utils::uint64_t_cast(*out.m_amount);
          params.m_using_outs.push_back(std::move(pop_index(remaining_unusedOuts, i)));
        }
      }
    }

    // TODO: factor this out to get spendable balance for display in the MM wallet:
    while (using_outs_amount < potential_total && remaining_unusedOuts.size() > 0) {
      auto out = pop_random_value(remaining_unusedOuts);
      if (!use_rct && (out.m_rct != boost::none && (*out.m_rct).empty() == false)) {
        // out.rct is set by the server
        continue; // skip rct outputs if not creating rct tx
      }
      if (gen_utils::uint64_t_cast(*out.m_amount) < get_dust_threshold()) { // amount is dusty..
        if (out.m_rct == boost::none || (*out.m_rct).empty()) {
          //cout << "Found a dusty but unmixable (non-rct) output... skipping it!" << endl;
          continue;
        } else {
          //cout << "Found a dusty but mixable (rct) amount... keeping it!" << endl;
        }
      }
      using_outs_amount += gen_utils::uint64_t_cast(*out.m_amount);
      //cout << "Using output: " << out.amount << " - " << out.public_key << endl;
      params.m_using_outs.push_back(std::move(out));
    }

    params.m_spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
    // Note: using_outs and using_outs_amount may still get modified below (so retVals.spendable_balance gets updated)
    
    //if (/*using_outs.size() > 1*/ && use_rct) { // FIXME? see original core js
    uint64_t needed_fee = estimate_fee(
      true/*use_per_byte_fee*/, use_rct,
      params.m_using_outs.size(), fake_outs_count, sending_amounts.size(), extra.size(),
      bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask
    );
    // if newNeededFee < neededFee, use neededFee instead (should only happen on the 2nd or later times through (due to estimated fee being too low))
    if (prior_attempt_size_calcd_fee != boost::none && needed_fee < attempt_at_min_fee) {
      needed_fee = attempt_at_min_fee;
    }
    //
    // NOTE: needed_fee may get further modified below when !is_sweeping if using_outs_amount < total_incl_fees and gets finalized (for this function's scope) as using_fee
    //
    params.m_required_balance = is_sweeping ? needed_fee : potential_total; // must store for needMoreMoneyThanFound return .... NOTE: this is set to needed_fee for is_sweeping because that's literally the required balance, which an caller may want to print in case they get needMoreMoneyThanFound - note this gets updated below when !is_sweeping
    //
    uint64_t total_wo_fee = is_sweeping
      ? /*now that we know outsAmount>needed_fee*/(using_outs_amount - needed_fee)
      : sum_sending_amounts;
    params.m_final_total_wo_fee = total_wo_fee;
    //
    uint64_t total_incl_fees;
    if (is_sweeping) {
      if (using_outs_amount < needed_fee) { // like checking if the result of the following total_wo_fee is < 0
        // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point
        throw std::runtime_error("need more money than found; sweeping, using_outs_amount: " + std::to_string(using_outs_amount) + ", needed_fee: " + std::to_string(needed_fee));
      }
      total_incl_fees = using_outs_amount;
    } else {
      total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed because using_outs.size() was updated
      while (using_outs_amount < total_incl_fees && remaining_unusedOuts.size() > 0) { // add outputs 1 at a time till we either have them all or can meet the fee
        {
          auto out = pop_random_value(remaining_unusedOuts);
          //cout << "Using output: " << out.amount << " - " << out.public_key << endl;
          using_outs_amount += gen_utils::uint64_t_cast(*out.m_amount);
          params.m_using_outs.push_back(std::move(out));
        }
        params.m_spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
        //
        // Recalculate fee, total incl fees
        needed_fee = estimate_fee(
          true/*use_per_byte_fee*/, use_rct,
          params.m_using_outs.size(), fake_outs_count, sending_amounts.size(), extra.size(),
          bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask
        );
        total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed
      }
      params.m_required_balance = total_incl_fees; // update required_balance b/c total_incl_fees changed
    }
    params.m_using_fee = needed_fee;
    //
    //cout << "Final attempt at fee: " << needed_fee << " for " << retVals.using_outs.size() << " inputs" << endl;
    //cout << "Balance to be used: " << total_incl_fees << endl;
    if (using_outs_amount < total_incl_fees) {
      // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point.
      throw std::runtime_error("need more money than found; using_outs_amount: " + std::to_string(using_outs_amount) + ", total_incl_fees: " + std::to_string(total_incl_fees) + ", needed_fee: " + std::to_string(needed_fee));
    }
    //
    // Change can now be calculated
    uint64_t change_amount = 0; // to initialize
    if (using_outs_amount > total_incl_fees) {
      if(is_sweeping) throw std::runtime_error("Unexpected total_incl_fees > using_outs_amount while sweeping");
      change_amount = using_outs_amount - total_incl_fees;
    }
    //cout << "Calculated change amount:" << change_amount << endl;
    params.m_change_amount = change_amount;
    //
    //uint64_t tx_estimated_weight = estimate_tx_weight(true/*use_rct*/, retVals.using_outs.size(), fake_outs_count, 1+1, extra.size(), true/*bulletproof*/);
    //if (tx_estimated_weight >= TX_WEIGHT_TARGET(get_upper_transaction_weight_limit(0, use_fork_rules_fn))) {
    // TODO?
    //}

    return params;
  }

  tied_spendable_to_random_outs tie_unspent_to_mix_outs(const std::vector<monero_light_output> &using_outs, std::vector<monero_light_random_outputs> mix_outs_from_server, const boost::optional<monero_light_spendable_random_outputs> &prior_attempt_unspent_outs_to_mix_outs) {
    // combine newly requested mix outs returned from the server, with the already known decoys from prior tx construction attempts,
    // so that the same decoys will be re-used with the same outputs in all tx construction attempts. This ensures fee returned
    // by calculate_fee() will be correct in the final tx, and also reduces number of needed trips to the server during tx construction.
    monero_light_spendable_random_outputs prior_attempt_unspent_outs_to_mix_outs_new;
    if (prior_attempt_unspent_outs_to_mix_outs) {
      prior_attempt_unspent_outs_to_mix_outs_new = *prior_attempt_unspent_outs_to_mix_outs;
    }

    std::vector<monero_light_random_outputs> mix_outs;
    mix_outs.reserve(using_outs.size());

    for (size_t i = 0; i < using_outs.size(); ++i) {
      auto out = using_outs[i];

      // if we don't already know of a particular out's mix outs (from a prior attempt),
      // then tie out to a set of mix outs retrieved from the server
      if (prior_attempt_unspent_outs_to_mix_outs_new.find(*out.m_public_key) == prior_attempt_unspent_outs_to_mix_outs_new.end()) {
        for (size_t j = 0; j < mix_outs_from_server.size(); ++j) {
          if ((out.m_rct != boost::none && gen_utils::uint64_t_cast(*mix_outs_from_server[j].m_amount) != 0) ||
            (out.m_rct == boost::none && mix_outs_from_server[j].m_amount != out.m_amount)) {
            continue;
          }

          monero_light_random_outputs output_mix_outs = pop_index(mix_outs_from_server, j);

          // if we need to retry constructing tx, will remember to use same mix outs for this out on subsequent attempt(s)
          prior_attempt_unspent_outs_to_mix_outs_new[*out.m_public_key] = *output_mix_outs.m_outputs;
          mix_outs.push_back(std::move(output_mix_outs));

          break;
        }
      } else {
        monero_light_random_outputs output_mix_outs;
        output_mix_outs.m_outputs = prior_attempt_unspent_outs_to_mix_outs_new[*out.m_public_key];
        output_mix_outs.m_amount = out.m_amount;
        mix_outs.push_back(std::move(output_mix_outs));
      }
    }

    // we expect to have a set of mix outs for every output in the tx
    if (mix_outs.size() != using_outs.size()) {
      throw std::runtime_error("not enough usable decoys found: " + std::to_string(mix_outs.size()));
    }

    // we expect to use up all mix outs returned by the server
    if (!mix_outs_from_server.empty()) {
      throw std::runtime_error("too many decoy remaining");
    }

    tied_spendable_to_random_outs result;
    result.m_mix_outs = std::move(mix_outs);
    result.m_prior_attempt_unspent_outs_to_mix_outs_new = std::move(prior_attempt_unspent_outs_to_mix_outs_new);

    return result;
  }

  monero_wallet_light::monero_wallet_light(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    m_light_client = new monero_light_client(std::move(http_client_factory));
  }

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close(false);
  }

  std::string monero_wallet_light::get_seed() const {
    MTRACE("monero_wallet_light::get_seed()");
    if (is_view_only()) throw std::runtime_error("The wallet is watch-only. Cannot retrieve seed.");
    return monero_wallet_keys::get_seed(); 
  }

  std::string monero_wallet_light::get_seed_language() const {
    if (is_view_only()) throw std::runtime_error("The wallet is watch-only. Cannot retrieve seed language.");
    return monero_wallet_keys::get_seed_language();
  }

  std::string monero_wallet_light::get_private_spend_key() const {
    MTRACE("monero_wallet_light::get_private_spend_key()");
    if (is_view_only()) throw std::runtime_error("The wallet is watch-only. Cannot retrieve spend key.");
    
    std::string spend_key = epee::string_tools::pod_to_hex(unwrap(unwrap(m_account.get_keys().m_spend_secret_key)));
    if (spend_key == "0000000000000000000000000000000000000000000000000000000000000000") spend_key = "";
    return spend_key;
  }

  void monero_wallet_light::set_daemon_connection(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy_uri) {
    if (m_light_client->is_connected()) m_light_client->disconnect();
    
    m_light_client->set_proxy(proxy_uri);
    m_light_client->set_server(uri);
    m_light_client->set_credentials(username, password);

    m_is_connected = is_connected_to_daemon();

    if (m_is_connected) {
      try { login(); }
      catch (...) { }
    }
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_rpc_connection> &connection) {    
    m_light_client->set_connection(connection);

    m_is_connected = is_connected_to_daemon();

    if (m_is_connected) {
      try { login(); }
      catch (...) { }
    }
  }

  boost::optional<monero_rpc_connection> monero_wallet_light::get_daemon_connection() const {
    monero_rpc_connection connection = m_light_client->get_connection();

    if (
      (connection.m_uri == boost::none || connection.m_uri->empty()) &&
      (connection.m_username == boost::none || connection.m_username->empty()) &&
      (connection.m_password == boost::none || connection.m_password->empty())
    ) {
      return boost::none;
    }

    return connection;
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    m_is_connected = m_light_client->is_connected();

    return m_is_connected;
  }

  uint64_t monero_wallet_light::get_daemon_height() const {
    const auto resp = get_address_info();

    if (resp.m_blockchain_height == boost::none) return 0;

    uint64_t height = *resp.m_blockchain_height;

    return height == 0 ? 0 : height + 1;
  }

  uint64_t monero_wallet_light::get_daemon_max_peer_height() const {
    return get_daemon_height();
  }

  void monero_wallet_light::add_listener(monero_wallet_listener& listener) {
    m_listeners.insert(&listener);
    m_wallet_listener->update_listening();
  }

  void monero_wallet_light::remove_listener(monero_wallet_listener& listener) {
    m_listeners.erase(&listener);
    m_wallet_listener->update_listening();
  }

  std::set<monero_wallet_listener*> monero_wallet_light::get_listeners() {
    return m_listeners;
  }

  monero_sync_result monero_wallet_light::sync() {
    MTRACE("sync()");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return lock_and_sync();
  }

  monero_sync_result monero_wallet_light::sync(monero_wallet_listener& listener) {
    MTRACE("sync(listener)");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // register listener
    add_listener(listener);

    // sync wallet
    monero_sync_result result = lock_and_sync(boost::none);

    // unregister listener
    remove_listener(listener);

    // return sync result
    return result;
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
    MTRACE("sync(" << start_height << ")");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return lock_and_sync(start_height);
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height, monero_wallet_listener& listener) {
    MTRACE("sync(" << start_height << ", listener)");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // wrap and register sync listener as wallet listener
    add_listener(listener);

    // sync wallet
    monero_sync_result result = lock_and_sync(start_height);

    // unregister sync listener
    remove_listener(listener);

    // return sync result
    return result;
  }

  void monero_wallet_light::start_syncing(uint64_t sync_period_in_ms) {
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    m_syncing_interval = sync_period_in_ms;
    if (!m_syncing_enabled) {
      m_syncing_enabled = true;
      run_sync_loop(); // sync wallet on loop in background
    }
  }

  void monero_wallet_light::stop_syncing() {
    m_syncing_enabled = false;
    //m_w2->stop();
  }

  void monero_wallet_light::scan_txs(const std::vector<std::string>& tx_ids) {
    sync();
  }

  void monero_wallet_light::rescan_spent() {
    sync();
  }

  void monero_wallet_light::rescan_blockchain() {
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    const auto response = import_request();

    if (response.m_payment_address != boost::none) throw std::runtime_error("Payment required");
    if (!response.m_request_fullfilled) throw std::runtime_error("Could not fullfill rescan request");
    
    m_rescan_on_sync = true;
    lock_and_sync();
  }

  bool monero_wallet_light::is_daemon_synced() const {
    return true;
  }

  bool monero_wallet_light::is_daemon_trusted() const {
    return true;
  }

  bool monero_wallet_light::is_synced() const {
    if (!is_connected_to_daemon()) return false;

    const auto resp = get_address_info();

    if (*resp.m_blockchain_height <= 1) {
      return false;
    }

    return *resp.m_scanned_block_height == *resp.m_blockchain_height;
  }

  monero_subaddress monero_wallet_light::get_address_index(const std::string& address) const {
    if (!monero_utils::is_valid_address(address, m_network_type)) throw std::runtime_error("Invalid address");

    std::string _address;

    try {
      auto integrated_address = decode_integrated_address(address);
      _address = integrated_address.m_standard_address;
    }
    catch (...) {
      _address = address;
    }
    
    auto subaddresses = get_subaddresses();

    for (auto subaddress : subaddresses) {
      if (_address == *subaddress.m_address) {
        return subaddress;
      }
    }

    throw std::runtime_error("Address doesn't belong to the wallet");
  }

  uint64_t monero_wallet_light::get_height() const {
    const auto resp = get_address_info();

    if (resp.m_scanned_block_height == boost::none) return 0;

    uint64_t height = *resp.m_scanned_block_height;

    return height + 1;
  }

  uint64_t monero_wallet_light::get_restore_height() const {
    const auto resp = get_address_info();

    if (resp.m_start_height == boost::none) return 0;

    uint64_t height = *resp.m_start_height;

    return height;
  }

  uint64_t monero_wallet_light::get_balance() const {
    return m_wallet_balance;
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_index) const {
    auto account_balance = m_account_balance_container.find(account_index);

    if (account_balance == m_account_balance_container.end()) {
      return 0;
    }
    else {
      return account_balance->second;
    }
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto account_subaddress_balance = m_subaddress_balance_container.find(account_idx);
    if (account_subaddress_balance == m_subaddress_balance_container.end()) {
      return 0;
    }

    auto subaddress_balance = account_subaddress_balance->second.find(subaddress_idx);
    if (subaddress_balance == account_subaddress_balance->second.end()) {
      return 0;
    }
    
    return subaddress_balance->second;
  }

  uint64_t monero_wallet_light::get_unlocked_balance() const {
    return m_wallet_unlocked_balance;
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_index) const {
    auto account_balance = m_account_unlocked_balance_container.find(account_index);

    if (account_balance == m_account_unlocked_balance_container.end()) {
      return 0;
    }
    else {
      return account_balance->second;
    }
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto account_subaddress_balance = m_subaddress_unlocked_balance_container.find(account_idx);
    if (account_subaddress_balance == m_subaddress_unlocked_balance_container.end()) {
      return 0;
    }

    auto subaddress_balance = account_subaddress_balance->second.find(subaddress_idx);
    if (subaddress_balance == account_subaddress_balance->second.end()) {
      return 0;
    }
    
    return subaddress_balance->second;
  }

  std::vector<monero_account> monero_wallet_light::get_accounts(bool include_subaddresses, const std::string& tag) const {
    std::cout << "monero_wallet_light::get_accounts()" << std::endl;

    std::vector<monero_account> result;
    bool default_found = false;

    const auto all_subaddrs = m_subaddrs.m_all_subaddrs;

    if (all_subaddrs != boost::none) {
      for (auto kv : all_subaddrs.get()) {
        if (kv.first == 0) default_found = true;
        monero_account account = get_account(kv.first, include_subaddresses);
        result.push_back(account);
      }
    }

    if (!default_found) {
      monero_account primary_account = get_account(0, include_subaddresses);
      result.push_back(primary_account);
    }

    return result;
  }

  monero_account monero_wallet_light::get_account(const uint32_t account_idx, bool include_subaddresses) const {
    std::cout << "monero_wallet_light::get_account(" << account_idx << ")" << std::endl;

    const auto subaddrs = m_subaddrs.m_all_subaddrs;

    if (account_idx != 0 && (subaddrs == boost::none || subaddrs->empty())) throw std::runtime_error("Account out of bounds"); 
    
    bool upsert = account_idx == 0;

    if (!upsert) {
      const auto all_subaddrs = subaddrs.get();
      for (auto kv : all_subaddrs) {
        if (kv.first == account_idx) {
          upsert = true;
          break;
        } 
      }
    }

    if (!upsert) throw std::runtime_error("account not upsert: " + std::to_string(account_idx));

    monero_account account = monero_wallet_keys::get_account(account_idx, false);

    account.m_balance = get_balance(account_idx);
    account.m_unlocked_balance = get_unlocked_balance(account_idx);

    try {
      boost::optional<std::string> label = get_subaddress_label(account_idx, 0);
      if (label != boost::none && !label->empty()) account.m_tag = label;
    }
    catch (...) {
      account.m_tag = boost::none;
    }

    if (include_subaddresses) {
      account.m_subaddresses = monero_wallet::get_subaddresses(account_idx);
      if (account.m_subaddresses.empty()) account.m_subaddresses.push_back(get_subaddress(account_idx, 0));
    }

    return account;
  }

  monero_account monero_wallet_light::create_account(const std::string& label) {
    uint32_t last_account_idx = 0;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      const auto all_subaddrs = m_subaddrs.m_all_subaddrs.get();
      for (auto kv : all_subaddrs) {
        if (kv.first > last_account_idx) {
          last_account_idx = kv.first;
        }
      }
    }

    uint32_t account_idx = last_account_idx + 1;

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(0, 0);

    subaddrs[account_idx] = std::vector<monero_light_index_range>();
    subaddrs[account_idx].push_back(index_range);

    m_subaddrs.m_all_subaddrs = upsert_subaddrs(subaddrs, true).m_all_subaddrs;

    monero_account account = monero_wallet_keys::get_account(account_idx, false);

    account.m_balance = 0;
    account.m_unlocked_balance = 0;

    if (label.empty()) account.m_tag = boost::none;
    else account.m_tag = label;

    set_subaddress_label(account_idx, 0, label);

    return account;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses_aux(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    // must provide subaddress indices
    std::vector<uint32_t> subaddress_idxs;

    if (subaddress_indices.empty() && m_subaddrs.m_all_subaddrs != boost::none) {
      const auto all_subaddrs = m_subaddrs.m_all_subaddrs.get();
      for (auto kv : all_subaddrs) {
        if (kv.first != account_idx) continue;

        for (auto index_range : kv.second) {
          for (auto subaddress_idx : index_range.to_subaddress_indices()) {
            subaddress_idxs.push_back(subaddress_idx);
          }
        }
      }
    }
    else {
      subaddress_idxs = subaddress_indices;
    }
    if (subaddress_idxs.empty()) {
      return std::vector<monero_subaddress>();
    }

    // initialize subaddresses at indices
    return monero_wallet_keys::get_subaddresses(account_idx, subaddress_idxs);
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    std::vector<monero_subaddress> subaddresses = get_subaddresses_aux(account_idx, subaddress_indices);

    for (auto &subaddress : subaddresses) {
      subaddress.m_label = get_subaddress_label(account_idx, *subaddress.m_index);
      subaddress.m_balance = get_balance(account_idx, *subaddress.m_index);
      subaddress.m_unlocked_balance = get_unlocked_balance(account_idx, *subaddress.m_index);
      subaddress.m_num_unspent_outputs = get_subaddress_num_unspent_outs(account_idx, *subaddress.m_index);
      subaddress.m_is_used = subaddress_is_used(account_idx, *subaddress.m_index);
      subaddress.m_num_blocks_to_unlock = get_subaddress_num_blocks_to_unlock(account_idx, *subaddress.m_index);
    }

    return subaddresses;
  }

  monero_subaddress monero_wallet_light::create_subaddress(uint32_t account_idx, const std::string& label) {
    bool account_found = false;
    uint32_t last_subaddress_idx = 0;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      const auto all_subaddrs = m_subaddrs.m_all_subaddrs.get();
      for (auto kv : all_subaddrs) {
        if (kv.first != account_idx) continue;

        account_found = true;

        for (auto index_range : kv.second) {
          last_subaddress_idx = index_range.at(1);
        }

        break;
      }
    }

    if (!account_found) {
      throw std::runtime_error("create_subaddress(): account index out of bounds");
    }

    uint32_t subaddress_idx = last_subaddress_idx + 1;

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(last_subaddress_idx, subaddress_idx);

    subaddrs[account_idx] = std::vector<monero_light_index_range>();
    subaddrs[account_idx].push_back(index_range);

    m_subaddrs.m_all_subaddrs = upsert_subaddrs(subaddrs, true).m_all_subaddrs;

    monero_subaddress subaddress = get_subaddress(account_idx, subaddress_idx);

    set_subaddress_label(account_idx, subaddress_idx, label);
    subaddress.m_label = label;
    subaddress.m_balance = 0;
    subaddress.m_unlocked_balance = 0;
    subaddress.m_num_unspent_outputs = 0;
    subaddress.m_is_used = false;
    subaddress.m_num_blocks_to_unlock = 0;

    return subaddress;
  }

  monero_subaddress monero_wallet_light::get_subaddress(const uint32_t account_idx, const uint32_t subaddress_idx) const {
    std::vector<uint32_t> indices;

    indices.push_back(subaddress_idx);

    auto subaddresses = monero_wallet_keys::get_subaddresses(account_idx, indices);

    monero_subaddress &subaddress = subaddresses[0];

    subaddress.m_balance = get_balance(account_idx, subaddress_idx);
    subaddress.m_unlocked_balance = get_unlocked_balance(account_idx, subaddress_idx);
    subaddress.m_label = get_subaddress_label(account_idx, subaddress_idx);
    subaddress.m_num_unspent_outputs = get_subaddress_num_unspent_outs(account_idx, subaddress_idx);
    subaddress.m_is_used = subaddress_is_used(account_idx, subaddress_idx);
    subaddress.m_num_blocks_to_unlock = get_subaddress_num_blocks_to_unlock(account_idx, subaddress_idx);

    return subaddress;
  }

  void monero_wallet_light::set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label) {
    //get_subaddress(account_idx, subaddr_account_idx);
    m_subaddress_labels[account_idx][subaddress_idx] = label;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    MTRACE("relay_txs()");

    // relay each metadata as a tx
    std::vector<std::string> tx_hashes;
    for (const auto& txMetadata : tx_metadatas) {

      // parse tx metadata hex
      cryptonote::blobdata blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(txMetadata, blob)) {
        throw std::runtime_error("Failed to parse hex");
      }

      // deserialize tx
      bool loaded = false;
      tools::wallet2::pending_tx ptx;
      try {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
        if (::serialization::serialize(ar, ptx)) loaded = true;
      } catch (...) {}
      if (!loaded) {
        try {
          std::istringstream iss(blob);
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> ptx;
          loaded = true;
        } catch (...) {}
      }
      if (!loaded) throw std::runtime_error("Failed to parse tx metadata");

      // commit tx
      try {
        m_light_client->submit_raw_tx(epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx)));
      } catch (const std::exception& e) {
        throw std::runtime_error("Failed to commit tx");
      }

      // collect resulting hash
      tx_hashes.push_back(epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
    }

    // notify listeners of spent funds
    m_wallet_listener->on_spend_tx_hashes(tx_hashes);

    // return relayed tx hashes
    return tx_hashes;
  }

  monero_tx_set monero_wallet_light::describe_tx_set(const monero_tx_set& tx_set) {

    // get unsigned and multisig tx sets
    std::string unsigned_tx_hex = tx_set.m_unsigned_tx_hex == boost::none ? "" : tx_set.m_unsigned_tx_hex.get();
    std::string multisig_tx_hex = tx_set.m_multisig_tx_hex == boost::none ? "" : tx_set.m_multisig_tx_hex.get();

    // validate request
    if (key_on_device()) throw std::runtime_error("command not supported by HW wallet");
    if (is_view_only()) throw std::runtime_error("command not supported by view-only wallet");
    if (unsigned_tx_hex.empty() && multisig_tx_hex.empty()) throw std::runtime_error("no txset provided");

    std::vector <tools::wallet2::tx_construction_data> tx_constructions;
    if (!unsigned_tx_hex.empty()) {
      try {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");
        tools::wallet2::unsigned_tx_set exported_txs = parse_unsigned_tx(blob);
        tx_constructions = exported_txs.txes;
      }
      catch (const std::exception &e) {
        throw std::runtime_error("failed to parse unsigned transfers: " + std::string(e.what()));
      }
    } else if (!multisig_tx_hex.empty()) {
      throw std::runtime_error("monero_wallet_light::describe_tx_set(): multisign not supported");
      /*
      try {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(multisig_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");
        tools::wallet2::multisig_tx_set exported_txs = parse_multisig_tx(blob, exported_txs);
        for (uint64_t n = 0; n < exported_txs.m_ptx.size(); ++n) {
          tx_constructions.push_back(exported_txs.m_ptx[n].construction_data);
        }
      }
      catch (const std::exception &e) {
        throw std::runtime_error("failed to parse multisig transfers: " + std::string(e.what()));
      }
      */
    }

    std::vector<tools::wallet2::pending_tx> ptx;  // TODO wallet_rpc_server: unused variable
    try {

      // gather info for each tx
      std::vector<std::shared_ptr<monero_tx_wallet>> txs;
      std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> dests;
      int first_known_non_zero_change_index = -1;
      for (int64_t n = 0; n < tx_constructions.size(); ++n)
      {
        // init tx
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
        tx->m_is_outgoing = true;
        tx->m_input_sum = 0;
        tx->m_output_sum = 0;
        tx->m_change_amount = 0;
        tx->m_num_dummy_outputs = 0;
        tx->m_ring_size = std::numeric_limits<uint32_t>::max(); // smaller ring sizes will overwrite

        const tools::wallet2::tx_construction_data &cd = tx_constructions[n];
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        bool has_encrypted_payment_id = false;
        crypto::hash8 payment_id8 = crypto::null_hash8;
        if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields))
        {
          cryptonote::tx_extra_nonce extra_nonce;
          if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
          {
            crypto::hash payment_id;
            if(cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
            {
              if (payment_id8 != crypto::null_hash8)
              {
                tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id8);
                has_encrypted_payment_id = true;
              }
            }
            else if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
            {
              tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
            }
          }
        }

        for (uint64_t s = 0; s < cd.sources.size(); ++s)
        {
          tx->m_input_sum = tx->m_input_sum.get() + cd.sources[s].amount;
          uint64_t ring_size = cd.sources[s].outputs.size();
          if (ring_size < tx->m_ring_size.get())
            tx->m_ring_size = ring_size;
        }
        for (uint64_t d = 0; d < cd.splitted_dsts.size(); ++d)
        {
          const cryptonote::tx_destination_entry &entry = cd.splitted_dsts[d];
          std::string address = cryptonote::get_account_address_as_str(get_nettype(), entry.is_subaddress, entry.addr);
          if (has_encrypted_payment_id && !entry.is_subaddress && address != entry.original)
            address = cryptonote::get_account_integrated_address_as_str(get_nettype(), entry.addr, payment_id8);
          auto i = dests.find(entry.addr);
          if (i == dests.end())
            dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
          else
            i->second.second += entry.amount;
          tx->m_output_sum = tx->m_output_sum.get() + entry.amount;
        }
        if (cd.change_dts.amount > 0)
        {
          auto it = dests.find(cd.change_dts.addr);
          if (it == dests.end()) throw std::runtime_error("Claimed change does not go to a paid address");
          if (it->second.second < cd.change_dts.amount) throw std::runtime_error("Claimed change is larger than payment to the change address");
          if (cd.change_dts.amount > 0)
          {
            if (first_known_non_zero_change_index == -1)
              first_known_non_zero_change_index = n;
            const tools::wallet2::tx_construction_data &cdn = tx_constructions[first_known_non_zero_change_index];
            if (memcmp(&cd.change_dts.addr, &cdn.change_dts.addr, sizeof(cd.change_dts.addr))) throw std::runtime_error("Change goes to more than one address");
          }
          tx->m_change_amount = tx->m_change_amount.get() + cd.change_dts.amount;
          it->second.second -= cd.change_dts.amount;
          if (it->second.second == 0)
            dests.erase(cd.change_dts.addr);
        }

        tx->m_outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
        uint64_t n_dummy_outputs = 0;
        for (auto i = dests.begin(); i != dests.end(); )
        {
          if (i->second.second > 0)
          {
            std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
            destination->m_address = i->second.first;
            destination->m_amount = i->second.second;
            tx->m_outgoing_transfer.get()->m_destinations.push_back(destination);
          }
          else
            tx->m_num_dummy_outputs = tx->m_num_dummy_outputs.get() + 1;
          ++i;
        }

        if (tx->m_change_amount.get() > 0)
        {
          const tools::wallet2::tx_construction_data &cd0 = tx_constructions[0];
          tx->m_change_address = get_account_address_as_str(get_nettype(), cd0.subaddr_account > 0, cd0.change_dts.addr);
        }

        tx->m_fee = tx->m_input_sum.get() - tx->m_output_sum.get();
        tx->m_unlock_time = cd.unlock_time;
        tx->m_extra_hex = epee::to_hex::string({cd.extra.data(), cd.extra.size()});
        txs.push_back(tx);
      }

      // build and return tx set
      monero_tx_set tx_set;
      tx_set.m_txs = txs;
      return tx_set;
    }
    catch (const std::exception &e)
    {
      throw std::runtime_error("failed to parse unsigned transfers");
    }
  }

  // implementation based on monero-project wallet_rpc_server.cpp::on_sign_transfer()
  monero_tx_set monero_wallet_light::sign_txs(const std::string& unsigned_tx_hex) {
    if (key_on_device()) throw std::runtime_error("command not supported by HW wallet");
    if (is_view_only()) throw std::runtime_error("command not supported by view-only wallet");

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");

    tools::wallet2::unsigned_tx_set exported_txs = parse_unsigned_tx(blob);

    std::vector<tools::wallet2::pending_tx> ptxs;
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    try {
      tools::wallet2::signed_tx_set signed_txs;
      std::string ciphertext = sign_tx(exported_txs, ptxs, signed_txs);
      if (ciphertext.empty()) throw std::runtime_error("Failed to sign unsigned tx");

      // init tx set
      monero_tx_set tx_set;
      tx_set.m_signed_tx_hex = epee::string_tools::buff_to_hex_nodelimer(ciphertext);
      for (auto &ptx : ptxs) {

        // init tx
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
        tx->m_is_outgoing = true;
        tx->m_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
        tx->m_key = epee::string_tools::pod_to_hex(unwrap(unwrap(ptx.tx_key)));
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys) {
            tx->m_key = tx->m_key.get() += epee::string_tools::pod_to_hex(unwrap(unwrap(additional_tx_key)));
        }
        tx_set.m_txs.push_back(tx);
      }
      return tx_set;
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to sign unsigned tx: ") + e.what());
    }
  }

  std::vector<std::string> monero_wallet_light::submit_txs(const std::string& signed_tx_hex) {
    if (key_on_device()) throw std::runtime_error("command not supported by HW wallet");

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(signed_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");
    
    std::vector<tools::wallet2::pending_tx> ptx_vector;
    
    try {
      ptx_vector = parse_signed_tx(blob);
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to parse signed tx: ") + e.what());
    }

    try {
      std::vector<std::string> tx_hashes;
      for (auto &ptx: ptx_vector) {
        std::cout << "submit_txs(): before submit raw tx" << std::endl;
        const auto res = m_light_client->submit_raw_tx(epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(ptx.tx)));
        if (res.m_status == boost::none || res.m_status.get() != std::string("OK")) throw std::runtime_error("Could not relay tx" + signed_tx_hex);
        std::cout << "submit_txs(): before get transaction hash" << std::endl;
        crypto::hash txid;
        txid = cryptonote::get_transaction_hash(ptx.tx);
        std::cout << "submit_txs(): after get transaction hash" << std::endl;
        tx_hashes.push_back(epee::string_tools::pod_to_hex(txid));
        std::cout << "submit_txs(): after push transaction hash" << std::endl;
      }

      std::cout << "submit_txs(): before listener call" << std::endl;
      m_wallet_listener->on_spend_tx_hashes(tx_hashes); // notify listeners of spent funds
      std::cout << "submit_txs(): before after listener call" << std::endl;
      return tx_hashes;
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to submit signed tx: ") + e.what());
    }

    /*
    std::vector<std::string> hashes;
    
    const auto res = m_light_client->submit_raw_tx(signed_tx_hex);

    if (!res.m_status) throw std::runtime_error("Could not relay tx" + signed_tx_hex);

    m_wallet_listener->on_spend_tx_hashes(hashes);

    return hashes;
    */
  }

  std::string monero_wallet_light::get_tx_key(const std::string& tx_hash) const {
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

  void monero_wallet_light::freeze_output(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to freeze");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");

    auto found = std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image);

    if (found == m_frozen_key_images.end()) {
      m_frozen_key_images.push_back(key_image);
    }
  }

  void monero_wallet_light::thaw_output(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");
    
    m_frozen_key_images.erase(std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image));
  }

  bool monero_wallet_light::is_output_frozen(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");
    
    const auto found = std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image);

    return found != m_frozen_key_images.end();
  }

  monero_tx_priority monero_wallet_light::get_default_fee_priority() const {
    return static_cast<monero_tx_priority>(get_default_priority());
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::create_txs(const monero_tx_config& config) {
    std::cout << "monero_wallet_light::create_txs()" << std::endl;
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    // validate config
    if (config.m_account_index == boost::none) throw std::runtime_error("Must specify account index to send from");
    uint32_t subaddr_account_idx = config.m_account_index.get();

    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_data_mutex);
    
    std::vector<std::shared_ptr<monero_tx_wallet>> result;
    uint64_t amount = 0;
    std::vector<uint64_t> sending_amounts;
    std::vector<std::string> dests;
    std::string multisig_tx_hex;
    std::string unsigned_tx_hex;
    tools::wallet2::pending_tx ptx;

    for(auto &dest : config.get_normalized_destinations()) {
      auto dest_address = *dest->m_address;
      if (!monero_utils::is_valid_address(dest_address, m_network_type)) throw std::runtime_error("Invalid destination address");
      dests.push_back(dest_address);
      sending_amounts.push_back(*dest->m_amount);
      amount += *dest->m_amount;
    }

    if (config.m_payment_id != boost::none && !config.m_payment_id->empty()) throw std::runtime_error("Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead");

    const auto unspent_outs_res = get_spendable_outs(subaddr_account_idx, config.m_subaddress_indices, 0, get_mixin_size());

    uint64_t fee_per_b = gen_utils::uint64_t_cast(*unspent_outs_res.m_per_byte_fee);
    uint64_t fee_mask = gen_utils::uint64_t_cast(*unspent_outs_res.m_fee_mask);
    if (unspent_outs_res.m_outputs == boost::none) throw std::runtime_error("not enough unlocked money");

    const auto unspent_outs = *unspent_outs_res.m_outputs;

    std::cout << "Got spendable outs: " << unspent_outs.size() << ", total: " << unspent_outs_res.m_amount.get() << ", requested: " << amount << std::endl;

    if (unspent_outs.empty()) throw std::runtime_error("not enough unlocked money");

    auto payment_id = config.m_payment_id;
    bool is_sweeping = config.m_sweep_each_subaddress != boost::none ? *config.m_sweep_each_subaddress : false;
    auto simple_priority = config.m_priority == boost::none ? 0 : config.m_priority.get();
    
    m_prior_attempt_size_calcd_fee = boost::none;
    m_prior_attempt_unspent_outs_to_mix_outs = boost::none;
    m_construction_attempt = 0;
    
    const auto random_outs_params = prepare_get_random_outs_params(payment_id, sending_amounts, is_sweeping, simple_priority, unspent_outs, fee_per_b, fee_mask, m_prior_attempt_size_calcd_fee, m_prior_attempt_unspent_outs_to_mix_outs);

    if(random_outs_params.m_using_outs.size() == 0) throw std::runtime_error("Expected non-0 using_outs");
    std::cout << "random_outs_params.m_using_outs: " << random_outs_params.m_using_outs.size() << std::endl;

    const auto random_outs_res = get_random_outs(random_outs_params.m_using_outs);

    auto tied_outs = tie_unspent_to_mix_outs(random_outs_params.m_using_outs, *random_outs_res.m_amount_outs, m_prior_attempt_unspent_outs_to_mix_outs);

    monero_light_constructed_transaction constructed_tx = create_transaction(subaddr_account_idx, dests, config.m_payment_id, sending_amounts, random_outs_params.m_change_amount, random_outs_params.m_using_fee, random_outs_params.m_using_outs, tied_outs.m_mix_outs, 0);
    
    if (constructed_tx.m_tx != boost::none) ptx.tx = constructed_tx.m_tx.get();
    
    std::cout << "monero_wallet_light::create_txs(): created tx" << std::endl;
 
    std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
    
    bool relayed = false;
    bool relay = config.m_relay == boost::none ? false : config.m_relay.get();
    if (relay) {
      try {
        std::cout << "monero_wallet_light::create_txs(): before relay" << std::endl;
        auto submit_res = m_light_client->submit_raw_tx(*constructed_tx.m_signed_serialized_tx_string);
        std::cout << "monero_wallet_light::create_txs(): after relay" << std::endl;

        if (submit_res.m_status != boost::none && submit_res.m_status == std::string("OK")) {
          relayed = true;
        }
      }
      catch(...) { }
    }

    tx->m_in_tx_pool = relayed;
    tx->m_is_relayed = relayed;
    tx->m_relay = relay;
    tx->m_is_confirmed = false;
    tx->m_is_miner_tx = false;
    tx->m_is_outgoing = true;
    tx->m_is_failed = relay && !relayed;
    tx->m_payment_id = config.m_payment_id;
    tx->m_hash = constructed_tx.m_tx_hash_string;
    tx->m_num_confirmations = 0;
    tx->m_ring_size = monero_utils::RING_SIZE;
    tx->m_unlock_time = 0;
    tx->m_is_locked = true;
    if (relayed) {
      tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
      tx->m_is_double_spend_seen = false;
    }
    tx->m_key = constructed_tx.m_tx_key_string;
    tx->m_unlock_time = constructed_tx.m_tx->unlock_time;
    tx->m_extra = constructed_tx.m_tx->extra;
    tx->m_prunable_hash = epee::string_tools::pod_to_hex(constructed_tx.m_tx->prunable_hash);
    tx->m_version = constructed_tx.m_tx->version;
    tx->m_full_hex = constructed_tx.m_signed_serialized_tx_string;
    tx->m_fee = constructed_tx.m_fee;
    tx->m_weight = constructed_tx.m_weight;
    tx->m_metadata = dump_ptx(ptx);

    std::cout << "monero_wallet_light::create_txs(): created tx A" << std::endl;
 
    if (is_view_only()) {
      unsigned_tx_hex = dump_pending_tx(constructed_tx, config.m_payment_id);
      if (unsigned_tx_hex.empty()) {
        throw std::runtime_error("Failed to save unsigned tx set after creation");
      }
    }
    else if (is_multisig()) {
      //multisig_tx_hex = constructed_tx.m_signed_serialized_tx_string.get();
    }

    std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
    outgoing_transfer->m_tx = tx;
    tx->m_outgoing_transfer = outgoing_transfer;

    outgoing_transfer->m_account_index = config.m_account_index;
    if (config.m_subaddress_indices.size() == 1) outgoing_transfer->m_subaddress_indices.push_back(config.m_subaddress_indices[0]);  // subaddress index is known iff 1 requested  // TODO: get all known subaddress indices here
    outgoing_transfer->m_destinations = config.m_destinations;
    outgoing_transfer->m_amount = amount;

    std::cout << "monero_wallet_light::create_txs(): spent key images: " << constructed_tx.m_spent_key_images->size() << std::endl;

    // init inputs with key images
    std::vector<std::string> input_key_images = constructed_tx.m_spent_key_images.get();
    for (const std::string& input_key_image : input_key_images) {
      std::shared_ptr<monero_output_wallet> input = std::make_shared<monero_output_wallet>();
      input->m_tx = tx;
      tx->m_inputs.push_back(input);
      input->m_key_image = std::make_shared<monero_key_image>();
      input->m_key_image.get()->m_hex = input_key_image;

      m_key_images_in_pool->push_back(input_key_image);
    }

    const tools::wallet2::tx_construction_data cdata = constructed_tx.m_construction_data.get();

    tx->m_change_amount = cdata.change_dts.amount;
    //tx->m_change_address = cdata.change_dts.;

    //init outputs

    result.push_back(tx);
    std::cout << "monero_wallet_light::create_txs(): created tx C" << std::endl;
    // build tx set
    std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
    tx_set->m_txs = result;
    for (int i = 0; i < result.size(); i++) result[i]->m_tx_set = tx_set;
    if (!multisig_tx_hex.empty()) tx_set->m_multisig_tx_hex = multisig_tx_hex;
    if (!unsigned_tx_hex.empty()) tx_set->m_unsigned_tx_hex = unsigned_tx_hex;

    std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
    tx->copy(tx, tx_wallet);
    m_unconfirmed_txs->push_back(tx_wallet);

    calculate_balance();

    if (relayed) {
      // store tx info
      m_wallet_listener->on_spend_txs(result);
    }

    return result;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs() const {
    return get_txs(monero_tx_query());
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs(const monero_tx_query& query) const {
    MTRACE("monero_wallet_light::get_txs(query)");

    // copy query
    std::shared_ptr<monero_tx_query> query_sp = std::make_shared<monero_tx_query>(query); // convert to shared pointer
    std::shared_ptr<monero_tx_query> _query = query_sp->copy(query_sp, std::make_shared<monero_tx_query>()); // deep copy

    // temporarily disable transfer and output queries in order to collect all tx context
    boost::optional<std::shared_ptr<monero_transfer_query>> transfer_query = _query->m_transfer_query;
    boost::optional<std::shared_ptr<monero_output_query>> input_query = _query->m_input_query;
    boost::optional<std::shared_ptr<monero_output_query>> output_query = _query->m_output_query;
    _query->m_transfer_query = boost::none;
    _query->m_input_query = boost::none;
    _query->m_output_query = boost::none;

    // fetch all transfers that meet tx query
    std::shared_ptr<monero_transfer_query> temp_transfer_query = std::make_shared<monero_transfer_query>();
    temp_transfer_query->m_tx_query = monero_utils::decontextualize(_query->copy(_query, std::make_shared<monero_tx_query>()));
    temp_transfer_query->m_tx_query.get()->m_transfer_query = temp_transfer_query;
    std::vector<std::shared_ptr<monero_transfer>> transfers = get_transfers_aux(*temp_transfer_query);
    monero_utils::free(temp_transfer_query->m_tx_query.get());

    // collect unique txs from transfers while retaining order
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();
    std::unordered_set<std::shared_ptr<monero_tx_wallet>> txsSet;
    for (const std::shared_ptr<monero_transfer>& transfer : transfers) {
      if (txsSet.find(transfer->m_tx) == txsSet.end()) {
        txs.push_back(transfer->m_tx);
        txsSet.insert(transfer->m_tx);
      }
    }

    // cache types into maps for merging and lookup
    std::map<std::string, std::shared_ptr<monero_tx_wallet>> tx_map;
    std::map<uint64_t, std::shared_ptr<monero_block>> block_map;
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      monero_utils::merge_tx(tx, tx_map, block_map);
    }

    // fetch and merge outputs if requested
    if ((_query->m_include_outputs != boost::none && *_query->m_include_outputs) || output_query != boost::none) {
      std::shared_ptr<monero_output_query> temp_output_query = std::make_shared<monero_output_query>();
      temp_output_query->m_tx_query = monero_utils::decontextualize(_query->copy(_query, std::make_shared<monero_tx_query>()));
      temp_output_query->m_tx_query.get()->m_output_query = temp_output_query;
      std::vector<std::shared_ptr<monero_output_wallet>> outputs = get_outputs_aux(*temp_output_query);
      monero_utils::free(temp_output_query->m_tx_query.get());

      // merge output txs one time while retaining order
      std::unordered_set<std::shared_ptr<monero_tx_wallet>> output_txs;
      for (const std::shared_ptr<monero_output_wallet>& output : outputs) {
        std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(output->m_tx);
        if (output_txs.find(tx) == output_txs.end()) {
          monero_utils::merge_tx(tx, tx_map, block_map);
          output_txs.insert(tx);
        }
      }
    }

    // restore transfer and output queries
    _query->m_transfer_query = transfer_query;
    _query->m_input_query = input_query;
    _query->m_output_query = output_query;

    // filter txs that don't meet transfer query
    std::vector<std::shared_ptr<monero_tx_wallet>> queried_txs;
    std::vector<std::shared_ptr<monero_tx_wallet>>::iterator tx_iter = txs.begin();
    while (tx_iter != txs.end()) {
      std::shared_ptr<monero_tx_wallet> tx = *tx_iter;
      if (_query->meets_criteria(tx.get())) {
        queried_txs.push_back(tx);
        tx_iter++;
      } else {
        tx_map.erase(tx->m_hash.get());
        tx_iter = txs.erase(tx_iter);
        if (tx->m_block != boost::none) tx->m_block.get()->m_txs.erase(std::remove(tx->m_block.get()->m_txs.begin(), tx->m_block.get()->m_txs.end(), tx), tx->m_block.get()->m_txs.end()); // TODO, no way to use tx_iter?
      }
    }
    txs = queried_txs;

    // special case: re-fetch txs if inconsistency caused by needing to make multiple wallet calls  // TODO monero-project: offer wallet.get_txs(...)
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      if (*tx->m_is_confirmed && tx->m_block == boost::none || !*tx->m_is_confirmed & tx->m_block != boost::none) {
        std::cout << "WARNING: Inconsistency detected building txs from multiple wallet2 calls, re-fetching" << std::endl;
        monero_utils::free(txs);
        txs.clear();
        txs = get_txs(*_query);
        monero_utils::free(_query);
        return txs;
      }
    }

    // if tx hashes requested, order txs
    if (!_query->m_hashes.empty()) {
      txs.clear();
      for (const std::string& tx_hash : _query->m_hashes) {
        std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.find(tx_hash);
        if (tx_iter != tx_map.end()) txs.push_back(tx_iter->second);
      }
    }

    // free query and return
    monero_utils::free(_query);
    return txs;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers(const monero_transfer_query& query) const {
    // get transfers directly if query does not require tx context (e.g. other transfers, outputs)
    if (!monero_utils::is_contextual(query)) return get_transfers_aux(query);

    // otherwise get txs with full models to fulfill query
    std::vector<std::shared_ptr<monero_transfer>> transfers;
    for (const std::shared_ptr<monero_tx_wallet>& tx : get_txs(*(query.m_tx_query.get()))) {
      for (const std::shared_ptr<monero_transfer>& transfer : tx->filter_transfers(query)) { // collect queried transfers, erase if excluded
        transfers.push_back(transfer);
      }
    }
    return transfers;
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
    // get outputs directly if query does not require tx context (e.g. other outputs, transfers)
    if (!monero_utils::is_contextual(query)) return get_outputs_aux(query);

    // otherwise get txs with full models to fulfill query
    std::vector<std::shared_ptr<monero_output_wallet>> outputs;
    for (const std::shared_ptr<monero_tx_wallet>& tx : get_txs(*(query.m_tx_query.get()))) {
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(query)) { // collect queried outputs, erase if excluded
        outputs.push_back(output);
      }
    }
    return outputs;
  }

  std::shared_ptr<monero_tx_wallet> get_output_transaction(monero_light_output &out, const std::vector<monero_light_transaction> &transactions, uint64_t current_height, std::vector<std::shared_ptr<monero_block>> &blocks) {
    for (const auto &transaction : transactions) {
      if (out.m_tx_hash.get() == transaction.m_hash.get()) {
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();

        tx->m_hash = transaction.m_hash;
        tx->m_is_confirmed = true;

        uint64_t total_sent = gen_utils::uint64_t_cast(*transaction.m_total_sent);    
        const uint64_t total_received = gen_utils::uint64_t_cast(*transaction.m_total_received);
        
        const uint64_t fee = gen_utils::uint64_t_cast(*transaction.m_fee);
        
        const bool is_incoming = total_received > 0;
        const bool is_outgoing = total_sent > 0;
        const bool is_change = is_incoming && is_outgoing;

        if (is_change) total_sent -= total_received;

        const bool is_locked = *transaction.m_unlock_time > current_height || current_height < (*transaction.m_height) + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
        const bool is_confirmed = !transaction.m_mempool.get();
        const bool is_miner_tx = *transaction.m_coinbase == true;
              
        const uint64_t timestamp = gen_utils::timestamp_to_epoch(*transaction.m_timestamp);
        const uint64_t transaction_height = is_confirmed ? *transaction.m_height : 0;
        const uint64_t num_confirmations = is_confirmed ? current_height - transaction_height : 0;
        const uint64_t change_amount =  is_change ? total_received : 0;        

        //tx->m_is_incoming = is_incoming && !is_change;
        //tx->m_is_outgoing = is_outgoing;
        tx->m_is_locked = is_locked;
        tx->m_is_relayed = true;
        tx->m_is_failed = false;
        tx->m_is_double_spend_seen = false;
        tx->m_is_confirmed = is_confirmed;
        //tx->m_is_kept_by_block = false;
        tx->m_is_miner_tx = is_miner_tx;
        tx->m_unlock_time = *transaction.m_unlock_time;
        //tx->m_last_relayed_timestamp = timestamp;
        if (!is_confirmed) tx->m_received_timestamp = timestamp;
        tx->m_in_tx_pool = !is_confirmed;
        tx->m_relay = true;
        tx->m_hash = *transaction.m_hash;
        tx->m_num_confirmations = num_confirmations;
        tx->m_fee = fee;
        if (!is_change && transaction.m_payment_id != boost::none && transaction.m_payment_id.get() != monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = transaction.m_payment_id;
        //tx->m_num_dummy_outputs = transaction.m_mixin;
        //tx->m_ring_size = *transaction.m_mixin + 1;
        //tx->m_change_amount = change_amount;

        if (is_confirmed) {
          auto it = std::find_if(blocks.begin(), blocks.end(), [transaction_height](const std::shared_ptr<monero_block>& p) {
            return *p->m_height == transaction_height; // Dereferenziamento del unique_ptr
          });

          std::shared_ptr<monero_block> block = nullptr;

          if (it != blocks.end()) {
            block = (*it);  
          } else {
            block = std::make_shared<monero_block>();
            block->m_height = transaction_height;
            block->m_timestamp = timestamp;

            blocks.push_back(block);
          }

          block->m_txs.push_back(tx);
          //block->m_tx_hashes.push_back(*tx_wallet->m_hash);

          //if (is_miner_tx) {
            //block->m_miner_tx = tx_wallet;
          //}

          tx->m_block = block;
        }

        // construct transfer
        //std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();
        //incoming_transfer->m_tx = tx;
        //tx->m_incoming_transfers.push_back(incoming_transfer);
        //incoming_transfer->m_amount = gen_utils::uint64_t_cast(out.m_amount.get());
        //incoming_transfer->m_account_index = out.m_recipient->m_maj_i.get();
        //incoming_transfer->m_subaddress_index = out.m_recipient->m_min_i.get();
        //incoming_transfer->m_address = m_w2.get_subaddress_as_str(pd.m_subaddr_index);

        return tx;
      }
    }

    throw std::runtime_error("transaction not found for output");
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs_aux(const monero_output_query& query) const {
    MTRACE("monero_wallet_light::get_outputs_aux(query)");

    // copy and normalize query
    std::shared_ptr<monero_output_query> _query;
    if (query.m_tx_query == boost::none) {
      std::shared_ptr<monero_output_query> query_ptr = std::make_shared<monero_output_query>(query); // convert to shared pointer for copy
      _query = query_ptr->copy(query_ptr, std::make_shared<monero_output_query>());
    } else {
      std::shared_ptr<monero_tx_query> tx_query = query.m_tx_query.get()->copy(query.m_tx_query.get(), std::make_shared<monero_tx_query>());
      if (query.m_tx_query.get()->m_output_query != boost::none && query.m_tx_query.get()->m_output_query.get().get() == &query) {
        _query = tx_query->m_output_query.get();
      } else {
        if (query.m_tx_query.get()->m_output_query != boost::none) throw std::runtime_error("Output query's tx query must be a circular reference or null");
        std::shared_ptr<monero_output_query> query_ptr = std::make_shared<monero_output_query>(query);  // convert query to shared pointer for copy
        _query = query_ptr->copy(query_ptr, std::make_shared<monero_output_query>());
        _query->m_tx_query = tx_query;
      }
    }
    if (_query->m_tx_query == boost::none) _query->m_tx_query = std::make_shared<monero_tx_query>();
    std::shared_ptr<monero_tx_query> tx_query = _query->m_tx_query.get();

    // get light wallet data
    const auto res = get_unspent_outs(false);
    std::vector<monero_light_output> outs = res.m_outputs.get();

    std::vector<std::shared_ptr<monero_output_wallet>> outputs;
    const auto address_txs_res = get_address_txs();
    const auto address_txs = address_txs_res.m_transactions.get();
    const auto current_height = address_txs_res.m_blockchain_height.get();

    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    std::vector<std::shared_ptr<monero_block>> blocks;

    for (auto &out : outs) {
      std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
      std::string out_tx_hash = out.m_tx_hash.get();

      auto found_tx = std::find_if(txs.begin(), txs.end(), [out_tx_hash](const std::shared_ptr<monero_tx_wallet> &tx) { return tx->m_hash.get() == out_tx_hash; });

      output->m_index = gen_utils::uint64_t_cast(*out.m_global_index);
      output->m_account_index = out.m_recipient->m_maj_i;
      output->m_subaddress_index = out.m_recipient->m_min_i;
      output->m_amount = gen_utils::uint64_t_cast(*out.m_amount);
      output->m_stealth_public_key = out.m_public_key;
      output->m_is_spent = out.is_spent();
      if (found_tx == txs.end()) {
        auto tx = get_output_transaction(out, address_txs, current_height + 1, blocks);
        output->m_tx = tx;
        txs.push_back(tx);
      }
      else {
        output->m_tx = (*found_tx);
      }
      output->m_tx->m_outputs.push_back(output);
      output->m_is_frozen = is_output_frozen(out);

      if (out.key_image_is_known()) {
        output->m_key_image = std::make_shared<monero_key_image>();
        (*output->m_key_image)->m_hex = out.m_key_image;
        output->m_is_frozen = is_output_frozen(out);
      }
      else {
        std::cout << "monero_wallet_light::get_outputs_aux(): unknown output key image " << out.m_public_key.get() << ", spent: " << output->m_is_spent.get() << std::endl;
      }

      //sort(output->m_tx->m_outputs.begin(), output->m_tx->m_outputs.end(), monero_utils::vout_before);

      //if (_query->meets_criteria(output.get())) outputs.push_back(output);
    }

    sort(txs.begin(), txs.end(), monero_utils::tx_height_less_than);

    // filter and return outputs
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {

      // sort outputs
      //sort(tx->m_outputs.begin(), tx->m_outputs.end(), monero_utils::vout_before);

      // collect queried outputs, erase if excluded
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(*_query)) outputs.push_back(output);

      // remove txs without outputs
      //if (tx->m_outputs.empty() && tx->m_block != boost::none) tx->m_block.get()->m_txs.erase(std::remove(tx->m_block.get()->m_txs.begin(), tx->m_block.get()->m_txs.end(), tx), tx->m_block.get()->m_txs.end()); // TODO, no way to use const_iterator?
    }

    // free query and return outputs
    monero_utils::free(tx_query);
    return outputs;
  }

  bool monero_wallet_light::is_output_frozen(const monero_light_output& output) const {
    if (output.m_key_image == boost::none || output.m_key_image.get().empty()) return false;

    std::string key_image = output.m_key_image.get();

    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");
    
    const auto found = std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image);

    return found != m_frozen_key_images.end();
  }

  std::string monero_wallet_light::export_outputs(bool all) const {
    uint32_t start = 0;
    uint32_t count = 0xffffffff;
    std::stringstream oss;
    binary_archive<true> ar(oss);

    auto outputs = export_outputs(all, start, count);
    if(!serialization::serialize(ar, outputs)) throw std::runtime_error("Failed to serialize output data");

    std::string magic(OUTPUT_EXPORT_FILE_MAGIC, strlen(OUTPUT_EXPORT_FILE_MAGIC));
    const cryptonote::account_public_address &keys = m_account.get_keys().m_account_address;
    std::string header;
    header += std::string((const char *)&keys.m_spend_public_key, sizeof(crypto::public_key));
    header += std::string((const char *)&keys.m_view_public_key, sizeof(crypto::public_key));

    std::string ciphertext = encrypt_with_private_view_key(header + oss.str());
    std::string outputs_str = magic + ciphertext;
    return epee::string_tools::buff_to_hex_nodelimer(outputs_str);
  }

  int monero_wallet_light::import_outputs(const std::string& outputs_hex) {
    throw std::runtime_error("monero_wallet_light::import_outputs(): not supported");
  }

  std::vector<std::shared_ptr<monero_key_image>> monero_wallet_light::export_key_images(bool all) const {
    std::vector<std::shared_ptr<monero_key_image>> key_images;
    
    const auto outputs_res = get_unspent_outs(false);
    const auto outputs = *outputs_res.m_outputs;

    size_t offset = 0;
    if (!all)
    {
      while (offset < outputs.size() && !m_generated_key_images.request(outputs[offset].m_tx_pub_key.get(), outputs[offset].m_index.get(), outputs[offset].m_recipient->m_maj_i.get(), outputs[offset].m_recipient->m_min_i.get()))
        ++offset;
    }
    key_images.reserve(outputs.size() - offset);

    for(size_t n = offset; n < outputs.size(); ++n) {
      const auto output = &outputs[n];
      std::shared_ptr<monero_key_image> key_image = std::make_shared<monero_key_image>();
      cryptonote::subaddress_index subaddr;
      uint32_t account_idx = *output->m_recipient->m_maj_i;
      uint32_t subaddress_idx = *output->m_recipient->m_min_i;
      subaddr.major = account_idx;
      subaddr.minor = subaddress_idx;

      auto cached_key_image = m_generated_key_images.get(output->m_tx_pub_key.get(), account_idx, subaddress_idx);

      if (cached_key_image != nullptr) {
        key_image = cached_key_image;
      }
      else if (!is_view_only()) {
        *key_image = generate_key_image(*output->m_tx_pub_key, *output->m_index, subaddr);
      }

      key_images.push_back(key_image);
    }

    return key_images;
  }

  std::shared_ptr<monero_key_image_import_result> monero_wallet_light::import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) {
    std::shared_ptr<monero_key_image_import_result> result = std::make_shared<monero_key_image_import_result>();
    result->m_height = 0;
    result->m_spent_amount = 0;
    result->m_unspent_amount = 0;
    
    if (key_images.empty()) {
      return result;
    }

    uint64_t spent_amount = 0;
    uint64_t unspent_amount = 0;

    // validate key images
    
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
    bool check_spent = is_connected_to_daemon();

    auto unspent_outs_res = get_unspent_outs(false);
    auto unspent_outs = *unspent_outs_res.m_outputs;

    if (key_images.size() > unspent_outs.size()) {
      throw std::runtime_error("blockchain is out of date compared to the signed key images");
    }

    size_t imported_key_images_size = m_imported_key_images.size();
    size_t key_images_size = key_images.size();

    if (imported_key_images_size < key_images_size) m_imported_key_images.resize(key_images_size);
    
    for (size_t i = 0; i < key_images_size; i++) {
      m_imported_key_images[i] = key_images[i];
      auto unspent_out = unspent_outs[i];
      uint64_t out_index = unspent_out.m_index.get();
      uint32_t account_idx = unspent_out.m_recipient->m_maj_i.get();
      uint32_t subaddress_idx = unspent_out.m_recipient->m_min_i.get();
      std::string tx_public_key = unspent_out.m_tx_pub_key.get();

      m_generated_key_images.set(key_images[i], tx_public_key, out_index, account_idx, subaddress_idx);
      
      if (check_spent) {
        if (key_image_is_spent(key_images[i])) {
          spent_amount += gen_utils::uint64_t_cast(unspent_outs[i].m_amount.get());
        }
        else {
          unspent_amount += gen_utils::uint64_t_cast(unspent_outs[i].m_amount.get());
        }
      }
    }

    result->m_height = unspent_outs[key_images_size - 1].m_height;
    result->m_spent_amount = spent_amount;
    result->m_unspent_amount = unspent_amount;

    if (spent_amount > 0 || unspent_amount > 0) calculate_balance();

    return result;
  }

  std::string monero_wallet_light::get_tx_note(const std::string& tx_hash) const {
    MTRACE("monero_wallet_light::get_tx_note()");
    cryptonote::blobdata tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(tx_hash, tx_blob) || tx_blob.size() != sizeof(crypto::hash)) {
      throw std::runtime_error("TX hash has invalid format");
    }
    crypto::hash _tx_hash = *reinterpret_cast<const crypto::hash*>(tx_blob.data());
    return get_tx_note(_tx_hash);
  }

  std::vector<std::string> monero_wallet_light::get_tx_notes(const std::vector<std::string>& tx_hashes) const {
    MTRACE("monero_wallet_light::get_tx_notes()");
    std::vector<std::string> notes;
    for (const auto& tx_hash : tx_hashes) notes.push_back(get_tx_note(tx_hash));
    return notes;
  }

  void monero_wallet_light::set_tx_note(const std::string& tx_hash, const std::string& note) {
    MTRACE("monero_wallet_light::set_tx_note()");
    cryptonote::blobdata tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(tx_hash, tx_blob) || tx_blob.size() != sizeof(crypto::hash)) {
      throw std::runtime_error("TX hash has invalid format");
    }
    crypto::hash _tx_hash = *reinterpret_cast<const crypto::hash*>(tx_blob.data());
    set_tx_note(_tx_hash, note);
  }

  void monero_wallet_light::set_tx_notes(const std::vector<std::string>& tx_hashes, const std::vector<std::string>& notes) {
    MTRACE("monero_wallet_light::set_tx_notes()");
    if (tx_hashes.size() != notes.size()) throw std::runtime_error("Different amount of txids and notes");
    for (int i = 0; i < tx_hashes.size(); i++) {
      set_tx_note(tx_hashes[i], notes[i]);
    }
  }

  std::vector<monero_address_book_entry> monero_wallet_light::get_address_book_entries(const std::vector<uint64_t>& indices) const {
    if (indices.empty()) return m_address_book;
    std::vector<monero_address_book_entry> result;

    for (uint64_t idx : indices) {
      if (idx >= m_address_book.size()) throw std::runtime_error("Index out of range: " + std::to_string(idx));
      const auto &entry = m_address_book[idx];
      result.push_back(entry);
    }

    return result;
  }

  uint64_t monero_wallet_light::add_address_book_entry(const std::string& address, const std::string& description) {
    MTRACE("monero_wallet_light::add_address_book_entry()");
    cryptonote::address_parse_info info;
    epee::json_rpc::error er;
    if(!get_account_address_from_str_or_url(info, get_nettype(), address,
      [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid) throw std::runtime_error(std::string("Invalid DNSSEC for ") + url);
        if (addresses.empty()) throw std::runtime_error(std::string("No Monero address found at ") + url);
        return addresses[0];
      }))
    {
      throw std::runtime_error(std::string("Invalid address: ") + address);
    }

    const auto old_size = m_address_book.size();

    monero_address_book_entry entry(old_size, address, description);
    m_address_book.push_back(entry);

    if (m_address_book.size() != old_size + 1) throw std::runtime_error("Failed to add address book entry");
    return m_address_book.size() - 1;
  }

  void monero_wallet_light::edit_address_book_entry(uint64_t index, bool set_address, const std::string& address, bool set_description, const std::string& description) {
    MTRACE("monero_wallet_light::edit_address_book_entry()");

    auto &ab = m_address_book;
    if (index >= ab.size()) throw std::runtime_error("Index out of range: " + std::to_string(index));

    monero_address_book_entry entry;

    entry.m_index = index;

    cryptonote::address_parse_info info;
    epee::json_rpc::error er;
    if (set_address) {
      er.message = "";
      if(!get_account_address_from_str_or_url(info, get_nettype(), address,
        [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
          if (!dnssec_valid) throw std::runtime_error(std::string("Invalid DNSSEC for ") + url);
          if (addresses.empty()) throw std::runtime_error(std::string("No Monero address found at ") + url);
          return addresses[0];
        }))
      {
        throw std::runtime_error("Invalid address: " + address);
      }

      if (info.has_payment_id) { 
        entry.m_address = cryptonote::get_account_integrated_address_as_str(get_nettype(), info.address, info.payment_id);    }
      else entry.m_address = address;
    }

    if (set_description) entry.m_description = description;
    
    ab[index] = entry;
  }

  void monero_wallet_light::delete_address_book_entry(uint64_t index) {  
    if (index >= m_address_book.size()) throw std::runtime_error("Index out of range: " + std::to_string(index));
    m_address_book.erase(m_address_book.begin()+index);
  }

  std::string monero_wallet_light::get_payment_uri(const monero_tx_config& config) const {
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
    std::string uri = make_uri(address, payment_id, amount, note, m_recipient_name, error);
    if (uri.empty()) throw std::runtime_error("Cannot make URI from supplied parameters: " + error);
    return uri;
  }

  std::shared_ptr<monero_tx_config> monero_wallet_light::parse_payment_uri(const std::string& uri) const {
    MTRACE("parse_payment_uri(" << uri << ")");

    // decode uri to parameters
    std::string address;
    std::string payment_id;
    uint64_t amount = 0;
    std::string note;
    std::string m_recipient_name;
    std::vector<std::string> unknown_parameters;
    std::string error;
    if (!parse_uri(uri, address, payment_id, amount, note, m_recipient_name, unknown_parameters, error)) {
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

  void monero_wallet_light::set_attribute(const std::string &key, const std::string &value) {
    m_attributes[key] = value;
  }

  bool monero_wallet_light::get_attribute(const std::string &key, std::string &value) const {
    std::unordered_map<std::string, std::string>::const_iterator i = m_attributes.find(key);
    if (i == m_attributes.end())
      return false;
    value = i->second;
    return true;
  }

  uint64_t monero_wallet_light::wait_for_next_block() {
    // use mutex and condition variable to wait for block
    boost::mutex temp;
    boost::condition_variable cv;

    // create listener which notifies condition variable when block is added
    struct block_notifier : monero_wallet_listener {
      boost::mutex* temp;
      boost::condition_variable* cv;
      uint64_t last_height;
      block_notifier(boost::mutex* temp, boost::condition_variable* cv) { this->temp = temp; this->cv = cv; }
      void on_new_block(uint64_t height) {
        last_height = height;
        cv->notify_one();
      }
    } block_listener(&temp, &cv);

    // register the listener
    add_listener(block_listener);

    // wait until condition variable is notified
    boost::mutex::scoped_lock lock(temp);
    cv.wait(lock);

    // unregister the listener
    remove_listener(block_listener);

    // return last height
    return block_listener.last_height;
  }

  monero_multisig_info monero_wallet_light::get_multisig_info() const {
    monero_multisig_info info;

    info.m_is_multisig = false;

    return info;
  }

  void monero_wallet_light::close(bool save) {
    MTRACE("monero_wallet_light::close()");
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    stop_syncing();
    if (m_sync_loop_running) {
      m_sync_cv.notify_one();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));  // TODO: in emscripten, m_sync_cv.notify_one() returns without waiting, so sleep; bug in emscripten upstream llvm?
      m_syncing_thread.join();
    }

    m_account.deinit();
    m_wallet_listener.reset();
  }

  // --------------------------- PRIVATE UTILS --------------------------

  void monero_wallet_light::init_common() {
    monero_wallet_keys::init_common();

    m_load_deprecated_formats = false;
    m_is_synced = false;
    m_rescan_on_sync = false;
    m_syncing_enabled = false;
    m_sync_loop_running = false;
    m_last_block_reward = TAIL_EMISSION_REWARD; // minumum tail emission

    m_unconfirmed_txs = std::make_unique<std::vector<std::shared_ptr<monero_tx_wallet>>>();
    m_key_images_in_pool = std::make_unique<std::vector<std::string>>();

    m_address_info.m_locked_funds = "0";
    m_address_info.m_total_received = "0";
    m_address_info.m_total_sent = "0";
    m_address_info.m_scanned_height = 0;
    m_address_info.m_scanned_block_height = 0;
    m_address_info.m_start_height = 0;
    m_address_info.m_transaction_height = 0;
    m_address_info.m_blockchain_height = 0;
    m_address_info.m_spent_outputs = std::vector<monero_light_spend>();

    m_address_txs.m_total_received = "0";
    m_address_txs.m_scanned_height = 0;
    m_address_txs.m_scanned_block_height = 0;
    m_address_txs.m_start_height = 0;
    m_address_txs.m_blockchain_height = 0;
    m_address_txs.m_transactions = std::vector<monero_light_transaction>();

    m_unspent_outs.m_per_byte_fee = "0";
    m_unspent_outs.m_fee_mask = "0";
    m_unspent_outs.m_amount = "0";
    m_unspent_outs.m_outputs = std::vector<monero_light_output>();

    monero_light_subaddrs subaddrs;
    m_subaddrs.m_all_subaddrs = subaddrs;

    m_wallet_listener = std::unique_ptr<wallet_light_listener>(new wallet_light_listener(*this));
  }

  monero_light_partial_constructed_transaction monero_wallet_light::create_partial_transaction(const uint32_t subaddr_account_idx, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses, const std::vector<cryptonote::address_parse_info> &to_addrs, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, std::vector<monero_light_random_outputs> &mix_outs, const std::vector<uint8_t> &extra, uint64_t unlock_time, bool rct) {
    std::cout << "monero_wallet_light::create_partial_transaction()" << std::endl;
    // TODO: do we need to sort destinations by amount, here, according to 'decompose_destinations'?
    const cryptonote::account_keys sender_account_keys = m_account.get_keys();
    uint32_t fake_outputs_count = get_mixin_size();
    rct::RangeProofType range_proof_type = rct::RangeProofPaddedBulletproof;
    int bp_version = 1;
    if (use_fork_rules(HF_VERSION_BULLETPROOF_PLUS, -10)) {
      bp_version = 4;
    }
    else if (use_fork_rules(HF_VERSION_CLSAG, -10)) {
      bp_version = 3;
    }
    else if (use_fork_rules(HF_VERSION_SMALLER_BP, -10)) {
      bp_version = 2;
    }
    const rct::RCTConfig rct_config {
      range_proof_type,
      bp_version,
    };
    if (mix_outs.size() != outputs.size() && fake_outputs_count != 0) {
      throw std::runtime_error("wrong number of mix outs provided: " + std::to_string(mix_outs.size()) + ", outputs: " + std::to_string(outputs.size()));
    }
    for (size_t i = 0; i < mix_outs.size(); i++) {
      if (mix_outs[i].m_outputs->size() < fake_outputs_count) {
        throw std::runtime_error("not enough outputs for mixing");
      }
    }
    if (is_view_only()) {
      if (!sender_account_keys.get_device().verify_keys(sender_account_keys.m_view_secret_key, sender_account_keys.m_account_address.m_view_public_key)) {
        throw std::runtime_error("Invalid view keys");
      }
    }
    else {
      if (!sender_account_keys.get_device().verify_keys(sender_account_keys.m_spend_secret_key, sender_account_keys.m_account_address.m_spend_public_key)
        || !sender_account_keys.get_device().verify_keys(sender_account_keys.m_view_secret_key, sender_account_keys.m_account_address.m_view_public_key)) {
        throw std::runtime_error("Invalid secret keys");
      }
    }

    /*
  XXX: need overflow check?
    if (sending_amount > std::numeric_limits<uint64_t>::max() - change_amount
      || sending_amount + change_amount > std::numeric_limits<uint64_t>::max() - fee_amount) {
      retVals.errCode = outputAmountOverflow;
      return;
    }
  */
    uint64_t needed_money = fee_amount + change_amount;
    for (uint64_t amount : sending_amounts) {
      needed_money += amount;
    }
    
    uint64_t found_money = 0;
    std::vector<cryptonote::tx_source_entry> sources;
    std::vector<std::string> spent_key_images;
    // TODO: log: "Selected transfers: " << outputs
    for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
      found_money += gen_utils::uint64_t_cast(*outputs[out_index].m_amount);
      if (found_money > UINT64_MAX) {
        throw std::runtime_error("input amount overflow");
      }
      auto src = cryptonote::tx_source_entry{};
      src.amount = gen_utils::uint64_t_cast(*outputs[out_index].m_amount);
      src.rct = outputs[out_index].m_rct != boost::none && (*(outputs[out_index].m_rct)).empty() == false;
      
      typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
      if (mix_outs.size() != 0) {
        // Sort fake outputs by global index
        std::sort(mix_outs[out_index].m_outputs->begin(), mix_outs[out_index].m_outputs->end(), [] (
          monero_light_random_output const& a,
          monero_light_random_output const& b
        ) {
          return gen_utils::uint64_t_cast(*a.m_global_index) < gen_utils::uint64_t_cast(*b.m_global_index);
        });
        for (
          size_t j = 0;
          src.outputs.size() < fake_outputs_count && j < mix_outs[out_index].m_outputs->size();
          j++
        ) {
          auto mix_out__output = mix_outs[out_index].m_outputs.get()[j];
          if (mix_out__output.m_global_index == outputs[out_index].m_global_index) {
            MDEBUG("got mixin the same as output, skipping");
            continue;
          }
          auto oe = tx_output_entry{};
          oe.first = gen_utils::uint64_t_cast(*mix_out__output.m_global_index);
          
          crypto::public_key public_key = AUTO_VAL_INIT(public_key);
          if(!epee::string_tools::hex_to_pod(*mix_out__output.m_public_key, public_key)) {
            throw std::runtime_error("given an invalid publick key");
          }
          oe.second.dest = rct::pk2rct(public_key);
          
          if (mix_out__output.m_rct != boost::none && (*(mix_out__output.m_rct)).empty() == false) {
            rct::key commit;
            _rct_hex_to_rct_commit(*mix_out__output.m_rct, commit);
            oe.second.mask = commit;
          } else {
            if (outputs[out_index].m_rct != boost::none && (*(outputs[out_index].m_rct)).empty() == false) {
              throw std::runtime_error("mix RCT outs missing commit");
            }
            oe.second.mask = rct::zeroCommit(src.amount); //create identity-masked commitment for non-rct mix input
          }
          src.outputs.push_back(oe);
        }
      }
      auto real_oe = tx_output_entry{};
      real_oe.first = gen_utils::uint64_t_cast(*outputs[out_index].m_global_index);
      

      crypto::public_key public_key = AUTO_VAL_INIT(public_key);
      if(!epee::string_tools::validate_hex(64, *outputs[out_index].m_public_key)) {
        throw std::runtime_error("given an invalid public key");
      }
      if (!epee::string_tools::hex_to_pod(*outputs[out_index].m_public_key, public_key)) {
        throw std::runtime_error("given an invalid public key");

      }
      real_oe.second.dest = rct::pk2rct(public_key);
      
      if (outputs[out_index].m_rct != boost::none
          && outputs[out_index].m_rct->empty() == false
          && *outputs[out_index].m_rct != "coinbase") {
        rct::key commit;
        _rct_hex_to_rct_commit(*(outputs[out_index].m_rct), commit);
        real_oe.second.mask = commit; //add commitment for real input
      } else {
        real_oe.second.mask = rct::zeroCommit(src.amount/*aka outputs[out_index].amount*/); //create identity-masked commitment for non-rct input
      }
      
      // Add real_oe to outputs
      uint64_t real_output_index = src.outputs.size();
      for (size_t j = 0; j < src.outputs.size(); j++) {
        if (real_oe.first < src.outputs[j].first) {
          real_output_index = j;
          break;
        }
      }
      src.outputs.insert(src.outputs.begin() + real_output_index, real_oe);
      crypto::public_key tx_pub_key = AUTO_VAL_INIT(tx_pub_key);
      if(!epee::string_tools::validate_hex(64, *outputs[out_index].m_tx_pub_key)) {
        throw std::runtime_error("given an invalid public key");
      }
      epee::string_tools::hex_to_pod(*outputs[out_index].m_tx_pub_key, tx_pub_key);
      src.real_out_tx_key = tx_pub_key;
      
      src.real_out_additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(extra);
      
      src.real_output = real_output_index;
      uint64_t internal_output_index = *outputs[out_index].m_index;
      src.real_output_in_tx_index = internal_output_index;
      
      src.rct = outputs[out_index].m_rct != boost::none && (*(outputs[out_index].m_rct)).empty() == false;
      if (src.rct) {
        rct::key decrypted_mask;
        bool r = _rct_hex_to_decrypted_mask(
          *(outputs[out_index].m_rct),
          sender_account_keys.m_view_secret_key,
          tx_pub_key,
          internal_output_index,
          decrypted_mask
        );
        if (!r) {
          throw std::runtime_error("can't get decrypted mask from RCT hex");
        }
        src.mask = decrypted_mask;
        /*
        rct::key calculated_commit = rct::commit(outputs[out_index].amount, decrypted_mask);
        rct::key parsed_commit;
        _rct_hex_to_rct_commit(*(outputs[out_index].rct), parsed_commit);
        if (!(real_oe.second.mask == calculated_commit)) { // real_oe.second.mask==parsed_commit(outputs[out_index].rct)
          retVals.errCode = invalidCommitOrMaskOnOutputRCT;
          return;
        }

        */
      } else {
        rct::identity(src.mask); // in the original cn_utils impl this was left as null for generate_key_image_helper_rct to fill in with identity I
      }
      // not doing multisig here yet
      src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
      sources.push_back(src);
      if (outputs[out_index].m_key_image != boost::none && !outputs[out_index].m_key_image->empty()) {
        spent_key_images.push_back(outputs[out_index].m_key_image.get());    
      }
    }
    
    // TODO: if this is a multisig wallet, create a list of multisig signers we can use
    std::vector<cryptonote::tx_destination_entry> splitted_dsts;
    if(to_addrs.size() != sending_amounts.size()) throw std::runtime_error("Amounts don't match destinations");
    for (size_t i = 0; i < to_addrs.size(); ++i) {
      cryptonote::tx_destination_entry to_dst = AUTO_VAL_INIT(to_dst);
      to_dst.addr = to_addrs[i].address;
      to_dst.amount = sending_amounts[i];
      to_dst.is_subaddress = to_addrs[i].is_subaddress;
      splitted_dsts.push_back(to_dst);
    }
    //
    cryptonote::tx_destination_entry change_dst = AUTO_VAL_INIT(change_dst);
    change_dst.amount = change_amount;
    
    if (change_dst.amount == 0) {
      if (splitted_dsts.size() == 1) {
        /**
        * If the change is 0, send it to a random address, to avoid confusing
        * the sender with a 0 amount output. We send a 0 amount in order to avoid
        * letting the destination be able to work out which of the inputs is the
        * real one in our rings
        */

        MDEBUG("generating dummy address for 0 change");
        cryptonote::account_base dummy;
        dummy.generate();
        change_dst.addr = dummy.get_keys().m_account_address;
        MDEBUG("generated dummy address for 0 change");
        splitted_dsts.push_back(change_dst);
      }
    } else {
      change_dst.addr = sender_account_keys.m_account_address;
      splitted_dsts.push_back(change_dst);
    }
    
    // TODO: log: "sources: " << sources
    if (found_money > needed_money) {
      if (change_dst.amount != fee_amount) {
        throw std::runtime_error("result fee not equal to given");
      }
    } 
    else if (found_money < needed_money) {
      throw std::runtime_error("need more money than found; found_money: " + std::to_string(found_money) + ", needed_money: " + std::to_string(needed_money));
    }
    
    cryptonote::transaction tx;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    
    if (sources.empty()) throw std::runtime_error("sources is empty");

    // unlock time not supported here...
    bool r = cryptonote::construct_tx_and_get_tx_key(
      sender_account_keys, subaddresses,
      sources, splitted_dsts, change_dst.addr, extra,
      tx, tx_key, additional_tx_keys,
      true, rct_config, true);

    std::cout << "constructed tx, r=" << r << std::endl;
    if (!r) {
      // TODO: return error::tx_not_constructed, sources, dsts, unlock_time, nettype
      throw std::runtime_error("transaction not constructed");
    }
    if (get_upper_transaction_weight_limit(0) <= get_transaction_weight(tx)) {
      throw std::runtime_error("transaction too big");
    }
    bool use_bulletproofs = !tx.rct_signatures.p.bulletproofs_plus.empty();
    if(use_bulletproofs != true) throw std::runtime_error("Expected tx use_bulletproofs to equal bulletproof flag");
    
    monero_light_partial_constructed_transaction result;

    result.m_tx = tx;
    result.m_tx_key = tx_key;
    result.m_additional_tx_keys = additional_tx_keys;
    result.m_spent_key_images = spent_key_images;
    result.m_fee = fee_amount;
    result.m_weight = get_transaction_weight(tx);

    tools::wallet2::tx_construction_data construction_data;

    std::vector<size_t> selected_transfers = get_output_indexes(outputs);

    construction_data.sources = sources;
    construction_data.change_dts = change_dst;
    construction_data.splitted_dsts = splitted_dsts;
    construction_data.selected_transfers = selected_transfers;
    construction_data.extra = tx.extra;
    construction_data.unlock_time = 0;
    construction_data.use_rct = true;
    construction_data.rct_config = rct_config;
    construction_data.use_view_tags = true;
    construction_data.dests = splitted_dsts;
    // record which subaddress indices are being used as inputs
    construction_data.subaddr_account = subaddr_account_idx;
    construction_data.subaddr_indices.clear();
    
    for (const auto selected_out : outputs) {
      if (selected_out.m_recipient->m_maj_i.get() != subaddr_account_idx) continue;
      construction_data.subaddr_indices.insert(selected_out.m_recipient->m_min_i.get());
    }
    
    LOG_PRINT_L2("transfer_selected_rct done");

    result.m_construction_data = construction_data;

    return result;
  }

  std::vector<size_t> monero_wallet_light::get_output_indexes(const std::vector<monero_light_output> &outputs) const {
    std::vector<size_t> indexes;

    const auto unspent_outs_res = get_unspent_outs(false);
    const auto unspent_outs = unspent_outs_res.m_outputs.get();

    for (const auto output : outputs) {
      std::string public_key = output.m_public_key.get();
      bool found = false;
      size_t index = 0;

      for (const auto unspent_out : unspent_outs) {
        if (unspent_out.m_public_key.get() == public_key) {
          found = true;
          break;
        }

        index++;
      }

      if (!found) throw std::runtime_error("output doesn't belong to the wallet");

      indexes.push_back(index);
    }

    return indexes;
  }

  monero_light_constructed_transaction monero_wallet_light::create_transaction(const uint32_t subaddr_account_idx, const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, std::vector<monero_light_random_outputs> &mix_outs, uint64_t unlock_time) {
    std::cout << "monero_wallet_light::create_transaction()" << std::endl;

    auto nettype = get_nettype();

    std::vector<cryptonote::address_parse_info> to_addr_infos(to_address_strings.size());
    size_t to_addr_idx = 0;
    for (const auto& addr : to_address_strings) {
      // assumed to be an OA address asXMR addresses do not have periods and OA addrs must
      if(addr.find(".") != std::string::npos) throw std::runtime_error("integrators must resolve OA addresses before calling Send"); // This would be an app code fault
      if (!cryptonote::get_account_address_from_str(to_addr_infos[to_addr_idx++], nettype, addr)) {
        throw std::runtime_error("Invalid destination address");
      }
    }

    std::vector<uint8_t> extra;
    _add_pid_to_tx_extra(payment_id_string, extra);

    bool payment_id_seen = payment_id_string != boost::none; // logically this is true since payment_id_string has passed validation (or we'd have errored)
    for (const auto& to_addr_info : to_addr_infos) {
      if (to_addr_info.is_subaddress && payment_id_seen) {
        throw std::runtime_error("cant use pid with subaddress");
      }
      if (to_addr_info.has_payment_id) {
        if (payment_id_seen) {
          // can't use int addr at same time as supplying manual pid
          throw std::runtime_error("non zero pid with int address");
        }
        if (to_addr_info.is_subaddress) {
          if(false) throw std::runtime_error("unexpected is_subaddress && has_payment_id"); // should never happen
        }
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, to_addr_info.payment_id);
        bool r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r) {
          throw std::runtime_error("couldn't add pid nonce to tx extra");
        }
        payment_id_seen = true;
      }
    }

    //uint32_t subaddr_account_idx = 0;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses = get_subaddresses_map();
    //subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};
    
    auto partial_tx = create_partial_transaction(
      subaddr_account_idx, subaddresses,
      to_addr_infos,
      sending_amounts, change_amount, fee_amount,
      outputs, mix_outs,
      extra, // TODO: move to after address
      unlock_time, true/*rct*/
    );

    std::cout << "monero_wallet_light::create_transaction(): created partial tx" << std::endl;

    auto txBlob = t_serializable_object_to_blob(*partial_tx.m_tx);
    size_t txBlob_byteLength = txBlob.size();
    //	cout << "txBlob: " << txBlob << endl;
    //	cout << "txBlob_byteLength: " << txBlob_byteLength << endl;
    
    if(txBlob_byteLength <= 0) throw std::runtime_error("Expected tx blob byte length > 0");
    
    // tx hash
    monero_light_constructed_transaction result;
    result.m_tx_hash_string = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(*partial_tx.m_tx));
    // signed serialized tx
    result.m_signed_serialized_tx_string = epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(*partial_tx.m_tx));
    // (concatenated) tx key
    // TODO is throwing Type must be trivially copiable
    crypto::secret_key _tx_key = *partial_tx.m_tx_key;
    epee::wipeable_string oss = epee::to_hex::wipeable_string(_tx_key);
    
    for (size_t i = 0; i < (*partial_tx.m_additional_tx_keys).size(); ++i) {
      oss += epee::to_hex::wipeable_string((*partial_tx.m_additional_tx_keys)[i]);
    }
    result.m_tx_key_string = std::string(oss.data(), oss.size());
    
    std::ostringstream oss2;
    oss2 << epee::string_tools::pod_to_hex(cryptonote::get_tx_pub_key_from_extra(*partial_tx.m_tx));
    result.m_tx_pub_key_string = oss2.str();
    
    result.m_tx = *partial_tx.m_tx; // for calculating block weight; FIXME: std::move?
    
    //	cout << "out 0: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[0].target).key) << endl;
    //	cout << "out 1: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[1].target).key) << endl;
    
    result.m_tx_blob_byte_length = txBlob_byteLength;
    result.m_spent_key_images = partial_tx.m_spent_key_images;
    result.m_construction_data = partial_tx.m_construction_data;
    result.m_fee = partial_tx.m_fee;
    result.m_weight = partial_tx.m_weight;

    return result;
  }

  std::vector<monero_light_output> get_tx_unspent_outs(std::string &tx_hash, std::vector<monero_light_output> &unspent_outputs) {
    std::vector<monero_light_output> found;

    for (const auto &output : unspent_outputs) {
      if (*output.m_tx_hash == tx_hash) {
        found.push_back(output);
      }
    }

    return found;
  }

  std::vector<monero_light_output> get_tx_unspent_outs(std::string &tx_hash, monero_light_get_unspent_outs_response res) {
    std::vector<monero_light_output> unspent_outputs = *res.m_outputs;

    return get_tx_unspent_outs(tx_hash, unspent_outputs);
  }

  cryptonote::subaddress_index get_transaction_sender(const monero_light_transaction &tx) {
    cryptonote::subaddress_index si;
    si.major = 0;
    si.minor = 0;

    for (const auto &output : *tx.m_spent_outputs) {
      si.major = *output.m_sender->m_maj_i;
      si.minor = *output.m_sender->m_min_i;
      break;
    }

    return si;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers_aux(const monero_transfer_query& query) const {
    std::cout << "monero_wallet_light::get_transfers_aux()" << std::endl;

    // copy and normalize query
    std::shared_ptr<monero_transfer_query> _query;
    if (query.m_tx_query == boost::none) {
      std::shared_ptr<monero_transfer_query> query_ptr = std::make_shared<monero_transfer_query>(query); // convert to shared pointer for copy  // TODO: does this copy unecessarily? copy constructor is not defined
      _query = query_ptr->copy(query_ptr, std::make_shared<monero_transfer_query>());
      _query->m_tx_query = std::make_shared<monero_tx_query>();
      _query->m_tx_query.get()->m_transfer_query = _query;
    } else {
      std::shared_ptr<monero_tx_query> tx_query = query.m_tx_query.get()->copy(query.m_tx_query.get(), std::make_shared<monero_tx_query>());
      _query = tx_query->m_transfer_query.get();
    }
    std::shared_ptr<monero_tx_query> tx_query = _query->m_tx_query.get();

    std::vector<std::shared_ptr<monero_transfer>> transfers;
    std::vector<std::shared_ptr<monero_block>> blocks;

    const auto address_txs_res = get_address_txs();
    const auto unspent_outs_res = get_unspent_outs(false);

    const auto current_height = *address_txs_res.m_blockchain_height + 1;
    const auto txs = *address_txs_res.m_transactions;
    const bool view_only = is_view_only();

    for (const auto &tx : txs) {
      const auto sender = get_transaction_sender(tx);

      uint64_t total_sent = gen_utils::uint64_t_cast(*tx.m_total_sent);    
      const uint64_t total_received = gen_utils::uint64_t_cast(*tx.m_total_received);
      
      const uint64_t fee = gen_utils::uint64_t_cast(*tx.m_fee);
      
      const bool is_incoming = total_received > 0;
      const bool is_outgoing = total_sent > 0;
      const bool is_change = is_incoming && is_outgoing;

      if (is_change) total_sent -= total_received;

      const bool is_locked = *tx.m_unlock_time > current_height || current_height < (*tx.m_height) + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
      const bool is_confirmed = !tx.m_mempool.get();
      const bool is_miner_tx = *tx.m_coinbase == true;
            
      const uint64_t timestamp = gen_utils::timestamp_to_epoch(*tx.m_timestamp);
      const uint64_t tx_height = is_confirmed ? *tx.m_height : 0;
      const uint64_t num_confirmations = is_confirmed ? current_height - tx_height : 0;
      const uint64_t change_amount =  is_change ? total_received : 0;
      uint64_t input_sum = 0;
      uint64_t output_sum = 0;
      std::string tx_hash = *tx.m_hash;
      std::shared_ptr<monero_block> block = nullptr;
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();

      tx_wallet->m_is_incoming = is_incoming && !is_change;
      tx_wallet->m_is_outgoing = is_outgoing;
      tx_wallet->m_is_locked = is_locked;
      tx_wallet->m_is_relayed = true;
      tx_wallet->m_is_failed = false;
      tx_wallet->m_is_double_spend_seen = false;
      tx_wallet->m_is_confirmed = is_confirmed;
      //tx_wallet->m_is_kept_by_block = false;
      tx_wallet->m_is_miner_tx = is_miner_tx;
      tx_wallet->m_unlock_time = *tx.m_unlock_time;
      //tx_wallet->m_last_relayed_timestamp = timestamp;
      if (!is_confirmed) tx_wallet->m_received_timestamp = timestamp;
      tx_wallet->m_in_tx_pool = !is_confirmed;
      tx_wallet->m_relay = true;
      tx_wallet->m_hash = *tx.m_hash;
      tx_wallet->m_num_confirmations = num_confirmations;
      tx_wallet->m_fee = fee;
      //tx_wallet->m_num_dummy_outputs = tx.m_mixin;
      //tx_wallet->m_ring_size = *tx.m_mixin + 1;
      //tx_wallet->m_change_amount = change_amount;

      //if (is_change && tx.m_recipient != boost::none) {
      //  tx_wallet->m_change_address = get_address(*tx.m_recipient->m_maj_i, *tx.m_recipient->m_min_i);
      //}

      if (is_confirmed) {
        remove_unconfirmed_tx(*tx.m_hash);

        auto it = std::find_if(blocks.begin(), blocks.end(), [tx_height](const std::shared_ptr<monero_block>& p) {
          return *p->m_height == tx_height; // Dereferenziamento del unique_ptr
        });

        if (it != blocks.end()) {
          block = (*it);  
        } else {
          block = std::make_shared<monero_block>();
          block->m_height = tx_height;
          block->m_timestamp = timestamp;

          blocks.push_back(block);
        }

        block->m_txs.push_back(tx_wallet);
        //block->m_tx_hashes.push_back(*tx_wallet->m_hash);

        //if (is_miner_tx) {
          //block->m_miner_tx = tx_wallet;
        //}

        tx_wallet->m_block = block;
      }

      if (is_incoming) {
        for (auto &out : get_tx_unspent_outs(tx_hash, unspent_outs_res)) {
          uint64_t out_amount = gen_utils::uint64_t_cast(*out.m_amount);
          uint32_t out_account_idx = *out.m_recipient->m_maj_i;
          uint32_t out_subaddress_idx = *out.m_recipient->m_min_i;

          if (is_change && sender.major == out_account_idx) continue;
          else if (is_change) {
            tx_wallet->m_is_incoming = true;
            total_sent += out_amount;
          }

          std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();

          const auto found = std::find_if(tx_wallet->m_incoming_transfers.begin(), tx_wallet->m_incoming_transfers.end(), [out_account_idx, out_subaddress_idx](const std::shared_ptr<monero_incoming_transfer>& transfer){
            return out_account_idx == transfer->m_account_index.get() && out_subaddress_idx == transfer->m_subaddress_index.get();
          });

          if (found != tx_wallet->m_incoming_transfers.end()) {
            (*found)->m_amount = (*found)->m_amount.get() + out_amount;
          }
          else {
            incoming_transfer->m_tx = tx_wallet;
            incoming_transfer->m_account_index = out_account_idx;
            incoming_transfer->m_subaddress_index = out_subaddress_idx;
            incoming_transfer->m_address = get_address(out_account_idx, out_subaddress_idx);
            incoming_transfer->m_amount = out_amount;

            // TODO wallet full gives to 2 piconero less
            if (current_height >= TAIL_EMISSION_HEIGHT) {
              uint64_t reward = m_last_block_reward > 1 ? m_last_block_reward - 2 : m_last_block_reward;
              monero_utils::set_num_suggested_confirmations(incoming_transfer, current_height, reward, *tx.m_unlock_time);
            } else {
              incoming_transfer->m_num_suggested_confirmations = 1;
            }

            tx_wallet->m_incoming_transfers.push_back(incoming_transfer);

            std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();

            if (out.m_key_image != boost::none) {
            auto out_key_image = std::make_shared<monero_key_image>();
              out_key_image->m_hex = *out.m_key_image;
              output->m_key_image = out_key_image;
            }
            
            output->m_account_index = out_account_idx;
            output->m_subaddress_index = out_subaddress_idx;
            output->m_amount = out_amount;
            output->m_is_spent = output_is_spent(out);
            output->m_index = gen_utils::uint64_t_cast(*out.m_global_index);
            
            output->m_tx = tx_wallet;
            output->m_stealth_public_key = out.m_public_key;

            output_sum += out_amount;
          }

          //if (monero_utils::is_contextual(*_query)) tx_wallet->m_outputs.push_back(output);
          //transfers.push_back(incoming_transfer);
        }
      }

      if (is_outgoing && !view_only) {
        std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();

        outgoing_transfer->m_tx = tx_wallet;
        
        outgoing_transfer->m_amount = total_sent - fee;
        outgoing_transfer->m_account_index = sender.major;

        for (const auto spent_output : *tx.m_spent_outputs) {
          uint32_t account_idx = *spent_output.m_sender->m_maj_i;
          uint32_t subaddress_idx = *spent_output.m_sender->m_min_i;
          uint64_t out_amount = gen_utils::uint64_t_cast(*spent_output.m_amount);

          //outgoing_transfer->m_account_index = account_idx;
          if (account_idx == sender.major && std::find_if(outgoing_transfer->m_subaddress_indices.begin(), outgoing_transfer->m_subaddress_indices.end(), [subaddress_idx](const uint32_t &idx) { return subaddress_idx == idx; }) == outgoing_transfer->m_subaddress_indices.end()) {
            outgoing_transfer->m_addresses.push_back(get_address(account_idx, subaddress_idx));
            outgoing_transfer->m_subaddress_indices.push_back(subaddress_idx);
          }

          /*
          if (is_change) {
            for (auto &out : get_tx_unspent_outs(tx_hash, unspent_outs_res)) {
              std::shared_ptr<monero_destination> dest = std::make_shared<monero_destination>();
              uint32_t account_idx = *out.m_recipient->m_maj_i;
              uint32_t subaddress_idx = *out.m_recipient->m_min_i;

              dest->m_address = get_address(account_idx, subaddress_idx);
              dest->m_amount = gen_utils::uint64_t_cast(*out.m_amount);

              outgoing_transfer->m_destinations.push_back(dest);
            }
          }
          */

          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
          
          if (spent_output.m_key_image != boost::none) {
            auto out_key_image = std::make_shared<monero_key_image>();
            out_key_image->m_hex = spent_output.m_key_image;
            output->m_key_image = out_key_image;
          }
          
          output->m_account_index = account_idx;
          output->m_subaddress_index = subaddress_idx;
          output->m_amount = out_amount;
          output->m_is_spent = true;
          output->m_index = spent_output.m_out_index;
          output->m_tx = tx_wallet;
          //output->m_stealth_public_key = spent_output.m_public_key;

          input_sum += out_amount;

          //if (monero_utils::is_contextual(*_query)) tx_wallet->m_inputs.push_back(output);
        }

        sort(outgoing_transfer->m_subaddress_indices.begin(), outgoing_transfer->m_subaddress_indices.end());

        tx_wallet->m_outgoing_transfer = outgoing_transfer;

        //transfers.push_back(outgoing_transfer);
      }

      if ((tx_wallet->m_is_incoming.get()) || (tx_wallet->m_is_incoming.get() && tx_wallet->m_is_outgoing.get())) {
        if (tx.m_payment_id != boost::none && tx.m_payment_id.get() != monero_tx::DEFAULT_PAYMENT_ID) tx_wallet->m_payment_id = tx.m_payment_id;
      }

      sort(tx_wallet->m_incoming_transfers.begin(), tx_wallet->m_incoming_transfers.end(), monero_utils::incoming_transfer_before);

      //tx_wallet->m_input_sum = input_sum;
      //tx_wallet->m_output_sum = output_sum;

      if (is_confirmed && block != nullptr && !tx_query->meets_criteria(tx_wallet.get())) {
        block->m_txs.erase(std::remove(block->m_txs.begin(), block->m_txs.end(), tx_wallet), block->m_txs.end());
      }

      for (const std::shared_ptr<monero_transfer>& transfer : tx_wallet->filter_transfers(*_query)) transfers.push_back(transfer);
    }

    std::cout << "monero_wallet_light::get_transfers_aux(): A" << std::endl;

    for (const std::shared_ptr<monero_tx_wallet> &txwallet : (*m_unconfirmed_txs)) {
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
      txwallet->copy(txwallet, tx_wallet);
      tx_wallet->m_weight = boost::none;
      tx_wallet->m_inputs = std::vector<std::shared_ptr<monero_output>>();
      tx_wallet->m_ring_size = boost::none;
      tx_wallet->m_key = boost::none;
      tx_wallet->m_full_hex = boost::none;
      tx_wallet->m_metadata = boost::none;
      tx_wallet->m_last_relayed_timestamp = boost::none;
      for (const std::shared_ptr<monero_transfer>& transfer : tx_wallet->filter_transfers(*_query)) transfers.push_back(transfer);
    }
    
    std::cout << "monero_wallet_light::get_transfers_aux(): B" << std::endl;

    return transfers;
  }

  uint64_t monero_wallet_light::estimated_tx_network_fee(uint64_t base_fee, uint32_t priority) {
    uint64_t fee_multiplier = get_fee_multiplier(priority, get_default_priority(), get_fee_algorithm());
    std::vector<uint8_t> extra; // blank extra
    size_t est_tx_size = estimate_rct_tx_size(2, get_mixin_size(), 2, extra.size(), true/*bulletproof*/, true/*clsag*/); // typically ~14kb post-rct, pre-bulletproofs
    uint64_t estimated_fee = calculate_fee_from_size(base_fee, est_tx_size, fee_multiplier);
    
    return estimated_fee;
  }

  uint64_t monero_wallet_light::get_upper_transaction_weight_limit(uint64_t upper_transaction_weight_limit__or_0_for_default) {
    if (upper_transaction_weight_limit__or_0_for_default > 0)
      return upper_transaction_weight_limit__or_0_for_default;

    uint64_t full_reward_zone = use_fork_rules(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : use_fork_rules(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;

    if (use_fork_rules(8, 10))
      return full_reward_zone / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    else
      return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
  }

  uint64_t monero_wallet_light::get_fee_multiplier(uint32_t priority, uint32_t default_priority, int fee_algorithm) {
    static const struct
    {
      size_t count;
      uint64_t multipliers[4];
    }
    multipliers[] =
    {
      { 3, {1, 2, 3} },
      { 3, {1, 20, 166} },
      { 4, {1, 4, 20, 166} },
      { 4, {1, 5, 25, 1000} },
    };
    
    if (fee_algorithm == -1)
      fee_algorithm = get_fee_algorithm();
    
    // 0 -> default (here, x1 till fee algorithm 2, x4 from it)
    if (priority == 0)
      priority = default_priority;
    if (priority == 0)
    {
      if (fee_algorithm >= 2)
        priority = 2;
      else
        priority = 1;
    }
    
    if(fee_algorithm < 0 || fee_algorithm > 3) throw std::runtime_error("Invalid priority");
    
    // 1 to 3/4 are allowed as priorities
    const uint32_t max_priority = multipliers[fee_algorithm].count;
    if (priority >= 1 && priority <= max_priority)
    {
      return multipliers[fee_algorithm].multipliers[priority-1];
    }
    
    return 1;
  }

  int monero_wallet_light::get_fee_algorithm() {
    // changes at v3, v5, v8
    if (use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0))
      return 3;
    if (use_fork_rules(5, 0))
      return 2;
    if (use_fork_rules(3, -720 * 14))
      return 1;
    return 0;
  }

  size_t monero_wallet_light::estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag) {
    size_t size = 0;
    
    // tx prefix
    
    // first few bytes
    size += 1 + 6;
    
    // vin
    size += n_inputs * (1+6+(mixin+1)*2+32);
    
    // vout
    size += n_outputs * (6+32);
    
    // extra
    size += extra_size;
    
    // rct signatures
    
    // type
    size += 1;
    
    // rangeSigs
    if (bulletproof)
    {
      size_t log_padded_outputs = 0;
      while ((1<<log_padded_outputs) < n_outputs)
        ++log_padded_outputs;
      size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
    }
    else
      size += (2*64*32+32+64*32) * n_outputs;
    
    // MGs/CLSAGs
    if (clsag)
      size += n_inputs * (32 * (mixin+1) + 64);
    else
      size += n_inputs * (64 * (mixin+1) + 32);
    
    // mixRing - not serialized, can be reconstructed
    /* size += 2 * 32 * (mixin+1) * n_inputs; */
    
    // pseudoOuts
    size += 32 * n_inputs;
    // ecdhInfo
    size += 8 * n_outputs;
    // outPk - only commitment is saved
    size += 32 * n_outputs;
    // txnFee
    size += 4;
    
    MDEBUG("estimated " << (bulletproof ? "bulletproof" : "borromean") << " rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
    return size;
  }

  size_t monero_wallet_light::estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag) {
    if (use_rct)
      return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
    else
      return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
  }

  uint64_t monero_wallet_light::estimate_tx_weight(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag) {
    size_t size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
    if (use_rct && bulletproof && n_outputs > 2)
    {
      const uint64_t bp_base = 368;
      size_t log_padded_outputs = 2;
      while ((1<<log_padded_outputs) < n_outputs)
        ++log_padded_outputs;
      uint64_t nlr = 2 * (6 + log_padded_outputs);
      const uint64_t bp_size = 32 * (9 + nlr);
      const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
      MDEBUG("clawback on size " << size << ": " << bp_clawback);
      size += bp_clawback;
    }
    return size;
  }

  uint64_t monero_wallet_light::estimate_fee(bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
    if (use_per_byte_fee)
    {
      const size_t estimated_tx_weight = estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
      return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
    }
    else
    {
      const size_t estimated_tx_size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
      return calculate_fee_from_size(base_fee, estimated_tx_size, fee_multiplier);
    }
  }

  uint64_t monero_wallet_light::calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
    uint64_t fee = weight * base_fee * fee_multiplier;
    fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
    return fee;
  }

  uint64_t monero_wallet_light::calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
    if (use_per_byte_fee) {
      return calculate_fee_from_weight(base_fee, cryptonote::get_transaction_weight(tx, blob_size), fee_multiplier, fee_quantization_mask);
    } else {
      return calculate_fee_from_size(base_fee, blob_size, fee_multiplier);
    }
  }

  bool monero_wallet_light::key_image_is_spent(crypto::key_image &key_image) const { 
    std::string ki = epee::string_tools::pod_to_hex(key_image);
    return key_image_is_spent(ki);
  }

  bool monero_wallet_light::key_image_is_spent(std::string &key_image) const {
    const auto res = get_address_info(false);
    const auto spends = *res.m_spent_outputs;

    for (const auto &spend : spends) {
      if (*spend.m_key_image == key_image) {
        return true;
      }
    }

    const auto found = std::find_if(m_key_images_in_pool->begin(), m_key_images_in_pool->end(), [key_image](const std::string& kip){
      return key_image == kip;
    });

    return found != m_key_images_in_pool->end();
  }

  bool monero_wallet_light::key_image_is_spent(std::shared_ptr<monero_key_image> key_image) const {
    if (key_image->m_hex == boost::none) return false;

    return key_image_is_spent(key_image->m_hex.get());
  }

  bool monero_wallet_light::key_image_is_spent(monero_key_image& key_image) const {
    if (key_image.m_hex == boost::none) return false;

    return key_image_is_spent(key_image.m_hex.get());
  }

  bool monero_wallet_light::subaddress_is_used(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto unspent_outs_res = get_unspent_outs(false);
    auto unspent_outs = *unspent_outs_res.m_outputs;

    for (auto out : unspent_outs) {
      if (*out.m_recipient->m_maj_i == account_idx && *out.m_recipient->m_min_i == subaddress_idx) return true;
    }
    
    return false;
  }

  uint64_t monero_wallet_light::get_subaddress_num_unspent_outs(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto unspent_outs_res = get_unspent_outs(true);
    auto unspent_outs = *unspent_outs_res.m_outputs;
    uint64_t result = 0;

    for (auto &out : unspent_outs) {
      if (*out.m_recipient->m_maj_i == account_idx && *out.m_recipient->m_min_i == subaddress_idx && !out.is_spent()) result++;
    }
    
    return result;
  }

  uint64_t monero_wallet_light::get_subaddress_num_blocks_to_unlock(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto unspent_outs_res = get_unspent_outs(true);
    auto unspent_outs = *unspent_outs_res.m_outputs;
    uint64_t result = 0;
    uint64_t current_height = get_height();
    uint64_t last_unlock_time = 0;

    for (auto &out : unspent_outs) {
      if (*out.m_recipient->m_maj_i == account_idx && *out.m_recipient->m_min_i == subaddress_idx && !out.is_spent()) {
        uint64_t num_blocks_to_unlock = get_output_num_blocks_to_unlock(out);

        if (num_blocks_to_unlock > result) result = num_blocks_to_unlock;
      }
    }
    
    return result;
  }

  uint64_t monero_wallet_light::get_output_num_blocks_to_unlock(monero_light_output &output) const {
    auto address_txs_res = get_address_txs();
    auto address_txs = *address_txs_res.m_transactions;
    uint64_t height = get_height();
    uint32_t account_idx = output.m_recipient->m_maj_i.get(); 
    uint32_t subaddress_idx = output.m_recipient->m_min_i.get();
    std::string tx_hash = output.m_tx_hash.get();
    uint64_t out_height = output.m_height.get();

    const auto found = std::find_if(address_txs.begin(), address_txs.end(), [tx_hash](const monero_light_transaction &tx) {
      return tx.m_hash.get() == tx_hash;
    });

    if (found == address_txs.end()) throw std::runtime_error("output doens't belong to the wallet");

    uint64_t default_spendable_age = out_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    uint64_t confirmations_needed = default_spendable_age > height ? default_spendable_age - height : 0;

    auto unlock_time = found->m_unlock_time.get();

    uint64_t num_blocks_to_unlock = unlock_time <= height ? 0 : unlock_time - height;

    return num_blocks_to_unlock > confirmations_needed ? num_blocks_to_unlock : confirmations_needed;
  }

  bool monero_wallet_light::output_is_spent(monero_light_output &output) const {
    auto key_images = *output.m_spend_key_images;
    const auto rcpt = *output.m_recipient;
    cryptonote::subaddress_index received_subaddr;

    received_subaddr.major = *rcpt.m_maj_i;
    received_subaddr.minor = *rcpt.m_min_i;
    bool spent = false;

    for (auto key_image : key_images) {
      if (key_image_is_ours(key_image, *output.m_tx_pub_key, *output.m_index, received_subaddr)) {
        output.m_key_image = key_image;
        spent = true;
        break;
      }
    }

    bool checked_unconfirmed = false;

    if (!is_view_only() && (key_images.empty() || !spent)) {
      output.m_key_image = generate_key_image(*output.m_tx_pub_key, *output.m_index, received_subaddr).m_hex;

      // check key image is spent in unconfirmed transactions
      spent = key_image_is_spent(output.m_key_image.get());
      checked_unconfirmed = true;
    }

    if (!checked_unconfirmed && !spent && output.m_key_image != boost::none) {
      // check key image is spent in unconfirmed transactions
      spent = key_image_is_spent(output.m_key_image.get());
    }

    return spent;
  }

  bool monero_wallet_light::output_is_spent(monero_light_spend &spend) const {
    if (spend.m_key_image == boost::none) return false;
    std::string key_image = *spend.m_key_image;
    const auto rcpt = *spend.m_sender;
    cryptonote::subaddress_index received_subaddr;

    received_subaddr.major = *rcpt.m_maj_i;
    received_subaddr.minor = *rcpt.m_min_i;

    return key_image_is_ours(key_image, *spend.m_tx_pub_key, *spend.m_out_index, received_subaddr);
  }

  bool monero_wallet_light::output_is_locked(monero_light_output output) const {
    const auto address_txs_res = get_address_txs();
    const auto address_txs = address_txs_res.m_transactions.get();
    const auto tx_hash = output.m_tx_hash.get();

    auto found = std::find_if(address_txs.begin(), address_txs.end(), [tx_hash](const monero_light_transaction& tx) {
      return tx.m_hash.get() == tx_hash;
    });

    if (found == address_txs.end()) throw std::runtime_error("Output doesn't belong to the wallet");

    if (found->m_mempool.get()) return true;

    const auto height = get_height();
    const auto unlock_time = found->m_unlock_time.get();

    return unlock_time > height || height < (*found->m_height) + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  }

  void monero_wallet_light::calculate_balance() {
    const auto resp = get_unspent_outs(true);

    m_wallet_balance = 0;
    m_wallet_unlocked_balance = 0;
    m_account_balance_container.clear();
    m_account_unlocked_balance_container.clear();
    m_subaddress_balance_container.clear();
    m_subaddress_unlocked_balance_container.clear();

    for (auto const &output : *resp.m_outputs) {
      uint32_t account_idx = *output.m_recipient->m_maj_i;
      uint32_t subaddress_idx = *output.m_recipient->m_min_i;
      uint64_t output_amount = gen_utils::uint64_t_cast(*output.m_amount);
      auto account_balance = m_account_balance_container.find(account_idx);
      bool locked = output_is_locked(output);
      uint64_t unlocked_output_amount = locked == true ? 0 : output_amount;

      if (account_balance == m_account_balance_container.end()) {
        m_account_balance_container[account_idx] = output_amount;
        m_account_unlocked_balance_container[account_idx] = unlocked_output_amount;
      }
      else {
        m_account_balance_container[account_idx] += output_amount;
        m_account_unlocked_balance_container[account_idx] += unlocked_output_amount;
      }

      auto account_subaddress_balance = m_subaddress_balance_container.find(account_idx);
      if (account_subaddress_balance == m_subaddress_balance_container.end()) {
        m_subaddress_balance_container[account_idx][subaddress_idx] = output_amount;
        m_subaddress_unlocked_balance_container[account_idx][subaddress_idx] = unlocked_output_amount;
      }
      else {
        auto subaddress_balance = account_subaddress_balance->second.find(subaddress_idx);
        if (subaddress_balance == account_subaddress_balance->second.end()) {
          m_subaddress_balance_container[account_idx][subaddress_idx] = output_amount;
          m_subaddress_unlocked_balance_container[account_idx][subaddress_idx] = unlocked_output_amount;
        }
        else {
          m_subaddress_balance_container[account_idx][subaddress_idx] += output_amount;
          m_subaddress_unlocked_balance_container[account_idx][subaddress_idx] += unlocked_output_amount;
        }
      }

      m_wallet_balance += output_amount;
      m_wallet_unlocked_balance += unlocked_output_amount;
    }

    // Calculate change amount

    for(auto const &tx : (*m_unconfirmed_txs)) {
      uint64_t change_amount = tx->m_change_amount.get();
      m_wallet_balance += change_amount;

      if (tx->m_outgoing_transfer != boost::none) {
        const auto &outgoing_transfer = tx->m_outgoing_transfer.get();

        for(auto const &dest : outgoing_transfer->m_destinations) {
          if (destination_is_ours(dest)) {
            auto address_index = get_address_index(dest->m_address.get());
            m_account_balance_container[address_index.m_account_index.get()] += dest->m_amount.get();
            m_subaddress_balance_container[address_index.m_account_index.get()][address_index.m_index.get()] += dest->m_amount.get();
            m_wallet_balance += dest->m_amount.get();
          }
        }
      }
    }

  }

  bool monero_wallet_light::destination_is_ours(const std::shared_ptr<monero_destination> &dest) const {
    try {
      get_address_index(dest->m_address.get());
      return true;
    }
    catch (...) {
      return false;
    }
  }

  uint64_t monero_wallet_light::get_tx_balance(const std::shared_ptr<monero_tx_wallet> &tx) const {
    uint64_t balance = 0;

    if (tx->m_change_amount != boost::none) balance = tx->m_change_amount.get();
    if (tx->m_outgoing_transfer != boost::none) {
      for (const auto &dest : (*tx->m_outgoing_transfer)->m_destinations) {
        if (destination_is_ours(dest)) {
          balance += dest->m_amount.get();
        }
      }
    }

    return balance;
  }

  void monero_wallet_light::run_sync_loop() {
    if (m_sync_loop_running) return;  // only run one loop at a time
    m_sync_loop_running = true;

    // start sync loop thread
    // TODO: use global threadpool, background sync wasm wallet in c++ thread
    m_syncing_thread = boost::thread([this]() {

      // sync while enabled
      while (m_syncing_enabled) {
        try { lock_and_sync(); }
        catch (std::exception const& e) { std::cout << "monero_wallet_full failed to background synchronize: " << e.what() << std::endl; }
        catch (...) { std::cout << "monero_wallet_full failed to background synchronize" << std::endl; }

        // only wait if syncing still enabled
        if (m_syncing_enabled) {
          boost::mutex::scoped_lock lock(m_syncing_mutex);
          boost::posix_time::milliseconds wait_for_ms(m_syncing_interval.load());
          m_sync_cv.timed_wait(lock, wait_for_ms);
        }
      }

      m_sync_loop_running = false;
    });
  }

  monero_sync_result monero_wallet_light::lock_and_sync(boost::optional<uint64_t> start_height) {
    bool rescan = m_rescan_on_sync.exchange(false);
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex); // synchronize sync() and syncAsync()
    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    do {
      // skip if daemon is not connected or synced
      if (m_is_connected && is_daemon_synced()) {

        // rescan blockchain if requested
        if (rescan) rescan_blockchain();

        // sync wallet
        result = sync_aux(start_height);
      }
    } while (!rescan && (rescan = m_rescan_on_sync.exchange(false))); // repeat if not rescanned and rescan was requested
    return result;
  }

  monero_sync_result monero_wallet_light::sync_aux(boost::optional<uint64_t> start_height) {
    MTRACE("sync_aux()");
    uint64_t last_height = get_height();
    bool received_money = false;
    // determine sync start height
    uint64_t sync_start_height = last_height;
    //if (sync_start_height < get_restore_height()) set_restore_height(sync_start_height); // TODO monero-project: start height processed > requested start height unless sync height manually set

    // notify listeners of sync start
    m_wallet_listener->on_sync_start(sync_start_height);
    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    if (is_connected_to_daemon()) {
      // attempt to refresh which may throw exception
      try {
        const std::string address = get_primary_address();
        const std::string view_key = get_private_view_key();

        const uint64_t old_outs_amount = gen_utils::uint64_t_cast(m_unspent_outs.m_amount.get());
        
        uint64_t blockchain_height = 1;
        auto addr_info = m_light_client->get_address_info(address, view_key);
        if (addr_info.m_blockchain_height != boost::none) blockchain_height = addr_info.m_blockchain_height.get() + 1;

        if (blockchain_height == last_height) {
          std::cout << "monero_wallet_light::sync(): skipping sync at height " << blockchain_height << std::endl; 
          m_wallet_listener->on_sync_end();
          return result;
        }

        std::cout << "monero_wallet_light::sync(): syncing at height " << blockchain_height << std::endl; 

        boost::unique_lock<boost::recursive_mutex> lock(m_sync_data_mutex);
        
        m_address_info = addr_info;
        m_address_txs = m_light_client->get_address_txs(address, view_key);
        m_unspent_outs = m_light_client->get_unspent_outs(address, view_key, "0", 0);
        m_subaddrs = m_light_client->get_subaddrs(address, view_key);

        const uint64_t new_outs_amount = gen_utils::uint64_t_cast(m_unspent_outs.m_amount.get());

        received_money = new_outs_amount > old_outs_amount;

        const auto txs = m_address_txs.m_transactions.get();

        uint64_t last_block_reward = TAIL_EMISSION_REWARD;

        for (const auto &tx : txs) {
          if (tx.m_coinbase.get()) {
            uint64_t tx_total_received = gen_utils::uint64_t_cast(tx.m_total_received.get());

            if (last_block_reward == 0 || tx_total_received < last_block_reward) last_block_reward = tx_total_received;
          }
        }

        if (m_last_block_reward < last_block_reward) m_last_block_reward = last_block_reward;

        if (!m_is_synced) m_is_synced = is_synced();

        calculate_balance();

        lock.unlock();

        m_wallet_listener->update_listening();  // cannot unregister during sync which would segfault
      } catch (std::exception& e) {
        m_wallet_listener->on_sync_end(); // signal end of sync to reset listener's start and end heights
        throw;
      }
    }
    else {
      m_wallet_listener->on_sync_end();
      return result;
    }

    uint64_t current_height = get_height();
    uint64_t daemon_height = get_daemon_height();
    uint64_t restore_height = get_restore_height();

    std::cout << "monero_wallet_light::sync(): current_height=" << current_height << ", daemon_height=" << daemon_height << ", restore_height=" << restore_height << ", last_height=" << last_height << std::endl;

    if (restore_height < current_height) {
      if (last_height < restore_height) last_height = restore_height;
      std::cout << "monero_wallet_light::sync(): last_height" << last_height << std::endl;
      result.m_num_blocks_fetched = current_height - last_height;
    
      if (current_height > last_height) m_wallet_listener->on_new_block(current_height);

      result.m_received_money = received_money;
    } else {
      result.m_num_blocks_fetched = 0;
      result.m_received_money = false;
    }

    // notify listeners of sync end and check for updated funds
    m_wallet_listener->on_sync_end();
    return result;
  }

  std::string monero_wallet_light::make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const {
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, get_nettype(), address))
    {
      error = std::string("wrong address: ") + address;
      return std::string();
    }

    // we want only one payment id
    if (info.has_payment_id && !payment_id.empty())
    {
      error = "A single payment id is allowed";
      return std::string();
    }

    if (!payment_id.empty())
    {
      error = "Standalone payment id deprecated, use integrated address instead";
      return std::string();
    }

    std::string uri = "monero:" + address;
    unsigned int n_fields = 0;

    if (!payment_id.empty())
    {
      uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
    }

    if (amount > 0)
    {
      // URI encoded amount is in decimal units, not atomic units
      uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
    }

    if (!recipient_name.empty())
    {
      uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
    }

    if (!tx_description.empty())
    {
      uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
    }

    return uri;
  }

  bool monero_wallet_light::parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) const {
    if (uri.substr(0, 7) != "monero:")
    {
      error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
      return false;
    }

    std::string remainder = uri.substr(7);
    const char *ptr = strchr(remainder.c_str(), '?');
    address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, get_nettype(), address))
    {
      error = std::string("URI has wrong address: ") + address;
      return false;
    }
    if (!strchr(remainder.c_str(), '?'))
      return true;

    std::vector<std::string> arguments;
    std::string body = remainder.substr(address.size() + 1);
    if (body.empty())
      return true;
    boost::split(arguments, body, boost::is_any_of("&"));
    std::set<std::string> have_arg;
    for (const auto &arg: arguments)
    {
      std::vector<std::string> kv;
      boost::split(kv, arg, boost::is_any_of("="));
      if (kv.size() != 2)
      {
        error = std::string("URI has wrong parameter: ") + arg;
        return false;
      }
      if (have_arg.find(kv[0]) != have_arg.end())
      {
        error = std::string("URI has more than one instance of " + kv[0]);
        return false;
      }
      have_arg.insert(kv[0]);

      if (kv[0] == "tx_amount")
      {
        amount = 0;
        if (!cryptonote::parse_amount(amount, kv[1]))
        {
          error = std::string("URI has invalid amount: ") + kv[1];
          return false;
        }
      }
      else if (kv[0] == "tx_payment_id")
      {
        if (info.has_payment_id)
        {
          error = "Separate payment id given with an integrated address";
          return false;
        }
        crypto::hash hash;
        if (!monero_utils::parse_long_payment_id(kv[1], hash))
        {
          error = "Invalid payment id: " + kv[1];
          return false;
        }
        payment_id = kv[1];
      }
      else if (kv[0] == "recipient_name")
      {
        recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
      }
      else if (kv[0] == "tx_description")
      {
        tx_description = epee::net_utils::convert_from_url_format(kv[1]);
      }
      else
      {
        unknown_parameters.push_back(arg);
      }
    }
    return true;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses() const {
    std::vector<monero_subaddress> result;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      const auto all_subaddrs = m_subaddrs.m_all_subaddrs.get();
      for (auto kv : all_subaddrs) {
        for(auto index_range : kv.second) {

          auto subaddresses = monero_wallet_keys::get_subaddresses(kv.first, index_range.to_subaddress_indices());

          for (auto subaddress : subaddresses) {
            //subaddress.m_balance = get_balance(kv.first, *subaddress.m_index);
            //subaddress.m_unlocked_balance = get_unlocked_balance(kv.first, *subaddress.m_index);
            //subaddress.m_label = get_subaddress_label(kv.first, *subaddress.m_index);
            //subaddress.m_num_unspent_outputs = get_subaddress_num_unspent_outs(kv.first, *subaddress.m_index);
            //subaddress.m_is_used = subaddress_is_used(kv.first, *subaddress.m_index);
            //subaddress.m_num_blocks_to_unlock = get_subaddress_num_blocks_to_unlock(kv.first, *subaddress.m_index);

            result.push_back(subaddress);
          }
        }
      }
    }

    return result;
  }

  void monero_wallet_light::set_tx_note(const crypto::hash &txid, const std::string &note) {
    m_tx_notes[txid] = note;
  }

  std::string monero_wallet_light::get_tx_note(const crypto::hash &txid) const {
    std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_notes.find(txid);
    if (i == m_tx_notes.end())
      return std::string();
    return i->second;
  }

  boost::optional<std::string> monero_wallet_light::get_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto subs = m_subaddress_labels.find(account_idx);
    if (subs == m_subaddress_labels.end()) return boost::none;
    auto sub = subs->second.find(subaddress_idx);
    if (sub == subs->second.end()) return boost::none;

    boost::optional<std::string> result = sub->second;

    return result;
  }

  std::tuple<uint64_t, uint64_t, std::vector<tools::wallet2::exported_transfer_details>> monero_wallet_light::export_outputs(bool all, uint32_t start, uint32_t count) const {
    std::vector<tools::wallet2::exported_transfer_details> outs;

    // invalid cases
    if(count == 0) throw std::runtime_error("Nothing requested");
    if(!all && start > 0) throw std::runtime_error("Incremental mode is incompatible with non-zero start");

    // valid cases:
    // all: all outputs, subject to start/count
    // !all: incremental, subject to count
    // for convenience, start/count are allowed to go past the valid range, then nothing is returned
    auto unspent_outs_res = get_unspent_outs(false);
    auto unspent_outs = *unspent_outs_res.m_outputs;

    size_t offset = 0;    
    if (!all)
      while (offset < unspent_outs.size() && (unspent_outs[offset].key_image_is_known() && !m_generated_key_images.request(unspent_outs[offset].m_tx_pub_key.get(), unspent_outs[offset].m_index.get(), unspent_outs[offset].m_recipient->m_maj_i.get(), unspent_outs[offset].m_recipient->m_min_i.get())))
        ++offset;
    else
      offset = start;

    auto address_txs_res = get_address_txs();
    auto address_txs = address_txs_res.m_transactions.get();

    outs.reserve(unspent_outs.size() - offset);
    for (size_t n = offset; n < unspent_outs.size() && n - offset < count; ++n)
    {
      const auto &out = unspent_outs[n];
      uint64_t out_amount = gen_utils::uint64_t_cast(*out.m_amount);
      auto internal_output_index = *out.m_index;
      std::string tx_hash = out.m_tx_hash.get();

      const auto found = std::find_if(address_txs.begin(), address_txs.end(), [tx_hash](const monero_light_transaction &tx) {
        return tx.m_hash.get() == tx_hash;
      });

      if (found == address_txs.end()) throw std::runtime_error("output doens't belong to the wallet");

      auto unlock_time = found->m_unlock_time.get();

      tools::wallet2::exported_transfer_details etd;
      
      crypto::public_key public_key;
      crypto::public_key tx_pub_key;

      epee::string_tools::hex_to_pod(*out.m_public_key, public_key);
      epee::string_tools::hex_to_pod(*out.m_tx_pub_key, tx_pub_key);

      cryptonote::transaction_prefix tx_prefix;

      add_tx_pub_key_to_extra(tx_prefix, tx_pub_key);

      cryptonote::tx_out txout;
      txout.target = cryptonote::txout_to_key(public_key);
      txout.amount = out_amount;
      tx_prefix.vout.resize(internal_output_index + 1);
      tx_prefix.vout[internal_output_index] = txout;
      tx_prefix.unlock_time = unlock_time;

      etd.m_pubkey = public_key;
      etd.m_tx_pubkey = tx_pub_key; // pk_index?
      etd.m_internal_output_index = internal_output_index;
      etd.m_global_output_index = gen_utils::uint64_t_cast(*out.m_global_index);
      etd.m_flags.flags = 0;
      etd.m_flags.m_spent = out.is_spent();
      etd.m_flags.m_frozen = false;
      etd.m_flags.m_rct = out.rct();
      etd.m_flags.m_key_image_known = out.key_image_is_known();
      etd.m_flags.m_key_image_request = false; //td.m_key_image_request;
      etd.m_flags.m_key_image_partial = is_multisig();
      etd.m_amount = out_amount;
      etd.m_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx_prefix);
      etd.m_subaddr_index_major = *out.m_recipient->m_maj_i;
      etd.m_subaddr_index_minor = *out.m_recipient->m_min_i;

      outs.push_back(etd);
    }

    return std::make_tuple(offset, unspent_outs.size(), outs);
  }

  std::vector<tools::wallet2::pending_tx> monero_wallet_light::parse_signed_tx(const std::string &signed_tx_st) const {
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
    if (version == '\003')
    {
      if (!m_load_deprecated_formats)
      {
        throw std::runtime_error("Not loading deprecated format");
      }
      try
      {
        std::istringstream iss(s);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> signed_txs;
      }
      catch (...)
      {
        throw std::runtime_error("Failed to parse data from signed transaction");
      }
    }
    else if (version == '\004')
    {
      if (!m_load_deprecated_formats)
      {
        throw std::runtime_error("Not loading deprecated format");
      }
      try
      {
        s = decrypt_with_private_view_key(s);
        try
        {
          std::istringstream iss(s);
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> signed_txs;
        }
        catch (...)
        {
          throw std::runtime_error("Failed to parse decrypted data from signed transaction");
        }
      }
      catch (const std::exception &e)
      {
        throw std::runtime_error(std::string("Failed to decrypt signed transaction: ") + e.what());
      }
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

    // import key images
    //bool r = import_key_images(signed_txs.key_images);
    //if (!r) return false;

    // remember key images for this tx, for when we get those txes from the blockchain
    //for (const auto &e: signed_txs.tx_key_images)
    //  m_cold_key_images.insert(e);

    return signed_txs.ptx;
  }

  tools::wallet2::unsigned_tx_set monero_wallet_light::parse_unsigned_tx(const std::string &unsigned_tx_st) const {
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
    if (version == '\003')
    {
      if (!m_load_deprecated_formats)
      {
        throw std::runtime_error("Not loading deprecated format");
      }
      try
      {
        std::istringstream iss(s);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> exported_txs;
      }
      catch (...)
      {
        throw std::runtime_error("Failed to parse data from unsigned tx");
      }
    }
    else if (version == '\004')
    {
      if (!m_load_deprecated_formats)
      {
        throw std::runtime_error("Not loading deprecated format");
      }
      try
      {
        s = decrypt_with_private_view_key(s);
        try
        {
          std::istringstream iss(s);
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> exported_txs;
        }
        catch (...)
        {
          throw std::runtime_error("Failed to parse data from unsigned tx");
        }
      }
      catch (const std::exception &e)
      {
        std::string msg = std::string("Failed to decrypt unsigned tx: ") + e.what();
        throw std::runtime_error(msg);
      }
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

    std::cout << "Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions" << std::endl;
  
    return exported_txs;
  }

  // implementation based on monero-project wallet2::sign_tx()
  std::string monero_wallet_light::sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes) {
    //if (!std::get<2>(exported_txs.new_transfers).empty())
    //  import_outputs(exported_txs.new_transfers);
    //else if (!std::get<2>(exported_txs.transfers).empty())
    //  import_outputs(exported_txs.transfers);

    auto subaddresses = get_subaddresses_map();

    // sign the transactions
    for (size_t n = 0; n < exported_txs.txes.size(); ++n)
    {
      tools::wallet2::tx_construction_data &sd = exported_txs.txes[n];
      if(sd.sources.empty()) throw std::runtime_error("empty sources");
      if(sd.unlock_time) throw std::runtime_error("unlock time is non-zero");
      std::cout << " " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size() << std::endl;
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
      //if (store_tx_info() && tx_key != crypto::null_skey)
      //{
      //  const crypto::hash txid = get_transaction_hash(ptx.tx);
      //  m_tx_keys[txid] = tx_key;
      //  m_additional_tx_keys[txid] = additional_tx_keys;
      //}

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
        std::cout << "Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping" << std::endl;
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
      }
      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        additional_derivations.push_back({});
        if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back()))
        {
          std::cout << "Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping" << std::endl;
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
          std::cout << "Failed to calculate key image" << std::endl;
      }
    }

    // add key images
    auto unspent_outs_res = get_unspent_outs();
    auto unspent_outs = *unspent_outs_res.m_outputs;
    signed_txes.key_images.resize(unspent_outs.size());

    for (size_t i = 0; i < unspent_outs.size(); ++i)
    {
      auto unspent_out = unspent_outs[i];
      
      //if (!m_transfers[i].m_key_image_known || m_transfers[i].m_key_image_partial)
      if (!unspent_out.key_image_is_known())
        std::cout << "WARNING: key image not known in signing wallet at index " << i << std::endl;

      crypto::key_image ski;
      epee::string_tools::hex_to_pod(*unspent_out.m_key_image, ski);
      
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
    std::cout << "Saving signed tx data (with encryption): " << oss.str() << std::endl;
    std::string ciphertext = encrypt_with_private_view_key(oss.str());
    return std::string(SIGNED_TX_PREFIX) + ciphertext;
  }

  std::string monero_wallet_light::dump_pending_tx(const monero_light_constructed_transaction &tx, boost::optional<std::string> payment_id) const {
    if (tx.m_construction_data == boost::none) throw std::runtime_error("could not dump tx: construction data not set");
    tools::wallet2::unsigned_tx_set txs;
    auto construction_data = tx.m_construction_data.get();

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

  bool monero_wallet_light::get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const {
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

  bool monero_wallet_light::get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const {
    bool r = get_tx_key_cached(txid, tx_key, additional_tx_keys);
    if (r)
    {
      MDEBUG("tx key cached for txid: " << txid);
      return true;
    }

    auto & hwdev = m_account.get_device();

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

    auto unspent_outs_res = get_unspent_outs();
    auto unspent_outs = *unspent_outs_res.m_outputs;
    std::string tx_hash = epee::string_tools::pod_to_hex(txid);

    auto found_out = std::find_if(unspent_outs.begin(), unspent_outs.end(), [tx_hash](const monero_light_output &out){
      return *out.m_tx_hash == tx_hash;
    });

    if (found_out == unspent_outs.end()) return false;

    tx_key_data.tx_prefix_hash = *found_out->m_tx_prefix_hash;

    if (tx_key_data.tx_prefix_hash.empty())
    {
      return false;
    }

    std::vector<crypto::secret_key> tx_keys;
    dev_cold->get_tx_key(tx_keys, tx_key_data, m_account.get_keys().m_view_secret_key);
    if (tx_keys.empty())
    {
      MDEBUG("Empty tx keys for txid: " << txid);
      return false;
    }

    if (tx_keys[0] == crypto::null_skey)
    {
      return false;
    }

    tx_key = tx_keys[0];
    tx_keys.erase(tx_keys.begin());
    additional_tx_keys = tx_keys;
    return true;
  }

  void monero_wallet_light::remove_unconfirmed_tx(const std::string &hash) const {
    const auto found = std::find_if(m_unconfirmed_txs->begin(), m_unconfirmed_txs->end(),[&hash](const std::shared_ptr<monero_tx_wallet>& ptr) {
      return ptr->m_hash != boost::none && ptr->m_hash.get() == hash;
    });

    std::vector<std::string> key_images_to_remove;

    if (found != m_unconfirmed_txs->end()) {
      auto unconfirmed_tx = (*found);
      auto inputs = unconfirmed_tx->m_inputs;

      std::cout << "removing key images from " << inputs.size() << " inputs" << std::endl;

      for (auto &_input : inputs) {
        std::shared_ptr<monero_output_wallet> input = std::dynamic_pointer_cast<monero_output_wallet>(_input);

        if (input == nullptr) {
          std::cout << "could not dynamic cast monero_output* to monero_output_wallet*" << std::endl;
          continue;
        }
        if (input->m_key_image == boost::none) {
          std::cout << "input has no key image" << std::endl;
          continue;
        }
        auto hex = input->m_key_image.get()->m_hex;
        if (hex == boost::none) throw std::runtime_error("key image without hex");
        key_images_to_remove.push_back(hex.get());
      }
    }

    std::unordered_set<std::string> ki_to_remove(key_images_to_remove.begin(), key_images_to_remove.end());

    m_unconfirmed_txs->erase(
      std::remove_if(
          m_unconfirmed_txs->begin(),
          m_unconfirmed_txs->end(),
          [&hash](const std::shared_ptr<monero_tx_wallet>& ptr) {
              return ptr->m_hash != boost::none && ptr->m_hash.get() == hash;
          }
      ), m_unconfirmed_txs->end());
    
    m_key_images_in_pool->erase(std::remove_if(m_key_images_in_pool->begin(), m_key_images_in_pool->end(),
    [&ki_to_remove](const std::string& ki) {
        return ki_to_remove.count(ki) > 0;
    }),
    m_key_images_in_pool->end());
  }

  // --------------------------- LWS UTILS --------------------------

  monero_light_get_address_info_response monero_wallet_light::get_address_info(bool filter_outputs) const {
    //boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);
    auto result = m_address_info;

    monero_light_get_address_info_response res;

    uint64_t total_sent = gen_utils::uint64_t_cast(*result.m_total_sent);

    res.m_blockchain_height = result.m_blockchain_height;
    res.m_locked_funds = result.m_locked_funds;
    res.m_scanned_block_height = result.m_scanned_block_height;
    res.m_scanned_height = result.m_scanned_height;
    res.m_transaction_height = result.m_transaction_height;
    res.m_start_height = result.m_start_height;
    res.m_total_received = result.m_total_received;
    res.m_total_sent = result.m_total_sent;
    res.m_rates = result.m_rates;
    res.m_spent_outputs = std::vector<monero_light_spend>();

    for (auto &output : *result.m_spent_outputs) {
      if (!output_is_spent(output)) {
        total_sent -= gen_utils::uint64_t_cast(*output.m_amount);
      }

      if (!filter_outputs) res.m_spent_outputs->push_back(output);
    }

    res.m_total_sent = std::to_string(total_sent);

    return res;
  }

  bool output_before(const monero_light_output& ow1, const monero_light_output& ow2) {
    //if (ow1 == ow2) return false; // ignore equal references

    // compare by height
    //if (tx_height_less_than(ow1->m_tx, ow2->m_tx)) return true;


    // compare by account index, subaddress index, output index, then key image hex
    if (ow1.m_recipient->m_maj_i.get() < ow2.m_recipient->m_maj_i.get()) return true;
    if (ow1.m_recipient->m_maj_i.get() == ow2.m_recipient->m_maj_i.get()) {
      if (ow1.m_recipient->m_min_i.get() < ow2.m_recipient->m_min_i.get()) return true;
      if (ow1.m_recipient->m_min_i.get() == ow2.m_recipient->m_min_i.get()) {
        if (ow1.m_global_index.get() < ow2.m_global_index.get()) return true;
        if (ow1.m_global_index.get() == ow2.m_global_index.get()) throw std::runtime_error("Should never sort outputs with duplicate indices");
      }
    }
    return false;
  }

  monero_light_get_address_txs_response monero_wallet_light::get_address_txs() const {
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_data_mutex);
    monero_light_get_address_txs_response result = m_address_txs;
    monero_light_get_address_txs_response res;

    res.m_blockchain_height = result.m_blockchain_height;
    res.m_scanned_block_height = result.m_scanned_block_height;
    res.m_scanned_height = result.m_scanned_height;
    res.m_start_height = result.m_start_height;
    res.m_total_received = result.m_total_received;
    res.m_transactions = std::vector<monero_light_transaction>();

    const auto txs = *result.m_transactions;

    for(auto &_tx : txs) {
      auto tx = std::make_shared<monero_light_transaction>();
      const auto __tx = std::make_shared<monero_light_transaction>(_tx);

      __tx.get()->copy(__tx, tx, true);
      uint64_t tx_total_sent = gen_utils::uint64_t_cast(*__tx->m_total_sent);
      uint64_t tx_total_received = gen_utils::uint64_t_cast(*__tx->m_total_received);
      
      for (auto spend : *__tx->m_spent_outputs) {
        if(!output_is_spent(spend)) {

          uint64_t spend_amount = gen_utils::uint64_t_cast(*spend.m_amount);
          
          if (spend_amount > tx_total_sent) {
            throw std::runtime_error("tx total sent is negative: " + _tx.m_hash.get());
          }
          
          tx_total_sent -= spend_amount;
        }
        else {
          tx->m_spent_outputs->push_back(spend);
        }
      }

      if (tx_total_received == 0 && tx_total_sent == 0) {
        continue;
      }

      tx->m_total_sent = std::to_string(tx_total_sent);
      tx->m_total_received = std::to_string(tx_total_received);
      res.m_transactions->push_back(*tx);
    }

    return res;
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(std::string amount, uint32_t mixin, bool use_dust, std::string dust_threshold, bool filter_spent) const {
    auto result = m_light_client->get_unspent_outs(get_primary_address(), get_private_view_key(), amount, mixin, use_dust, dust_threshold);

    monero_light_get_unspent_outs_response response;

    uint64_t _amount = gen_utils::uint64_t_cast(*result.m_amount);

    response.m_fee_mask = result.m_fee_mask;
    response.m_per_byte_fee = result.m_per_byte_fee;
    response.m_outputs = std::vector<monero_light_output>();

    if (result.m_outputs == boost::none) {
      return response;
    }

    const auto outputs = *result.m_outputs;

    for (auto output : outputs) {
      if (output_is_spent(output)) {
        _amount -= gen_utils::uint64_t_cast(*output.m_amount);
        if (filter_spent) continue;
      }

      response.m_outputs->push_back(output);
    }

    response.m_amount = std::to_string(_amount);

    return response;
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(uint64_t amount, uint32_t mixin, bool use_dust, uint64_t dust_threshold, bool filter_spent) const {
    std::string _amount = std::to_string(amount);
    std::string _dust_threshold = std::to_string(dust_threshold);

    return get_unspent_outs(_amount, mixin, use_dust, _dust_threshold, filter_spent);
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(bool filter_spent) const {
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_data_mutex);
    auto result = m_unspent_outs;

    monero_light_get_unspent_outs_response response;

    uint64_t _amount = gen_utils::uint64_t_cast(*result.m_amount);

    response.m_fee_mask = result.m_fee_mask;
    response.m_per_byte_fee = result.m_per_byte_fee;
    response.m_outputs = std::vector<monero_light_output>();

    const auto outputs = *result.m_outputs;

    for (auto output : outputs) {
      if (output_is_spent(output)) {
        _amount -= gen_utils::uint64_t_cast(*output.m_amount);
        if (filter_spent) continue;
      }

      response.m_outputs->push_back(output);
    }

    sort(response.m_outputs->begin(), response.m_outputs->end(), output_before);
    
    response.m_amount = std::to_string(_amount);

    return response;
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_spendable_outs(const uint32_t account_idx, const std::vector<uint32_t> &subaddresses_indices, uint64_t amount, uint32_t mixin, bool use_dust, uint64_t dust_threshold, bool filter_spent) const {
    monero_light_get_unspent_outs_response res = get_unspent_outs(amount, mixin, use_dust, dust_threshold, filter_spent);
    const uint64_t height = get_height();
    monero_light_get_unspent_outs_response result;
    auto outputs = res.m_outputs.get();

    uint64_t _amount = gen_utils::uint64_t_cast(res.m_amount.get());
    result.m_fee_mask = res.m_fee_mask;
    result.m_per_byte_fee = res.m_per_byte_fee;
    result.m_outputs = std::vector<monero_light_output>();

    for (auto &out : outputs) {
      const uint64_t out_height = out.m_height.get();
      const uint64_t out_amount = gen_utils::uint64_t_cast(out.m_amount.get());
      const uint32_t out_account_idx = out.m_recipient->m_maj_i.get();
      const uint32_t out_subaddr_idx = out.m_recipient->m_min_i.get();

      bool found = std::find(subaddresses_indices.begin(), subaddresses_indices.end(), out_subaddr_idx) != subaddresses_indices.end();

      if (out_account_idx != account_idx || (!subaddresses_indices.empty() && !found)) continue;

      if (height < out_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE) {
        if (_amount < out_amount) throw std::runtime_error("spendable amount is negative");
        _amount -= out_amount;
        continue;
      }

      if (is_output_frozen(out)) {
        if (_amount < out_amount) throw std::runtime_error("spendable amount is negative");
        _amount -= out_amount;
        continue;
      }

      const uint64_t unlock_time = get_output_num_blocks_to_unlock(out);
      if (unlock_time > 0) {
        if (_amount < out_amount) throw std::runtime_error("spendable amount is negative");
        _amount -= out_amount;
        continue;
      }

      result.m_outputs->push_back(out);
    }

    result.m_amount = std::to_string(_amount);

    if (_amount < amount) std::cout << "monero_wallet_light::get_spendable_outs(): got less than requested amount" << std::endl;

    return result;
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(uint32_t count, std::vector<uint64_t> &amounts) const {
    std::vector<std::string> _amounts;

    for (auto amount : amounts) {
      _amounts.push_back(std::to_string(amount));
    }

    return get_random_outs(count, _amounts);
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(uint32_t count, std::vector<std::string> &amounts) const {
    return m_light_client->get_random_outs(count, amounts);
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(const std::vector<monero_light_output> &using_outs) const {
      // request decoys for any newly selected inputs
    std::vector<monero_light_output> decoy_requests;
    if (m_prior_attempt_unspent_outs_to_mix_outs) {
      for (size_t i = 0; i < using_outs.size(); ++i) {
        // only need to request decoys for outs that were not already passed in
        if (m_prior_attempt_unspent_outs_to_mix_outs->find(*using_outs[i].m_public_key) == m_prior_attempt_unspent_outs_to_mix_outs->end()) {
          decoy_requests.push_back(using_outs[i]);
        }
      }
    } else {
      decoy_requests = using_outs;
    }

    std::vector<std::string> decoy_req__amounts;
    for (auto &using_out : decoy_requests) {
      if (using_out.m_rct != boost::none && (*(using_out.m_rct)).size() > 0) {
        decoy_req__amounts.push_back("0");
      } else {
        std::ostringstream amount_ss;
        amount_ss << using_out.m_amount;
        decoy_req__amounts.push_back(amount_ss.str());
        std::cout << "pushing decoy req amount: " << amount_ss.str() << std::endl;
      }
    }

    return get_random_outs(get_mixin_size() + 1, decoy_req__amounts);
  }

  monero_light_get_subaddrs_response monero_wallet_light::get_subaddrs() const {
    return m_light_client->get_subaddrs(get_primary_address(), get_private_view_key());
  }

  monero_light_upsert_subaddrs_response monero_wallet_light::upsert_subaddrs(monero_light_subaddrs subaddrs, bool get_all) const {
    return m_light_client->upsert_subaddrs(get_primary_address(), get_private_view_key(), subaddrs, get_all);
  }

  monero_light_upsert_subaddrs_response monero_wallet_light::upsert_subaddrs(uint32_t account_idx, uint32_t subaddress_idx, bool get_all) const {
    std::cout << "monero_wallet_light::upsert_subaddrs(" << account_idx << ", " << subaddress_idx << ")" << std::endl;
    if (account_idx == 0) throw std::runtime_error("subaddress major lookahead may not be zero");
    if (subaddress_idx == 0) throw std::runtime_error("subaddress minor lookahead may not be zero");

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(0, subaddress_idx - 1);
    
    for(uint32_t i = 0; i < account_idx; i++) {
      subaddrs[i] = std::vector<monero_light_index_range>();
      subaddrs[i].push_back(index_range);
    }

    return upsert_subaddrs(subaddrs, get_all);
  }

  monero_light_provision_subaddrs_response monero_wallet_light::provision_subaddrs(uint32_t n_maj_i, uint32_t n_min_i, uint32_t n_maj, uint32_t n_min, bool get_all) const {
    return m_light_client->provision_subaddrs(get_primary_address(), get_private_view_key(), n_maj_i, n_min_i, n_maj, n_min, get_all);
  }

  monero_light_login_response monero_wallet_light::login(bool create_account, bool generated_locally) const {
    return m_light_client->login(get_primary_address(), get_private_view_key());
  }

  monero_light_import_request_response monero_wallet_light::import_request(uint64_t height) const {
    return m_light_client->import_request(get_primary_address(), get_private_view_key(), height);
  }

  monero_light_submit_raw_tx_response monero_wallet_light::submit_raw_tx(const std::string tx) const {
    return m_light_client->submit_raw_tx(tx);
  }

  // --------------------------- STATIC WALLET UTILS --------------------------

  bool monero_wallet_light::wallet_exists(const std::string& primary_address, const std::string& private_view_key, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("monero_wallet_light::wallet_exists(" << primary_address << ")");

    monero_light_client client(std::move(http_client_factory));    
    client.set_server(server_uri);

    try {
      const auto address_info = client.get_address_info(primary_address, private_view_key);

      return true;
    }
    catch (...) {
      return false;
    }
  }

  bool monero_wallet_light::wallet_exists(const monero_wallet_config& config, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    bool empty_seed = config.m_seed == boost::none || config.m_seed->empty();
    if (empty_seed) {
      if (config.m_primary_address == boost::none || config.m_primary_address.get().empty()) throw std::runtime_error("must provide a valid primary address");
      if (config.m_private_view_key == boost::none || config.m_private_view_key.get().empty()) throw std::runtime_error("must provide a valid private view key");
    }
    if (config.m_server == boost::none || config.m_server->m_uri == boost::none || config.m_server->m_uri->empty()) throw std::runtime_error("must provide a lws connection");

    if (!empty_seed) {
      monero_wallet_keys *wallet_keys = monero_wallet_keys::create_wallet_from_seed(config);

      return wallet_exists(wallet_keys->get_primary_address(), wallet_keys->get_private_view_key(), *config.m_server->m_uri, std::move(http_client_factory));
    }

    return wallet_exists(config.m_primary_address.get(), config.m_private_view_key.get(), *config.m_server->m_uri, std::move(http_client_factory));
  }

  monero_wallet_light* monero_wallet_light::open_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    monero_wallet_config _config = config.copy();
    if (config.m_seed != boost::none && !config.m_seed->empty()) {
      return create_wallet_from_seed(_config, std::move(http_client_factory));
    }

    return create_wallet_from_keys(_config, std::move(http_client_factory));
  }

  monero_wallet_light* monero_wallet_light::create_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet(config)");
    std::cout << "create_wallet(...)" << std::endl;

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
    std::cout << "create_wallet(...): config normalized seed: " << config_normalized.m_seed.get() << std::endl;
    // create wallet

    if (!config_normalized.m_seed.get().empty()) {
      if (config_normalized.m_server != boost::none && config_normalized.m_server->m_uri != boost::none && wallet_exists(config_normalized, config_normalized.m_server->m_uri.get(), std::move(http_client_factory))) {
        throw std::runtime_error("Wallet already exists");
      }
      return create_wallet_from_seed(config_normalized, std::move(http_client_factory));

    } else if (!config_normalized.m_primary_address.get().empty() || !config_normalized.m_private_spend_key.get().empty() || !config_normalized.m_private_view_key.get().empty()) {
      if (config_normalized.m_server != boost::none && config_normalized.m_server->m_uri != boost::none && wallet_exists(config_normalized, config_normalized.m_server->m_uri.get(), std::move(http_client_factory))) {
        throw std::runtime_error("Wallet already exists");
      }
    
      return create_wallet_from_keys(config_normalized, std::move(http_client_factory));
    } else {
      return create_wallet_random(config_normalized, std::move(http_client_factory));
    }
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_seed(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    std::cout << "create_wallet_from_seed(...)" << std::endl;

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
    monero_wallet_light* wallet = new monero_wallet_light(std::move(http_client_factory));
    wallet->m_account = cryptonote::account_base{};
    wallet->m_account.generate(spend_key_sk, true, false);

    // initialize remaining wallet
    wallet->m_network_type = config.m_network_type.get();
    wallet->m_language = language;
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    wallet->init_common();
    wallet->m_is_view_only = false;

    wallet->set_daemon_connection(config.m_server);
    bool is_connected = wallet->is_connected_to_daemon();

    if (is_connected) {
      if (config.m_account_lookahead != boost::none) {
        wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
        wallet->m_subaddrs = wallet->get_subaddrs();
      }

      if (config.m_restore_height != boost::none)
      {
        wallet->import_request(config.m_restore_height.get());
      }

    } else if (config.m_restore_height != boost::none) throw std::runtime_error("Cannote restore wallet from height: wallet is not connected to lws");

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("monero_wallet_light::create_wallet_from_keys(...)");

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
    if (config_normalized.m_primary_address == boost:: none || config_normalized.m_primary_address.get().empty()) {
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
    monero_wallet_light* wallet = new monero_wallet_light(std::move(http_client_factory));
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
    wallet->set_daemon_connection(config.m_server);

    bool is_connected = wallet->is_connected_to_daemon();

    if (is_connected) {
      if (config.m_account_lookahead != boost::none) {
        wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
        wallet->m_subaddrs = wallet->get_subaddrs();
      }

      if (config.m_restore_height != boost::none)
      {
        wallet->import_request(config.m_restore_height.get());
      }
      
    } else if (config.m_restore_height != boost::none) throw std::runtime_error("Cannote restore wallet from height: wallet is not connected to lws");

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet_random(...)");
    std::cout << "monero_wallet_light::create_wallet_random(...)" << std::endl;

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config_normalized.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config_normalized.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

    // initialize random wallet account
    monero_wallet_light* wallet = new monero_wallet_light(std::move(http_client_factory));
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
    wallet->m_is_view_only = false;

    wallet->set_daemon_connection(config.m_server);

    if (config.m_account_lookahead != boost::none && wallet->is_connected_to_daemon()) {
      wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      wallet->m_subaddrs = wallet->get_subaddrs();
    }

    return wallet;
  }

  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> monero_wallet_light::get_subaddresses_map() const {
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;

    auto account_keys = m_account.get_keys();
    hw::device &hwdev = m_account.get_device();

    subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      const auto all_subaddrs = *m_subaddrs.m_all_subaddrs;
      for (auto kv : all_subaddrs) {

        for (auto index_range : kv.second) {
          for (uint32_t i = index_range.at(0); i <= index_range.at(1); i++) {
            if (kv.first == 0 && i == 0) continue;

            auto subaddress_spend_pub_key = hwdev.get_subaddress_spend_public_key(account_keys, {kv.first, i});

            subaddresses[subaddress_spend_pub_key] = {kv.first, i};
          }
        }
      }
    }

    return subaddresses;
  }

}
