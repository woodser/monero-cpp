#include <stdio.h>
#include <iostream>
#include <chrono>
#include <thread>
#include "wallet2.h"
#include "daemon/monero_daemon_rpc.h"
#include "wallet/monero_wallet_full.h"
#include "wallet/monero_wallet_rpc.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"

using namespace std;

bool FUNDS_RECEIVED = false;

/**
 * This code introduces the API.
 *
 * NOTE: depending on feedback, fields might change to become private and accessible only
 * through public accessors/mutators for pure object-oriented, etc.
 */
int main(int argc, const char* argv[]) {

//  // configure logging
//  mlog_configure("log_cpp_sample_code.txt", true);
//  mlog_set_log_level(1);

  // connect to daemon
  monero_daemon* daemon = new monero_daemon_rpc("http://localhost:28081", "", "");
  uint64_t height = daemon->get_height();                            // 1523651
  vector<shared_ptr<monero_tx>> txs_in_pool = daemon->get_tx_pool(); // get transactions in the pool
  for (const shared_ptr<monero_tx>& tx : txs_in_pool) monero_utils::free(tx);

  // create wallet from seed using native bindings to monero-project
  tools::create_directories_if_necessary("test_wallets"); // *** REMOVE FROM README SAMPLE ***
  monero_wallet_config wallet_config;
  wallet_config.m_path = "test_wallets/sample_wallet_full_" + gen_utils::get_uuid(); // *** CHANGE README TO "sample_wallet_full" ***
  wallet_config.m_password = "supersecretpassword123";
  wallet_config.m_network_type = monero_network_type::TESTNET;
  wallet_config.m_server = make_shared<monero_rpc_connection>("http://localhost:28081", "superuser", "abctesting123");
  wallet_config.m_seed = "silk mocked cucumber lettuce hope adrenalin aching lush roles fuel revamp baptism wrist long tender teardrop midst pastry pigment equip frying inbound pinched ravine frying";
  wallet_config.m_restore_height = 5085;
  monero_wallet* wallet_full = monero_wallet_full::create_wallet(wallet_config);

  // synchronize the wallet and receive progress notifications
  struct : monero_wallet_listener {
    void on_sync_progress(uint64_t height, uint64_t start_height, uint64_t end_height, double percent_done, const string& message) {
      // feed a progress bar?
    }
  } my_sync_listener;
  wallet_full->sync(my_sync_listener);

  // synchronize in the background every 5 seconds
  wallet_full->start_syncing(5000);

  // receive notifications when funds are received, confirmed, and unlocked
  struct : monero_wallet_listener {
    void on_output_received(const monero_output_wallet& output) {
      uint64_t amount = output.m_amount.get();
      string tx_hash = output.m_tx->m_hash.get();
      bool is_confirmed = output.m_tx->m_is_confirmed.get();
      bool is_locked = dynamic_pointer_cast<monero_tx_wallet>(output.m_tx)->m_is_locked.get();
      FUNDS_RECEIVED = true;
    }
  } my_listener;
  wallet_full->add_listener(my_listener);

  // connect to wallet RPC and open wallet
  monero_wallet_rpc* wallet_rpc = new monero_wallet_rpc("http://localhost:28084", "rpc_user", "abc123");
  wallet_rpc->open_wallet("test_wallet_1", "supersecretpassword123");
  string primary_address = wallet_rpc->get_primary_address();       // 555zgduFhmKd2o8rPUz...
  uint64_t balance = wallet_rpc->get_balance();                     // 533648366742
  vector<shared_ptr<monero_tx_wallet>> txs = wallet_rpc->get_txs(); // get transactions containing transfers to/from the wallet
  monero_utils::free(txs);

  // send funds from RPC wallet to full wallet
  monero_tx_config tx_config;
  tx_config.m_account_index = 0;
  tx_config.m_address = wallet_full->get_address(1, 0);
  tx_config.m_amount = 250000000000; // send 0.25 XMR (denominated in atomic units)
  tx_config.m_relay = false; // create transaction and relay to the network if true
  shared_ptr<monero_tx_wallet> created_tx = wallet_rpc->create_tx(tx_config);
  uint64_t fee = created_tx->m_fee.get(); // "Are you sure you want to send... ?"
  wallet_rpc->relay_tx(*created_tx); // relay the transaction
  monero_utils::free(created_tx);

  // recipient receives unconfirmed funds within 5 seconds
  this_thread::sleep_for(chrono::seconds(5));
  if (FUNDS_RECEIVED) cout << "Sample code completed successfully" << endl;
  else throw runtime_error("Output should have been received");

  // save and close full wallet
  wallet_full->close(true);
  delete wallet_full;
  delete wallet_rpc;
  delete daemon;
}
