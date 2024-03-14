#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_light.h"
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
  mlog_configure("log_cpp_light_tests.txt", true);
  mlog_set_log_level(4);
  // create a wallet from keys
  MINFO("===== Light Tests =====");
  MINFO("===== Create wallet from keys =====");
  monero_wallet_config wallet_config;
  wallet_config.m_seed = "hefty value later extra artistic firm radar yodel talent future fungal nutshell because sanity awesome nail unjustly rage unafraid cedar delayed thumbs comb custom sanity";
  wallet_config.m_primary_address = "A1y9sbVt8nqhZAVm3me1U18rUVXcjeNKuBd1oE2cTs8biA9cozPMeyYLhe77nPv12JA3ejJN3qprmREriit2fi6tJDi99RR";
  wallet_config.m_private_view_key = "198820da9166ee114203eb38c29e00b0e8fc7df508aa632d56ead849093d3808";
  wallet_config.m_path = "MyWalletRestored";
  wallet_config.m_password = "supersecretpassword123";
  wallet_config.m_network_type = monero_network_type::TESTNET;
  wallet_config.m_server = monero_rpc_connection("http://localhost:8443", "superuser", "abctesting123");
  wallet_config.m_restore_height = 380104;
  wallet_config.m_seed_offset = "";
  monero_wallet* wallet_restored = monero_wallet_light::create_wallet(wallet_config);
  MINFO("===== Wallet Light created successfully =====");
  /*
  // synchronize the wallet and receive progress notifications
  struct : monero_wallet_listener {
    void on_sync_progress(uint64_t height, uint64_t start_height, uint64_t end_height, double percent_done, const string& message) {
      // feed a progress bar?
    }
  } my_sync_listener;
  wallet_restored->sync(my_sync_listener);
  */
 MINFO("===== Syncing wallet light... =====");
  // start syncing the wallet continuously in the background
  wallet_restored->sync();
  MINFO("===== Wallet synced =====");

  // get balance, account, subaddresses
  string restored_primary = wallet_restored->get_primary_address();
  uint64_t balance = wallet_restored->get_balance(); // can specify account and subaddress indices
  monero_account account = wallet_restored->get_account(0, false); // get account without subaddresses
  uint64_t unlocked_account_balance = account.m_unlocked_balance.get(); // get boost::optional value

  // query a transaction by hash
  monero_tx_query tx_query;
  tx_query.m_hash = "314a0f1375db31cea4dac4e0a51514a6282b43792269b3660166d4d2b46437ca";
  vector<shared_ptr<monero_tx_wallet>> txs = wallet_restored->get_txs(tx_query);
  shared_ptr<monero_tx_wallet> tx = txs[0];
  for (const shared_ptr<monero_transfer> transfer : tx->get_transfers()) {
    bool is_incoming = transfer->is_incoming().get();
    uint64_t in_amount = transfer->m_amount.get();
    int account_index = transfer->m_account_index.get();
  }
  monero_utils::free(txs);

  // query incoming transfers to account 1
  monero_transfer_query transfer_query;
  transfer_query.m_is_incoming = true;
  transfer_query.m_account_index = 1;
  vector<shared_ptr<monero_transfer>> transfers = wallet_restored->get_transfers(transfer_query);
  monero_utils::free(transfers);

  // query unspent outputs
  monero_output_query output_query;
  output_query.m_is_spent = false;
  vector<shared_ptr<monero_output_wallet>> outputs = wallet_restored->get_outputs(output_query);
  monero_utils::free(outputs);

  // save and close the wallets
  wallet_restored->close(true);
  delete wallet_restored;
  MINFO("===== End Light Tests =====");
}
