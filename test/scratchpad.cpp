#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_full.h"
#include "utils/monero_utils.h"

using namespace std;

/**
 * Scratchpad main entry point.
 */
int main(int argc, const char* argv[]) {

  // configure logging
  mlog_configure("log_cpp_scratchpad.txt", true);
  mlog_set_log_level(1);
  //MINFO("logging info!!!");
  //MWARNING("logging a warning!!!");
  //MERROR("logging an error!!!");

  // print header
  MINFO("===== Scratchpad =====");
  for (int i = 0; i < argc; i++) {
    MINFO("Argument" << i << ": " << argv[i]);
  }

  string path = "test_wallet_1";
  string password = "supersecretpassword123";
  string language = "English";
  int network_type = 2;

  // load wallet
  monero_wallet* wallet = monero_wallet_full::open_wallet("../../test_wallets/test_wallet_1", "supersecretpassword123", monero_network_type::TESTNET);
  wallet->set_daemon_connection("http://localhost:28081", "", "");

  // get txs
  vector<shared_ptr<monero_tx_wallet>> txs = wallet->get_txs();
  MINFO("Wallet has " << txs.size() << " txs");
  for (int i = 0; i < txs.size() && i < 10; i++) MINFO(txs[i]->serialize());
  monero_utils::free(txs);

  // get transfers
  vector<shared_ptr<monero_transfer>> transfers = wallet->get_transfers(monero_transfer_query());
  MINFO("Wallet has " << transfers.size() << " transfers");
  monero_utils::free(transfers);

  // get outputs
  vector<shared_ptr<monero_output_wallet>> outputs = wallet->get_outputs(monero_output_query());
  MINFO("Wallet has " << outputs.size() << " outputs");
  monero_utils::free(outputs);

  // close wallet and free pointer
  wallet->close(true);
  delete wallet;
}
