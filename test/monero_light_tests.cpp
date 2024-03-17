#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_light.h"
#include "wallet/monero_wallet_full.h"
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
  //wallet_config.m_seed = "hefty value later extra artistic firm radar yodel talent future fungal nutshell because sanity awesome nail unjustly rage unafraid cedar delayed thumbs comb custom sanity";
  //wallet_config.m_seed = "silk mocked cucumber lettuce hope adrenalin aching lush roles fuel revamp baptism wrist long tender teardrop midst pastry pigment equip frying inbound pinched ravine frying";
  wallet_config.m_primary_address = "A1y9sbVt8nqhZAVm3me1U18rUVXcjeNKuBd1oE2cTs8biA9cozPMeyYLhe77nPv12JA3ejJN3qprmREriit2fi6tJDi99RR";
  wallet_config.m_private_view_key = "198820da9166ee114203eb38c29e00b0e8fc7df508aa632d56ead849093d3808";
  wallet_config.m_path = "MyLightWalletRestored";
  wallet_config.m_password = "supersecretpassword123";
  wallet_config.m_network_type = monero_network_type::TESTNET;
  wallet_config.m_server = monero_rpc_connection("http://localhost:8443", "superuser", "abctesting123");
  //wallet_config.m_server = monero_rpc_connection("http://localhost:28081");
  wallet_config.m_restore_height = 2367336;
  wallet_config.m_seed_offset = "";
  monero_wallet_light* wallet_restored = monero_wallet_light::create_wallet(wallet_config);
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
  MINFO("Get primary address");
  string restored_primary = wallet_restored->get_primary_address();
  MINFO("Got primary address: " << restored_primary);
  MINFO("Get balance");
  uint64_t balance = wallet_restored->get_balance(); // can specify account and subaddress indices
  MINFO("Got balance: " << balance);
  MINFO("Get account");
  monero_account account = wallet_restored->get_account(0, false); // get account without subaddresses
  MINFO("Got account: " << account.m_index.get());
  uint64_t unlocked_account_balance = account.m_unlocked_balance.get(); // get boost::optional value
  MINFO("Got unlocked balance: " << unlocked_account_balance);
  // query a transaction by hash
  monero_tx_query tx_query;
  tx_query.m_hash = "314a0f1375db31cea4dac4e0a51514a6282b43792269b3660166d4d2b46437ca";
  MINFO("Get txs");
  vector<shared_ptr<monero_tx_wallet>> txs = wallet_restored->get_txs(tx_query);
  if (!txs.empty()) {
    shared_ptr<monero_tx_wallet> tx = txs[0];
    MINFO("Got tx: " << tx->m_hash.get());
    for (const shared_ptr<monero_transfer> transfer : tx->get_transfers()) {
      MINFO("Got transfer tx id: " << transfer->m_tx->m_hash.get());
      bool is_incoming = transfer->is_incoming().get();
      uint64_t in_amount = transfer->m_amount.get();
      int account_index = transfer->m_account_index.get();
    }
  } else {
    MINFO("Txs are empty!");
  }
  monero_utils::free(txs);

  MINFO("Exporting outputs...");
  for(std::shared_ptr<monero_output> output : wallet_restored->get_outputs(monero_output_query())) {
    MINFO("Got output amount: " << output->m_amount.get() << ", index: " << output->m_index.get());
  }
  string outputsHex = wallet_restored->export_outputs(true);
  MINFO("Exported outputs hex: " << outputsHex);
  /*

  // offline wallet sign txs test
  monero_wallet_config offline_config; 
  offline_config = wallet_config.copy();
  offline_config.m_seed = "silk mocked cucumber lettuce hope adrenalin aching lush roles fuel revamp baptism wrist long tender teardrop midst pastry pigment equip frying inbound pinched ravine frying";
  offline_config.m_path = "MyOfflineWalletRestored";
  offline_config.m_server = boost::none;
  monero_wallet *offline_wallet = monero_wallet_full::create_wallet(offline_config);
  
  if (wallet_restored->get_primary_address() != offline_wallet->get_primary_address()) {
    MINFO("restored primary address: " << wallet_restored->get_primary_address() << ", offline primary address: " << offline_wallet->get_primary_address());
    throw std::runtime_error("Primary address check failed");
  }
  if (wallet_restored->get_private_view_key() != offline_wallet->get_private_view_key()) throw std::runtime_error("Private view key check failed");
  MINFO("Importing outputs"); 
  if (offline_wallet->is_connected_to_daemon()) throw std::runtime_error("Offline wallet is connected to daemon.");
  MINFO("[OK] Offline wallet is not connected to daemon");
  if (offline_wallet->is_view_only()) throw std::runtime_error("Offline wallet is view only.");
  MINFO("[OK] Offline wallet is not view only");
  int imported_outputs = offline_wallet->import_outputs(outputsHex);
  //if (imported_outputs == 0) throw std::runtime_error("Offline wallet has not imported view only outputs.");
  MINFO("Imported outputs: " << imported_outputs);
  MINFO("Importing key images");
  std::vector<std::shared_ptr<monero_key_image>> signed_key_images = offline_wallet->export_key_images();
  
  //if (signed_key_images.empty()) throw std::runtime_error("Offline wallet should have signed key images at this point.");
  wallet_restored->import_key_images(signed_key_images);
  MINFO("Imported key images");
  monero_tx_config tx_config;
  tx_config.m_account_index = 0;
  tx_config.m_address = wallet_restored->get_primary_address();
  tx_config.m_amount = wallet_restored->get_balance();
  tx_config.m_relay = false;

  std::shared_ptr<monero_tx_wallet> unsigned_tx = wallet_restored->create_tx(tx_config);
  std::string unsigned_tx_hex = unsigned_tx->m_tx_set.get()->m_unsigned_tx_hex.get();
  MINFO("Created unsigned tx hash: " << unsigned_tx_hex);
  monero_tx_set signed_tx_set = offline_wallet->sign_txs(unsigned_tx_hex);  
  std::string signed_tx_hex = signed_tx_set.m_signed_tx_hex.get();
  MINFO("Create signed tx hash: " << signed_tx_hex);
  // query incoming transfers to account 1
  monero_transfer_query transfer_query;
  transfer_query.m_is_incoming = true;
  transfer_query.m_account_index = 0;
  MINFO("Get transfers");
  vector<shared_ptr<monero_transfer>> transfers = wallet_restored->get_transfers(transfer_query);
  monero_utils::free(transfers);

  // query unspent outputs
  monero_output_query output_query;
  output_query.m_is_spent = false;
  MINFO("Get outputs");
  vector<shared_ptr<monero_output_wallet>> outputs = wallet_restored->get_outputs(output_query);
  monero_utils::free(outputs);
  MINFO("close");
*/
  // save and close the wallets
  wallet_restored->close(false);
  MINFO("after close");
  delete wallet_restored;
  MINFO("===== End Light Tests =====");
}
