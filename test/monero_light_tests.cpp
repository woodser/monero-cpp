#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_light.h"
#include "wallet/monero_wallet_full.h"
#include "utils/monero_utils.h"

using namespace std;

const std::string DEFAULT_PRIMARY_ADDRESS = "A19buHUcWkLTq79ExrEhazUCbVdGLeEQqEMMeBMncAEggWaU3h2H68M2Duf4mrZzwainYSWARpjsGgxwykP7XczCMbBHRCC";
const std::string DEFAULT_PRIVATE_VIEW_KEY = "44468fcffea57b6550cd3fc9c0503e06fa02b1c44fa4c31c79426454df7c1b0d";
//const std::string DEFAULT_SPEND_KEY = "ca77112364c9b489e42db8d84a0b371de637688636d1bc9ee0278f352cfc250c";
const std::string DEFAULT_SEED = "gang sunken soya nautical gone woozy pram imitate iceberg wade wives unknown anybody distance cigar fungal outbreak quick goggles voucher simplest suffice jive jive iceberg";
const std::string LWS_URI = "http://localhost:8443";
const std::string DAEMON_URI = "http://localhost:28081";

bool FUNDS_RECEIVED = false;
const bool TEST_RELAYS = true;

void test_view_only_and_offline_wallets(monero_wallet* view_only_wallet, monero_wallet* offline_wallet) {
  MTRACE("test_view_only_and_offline_wallets()");

  if (view_only_wallet->get_txs().empty()) {
    throw std::runtime_error("View only wallet has no transactions");
  }

  if (view_only_wallet->get_transfers().empty()) {
    throw std::runtime_error("View only wallet has no transfers");
  }

  if (view_only_wallet->get_outputs(monero_output_query()).empty()) {
    throw std::runtime_error("View only wallet has no outputs");
  }

  std::string primary_address = offline_wallet->get_primary_address();
  std::string private_view_key = offline_wallet->get_private_view_key();
  
  if (view_only_wallet->get_primary_address() != primary_address) {
    throw std::runtime_error("Primary address check failed");
  }

  if (view_only_wallet->get_private_view_key() != private_view_key) {
    throw std::runtime_error("Private view key check failed");
  }

  std::string error_msg = "Should have failed";

  try {
    view_only_wallet->get_seed();
    throw std::runtime_error(error_msg);
  } catch (std::exception& ex) {
    MWARNING(ex.what());
  }

  try {
    view_only_wallet->get_seed_language();
    throw std::runtime_error(error_msg);
  } catch (std::exception& ex) {
    MWARNING(ex.what());
  }

  try {
    view_only_wallet->get_private_spend_key();
    throw std::runtime_error(error_msg);
  } catch (std::exception& ex) {
    MWARNING(ex.what());
  }

  if (!view_only_wallet->is_connected_to_daemon()) {
    throw std::runtime_error("View only wallet is not connected to daemon");
  }

  if(!view_only_wallet->is_synced()) view_only_wallet->sync();

  if (view_only_wallet->get_txs().empty()) {
    throw std::runtime_error("View only wallet has no txs");
  }

  // export outputs from view-only wallet
  std::string outputs_hex = view_only_wallet->export_outputs();

  // test offline wallet
  if(offline_wallet->is_connected_to_daemon()) throw std::runtime_error("Offline wallet is connected to daemon");
  if(offline_wallet->is_view_only()) throw std::runtime_error("Offline wallet is view only");
  monero_tx_query offline_tx_query;
  offline_tx_query.m_in_tx_pool = false;
  if (!offline_wallet->get_txs(offline_tx_query).empty()) throw std::runtime_error("Offline wallet has unconfirmed transactions");

  // import outputs to offline wallet
  int num_outputs_imported = offline_wallet->import_outputs(outputs_hex);

  if (num_outputs_imported == 0) throw std::runtime_error("No outputs imported");
  MINFO("Imported " << num_outputs_imported << " outputs in offline wallet");
  auto key_images = offline_wallet->export_key_images();
  MINFO("Exported " << key_images.size() << " key images from offline wallet");

  if (!view_only_wallet->is_connected_to_daemon()) throw std::runtime_error("View only wallet is not connected to daemon");
  auto import_result = view_only_wallet->import_key_images(key_images);

  auto view_only_balance = view_only_wallet->get_balance();
  auto offline_balance = offline_wallet->get_balance();

  if (view_only_balance > offline_balance) {
    MERROR("TEST FAILED view-only balance: " << view_only_balance << ", offline balance: " << offline_balance);
    throw std::runtime_error("View only - Offline wallet balance mismatch");
  }
  
  monero_tx_config tx_config;
  tx_config.m_account_index = 0;
  tx_config.m_address = primary_address;
  tx_config.m_amount = 500000000;
  
  auto unsigned_tx = view_only_wallet->create_tx(tx_config);
  auto signed_tx_set = offline_wallet->sign_txs(unsigned_tx->m_tx_set.get()->m_unsigned_tx_hex.get());

  if (TEST_RELAYS) {
    auto tx_hashes = view_only_wallet->submit_txs(signed_tx_set.m_signed_tx_hex.get());
    if (tx_hashes.size() != 1) throw std::runtime_error("No transaction relayed");
    monero_tx_query tx_query;
    
    tx_query.m_hash = tx_hashes[0];

    auto txs = view_only_wallet->get_txs(tx_query);

    if (txs.empty()) {
      MERROR("txs are empty!");

      tx_query.m_hash = boost::none;
      tx_query.m_is_locked = true;

      txs = view_only_wallet->get_txs(tx_query);
      MERROR("tx are still empty");
    }
  }
}

monero_rpc_connection create_connection() {
  return monero_rpc_connection(LWS_URI, "superuser", "abctesting123");
}

monero_rpc_connection create_connection_full() {
  return monero_rpc_connection(DAEMON_URI, "superuser", "abctesting123");
}

monero_wallet_config create_base_wallet_config() {
  monero_wallet_config config;
  config.m_network_type = monero_network_type::TESTNET;
  config.m_server = create_connection();
  config.m_seed_offset = "";
  config.m_restore_height = 2537000;
  config.m_path = "MyLightWalletRestored";
  config.m_password = "supersecretpassword123";
  config.m_account_lookahead = 1;
  config.m_subaddress_lookahead = 11;

  return config;
}

monero_wallet_config create_wallet_config(std::string primary_address, std::string private_view_key, std::string private_spend_key) {
  monero_wallet_config config = create_base_wallet_config();
  config.m_primary_address = primary_address;
  config.m_private_view_key = private_view_key;
  config.m_private_spend_key = private_spend_key;

  return config;
}

monero_wallet_config create_wallet_config(std::string primary_address, std::string private_view_key) {
  return create_wallet_config(primary_address, private_view_key, std::string(""));
}

monero_wallet_config create_wallet_config(std::string seed) {
  monero_wallet_config config = create_base_wallet_config();
  config.m_seed = seed;

  return config; 
}

monero_wallet_config create_view_only_config() {
  return create_wallet_config(DEFAULT_PRIMARY_ADDRESS, DEFAULT_PRIVATE_VIEW_KEY);
}

monero_wallet_config create_offline_config() {
  monero_wallet_config offline_config = create_wallet_config(DEFAULT_SEED);
  offline_config.m_server = monero_rpc_connection("offline_server_uri");
  offline_config.m_path = "MyOfflineWalletRestored";

  return offline_config;
}

monero_wallet_config create_full_config() {
  monero_wallet_config config = create_offline_config();
  config.m_server = create_connection_full();
  config.m_restore_height = 2537000;
  config.m_path = "MyFullWalletRestored";
  config.m_account_lookahead = 11;
  config.m_subaddress_lookahead = 11;
  return config;
}

/**
 * This code introduces the API.
 *
 * NOTE: depending on feedback, fields might change to become private and accessible only
 * through public accessors/mutators for pure object-oriented, etc.
 */
int main(int argc, const char* argv[]) {

//  // configure logging
  mlog_configure("log_cpp_light_tests.txt", true);
  mlog_set_log_level(1);
  // create a wallet from keys
  MINFO("===== Light Tests =====");
  MINFO("===== Create wallet from keys =====");
  monero_wallet_config view_only_config = create_view_only_config();
  monero_wallet_config offline_config = create_offline_config();
  monero_wallet_config light_config = create_wallet_config(DEFAULT_SEED);
  light_config.m_path = "MyKeysLightWalletRestored";

  monero_wallet* light_wallet = monero_wallet_light::create_wallet(light_config);
  monero_wallet* wallet_view_only = monero_wallet_light::create_wallet(view_only_config);
  monero_wallet* offline_wallet = monero_wallet_full::create_wallet(offline_config);
  monero_wallet* full_wallet = monero_wallet_full::create_wallet(create_full_config());
  MINFO("===== Syncing full wallet ... =====");
  full_wallet->sync();
  
  if (!full_wallet->is_synced()) {
    MERROR("===== Full wallet not synced =====");
    return 0;
  }
  
  MINFO("Full wallet sync end - height: " << full_wallet->get_height() << ", balance: " << full_wallet->get_balance() << ", unlocked balance: " << full_wallet->get_unlocked_balance() << ", connected: " << full_wallet->is_connected_to_daemon());
  MINFO("===== Full wallet synced =====");

  MINFO("===== Syncing view only light wallet... =====");
  wallet_view_only->sync();
  if (!wallet_view_only->is_synced()) {
    MERROR("===== View only light wallet not synced =====");
    return 0;
  }

  MINFO("View only light wallet sync end - height: " << wallet_view_only->get_height() << ", balance: " << wallet_view_only->get_balance() << ", unlocked balance: " << wallet_view_only->get_unlocked_balance() << ", connected: " << wallet_view_only->is_connected_to_daemon());
  MINFO("===== View only light wallet synced =====");

  MINFO("===== Syncing light wallet... =====");
  light_wallet->sync();
  if (!light_wallet->is_synced()) {
    MERROR("===== Light wallet not synced =====");
    return 0;
  }

  MINFO("Light wallet sync end - height: " << light_wallet->get_height() << ", balance: " << light_wallet->get_balance() << ", unlocked balance: " << light_wallet->get_unlocked_balance() << ", connected: " << light_wallet->is_connected_to_daemon());
  MINFO("===== Light wallet synced =====");
  full_wallet->start_syncing(5000);
  wallet_view_only->start_syncing(5000);
  light_wallet->start_syncing(5000);
  /*
  MINFO("===== Getting wallets txs =====");
  monero_tx_query t_query;
  t_query.m_is_outgoing = true;

  auto outgoing_txs = full_wallet->get_txs(t_query);

  MINFO("===== Full wallet outgoing txs: " << outgoing_txs.size() << " =====");

  for (auto out_tx : outgoing_txs) {
    uint64_t amount = out_tx->m_outgoing_transfer.get()->m_amount.get();
    std::string hash =  out_tx->m_hash.get();
    uint64_t fee = out_tx->m_fee.get();
    for (auto transfer : out_tx->get_transfers()) {
      std::string ttype = "unknown";

      if (transfer->is_incoming() && transfer->is_outgoing()) {
        ttype = "incoming/outgoing";
      }
      else if (transfer->is_incoming()) {
        ttype = "incoming";
      } else if (transfer->is_outgoing()) {
        ttype = "outgoing";
      }

      MINFO("=====> found " << ttype << " transfer: amount: " << transfer->m_amount);
    }
    MINFO("===== Got full wallet outgoing tx: " << hash << ", amount: " << amount << ", fee: " << fee << " =====");
  }
  
  outgoing_txs = light_wallet->get_txs(t_query);

  MINFO("===== Light wallet outgoing txs: " << outgoing_txs.size() << " =====");

  for (auto out_tx : outgoing_txs) {
    uint64_t amount = out_tx->m_outgoing_transfer.get()->m_amount.get();
    std::string hash =  out_tx->m_hash.get();
    uint64_t fee = out_tx->m_fee.get();
    for (auto transfer : out_tx->get_transfers()) {
      std::string ttype = "unknown";

      if (transfer->is_incoming() && transfer->is_outgoing()) {
        ttype = "incoming/outgoing";
      }
      else if (transfer->is_incoming()) {
        ttype = "incoming";
      } else if (transfer->is_outgoing()) {
        ttype = "outgoing";
      }

      MINFO("=====> found " << ttype << " transfer: amount: " << transfer->m_amount);
    }
    MINFO("===== Got light wallet outgoing tx: " << hash << ", amount: " << amount << ", fee: " << fee << " =====");
  }

  monero_tx_query in_query;
  in_query.m_is_incoming = true;
  auto incoming_txs = light_wallet->get_txs(in_query);

  MINFO("===== Light wallet incoming txs: " << incoming_txs.size() << " =====");

  for(auto in_tx : incoming_txs) {
    uint64_t amount = 0;
    for (auto in_transfer : in_tx->m_incoming_transfers) {
      amount += in_transfer->m_amount.get();
    }    
    std::string hash =  in_tx->m_hash.get();
    uint64_t fee = in_tx->m_fee.get();

    MINFO("===== Got light wallet incoming tx: " << hash << ", amount: " << amount << ", fee: " << fee << " =====");
  }

  incoming_txs = full_wallet->get_txs(in_query);

  MINFO("===== Full wallet incoming txs: " << incoming_txs.size() << " =====");

  for(auto in_tx : incoming_txs) {
    uint64_t amount = 0;
    for (auto in_transfer : in_tx->m_incoming_transfers) {
      amount += in_transfer->m_amount.get();
    }    
    std::string hash =  in_tx->m_hash.get();
    uint64_t fee = in_tx->m_fee.get();

    MINFO("===== Got full wallet incoming tx: " << hash << ", amount: " << amount << ", fee: " << fee << " =====");
  }

  auto outputs = light_wallet->get_outputs(monero_output_query());

  MINFO("Got light wallet outputs: " << outputs.size());

  for(auto output : outputs) {
    auto pub_key = output->m_stealth_public_key.get();
    auto index = output->m_index.get();
    auto spent = output->m_is_spent.get();

    MINFO("===== Got light wallet output public key: " << pub_key << ", index: " << index << ", spent: " << spent << " =====");
  }

  outputs = full_wallet->get_outputs(monero_output_query());

  MINFO("===== Got full wallet outputs: " << outputs.size() << " =====");

  for(auto output : outputs) {
    auto pub_key = output->m_stealth_public_key.get();
    auto index = output->m_index.get();
    auto spent = output->m_is_spent.get();

    MINFO("===== Got full wallet output public key: " << pub_key << ", index: " << index << ", spent: " << spent << " =====");
  }

  MINFO("===== Light wallet balance: " << light_wallet->get_balance() << ", Full wallet balance: " << full_wallet->get_balance() << " =====");
  MINFO("===== Light wallet unlocked balance: " << light_wallet->get_unlocked_balance() << ", Full wallet unlocked balance: " << full_wallet->get_unlocked_balance() << " =====");

  light_wallet->get_txs();
  full_wallet->get_txs();
  */
  auto transfers = light_wallet->get_transfers();

  MINFO("===== Got light wallet transfers: " << transfers.size() << " =====");

  for(auto transfer : transfers) {
    auto hash = transfer->m_tx->m_hash.get();
    std::string type = "unknown";
    
    if (transfer->is_incoming() && transfer->is_outgoing()) {
      type = "incoming/outgoing";
    } else if (transfer->is_incoming()) {
      type = "incoming";
    } else if (transfer->is_outgoing()) {
      type = "outgoing";
    }
    
    MINFO("===== Got light wallet " << type << " transfer hash: " << hash << ", amount: " << transfer->m_amount.get() << ", account index: " << transfer->m_account_index.get() << " =====");
  }

  transfers = full_wallet->get_transfers();

  MINFO("===== Got full wallet transfers: " << transfers.size() << " =====");

  for(auto transfer : transfers) {
    auto hash = transfer->m_tx->m_hash.get();
    std::string type = "unknown";
    
    if (transfer->is_incoming() && transfer->is_outgoing()) {
      type = "incoming/outgoing";
    } else if (transfer->is_incoming()) {
      type = "incoming";
    } else if (transfer->is_outgoing()) {
      type = "outgoing";
    }
    
    MINFO("===== Got full wallet " << type << " transfer hash: " << hash << ", amount: " << transfer->m_amount.get() << ", account index: " << transfer->m_account_index.get() << " =====");
  }

  //test_view_only_and_offline_wallets(wallet_view_only, offline_wallet);
  auto account = light_wallet->get_account(0);

  MINFO("Account 0 balance: " << account.m_balance.get());
  MINFO("Full account 0 balance: " << full_wallet->get_account(0).m_balance);
  return 0;
}