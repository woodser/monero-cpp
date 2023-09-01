#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_full.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
//#include "monero_wallet_model.h"

using namespace std;

// ----------------------------- TEST CONFIG ----------------------------------

// constants
const int LOG_LEVEL = 2;
const string DAEMON_URI = "http://localhost:28081";
const monero_network_type NETWORK_TYPE = monero_network_type::TESTNET;

// ------------------------ MULTISIG STRESS TEST ------------------------------

void synchronize_multisig_participants(vector<monero_wallet*> wallets) {

  // collect multisig hex of all participants to synchronize
  vector<string> multisig_hexes;
  for (int i = 0; i < wallets.size(); i++) {
    monero_wallet* wallet = wallets[i];
    wallet->sync();
    multisig_hexes.push_back(wallet->export_multisig_hex()); // TODO: does wallet need saved?
  }
  
  // import each wallet's peer multisig hex
  for (int i = 0; i < wallets.size(); i++) {
    vector<string> peer_multisig_hexes;
    for (int j = 0; j < wallets.size(); j++) if (j != i) peer_multisig_hexes.push_back(multisig_hexes[j]);
    monero_wallet* wallet = wallets[i];
    wallet->sync();  // TODO monero-project: creating multisig tx fails if wallet not explicitly synced before import_multisig_hex: https://github.com/monero-project/monero/issues/6850
    wallet->import_multisig_hex(peer_multisig_hexes);
  }
}

void init_multisig_wallets(monero_wallet* funding_wallet, vector<monero_wallet*> participants, int M, int N, int account_idx, int num_addresses_to_fund) {

  std::cout << "init_multisig_wallets(" << M << ", " << N << ")" << std::endl;
  if (participants.size() != N) throw std::runtime_error("participants != N");

  // prepare multisig hexes
  vector<string> prepared_multisig_hexes;
  for (int i = 0; i < N; i++) {
    monero_wallet* participant = participants[i];
    prepared_multisig_hexes.push_back(participant->prepare_multisig());
  }

  // make wallets multisig
  vector<string> made_multisig_hexes;
  for (int i = 0; i < participants.size(); i++) {
    monero_wallet* participant = participants[i];
    
    // // test bad input
    // try {
    //   participant.make_multisig(Arrays.asList("asd", "dsa"), M, TestUtils.WALLET_PASSWORD);
    //   throw new RuntimeException("Should have thrown error making wallet multisig with incorrect values");
    // } catch (MoneroError e) {
    //   assertEquals("basic_string", e.getMessage()); // TODO (monero-project): improve error message https://github.com/monero-project/monero/issues/8493
    // }
    
    // collect prepared multisig hexes from wallet's peers
    vector<string> peer_multisig_hexes;
    for (int j = 0; j < participants.size(); j++) if (j != i) peer_multisig_hexes.push_back(prepared_multisig_hexes[j]);

    // make the wallet multisig
    string multisig_hex = participant->make_multisig(peer_multisig_hexes, M, "");
    made_multisig_hexes.push_back(multisig_hex);
  }

  // try to get seed before wallet initialized
  try {
    participants[0]->get_seed();
    throw std::runtime_error("Expected error getting seed before multisig wallet initialized");
  } catch (exception& e) {
    string msg = string(e.what());
    if (msg != "This wallet is multisig, but not yet finalized") throw std::runtime_error("unexpected error: " + msg);
  }

  // exchange keys N - M + 1 times
  string address;
  if (N != made_multisig_hexes.size()) throw std::runtime_error("N != made_multisig_hexes.size()");
  vector<string> prev_multisig_hexes = made_multisig_hexes;
  for (int i = 0; i < N - M + 1; i++) {
    //System.out.println("Exchanging multisig keys round " + (i + 1) + " / " + (N - M + 1));

    // exchange multisig keys with each wallet and collect results
    vector<string> exchange_multisig_hexes;
    for (int j = 0; j < participants.size(); j++) {
      monero_wallet* participant = participants[j];
      
      // // test bad input
      // try {
      //   participant->exchange_multisig_keys(Arrays.asList("asd", "dsa"), TestUtils.WALLET_PASSWORD);
      //   throw new RuntimeException("Should have thrown error exchanging multisig keys with bad input");
      // } catch (MoneroError e) {
      //   assertTrue(e.getMessage().length() > 0);
      // }
      
      // collect the multisig hexes of the wallet's peers from last round
      vector<string> peer_multisig_hexes;
      for (int k = 0; k < participants.size(); k++) if (k != j) peer_multisig_hexes.push_back(prev_multisig_hexes[k]);
      
      // import the multisig hexes of the wallet's peers
      monero_multisig_init_result result = participant->exchange_multisig_keys(peer_multisig_hexes, "");
      
      // test result
      if (result.m_multisig_hex->empty()) throw runtime_error("m_multisig_hex is empty");
      if (i == N - M) {  // result on last round has address
        if (result.m_address->empty()) throw runtime_error("address is empty");
        if (address.empty()) address = result.m_address.get();
        else if (address != result.m_address.get()) throw runtime_error("address != result address");
      } else {
        if (result.m_address) throw runtime_error("address should be empty");
        exchange_multisig_hexes.push_back(result.m_multisig_hex.get());
      }
    }
    
    // use results for next round of exchange
    prev_multisig_hexes = exchange_multisig_hexes;
  }

  // validate final multisig
  monero_wallet* participant = participants[0];
  monero_utils::validate_address(participant->get_primary_address(), NETWORK_TYPE);
  //test_multisig_info(participant->get_multisig_info(), M, N); // TODO
  string seed = participant->get_seed();
  if (seed.empty()) throw std::runtime_error("seed should not be empty");

  // restore participant from multisig seed
  // participant->close();
  // delete participant;
  // participant = createWallet(new MoneroWalletConfig().setSeed(seed).setIsMultisig(true));
  // MoneroUtils.validateAddress(participant.getPrimaryAddress(), TestUtils.NETWORK_TYPE);
  // assertEquals(address, participant.getPrimaryAddress());
  // testMultisigInfo(participant.getMultisigInfo(), M, N);
  // assertEquals(seed, participant.getSeed());
  // participants.set(0, participant);
  
  // test sending a multisig transaction if configured
  if (num_addresses_to_fund == 0) return;
    
  // create accounts in the first multisig wallet to receive funds
  for (int i = 0; i < account_idx; i++) participant->create_account();
  
  // get destinations to subaddresses within the account of the multisig wallet
  vector<shared_ptr<monero_destination>> destinations;
  for (int i = 0; i < num_addresses_to_fund; i++) {
    shared_ptr<monero_destination> destination = make_shared<monero_destination>();
    destination->m_address = participant->get_address(account_idx, i);
    destination->m_amount = 200000000000; // TODO: add a 0 for 2 XMR
    destinations.push_back(destination);
    if (i + 1 < num_addresses_to_fund) participant->create_subaddress(account_idx);
  }
  
  // // wait for txs to confirm and for sufficient unlocked balance
  // TestUtils.WALLET_TX_TRACKER.waitForWalletTxsToClearPool(wallet);
  // TestUtils.WALLET_TX_TRACKER.waitForUnlockedBalance(wallet, 0, null, TestUtils.MAX_FEE.multiply(new BigInteger("20")));
  
  // send funds from the main test wallet to destinations in the first multisig wallet
  std::cout << "Sending funds from main wallet" << std::endl;
  monero_tx_config tx_config;
  tx_config.m_account_index = 0;
  tx_config.m_destinations = destinations;
  tx_config.m_relay = true;
  shared_ptr<monero_tx_wallet> tx = funding_wallet->create_tx(tx_config);
  monero_utils::free(tx);
  
  // attempt to start mining
  std::cout << "Starting mining" << std::endl;
  try { funding_wallet->start_mining(1, false, false); }
  catch (const exception& e) { if (string("BUSY") == string(e.what())) throw e; }
  
  uint64_t last_num_confirmations = 0;
  while (true) {
    
    // wait a moment
    gen_utils::wait_for(5000);
    
    // fetch and test outputs
    monero_output_query query;
    vector<shared_ptr<monero_output_wallet>> outputs = participant->get_outputs(query);
    if (outputs.size() == 0) std::cout << "No output reported yet" << endl;
    else {

      // print num confirmations
      uint64_t height = funding_wallet->get_height();
      uint64_t num_confirmations = height - *outputs[0]->m_tx->get_height();
      if (last_num_confirmations != num_confirmations) std::cout << "Output has " << (height - *outputs[0]->m_tx->get_height()) << " confirmations" << endl;

      // outputs are not spent
      
      // break if output is unlocked
      shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(outputs[0]->m_tx);
      if (!tx->m_is_locked.get()) {
        monero_utils::free(outputs);
        break;
      }
    }
    monero_utils::free(outputs);
  }
  
  // stop mining
  funding_wallet->stop_mining();
    
  // multisig wallet should have unlocked balance in subaddresses
  for (int i = 0; i < num_addresses_to_fund; i++) {
    if (participant->get_unlocked_balance(account_idx, i) == 0) throw std::runtime_error("balance expected to be > 0");
  }
  monero_output_query output_query;
  output_query.m_account_index = account_idx;
  vector<shared_ptr<monero_output_wallet>> outputs = participant->get_outputs(output_query);
  if (outputs.size() == 0) throw runtime_error("no outputs returned");
  if (outputs.size() < 3) std::cout << "WARNING: not one output per subaddress?";
  monero_utils::free(outputs);
  
  // wallet requires importing multisig to be reliable
  if (!participant->is_multisig_import_needed()) throw std::runtime_error("multisig import should be needed");
  
  // // attempt creating and relaying transaction without synchronizing with participants
  // String returnAddress = wallet.getPrimaryAddress(); // funds will be returned to this address from the multisig wallet
  // try {
  //   participant.createTxs(new MoneroTxConfig().setAccountIndex(accountIdx).setAddress(returnAddress).setAmount(TestUtils.MAX_FEE.multiply(BigInteger.valueOf(3))));
  //   throw new RuntimeException("Should have failed sending funds without synchronizing with peers");
  // } catch (MoneroError e) {
  //   assertEquals("No transaction created", e.getMessage());
  // }
  
  // synchronize the multisig participants since receiving outputs
  std::cout << "Synchronizing participants" << std::endl;
  synchronize_multisig_participants(participants);
  
  // // expect error exporting key images
  // try {
  //   participant.exportKeyImages(true);
  // } catch (Exception e) {
  //   assertTrue(e.getMessage().contains("key_image generated not matched with cached key image"), "Unexpected error: " + e.getMessage());
  // }
  
  // // attempt relaying created transactions without co-signing
  // try {
  //   participant.createTx(new MoneroTxConfig().setAddress(returnAddress).setAmount(TestUtils.MAX_FEE).setAccountIndex(accountIdx).setSubaddressIndex(0).setRelay(true));
  //   throw new RuntimeException("Should have failed");
  // } catch (Exception e) {
  //   assertTrue(e instanceof MoneroError);
  //   assertEquals("Cannot relay multisig transaction until co-signed", e.getMessage());
  // }
}

void test_multisig_stress(monero_wallet* funding_wallet, string wallet_name = "") {

  // test config
  int M = 2;
  int N = 2;
  int account_idx = 0;
  int num_addresses_to_fund = 5;
  int max_txs = 200;
  //wallet_name = "multisig_stress_0d7c76d1-69b9-46b7-b0e0-5128bd5c725a";
  if (wallet_name.empty()) wallet_name = "multisig_stress_" + gen_utils::get_uuid();
  std::string wallet_path = wallet_name;
  std::cout << "Stress testing multisig wallets: " << wallet_path << std::endl;

  // open or create multisig wallets
  vector<monero_wallet*> participants;
  try {
    for (int i = 0; i < N; i++) {
      participants.push_back(monero_wallet_full::open_wallet(wallet_path + string("_") + std::to_string(i), "", NETWORK_TYPE));
    }
    for (int i = 0; i < participants.size(); i++) {
      participants[i]->set_daemon_connection(DAEMON_URI);
      participants[i]->sync();
      participants[i]->start_syncing(5000);
    }
  } catch (const exception& e) {
    for (int i = 0; i < N; i++) {
      monero_wallet_config wallet_config;
      wallet_config.m_path = wallet_path + string("_") + std::to_string(i);
      wallet_config.m_network_type = monero_network_type::TESTNET;
      wallet_config.m_server = monero_rpc_connection(DAEMON_URI);
      participants.push_back(monero_wallet_full::create_wallet(wallet_config));
    }
    for (int i = 0; i < participants.size(); i++) {
      participants[i]->sync();
      participants[i]->start_syncing(5000);
    }
    init_multisig_wallets(funding_wallet, participants, M, N, account_idx, num_addresses_to_fund);
  }
  monero_wallet* participant = participants[0];

  // start mining
  funding_wallet->start_mining(1, false, false);

  // receive notifications when the wallet receives funds
  struct : monero_wallet_listener {
    void on_output_received(const monero_output_wallet& output) {
      cout << "Wallet received funds!" << endl;
      uint64_t amount = output.m_amount.get();
      string tx_hash = output.m_tx->m_hash.get();
      bool is_confirmed = output.m_tx->m_is_confirmed.get();
      bool is_locked = static_pointer_cast<monero_tx_wallet>(output.m_tx)->m_is_locked.get();
      int account_index = output.m_account_index.get();
      int subaddress_index = output.m_subaddress_index.get();
    }
  } my_listener;
  participant->add_listener(my_listener);

  // cycle funds
  int num_txs = 0;
  while (num_txs < max_txs) {
    try {
      uint64_t unlocked_balance = participant->get_unlocked_balance(0);
      while (unlocked_balance > 0) {

        // synchronize the multisig participants since spending outputs
        std::cout << "Synchronizing participants" << std::endl;
        synchronize_multisig_participants(participants);

        // create txs to cycle funds
        monero_tx_config tx_config;
        tx_config.m_account_index = account_idx;
        for (int i = 0; i < num_addresses_to_fund; i++) {
          shared_ptr<monero_destination> destination = make_shared<monero_destination>();
          destination->m_address = participant->get_address(0, i);
          destination->m_amount = unlocked_balance / (num_addresses_to_fund * 3);
          tx_config.m_destinations.push_back(destination);
        }
        vector<shared_ptr<monero_tx_wallet>> txs = participant->create_txs(tx_config);
        if (txs.empty()) throw runtime_error("txs is empty");
        if ((*txs[0]->m_tx_set.get()->m_multisig_tx_hex).empty()) throw runtime_error("multisig_tx_hex is empty");
        //assertNull(txSet.getSignedTxHex());
        //assertNull(txSet.getUnsignedTxHex());

        // describe multisig tx hex and test
        monero_tx_set tx_set = participant->describe_tx_set(*txs[0]->m_tx_set.get());
        monero_utils::free(tx_set.m_txs);
            
        // sign the tx with participants 1 through m - 1 to meet threshold
        string multisig_tx_hex = txs[0]->m_tx_set.get()->m_multisig_tx_hex.get();
        monero_utils::free(txs);
        std::cout << "Signing" << std::endl;
        for (int j = 1; j < M; j++) {
          monero_multisig_sign_result result = participants[j]->sign_multisig_tx_hex(multisig_tx_hex);
          multisig_tx_hex = result.m_signed_multisig_tx_hex.get();
        }
        
        // submit the signed multisig tx hex to the network
        std::cout << "Submitting: " <<  multisig_tx_hex.length() << std::endl;
        vector<string> tx_hashes = participant->submit_multisig_tx_hex(multisig_tx_hex);
        if (tx_hashes.empty()) throw runtime_error("tx hashes is empty");
        std::cout << "Tx submitted successfully!" << std::endl;

        // fetch the wallet's multisig txs
        monero_tx_query tx_query;
        tx_query.m_hashes = tx_hashes;
        vector<shared_ptr<monero_tx_wallet>> multisig_txs = participant->get_txs(tx_query);
        if (multisig_txs.size() != tx_hashes.size()) throw runtime_error("multisigTxs.size() != txHashes.size()");
        vector<shared_ptr<monero_tx_wallet>> all_txs = participant->get_txs();
        num_txs = all_txs.size();
        std::cout << "All txs size: " << all_txs.size() << std::endl;
        monero_utils::free(multisig_txs);
        monero_utils::free(all_txs);
        if (num_txs >= max_txs) break;
      }
    } catch (const exception& e) {
      std::cout << "There was an error: " << string(e.what()) << std::endl;
    }

    // save wallets
    for (int i = 0; i < participants.size(); i++) {
      participants[i]->save();
    }
    
    // loop
    std::cout << "Starting another loop" << std::endl;
    gen_utils::wait_for(5000);
  }
  
  // save and close wallets
  for (int i = 0; i < participants.size(); i++) {
    participants[i]->close(true);
    delete participants[i];
  }
  participant = 0;
  
  // stop mining
  funding_wallet->stop_mining();
}

// ----------------------------------- MAIN -----------------------------------

/**
 * Main entry point for tests.
 */
int main(int argc, const char* argv[]) {

  // configure logging
  //mlog_configure("log_cpp_scratchpad.txt", true);
  //mlog_set_log_level(LOG_LEVEL);
  //MINFO("logging info!!!");
  //MWARNING("logging a warning!!!");
  //MERROR("logging an error!!!");

  // print header
  MINFO("===== Tests =====");
  for (int i = 0; i < argc; i++) {
    MINFO("Argument" << i << ": " << argv[i]);
  }

  string path = "test_wallet_1";
  string password = "supersecretpassword123";
  string language = "English";
  int network_type = 2;

  // load test wallet
  monero_wallet* wallet = monero_wallet_full::open_wallet("../../test_wallets/test_wallet_1", "supersecretpassword123", monero_network_type::TESTNET);
  wallet->set_daemon_connection(DAEMON_URI);
  wallet->sync();
  wallet->start_syncing(5000);
  
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

  // multisig stress test
  test_multisig_stress(wallet);

  // close wallet and free pointer
  wallet->close(true);
  delete wallet;
}