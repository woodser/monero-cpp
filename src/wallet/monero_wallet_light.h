
#include "monero_wallet_keys.h"
#include "utils/monero_light_client.h"
#include "utils/monero_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/condition_variable.hpp>

#define DUST_THRESHOLD 2000000000

namespace monero {

  // -------------------------------- LISTENERS -------------------------------

  struct wallet_light_listener;

  // there is a light that never goes out
  class monero_wallet_light : public monero_wallet_keys {
  
  public:

    /**
      * Indicates if a wallet exists at the light wallet server.
      *
      * @param primary_address wallet standard address
      * @param private_view_key wallet private view key
      * @param server_uri light wallet server uri
      * @param http_client_factory allows use of custom http clients
      * @return true if a wallet exists at the light wallet server, false otherwise
      */
    static bool wallet_exists(const std::string& primary_address, const std::string& private_view_key, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
      * Indicates if a wallet exists at the light wallet server.
      *
      * @param config wallet configuration
      * @param server_uri light wallet server uri
      * @param http_client_factory allows use of custom http clients
      * @return true if a wallet exists at the light wallet server, false otherwise
      */
    static bool wallet_exists(const monero_wallet_config& config, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
      * Open an existing wallet from a light wallet server.
      *
      * @param primary_address wallet standard address
      * @param private_view_key wallet private view key
      * @param server_uri light wallet server uri
      * @param network_type is the wallet's network type
      * @param http_client_factory allows use of custom http clients
      * @return a pointer to the wallet instance
      */
    static monero_wallet_light* open_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
      * Create a new wallet with the given configuration.
      *
      * @param config is the wallet configuration
      * @param http_client_factory allows use of custom http clients
      * @return a pointer to the wallet instance
      */
    static monero_wallet_light* create_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);
    
    monero_wallet_light(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);
    ~monero_wallet_light();

    std::string get_seed() const override;
    std::string get_seed_language() const override;
    std::string get_private_spend_key() const override;

    void set_daemon_connection(const std::string& uri, const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "") override;
    void set_daemon_connection(const boost::optional<monero_rpc_connection>& connection) override;
    boost::optional<monero_rpc_connection> get_daemon_connection() const override;
    bool is_connected_to_daemon() const override;
    bool is_daemon_synced() const override;
    bool is_daemon_trusted() const override;
    bool is_synced() const override;

    monero_subaddress get_address_index(const std::string& address) const override;

    uint64_t get_height() const override;
    uint64_t get_restore_height() const override;

    uint64_t get_daemon_height() const override;
    uint64_t get_daemon_max_peer_height() const override;

    void add_listener(monero_wallet_listener& listener) override;
    void remove_listener(monero_wallet_listener& listener) override;
    std::set<monero_wallet_listener*> get_listeners() override;
    monero_sync_result sync() override;
    monero_sync_result sync(monero_wallet_listener& listener) override;
    monero_sync_result sync(uint64_t start_height) override;
    monero_sync_result sync(uint64_t start_height, monero_wallet_listener& listener) override;
    void start_syncing(uint64_t sync_period_in_ms) override;
    void stop_syncing() override;

    void scan_txs(const std::vector<std::string>& tx_ids) override;
    void rescan_spent() override;
    void rescan_blockchain() override;
    uint64_t get_balance() const override;
    uint64_t get_balance(uint32_t account_idx) const override;
    uint64_t get_balance(uint32_t account_idx, uint32_t subaddress_idx) const override;
    uint64_t get_unlocked_balance() const override;
    uint64_t get_unlocked_balance(uint32_t account_idx) const override;
    uint64_t get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const override;
    std::vector<monero_account> get_accounts(bool include_subaddresses, const std::string& tag) const override;
    monero_account get_account(const uint32_t account_idx, bool include_subaddresses) const override;
    monero_account create_account(const std::string& label = "") override;
    monero_subaddress get_subaddress(const uint32_t account_idx, const uint32_t subaddress_idx) const override;
    std::vector<monero_subaddress> get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const override;
    monero_subaddress create_subaddress(uint32_t account_idx, const std::string& label = "") override;
    void set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label = "") override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> get_txs(const monero_tx_query& query) const override;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers(const monero_transfer_query& query) const override;
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs() const { return get_outputs(monero_output_query()); };
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs(const monero_output_query& query) const override;
    std::string export_outputs(bool all = false) const override;
    int import_outputs(const std::string& outputs_hex) override;
    std::vector<std::shared_ptr<monero_key_image>> export_key_images(bool all = true) const override;
    std::shared_ptr<monero_key_image_import_result> import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) override;
    void freeze_output(const std::string& key_image) override;
    void thaw_output(const std::string& key_image) override;
    bool is_output_frozen(const std::string& key_image) override;
    monero_tx_priority get_default_fee_priority() const override;
    std::vector<std::shared_ptr<monero_tx_wallet>> create_txs(const monero_tx_config& config) override;
    
    std::vector<std::string> relay_txs(const std::vector<std::string>& tx_metadatas) override;
    monero_tx_set describe_tx_set(const monero_tx_set& tx_set) override;
    monero_tx_set sign_txs(const std::string& unsigned_tx_hex) override;
    std::vector<std::string> submit_txs(const std::string& signed_tx_hex) override;
    std::string get_tx_key(const std::string& tx_hash) const override;

    std::string get_tx_note(const std::string& tx_hash) const override;
    std::vector<std::string> get_tx_notes(const std::vector<std::string>& tx_hashes) const override;
    void set_tx_note(const std::string& tx_hash, const std::string& note) override;
    void set_tx_notes(const std::vector<std::string>& tx_hashes, const std::vector<std::string>& notes) override;

    std::vector<monero_address_book_entry> get_address_book_entries(const std::vector<uint64_t>& indices) const override;
    uint64_t add_address_book_entry(const std::string& address, const std::string& description) override;
    void edit_address_book_entry(uint64_t index, bool set_address, const std::string& address, bool set_description, const std::string& description) override;
    void delete_address_book_entry(uint64_t index) override;
    std::string get_payment_uri(const monero_tx_config& config) const override;
    std::shared_ptr<monero_tx_config> parse_payment_uri(const std::string& uri) const override;
    bool get_attribute(const std::string& key, std::string& value) const override;
    void set_attribute(const std::string& key, const std::string& val) override;

    uint64_t wait_for_next_block() override;
    bool is_multisig_import_needed() const override { return false; };
    monero_multisig_info get_multisig_info() const override;

    void close(bool save) override;

  protected:
    friend struct wallet_light_listener;
    std::unique_ptr<wallet_light_listener> m_wallet_listener;
    std::set<monero_wallet_listener*> m_listeners;
    monero_light_client* m_light_client;
    boost::optional<uint64_t> m_prior_attempt_size_calcd_fee;
    boost::optional<monero_light_spendable_random_outputs> m_prior_attempt_unspent_outs_to_mix_outs;
    size_t m_construction_attempt;
    uint64_t m_last_block_reward;

    // blockchain sync management
    mutable std::atomic<bool> m_is_synced;       // whether or not wallet is synced
    mutable std::atomic<bool> m_is_connected;    // cache connection status to avoid unecessary RPC calls
    boost::condition_variable m_sync_cv;         // to make sync threads woke
    mutable boost::recursive_mutex m_sync_mutex;                   // synchronize sync() and syncAsync() requests
    std::atomic<bool> m_rescan_on_sync;          // whether or not to rescan on sync
    std::atomic<bool> m_syncing_enabled;         // whether or not auto sync is enabled
    std::atomic<bool> m_sync_loop_running;       // whether or not the syncing thread is shut down
    std::atomic<int> m_syncing_interval;         // auto sync loop interval in milliseconds
    boost::thread m_syncing_thread;              // thread for auto sync loop
    boost::mutex m_syncing_mutex;                // synchronize auto sync loop
    void run_sync_loop();                        // run the sync loop in a thread
    monero_sync_result lock_and_sync(boost::optional<uint64_t> start_height = boost::none);  // internal function to synchronize request to sync and rescan
    monero_sync_result sync_aux(boost::optional<uint64_t> start_height = boost::none);       // internal function to immediately block, sync, and report progress

    mutable boost::recursive_mutex m_sync_data_mutex;
    monero_light_get_address_info_response m_address_info;
    monero_light_get_address_txs_response m_address_txs;
    monero_light_get_unspent_outs_response m_unspent_outs;
    monero_light_get_subaddrs_response m_subaddrs;

    std::vector<monero_address_book_entry> m_address_book;
    serializable_unordered_map<crypto::hash, std::string> m_tx_notes;
    serializable_unordered_map<std::string, std::string> m_attributes;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::string>> m_subaddress_labels;

    std::vector<std::shared_ptr<monero_key_image>> m_imported_key_images;
    std::vector<std::string> m_frozen_key_images;

    serializable_unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
    serializable_unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;

    std::unique_ptr<std::vector<std::shared_ptr<monero_tx_wallet>>> m_unconfirmed_txs;
    std::unique_ptr<std::vector<std::string>> m_key_images_in_pool;

    bool m_load_deprecated_formats;

    // balance cache
    uint64_t m_wallet_balance = 0;
    uint64_t m_wallet_unlocked_balance = 0;
    serializable_unordered_map<uint32_t, uint64_t> m_account_balance_container;
    serializable_unordered_map<uint32_t, uint64_t> m_account_unlocked_balance_container;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>> m_subaddress_balance_container;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>> m_subaddress_unlocked_balance_container;

    static monero_wallet_light* create_wallet_from_seed(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
    static monero_wallet_light* create_wallet_from_keys(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);
    static monero_wallet_light* create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory);

    monero_light_get_address_info_response get_address_info(bool filter_outputs = true) const;
    monero_light_get_address_txs_response get_address_txs() const;
    monero_light_get_unspent_outs_response get_unspent_outs(bool filter_spent) const;
    monero_light_get_unspent_outs_response get_unspent_outs(uint64_t amount, uint32_t mixin = 0, bool use_dust = true, uint64_t dust_threshold = 0, bool filter_spent = true) const;
    monero_light_get_unspent_outs_response get_unspent_outs(std::string amount = "0", uint32_t mixin = 0, bool use_dust = true, std::string dust_threshold = "0", bool filter_spent = true) const;
    monero_light_get_unspent_outs_response get_spendable_outs(const uint32_t account_idx, const std::vector<uint32_t> &subaddresses_indices, uint64_t amount, uint32_t mixin = 0, bool use_dust = true, uint64_t dust_threshold = 0, bool filter_spent = true) const;
    monero_light_get_random_outs_response get_random_outs(uint32_t count, std::vector<uint64_t> &amounts) const;
    monero_light_get_random_outs_response get_random_outs(uint32_t count, std::vector<std::string> &amounts) const;
    monero_light_get_random_outs_response get_random_outs(const std::vector<monero_light_output> &outputs) const;
    monero_light_get_subaddrs_response get_subaddrs() const;
    monero_light_provision_subaddrs_response provision_subaddrs(uint32_t maj_i = 0, uint32_t min_i = 0, uint32_t n_maj = 0, uint32_t n_min = 0, bool get_all = true) const;
    monero_light_upsert_subaddrs_response upsert_subaddrs(monero_light_subaddrs subaddrs, bool get_all = true) const;
    monero_light_upsert_subaddrs_response upsert_subaddrs(uint32_t account_idx, uint32_t subaddress_idx, bool get_all = true) const;
    monero_light_login_response login(bool create_account = true, bool generated_locally = true) const;
    monero_light_import_request_response import_request(uint64_t height = 0) const;
    monero_light_submit_raw_tx_response submit_raw_tx(const std::string tx) const;

    monero_light_get_random_outs_params prepare_get_random_outs_params(
      const boost::optional<std::string>& payment_id_string,
      const std::vector<uint64_t>& sending_amounts,
      bool is_sweeping,
      uint32_t simple_priority,
      const std::vector<monero_light_output> &unspent_outs,
      uint64_t fee_per_b, // per v8
      uint64_t fee_quantization_mask,
      boost::optional<uint64_t> prior_attempt_size_calcd_fee, // use this for passing step2 "must-reconstruct" return values back in, i.e. re-entry; when nil, defaults to attempt at network min
      boost::optional<monero_light_spendable_random_outputs> prior_attempt_unspent_outs_to_mix_outs = boost::none // use this to make sure upon re-attempting, the calculated fee will be the result of calculate_fee()
    );

    void calculate_balance();
    void init_common() override;

    // Hard fork utils

    /**
      * Hard coded light wallet fork rules
      * 
      * TODO - we don't have the actual fork rules from the lightwallet server yet
      * 
      * @param version
      * @param early_blocks
      */
    bool use_fork_rules(uint8_t version, int64_t early_blocks) const { return true; };

    /**
      * V15 Protocol defaults
      */
    uint32_t get_ring_size() const { return 16; };
    uint32_t get_mixin_size() const { return get_ring_size() - 1; }
    uint64_t get_dust_threshold() const { return DUST_THRESHOLD; }

    // Fee utils

    uint32_t get_default_priority() const { return 1; };
    uint64_t get_upper_transaction_weight_limit(uint64_t upper_transaction_weight_limit__or_0_for_default);
    uint64_t get_fee_multiplier(uint32_t priority, uint32_t default_priority, int fee_algorithm);
    int get_fee_algorithm();
    /**
      * Added as of v8
      * 
      * @param fee_per_b
      */
    uint64_t get_base_fee(uint64_t fee_per_b) const { return fee_per_b; };
    uint64_t estimate_fee(bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask);
    
    uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask);
    uint64_t calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask);
    uint64_t calculate_fee_from_size(uint64_t fee_per_b, size_t bytes, uint64_t fee_multiplier) const { return bytes * fee_per_b * fee_multiplier; };
    
    size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag);
    uint64_t estimate_tx_weight(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag);
    size_t estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag);
    /**
      * Convenience function for size + calc
      * 
      * @param fee_per_b
      * @param priority when priority=0, falls back to monero_wallet_light::get_default_priority()
      */
    uint64_t estimated_tx_network_fee(uint64_t fee_per_b, uint32_t priority);

    std::tuple<uint64_t, uint64_t, std::vector<tools::wallet2::exported_transfer_details>> export_outputs(bool all, uint32_t start, uint32_t count = 0xffffffff) const;

    bool output_is_spent(monero_light_output &output) const;
    bool output_is_spent(monero_light_spend &spend) const;
    bool output_is_locked(monero_light_output output) const;
    bool key_image_is_spent(std::string &key_image) const;
    bool key_image_is_spent(crypto::key_image &key_image) const;
    bool key_image_is_spent(std::shared_ptr<monero_key_image> key_image) const;
    bool key_image_is_spent(monero_key_image& key_image) const;
    bool subaddress_is_used(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_subaddress_num_unspent_outs(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_subaddress_num_blocks_to_unlock(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_output_num_blocks_to_unlock(monero_light_output &output) const;

    std::vector<std::shared_ptr<monero_transfer>> get_transfers_aux(const monero_transfer_query& query) const;
    std::vector<std::shared_ptr<monero_transfer>> get_transfers_aux() const { return get_transfers_aux(monero_transfer_query()); };
    std::vector<std::shared_ptr<monero_output_wallet>> get_outputs_aux(const monero_output_query& query) const;
    std::vector<size_t> get_output_indexes(const std::vector<monero_light_output> &outputs) const;
    bool is_output_frozen(const monero_light_output& output) const;

    /**
      * 
      * @param sender_account_keys this will reference a particular hw::device
      */
    monero_light_partial_constructed_transaction create_partial_transaction(const uint32_t subaddr_account_idx, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses, const std::vector<cryptonote::address_parse_info> &to_addrs, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, std::vector<monero_light_random_outputs> &mix_outs, const std::vector<uint8_t> &extra, uint64_t unlock_time, bool rct);
    monero_light_constructed_transaction create_transaction(const uint32_t subaddr_account_idx, const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, std::vector<monero_light_random_outputs> &mix_outs, uint64_t unlock_time);

    boost::optional<std::string> get_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx) const;

    std::string make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const;
    bool parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) const;

    std::vector<monero_subaddress> get_subaddresses_aux(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const;
    std::vector<monero_subaddress> get_subaddresses() const;
    void set_tx_note(const crypto::hash &txid, const std::string &note);
    std::string get_tx_note(const crypto::hash &txid) const;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> get_subaddresses_map() const;
    std::vector<tools::wallet2::pending_tx> parse_signed_tx(const std::string &signed_tx_st) const;
    tools::wallet2::unsigned_tx_set parse_unsigned_tx(const std::string &unsigned_tx_st) const;
    std::string dump_pending_tx(const monero_light_constructed_transaction &tx, boost::optional<std::string> payment_id) const;
    std::string sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes);
    bool get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;
    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;

    void remove_unconfirmed_tx(const std::string &hash) const;
    bool destination_is_ours(const std::shared_ptr<monero_destination> &dest) const;
    uint64_t get_tx_balance(const std::shared_ptr<monero_tx_wallet> &tx) const;
};

}