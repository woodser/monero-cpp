#include "monero_wallet_light.h"
#include "utils/gen_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "common/threadpool.h"
#include "net/jsonrpc_structs.h"
#include "serialization/serialization.h"

#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\004"
#define TAIL_EMISSION_HEIGHT 2641623
#define APPROXIMATE_INPUT_BYTES 80

namespace monero {

  // ------------------------- INITIALIZE CONSTANTS ---------------------------

  static const int BULLETPROOF_VERSION = 4; // default bulletproof version
  static const uint32_t RING_SIZE = 16;
  static const uint32_t MIXIN_SIZE = RING_SIZE - 1;
  static const uint32_t DEFAULT_FEE_PRIORITY = 1;
  static const uint32_t DUST_THRESHOLD = 2000000000;

  // ----------------------- INTERNAL PRIVATE HELPERS -----------------------

  uint64_t get_fee_multiplier(uint32_t priority) {
    // v8 fee algorithm 3
    if (priority == 2) return 5;
    if (priority == 3) return 25;
    if (priority == 4) return 1000;
    return 1;
  }

  size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size) {
    size_t size = 0;
    // tx prefix first few bytes
    size += 1 + 6;
    
    // vin
    size += n_inputs * (1+6+(mixin+1)*2+32);
    
    // vout
    size += n_outputs * (6+32);
    
    // extra
    size += extra_size;
    if (!extra_size && n_outputs <= 2)
      size += 3 + sizeof(crypto::hash8);
    
      // rct signatures
    size += 1;
    
    // rangeSigs
    size_t log_padded_outputs = 0;
    while ((1<<log_padded_outputs) < n_outputs) ++log_padded_outputs;
    size += (2 * (6 + log_padded_outputs) + 6) * 32 + 3;
    
    // MGs/CLSAGs
    size += n_inputs * (32 * (mixin+1) + 64);
    
    // View tags
    size += n_outputs * sizeof(crypto::view_tag);
    
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
    
    return size;
  }

  uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
    uint64_t fee = weight * base_fee * fee_multiplier;
    fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
    return fee;
  }

  uint64_t estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size) {
    size_t size = estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size);
    if (n_outputs > 2) {
      const uint64_t bp_base = 368;
      size_t log_padded_outputs = 2;
      while ((1<<log_padded_outputs) < n_outputs) 
        ++log_padded_outputs;
      uint64_t nlr = 2 * (6 + log_padded_outputs);
      const uint64_t bp_size = 32 * (6 + nlr);
      const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
      MDEBUG("clawback on size " << size << ": " << bp_clawback);
      size += bp_clawback;
    }
    return size;
  }

  uint64_t estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask) {
    const size_t estimated_tx_weight = estimate_tx_weight(n_inputs, mixin, n_outputs, extra_size);
    return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
  }

  uint64_t get_tx_weight_limit(uint64_t default_limit = 0) {
    if (default_limit > 0) return default_limit;
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE; // v8
  }

  void normalize_unconfirmed_tx(const std::shared_ptr<monero_tx_wallet> &tx) {
    tx->m_outputs.clear();
    
    const auto &transfer = tx->m_outgoing_transfer.get();
    tx->m_change_address = boost::none;
    tx->m_change_amount = boost::none;
    
    if (transfer->m_subaddress_indices.size() > 0) {
      const auto &subaddress_idx = transfer->m_subaddress_indices[0];
      transfer->m_subaddress_indices.clear();
      transfer->m_subaddress_indices.push_back(subaddress_idx); // subaddress index is known iff 1 requested  // TODO: get all known subaddress indices here
    }

    for(const auto &input : tx->m_inputs) {
      input->m_amount = boost::none;
    }
  }

  void validate_transfer(const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, cryptonote::network_type nettype, std::vector<cryptonote::address_parse_info>& infos, std::vector<uint8_t>& extra) {
    if (to_address_strings.empty()) throw std::runtime_error("No destinations for this transfer");
    crypto::hash8 integrated_payment_id = crypto::null_hash8;
    std::string extra_nonce;
    std::vector<cryptonote::address_parse_info> addr_infos(to_address_strings.size());
    size_t to_addr_idx = 0;
    for (const auto& addr : to_address_strings) {
      if (!cryptonote::get_account_address_from_str(addr_infos[to_addr_idx++], nettype, addr)) {
        throw std::runtime_error("Invalid destination address");
      }
    }

    bool payment_id_seen = payment_id_string != boost::none && !payment_id_string->empty();
    for (const auto& info : addr_infos) {
      infos.push_back(info);
      if (!info.has_payment_id) continue;
      if (payment_id_seen || integrated_payment_id != crypto::null_hash8) {
        throw std::runtime_error("A single payment id is allowed per transaction");
      }
      integrated_payment_id = info.payment_id;
      cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, integrated_payment_id);
      if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
        throw std::runtime_error("Something went wrong with integrated payment_id.");
      }
    }

    if (payment_id_seen) throw std::runtime_error("Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead");
  }

  void validate_cn_tx(const cryptonote::transaction &tx) {
    if (get_tx_weight_limit() <= get_transaction_weight(tx)) throw std::runtime_error("transaction is too big");
    if(tx.rct_signatures.p.bulletproofs_plus.empty()) throw std::runtime_error("Expected tx to use bulletproofs");
    
    auto tx_blob = t_serializable_object_to_blob(tx);
    size_t tx_blob_size = tx_blob.size();
    if(tx_blob_size <= 0) throw std::runtime_error("Expected tx blob byte length > 0");
  }

  std::shared_ptr<monero_tx_wallet> build_tx_with_vout(const monero_light_tx_store& tx_store, const monero_light_output_store& output_store, const monero_light_output& out, uint64_t current_height) {

    // construct block
    std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
    block->m_height = out.m_height;

    // construct tx
    std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
    tx->m_block = block;
    block->m_txs.push_back(tx);
    tx->m_hash = out.m_tx_hash;
    tx->m_is_confirmed = true;
    tx->m_is_failed = false;
    tx->m_is_relayed = true;
    tx->m_in_tx_pool = false;
    tx->m_relay = true;
    tx->m_is_double_spend_seen = false;
    tx->m_is_locked = tx_store.is_locked(out.m_tx_hash.get(), current_height);

    // construct output
    std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
    output->m_tx = tx;
    tx->m_outputs.push_back(output);
    output->m_amount = out.m_amount;
    output->m_index = out.m_global_index;
    output->m_account_index = out.m_recipient.m_maj_i;
    output->m_subaddress_index = out.m_recipient.m_min_i;
    output->m_is_spent = out.is_spent();
    output->m_is_frozen = false;
    output->m_stealth_public_key = out.m_public_key;
    if (out.key_image_is_known()) {
      output->m_key_image = std::make_shared<monero_key_image>();
      output->m_key_image.get()->m_hex = out.m_key_image;
      output->m_is_frozen = output_store.is_frozen(out);
    }

    // return pointer to new tx
    return tx;
  }

  monero_light_get_random_outs_response get_random_outs(const std::unique_ptr<monero_light_client>& client, const std::vector<monero_light_output> &using_outs, boost::optional<monero_light_spendable_random_outputs>& prior_attempt) {
    // request decoys for any newly selected inputs
    std::vector<monero_light_output> decoy_requests;
    if (prior_attempt != boost::none) {
      for (size_t i = 0; i < using_outs.size(); ++i) {
        // only need to request decoys for outs that were not already passed in
        if (prior_attempt->find(*using_outs[i].m_public_key) == prior_attempt->end()) {
          decoy_requests.push_back(using_outs[i]);
        }
      }
    } else {
      decoy_requests = using_outs;
    }

    std::vector<uint64_t> decoy_amounts;
    for (auto &using_out : decoy_requests) {
      if (using_out.is_rct()) {
        decoy_amounts.push_back(0);
      } else {
        decoy_amounts.push_back(using_out.m_amount.get());
        MDEBUG("pushing decoy req amount: " << using_out.m_amount.get());
      }
    }

    return client->get_random_outs(MIXIN_SIZE + 1, decoy_amounts);
  }

  bool output_before(const monero_light_output& ow1, const monero_light_output& ow2) {
    // compare by account index, subaddress index, output index, then global index
    if (ow1.m_recipient.m_maj_i < ow2.m_recipient.m_maj_i) return true;
    if (ow1.m_recipient.m_maj_i == ow2.m_recipient.m_maj_i) {
      if (ow1.m_recipient.m_min_i < ow2.m_recipient.m_min_i) return true;
      if (ow1.m_recipient.m_min_i == ow2.m_recipient.m_min_i) {
        if (ow1.m_global_index.get() < ow2.m_global_index.get()) return true;
        if (ow1.m_global_index.get() == ow2.m_global_index.get()) throw std::runtime_error("Should never sort outputs with duplicate indices");
      }
    }
    return false;
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
          if ((out.m_rct != boost::none && mix_outs_from_server[j].m_amount.get() != 0) ||
            (out.m_rct == boost::none && mix_outs_from_server[j].m_amount.get() != out.m_amount.get())) {
            continue;
          }

          monero_light_random_outputs output_mix_outs = monero_utils::pop_index(mix_outs_from_server, j);

          // if we need to retry constructing tx, will remember to use same mix outs for this out on subsequent attempt(s)
          prior_attempt_unspent_outs_to_mix_outs_new[*out.m_public_key] = output_mix_outs.m_outputs;
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

  monero_light_get_random_outs_params prepare_get_random_outs_params(const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, bool is_sweeping, uint32_t simple_priority, const std::vector<monero_light_output> &unspent_outs, uint64_t fee_per_b, uint64_t fee_quantization_mask, boost::optional<uint64_t> prior_attempt_size_calcd_fee, boost::optional<monero_light_spendable_random_outputs> prior_attempt_unspent_outs_to_mix_outs = boost::none) {
    monero_light_get_random_outs_params params;

    if (!is_sweeping) {
      for (uint64_t sending_amount : sending_amounts) {
        if (sending_amount == 0) {
          throw std::runtime_error("entered amount is too low");
        }
      }
    }
    
    params.m_mixin = MIXIN_SIZE;
    
    std::vector<uint8_t> extra;
    monero_utils::add_pid_to_tx_extra(payment_id_string, extra);

    const uint64_t base_fee = fee_per_b;
    const uint64_t fee_multiplier = get_fee_multiplier(simple_priority);
    
    uint64_t attempt_at_min_fee;
    // use a minimum viable estimate_fee() with 1 input. It would be better to under-shoot this estimate, and then need to use a higher fee  from calculate_fee() because the estimate is too low,
    // versus the worse alternative of over-estimating here and getting stuck using too high of a fee that leads to fingerprinting
    if (prior_attempt_size_calcd_fee == boost::none)
      attempt_at_min_fee = estimate_fee(1, MIXIN_SIZE, 2, extra.size(), base_fee, fee_multiplier, fee_quantization_mask);
    else 
      attempt_at_min_fee = *prior_attempt_size_calcd_fee;
    
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
    // Gather outputs and amount to use for getting decoy outputs…
    uint64_t using_outs_amount = 0;
    std::vector<monero_light_output>  remaining_outs = unspent_outs; // take copy so not to modify original

    // start by using all the passed in outs that were selected in a prior tx construction attempt
    if (prior_attempt_unspent_outs_to_mix_outs != boost::none) {
      for (size_t i = 0; i < remaining_outs.size(); ++i) {
        monero_light_output &out = remaining_outs[i];

        // search for out by public key to see if it should be re-used in an attempt
        if (prior_attempt_unspent_outs_to_mix_outs->find(*out.m_public_key) != prior_attempt_unspent_outs_to_mix_outs->end()) {
          using_outs_amount += out.m_amount.get();
          params.m_using_outs.push_back(std::move(monero_utils::pop_index(remaining_outs, i)));
        }
      }
    }

    while (using_outs_amount < potential_total && remaining_outs.size() > 0) {
      auto out = monero_utils::pop_random_value(remaining_outs);
      if (out.m_amount.get() < DUST_THRESHOLD) {
        if (!out.is_rct())
          continue; // unmixable (non-rct) dusty output
      }
      using_outs_amount += out.m_amount.get();
      params.m_using_outs.push_back(std::move(out));
    }
    
    //if (/*using_outs.size() > 1*/) { // FIXME? see original core js
    uint64_t needed_fee = estimate_fee(
      params.m_using_outs.size(), MIXIN_SIZE, sending_amounts.size(), extra.size(),
      base_fee, fee_multiplier, fee_quantization_mask
    );
    // if newNeededFee < neededFee, use neededFee instead (should only happen on the 2nd or later times through (due to estimated fee being too low))
    if (prior_attempt_size_calcd_fee != boost::none && needed_fee < attempt_at_min_fee) {
      needed_fee = attempt_at_min_fee;
    }
    
    // NOTE: needed_fee may get further modified below when !is_sweeping if using_outs_amount < total_incl_fees and gets finalized (for this function's scope) as using_fee
    uint64_t total_wo_fee = is_sweeping
      ? /*now that we know outsAmount>needed_fee*/(using_outs_amount - needed_fee)
      : sum_sending_amounts;
    params.m_final_total_wo_fee = total_wo_fee;
    
    uint64_t total_incl_fees;
    if (is_sweeping) {
      if (using_outs_amount < needed_fee) { // like checking if the result of the following total_wo_fee is < 0
        // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point
        throw std::runtime_error("need more money than found; sweeping, using_outs_amount: " + std::to_string(using_outs_amount) + ", needed_fee: " + std::to_string(needed_fee));
      }
      total_incl_fees = using_outs_amount;
    } else {
      total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed because using_outs.size() was updated
      while (using_outs_amount < total_incl_fees && remaining_outs.size() > 0) { // add outputs 1 at a time till we either have them all or can meet the fee
        {
          auto out = monero_utils::pop_random_value(remaining_outs);
          using_outs_amount += out.m_amount.get();
          params.m_using_outs.push_back(std::move(out));
        }
        // Recalculate fee, total including fees
        needed_fee = estimate_fee(
          params.m_using_outs.size(), MIXIN_SIZE, sending_amounts.size(), extra.size(),
          base_fee, fee_multiplier, fee_quantization_mask
        );
        total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed
      }
    }
    params.m_using_fee = needed_fee;

    if (using_outs_amount < total_incl_fees) {
      // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point.
      throw std::runtime_error("need more money than found; using_outs_amount: " + std::to_string(using_outs_amount) + ", total_incl_fees: " + std::to_string(total_incl_fees) + ", needed_fee: " + std::to_string(needed_fee));
    }
    
    // Change can now be calculated
    uint64_t change_amount = 0; // to initialize
    if (using_outs_amount > total_incl_fees) {
      if(is_sweeping) throw std::runtime_error("Unexpected total_incl_fees > using_outs_amount while sweeping");
      change_amount = using_outs_amount - total_incl_fees;
    }
    params.m_change_amount = change_amount;
    
    // TODO create another tx if tx_estimated_weight >= TX_WEIGHT_TARGET(get_tx_weight_limit())

    return params;
  }

  tools::wallet2::pending_tx construct_tx(
    cryptonote::network_type nettype, const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& subaddresses,
    const cryptonote::account_keys& sender_account_keys, bool view_only,
    const uint32_t subaddr_account_idx, const std::vector<std::string> &to_address_strings, 
    const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts,
    std::vector<size_t>& selected_transfers,
    uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, 
    std::vector<monero_light_random_outputs> &mix_outs
  ) {
    std::vector<uint8_t> extra;
    std::vector<cryptonote::address_parse_info> to_addrs;
    validate_transfer(to_address_strings, payment_id_string, nettype, to_addrs, extra);
    // TODO: do we need to sort destinations by amount, here, according to 'decompose_destinations'?
    if (mix_outs.size() != outputs.size()) {
      throw std::runtime_error("wrong number of mix outs provided: " + std::to_string(mix_outs.size()) + ", outputs: " + std::to_string(outputs.size()));
    }
    for (size_t i = 0; i < mix_outs.size(); i++) {
      if (mix_outs[i].m_outputs.size() < MIXIN_SIZE) {
        throw std::runtime_error("not enough outputs for mixing");
      }
    }
    if (view_only) {
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

    uint64_t needed_money = fee_amount + change_amount;
    for (uint64_t amount : sending_amounts) {
      needed_money += amount;
      if (needed_money < amount) throw std::runtime_error("transaction sum + fee exceeds " + cryptonote::print_money(std::numeric_limits<uint64_t>::max()));
    }
    
    uint64_t found_money = 0;
    std::vector<cryptonote::tx_source_entry> sources;
    std::string spent_key_images;
    LOG_PRINT_L2("preparing outputs");
    for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
      found_money += outputs[out_index].m_amount.get();
      if (found_money > UINT64_MAX) {
        throw std::runtime_error("input amount overflow");
      }
      auto src = cryptonote::tx_source_entry{};
      src.amount = outputs[out_index].m_amount.get();
      src.rct = outputs[out_index].is_rct();
      
      typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
      if (mix_outs.size() != 0) {
        // Sort fake outputs by global index
        std::sort(mix_outs[out_index].m_outputs.begin(), mix_outs[out_index].m_outputs.end(), [] (
          monero_light_output const& a,
          monero_light_output const& b
        ) {
          return a.m_global_index.get() < b.m_global_index.get();
        });
        for (
          size_t j = 0;
          src.outputs.size() < MIXIN_SIZE && j < mix_outs[out_index].m_outputs.size();
          j++
        ) {
          auto mix_out__output = mix_outs[out_index].m_outputs[j];
          if (mix_out__output.m_global_index == outputs[out_index].m_global_index) {
            MDEBUG("got mixin the same as output, skipping");
            continue;
          }
          auto oe = tx_output_entry{};
          oe.first = mix_out__output.m_global_index.get();
          
          crypto::public_key public_key = AUTO_VAL_INIT(public_key);
          if(!epee::string_tools::hex_to_pod(*mix_out__output.m_public_key, public_key)) {
            throw std::runtime_error("given an invalid public key");
          }
          oe.second.dest = rct::pk2rct(public_key);
          
          if (mix_out__output.is_rct()) {
            rct::key commit;
            monero_utils::rct_hex_to_rct_commit(mix_out__output.m_rct.get(), commit);
            oe.second.mask = commit;
          } else {
            if (outputs[out_index].is_rct()) {
              throw std::runtime_error("mix RCT outs missing commit");
            }
            oe.second.mask = rct::zeroCommit(src.amount); //create identity-masked commitment for non-rct mix input
          }
          src.outputs.push_back(oe);
        }
      }

      auto real_oe = tx_output_entry{};
      real_oe.first = outputs[out_index].m_global_index.get();

      crypto::public_key public_key = AUTO_VAL_INIT(public_key);
      if(!epee::string_tools::validate_hex(64, *outputs[out_index].m_public_key)) {
        throw std::runtime_error("given an invalid public key");
      }
      if (!epee::string_tools::hex_to_pod(*outputs[out_index].m_public_key, public_key)) {
        throw std::runtime_error("given an invalid public key");
      }
      real_oe.second.dest = rct::pk2rct(public_key);
      
      if (outputs[out_index].is_rct() && !outputs[out_index].is_mined()) {
        rct::key commit;
        monero_utils::rct_hex_to_rct_commit(outputs[out_index].m_rct.get(), commit);
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
      
      src.rct = outputs[out_index].is_rct();
      if (src.rct) {
        rct::key decrypted_mask;
        bool r = monero_utils::rct_hex_to_decrypted_mask(
          outputs[out_index].m_rct.get(),
          sender_account_keys.m_view_secret_key,
          tx_pub_key,
          internal_output_index,
          decrypted_mask
        );
        if (!r) throw std::runtime_error("can't get decrypted mask from RCT hex");
        src.mask = decrypted_mask;

        rct::key calculated_commit = rct::commit(outputs[out_index].m_amount.get(), decrypted_mask);
        rct::key parsed_commit;
        monero_utils::rct_hex_to_rct_commit(outputs[out_index].m_rct.get(), parsed_commit);
        if (!(real_oe.second.mask == calculated_commit)) {
          throw std::runtime_error("rct commit hash mismatch");
        }
      } else {
        // in the original cn_utils impl this was left as null for generate_key_image_helper_rct to fill in with identity I
        rct::identity(src.mask);
      }
      // not doing multisig here yet
      src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
      sources.push_back(src);
      auto& key_image = outputs[out_index].m_key_image;
      if (key_image != boost::none && !key_image->empty()) {
        spent_key_images += key_image.get() + " ";
      }
    }
    LOG_PRINT_L2("outputs prepared");
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

    cryptonote::tx_destination_entry change_dst = AUTO_VAL_INIT(change_dst);
    change_dst.amount = change_amount;
    if (change_dst.amount == 0) {
      if (splitted_dsts.size() == 1) {
        // If the change is 0, send it to a random address, to avoid confusing
        // the sender with a 0 amount output. We send a 0 amount in order to avoid
        // letting the destination be able to work out which of the inputs is the
        // real one in our rings
        LOG_PRINT_L2("generating dummy address for 0 change");
        cryptonote::account_base dummy;
        dummy.generate();
        change_dst.addr = dummy.get_keys().m_account_address;
        LOG_PRINT_L2("generated dummy address for 0 change");
        splitted_dsts.push_back(change_dst);
      }
    } else {
      change_dst.addr = sender_account_keys.m_account_address;
      splitted_dsts.push_back(change_dst);
    }
    
    if (found_money > needed_money) {
      if (change_dst.amount != fee_amount) {
        throw std::runtime_error("result fee not equal to given");
      }
    } 
    else if (found_money < needed_money) {
      throw std::runtime_error("need more money than found; found_money: " + std::to_string(found_money) + ", needed_money: " + std::to_string(needed_money));
    }

    if (sources.empty()) throw std::runtime_error("sources is empty");

    cryptonote::transaction tx;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    
    const rct::RCTConfig rct_config {rct::RangeProofPaddedBulletproof, BULLETPROOF_VERSION};
    LOG_PRINT_L2("constructing tx");
    bool r = cryptonote::construct_tx_and_get_tx_key(
      sender_account_keys, subaddresses,
      sources, splitted_dsts, change_dst.addr, extra,
      tx, tx_key, additional_tx_keys,
      true, rct_config, true);

    LOG_PRINT_L2("constructed tx, r=" << r);
    if (!r) throw std::runtime_error("transaction was not constructed");
    validate_cn_tx(tx);

    tools::wallet2::pending_tx ptx;
    ptx.key_images = spent_key_images;
    ptx.dust = 0;
    ptx.dust_added_to_fee = false;
    ptx.tx = tx;
    ptx.change_dts = change_dst;
    ptx.tx_key = tx_key;
    ptx.additional_tx_keys = additional_tx_keys;
    ptx.fee = fee_amount;
    ptx.dests = splitted_dsts;
    ptx.selected_transfers = selected_transfers;
    ptx.construction_data.sources = sources;
    ptx.construction_data.change_dts = change_dst;
    ptx.construction_data.splitted_dsts = splitted_dsts;
    ptx.construction_data.selected_transfers = selected_transfers;
    ptx.construction_data.extra = tx.extra;
    ptx.construction_data.unlock_time = 0;
    ptx.construction_data.use_rct = true;
    ptx.construction_data.rct_config = rct_config;
    ptx.construction_data.use_view_tags = true;
    ptx.construction_data.dests = splitted_dsts;
    // record which subaddress indices are being used as inputs
    ptx.construction_data.subaddr_account = subaddr_account_idx;
    ptx.construction_data.subaddr_indices.clear();
    for (const auto& selected_out : outputs) {
      if (selected_out.m_recipient.m_maj_i != subaddr_account_idx) continue;
      ptx.construction_data.subaddr_indices.insert(selected_out.m_recipient.m_min_i);
    }
    
    LOG_PRINT_L2("transfer_selected_rct done");
    
    return ptx;
  }

  monero_wallet_light::monero_wallet_light(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    m_client = std::make_unique<monero_light_client>(std::move(http_client_factory));
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
    m_client->set_connection(uri, username, password, proxy_uri);
    if (is_connected_to_daemon()) {
      try { login(); }
      catch (...) { }
    }
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_rpc_connection> &connection) {    
    m_client->set_connection(connection);
    if (is_connected_to_daemon()) {
      try { login(); }
      catch (...) { }
    }
  }

  boost::optional<monero_rpc_connection> monero_wallet_light::get_daemon_connection() const {
    return m_client->get_connection();
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    m_is_connected = m_client->is_connected();
    return m_is_connected;
  }

  uint64_t monero_wallet_light::get_daemon_height() const {
    if (m_address_info.m_blockchain_height == boost::none) return 0;
    uint64_t height = m_address_info.m_blockchain_height.get();
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
  }

  void monero_wallet_light::scan_txs(const std::vector<std::string>& tx_ids) {
    sync();
  }

  void monero_wallet_light::rescan_spent() {
    sync();
  }

  void monero_wallet_light::rescan_blockchain() {
    MTRACE("rescan_blockchain()");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    // m_rescan_on_sync = true;
    lock_and_sync();
  }

  bool monero_wallet_light::is_daemon_synced() const {
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return true;
  }

  bool monero_wallet_light::is_daemon_trusted() const {
    return true;
  }

  bool monero_wallet_light::is_synced() const {
    if (!is_connected_to_daemon()) return false;

    if (m_address_info.m_blockchain_height.get() <= 1) {
      return false;
    }

    return m_address_info.m_scanned_block_height == m_address_info.m_blockchain_height.get();
  }

  monero_subaddress monero_wallet_light::get_address_index(const std::string& address) const {
    MTRACE("get_address_index(" << address << ")");
    // validate address
    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, get_nettype(), address)) {
      throw std::runtime_error("Invalid address");
    }

    // get index of address in wallet
    auto index = m_subaddresses.find(info.address.m_spend_public_key);
    if (index == m_subaddresses.end()) throw std::runtime_error("Address doesn't belong to the wallet");

    // return indices in subaddress
    monero_subaddress subaddress;
    cryptonote::subaddress_index cn_index = index->second;
    subaddress.m_account_index = cn_index.major;
    subaddress.m_index = cn_index.minor;
    return subaddress;
  }

  uint64_t monero_wallet_light::get_height() const {
    if (m_address_info.m_scanned_block_height == boost::none) return 0;
    uint64_t height = m_address_info.m_scanned_block_height.get();
    return height + 1;
  }

  void monero_wallet_light::set_restore_height(uint64_t restore_height) {
    auto response = m_client->import_request(get_primary_address(), get_private_view_key(), restore_height);
    
    if (response.m_import_fee != boost::none) {
      throw std::runtime_error("Payment is required to rescan blockchain: address " + response.m_payment_address.get() + ", amount " + std::to_string(response.m_import_fee.get()));
    }
  }

  uint64_t monero_wallet_light::get_restore_height() const {
    if (m_address_info.m_start_height == boost::none) return 0;
    uint64_t height = m_address_info.m_start_height.get();
    return height == 0 ? 0 : height + 1;
  }

  uint64_t monero_wallet_light::get_balance() const {
    return m_output_store.get_balance();
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_index) const {
    return m_output_store.get_balance(account_index);
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    return m_output_store.get_balance(account_idx, subaddress_idx);
  }

  uint64_t monero_wallet_light::get_unlocked_balance() const {
    return m_output_store.get_unlocked_balance();
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_index) const {
    return m_output_store.get_unlocked_balance(account_index);
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    return m_output_store.get_unlocked_balance(account_idx, subaddress_idx);
  }

  std::vector<monero_account> monero_wallet_light::get_accounts(bool include_subaddresses, const std::string& tag) const {
    std::vector<monero_account> result;
    bool default_found = false;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      const auto& all_subaddrs = m_subaddrs.m_all_subaddrs.get();
      for (const auto& kv : all_subaddrs) {
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
    const auto& subaddrs = m_subaddrs.m_all_subaddrs;

    if (account_idx != 0 && (subaddrs == boost::none || subaddrs->empty())) throw std::runtime_error("Account out of bounds"); 
    
    const auto& all_subaddrs = subaddrs.get();
    if (!all_subaddrs.is_upsert(account_idx)) throw std::runtime_error("account not upsert: " + std::to_string(account_idx));

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
    }

    return account;
  }

  monero_account monero_wallet_light::create_account(const std::string& label) {
    uint32_t last_account_idx = 0;
    if (m_subaddrs.m_all_subaddrs != boost::none) {
      last_account_idx = m_subaddrs.m_all_subaddrs->get_last_account_index();
    }

    uint32_t account_idx = last_account_idx + 1;
    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(0, 0);
    subaddrs[account_idx] = std::vector<monero_light_index_range>();
    subaddrs[account_idx].push_back(index_range);
    upsert_subaddrs(subaddrs);
    monero_account account = monero_wallet_keys::get_account(account_idx, false);
    set_subaddress_label(account_idx, 0, label);
    account.m_balance = 0;
    account.m_unlocked_balance = 0;
    if (label.empty()) account.m_tag = boost::none;
    else account.m_tag = label;
    return account;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    std::vector<monero_subaddress> subaddresses = get_subaddresses_aux(account_idx, subaddress_indices);
    for(monero_subaddress& subaddress : subaddresses) {
      init_subaddress(subaddress);
    }
    return subaddresses;
  }

  monero_subaddress monero_wallet_light::create_subaddress(uint32_t account_idx, const std::string& label) {
    bool account_found = false;
    uint32_t last_subaddress_idx = 0;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      account_found = m_subaddrs.m_all_subaddrs->contains(account_idx);
      if (account_found) last_subaddress_idx = m_subaddrs.m_all_subaddrs->get_last_subaddress_index(account_idx);
    }

    if (!account_found) throw std::runtime_error("create_subaddress(): account index out of bounds");

    uint32_t subaddress_idx = last_subaddress_idx + 1;

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(last_subaddress_idx, subaddress_idx);

    subaddrs[account_idx] = std::vector<monero_light_index_range>();
    subaddrs[account_idx].push_back(index_range);

    upsert_subaddrs(subaddrs);

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
    std::vector<monero_subaddress> subaddresses = monero_wallet_keys::get_subaddresses(account_idx, indices);
    monero_subaddress& subaddress = subaddresses[0];
    init_subaddress(subaddress);
    return subaddress;
  }

  void monero_wallet_light::set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label) {
    m_subaddress_labels[account_idx][subaddress_idx] = label;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    MTRACE("relay_txs()");

    // relay each metadata as a tx
    std::vector<std::string> tx_hashes;
    for (const auto& tx_metadata : tx_metadatas) {

      // parse tx metadata hex
      cryptonote::blobdata blob;
      if (!epee::string_tools::parse_hexstr_to_binbuff(tx_metadata, blob)) {
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
        m_client->submit_raw_tx(epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx)));
      } catch (const std::exception& e) {
        throw std::runtime_error("Failed to commit tx");
      }
      std::shared_ptr<monero_tx_wallet> tx = monero_utils::ptx_to_tx(ptx, get_nettype(), this);
      m_tx_store.set_unconfirmed(tx);
      // collect resulting hash
      std::string pending_tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
      tx_hashes.push_back(pending_tx_hash);
    }

    calculate_balance();

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
      const auto& outputs = m_output_store.m_all;
      std::vector<std::string> signed_kis;
      for(const auto& output : outputs) signed_kis.push_back(output.key_image_is_known() ? output.m_key_image.get() : "");
      std::string ciphertext = sign_tx(exported_txs, ptxs, signed_txs, signed_kis);
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
    MTRACE("monero_wallet_light::submit_txs()");
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
        const auto res = m_client->submit_raw_tx(epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(ptx.tx)));
        if (res.m_status == boost::none || res.m_status.get() != std::string("OK")) throw std::runtime_error("Could not relay tx" + signed_tx_hex);
        crypto::hash txid;
        txid = cryptonote::get_transaction_hash(ptx.tx);
        std::string pending_tx_hash = epee::string_tools::pod_to_hex(txid);
        tx_hashes.push_back(pending_tx_hash);
        std::shared_ptr<monero_tx_wallet> tx = monero_utils::ptx_to_tx(ptx, get_nettype(), this);
        m_tx_store.set_unconfirmed(tx);
      }

      m_wallet_listener->on_spend_tx_hashes(tx_hashes); // notify listeners of spent funds
      return tx_hashes;
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to submit signed tx: ") + e.what());
    }
  }

  void monero_wallet_light::freeze_output(const std::string& key_image) {
    m_output_store.freeze(key_image);
  }

  void monero_wallet_light::thaw_output(const std::string& key_image) {
    m_output_store.thaw(key_image);
  }

  bool monero_wallet_light::is_output_frozen(const std::string& key_image) {
    return m_output_store.is_frozen(key_image);
  }

  monero_tx_priority monero_wallet_light::get_default_fee_priority() const {
    return static_cast<monero_tx_priority>(DEFAULT_FEE_PRIORITY);
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::create_txs(const monero_tx_config& config) {
    MINFO("monero_wallet_light::create_txs()");
    if (is_multisig()) throw std::runtime_error("Multisig wallet not supported");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    // validate config
    if (config.m_sweep_each_subaddress != boost::none && config.m_sweep_each_subaddress.get() == true) throw std::runtime_error("Light wallet do not support sweep each subaddress individually");
    if (config.m_subtract_fee_from.size() > 0) throw std::runtime_error("Light wallet do not support subtracting fees from destinations");
    if (config.m_account_index == boost::none) throw std::runtime_error("Must specify account index to send from");

    std::vector<std::shared_ptr<monero_tx_wallet>> result;
    uint32_t subaddr_account_idx = config.m_account_index.get();
    uint64_t amount = 0;
    std::vector<uint64_t> sending_amounts;
    std::vector<std::string> dests;
    std::string multisig_tx_hex;
    std::string unsigned_tx_hex;

    for(const auto &dest : config.get_normalized_destinations()) {
      const auto &dest_address = dest->m_address.get();
      if (!monero_utils::is_valid_address(dest_address, m_network_type)) throw std::runtime_error("Invalid destination address");
      dests.push_back(dest_address);
      sending_amounts.push_back(*dest->m_amount);
      amount += *dest->m_amount;
    }

    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_data_mutex);

    const auto unspent_outs = m_output_store.get_spendable(subaddr_account_idx, config.m_subaddress_indices, m_tx_store, get_height());
    uint64_t fee_per_b = m_unspent_outs.m_per_byte_fee.get();
    uint64_t fee_mask = m_unspent_outs.m_fee_mask.get();
    if (unspent_outs.empty()) throw std::runtime_error("not enough unlocked money");
    MINFO("monero_wallet_light::create_txs(): spendable outs: " << unspent_outs.size());

    auto payment_id = config.m_payment_id;
    bool is_sweeping = config.m_sweep_each_subaddress != boost::none ? *config.m_sweep_each_subaddress : false;
    auto simple_priority = config.m_priority == boost::none ? 0 : config.m_priority.get();
    
    m_prior_attempt_size_calcd_fee = boost::none;
    m_prior_attempt_unspent_outs_to_mix_outs = boost::none;
    m_construction_attempt = 0;
    
    const auto random_outs_params = prepare_get_random_outs_params(payment_id, sending_amounts, is_sweeping, simple_priority, unspent_outs, fee_per_b, fee_mask, m_prior_attempt_size_calcd_fee, m_prior_attempt_unspent_outs_to_mix_outs);

    if(random_outs_params.m_using_outs.size() == 0) throw std::runtime_error("Expected non-0 using_outs");

    const auto random_outs_res = get_random_outs(std::move(m_client), random_outs_params.m_using_outs, m_prior_attempt_unspent_outs_to_mix_outs);
    auto tied_outs = tie_unspent_to_mix_outs(random_outs_params.m_using_outs, random_outs_res.m_amount_outs, m_prior_attempt_unspent_outs_to_mix_outs);
    auto selected_transfers = m_output_store.get_indexes(random_outs_params.m_using_outs);
    
    tools::wallet2::pending_tx ptx = construct_tx(get_nettype(), m_subaddresses, m_account.get_keys(), is_view_only(), subaddr_account_idx, dests, config.m_payment_id, sending_amounts, selected_transfers, random_outs_params.m_change_amount, random_outs_params.m_using_fee, random_outs_params.m_using_outs, tied_outs.m_mix_outs);
    std::string full_hex = epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(ptx.tx));
    
    if (ptx.tx_key != crypto::null_skey) {
      const crypto::hash txid = get_transaction_hash(ptx.tx);
      m_tx_keys[txid] = ptx.tx_key;
      m_additional_tx_keys[txid] = ptx.additional_tx_keys;
    }
    
    std::shared_ptr<monero_tx_wallet> tx = std::dynamic_pointer_cast<monero_tx_wallet>(monero_utils::ptx_to_tx(ptx, get_nettype(), this));
    
    bool relayed = false;
    bool relay = config.m_relay == boost::none ? false : config.m_relay.get();
    if (relay) {
      try {
        auto submit_res = m_client->submit_raw_tx(full_hex);

        if (submit_res.m_status != boost::none && submit_res.m_status == std::string("OK")) {
          MINFO("monero_wallet_light::create_txs(): relayed tx");
          relayed = true;
        }
        else MINFO("monero_wallet_light::create_txs(): tx not relayed");
      }
      catch(...) { }
    }

    tx->m_in_tx_pool = relayed;
    tx->m_is_relayed = relayed;
    tx->m_relay = relay;
    tx->m_is_outgoing = true;
    tx->m_is_failed = relay && !relayed;
    tx->m_payment_id = config.m_payment_id;
    tx->m_key = get_tx_key(tx->m_hash.get());
    tx->m_full_hex = full_hex;

    if (!relayed) {
      tx->m_last_relayed_timestamp = boost::none;
      tx->m_is_double_spend_seen = boost::none;
    }
 
    if (is_view_only()) {
      unsigned_tx_hex = dump_pending_tx(ptx.construction_data, config.m_payment_id);
      if (unsigned_tx_hex.empty()) throw std::runtime_error("Failed to save unsigned tx set after creation");
    }
    
    std::shared_ptr<monero_tx_wallet> unconfirmed_tx = std::make_shared<monero_tx_wallet>();
    tx->copy(tx, unconfirmed_tx);
    normalize_unconfirmed_tx(unconfirmed_tx);
    result.push_back(unconfirmed_tx);

    MINFO("monero_wallet_light::create_txs(): created unconfirmed tx with " << tx->m_outputs.size() << " outputs and " << tx->m_inputs.size() << " inputs");
    
    // build tx set
    std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
    tx_set->m_txs = result;
    for (int i = 0; i < result.size(); i++) result[i]->m_tx_set = tx_set;
    if (!multisig_tx_hex.empty()) tx_set->m_multisig_tx_hex = multisig_tx_hex;
    if (!unsigned_tx_hex.empty()) tx_set->m_unsigned_tx_hex = unsigned_tx_hex;
    if (!is_view_only() && relayed) m_tx_store.set_unconfirmed(tx);

    calculate_balance();

    if (relayed) m_wallet_listener->on_spend_txs(result);

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

  std::string monero_wallet_light::export_outputs(bool all) const {
    uint32_t start = 0;
    uint32_t count = 0xffffffff;
    std::stringstream oss;
    binary_archive<true> ar(oss);

    auto outputs = m_output_store.export_outputs(m_tx_store, m_generated_key_images, all, start, count);
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
    
    const auto& outputs = m_output_store.m_all;

    size_t offset = 0;
    if (!all)
    {
      while (offset < outputs.size() && !m_generated_key_images.request(outputs[offset].m_tx_pub_key.get(), outputs[offset].m_index.get(), outputs[offset].m_recipient.m_maj_i, outputs[offset].m_recipient.m_min_i))
        ++offset;
    }
    key_images.reserve(outputs.size() - offset);

    for(size_t n = offset; n < outputs.size(); ++n) {
      const auto output = &outputs[n];
      std::shared_ptr<monero_key_image> key_image = std::make_shared<monero_key_image>();
      cryptonote::subaddress_index subaddr;
      uint32_t account_idx = output->m_recipient.m_maj_i;
      uint32_t subaddress_idx = output->m_recipient.m_min_i;
      subaddr.major = account_idx;
      subaddr.minor = subaddress_idx;

      auto cached_key_image = m_generated_key_images.get(output->m_tx_pub_key.get(), account_idx, subaddress_idx);

      if (cached_key_image != nullptr) {
        key_image = cached_key_image;
      }
      else if (!is_view_only()) {
        *key_image = generate_key_image(output->m_tx_pub_key.get(), output->m_index.get(), subaddr);
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

    auto& unspent_outs = m_output_store.m_all;

    if (key_images.size() > unspent_outs.size()) {
      throw std::runtime_error("blockchain is out of date compared to the signed key images");
    }

    size_t key_images_size = key_images.size();
    
    for (size_t i = 0; i < key_images_size; i++) {
      auto& unspent_out = unspent_outs[i];
      uint64_t out_index = unspent_out.m_index.get();
      uint32_t account_idx = unspent_out.m_recipient.m_maj_i;
      uint32_t subaddress_idx = unspent_out.m_recipient.m_min_i;
      const std::string& tx_public_key = unspent_out.m_tx_pub_key.get();
      m_output_store.set_key_image(key_images[i]->m_hex.get(), i);
      m_generated_key_images.set(key_images[i], tx_public_key, out_index, account_idx, subaddress_idx);
      
      if (!check_spent) continue;
      if (m_tx_store.is_key_image_spent(key_images[i])) {
        spent_amount += unspent_outs[i].m_amount.get();
      }
      else {
        unspent_amount += unspent_outs[i].m_amount.get();
      }
    }

    result->m_height = unspent_outs[key_images_size - 1].m_height;
    result->m_spent_amount = spent_amount;
    result->m_unspent_amount = unspent_amount;

    if (spent_amount > 0 || unspent_amount > 0) {
      process_outputs();
      m_output_store.set(m_tx_store, m_unspent_outs);
      calculate_balance();
    }
    return result;
  }

  std::string monero_wallet_light::get_tx_note(const std::string& tx_hash) const {
    MTRACE("monero_wallet_light::get_tx_note()");
    cryptonote::blobdata tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(tx_hash, tx_blob) || tx_blob.size() != sizeof(crypto::hash)) {
      throw std::runtime_error("TX hash has invalid format");
    }
    crypto::hash _tx_hash = *reinterpret_cast<const crypto::hash*>(tx_blob.data());
    std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_notes.find(_tx_hash);
    if (i == m_tx_notes.end()) return std::string();
    return i->second;
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
    m_tx_notes[_tx_hash] = note;
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
    if (index >= m_address_book.size()) throw std::runtime_error("Index out of range: " + std::to_string(index));

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
    
    m_address_book[index] = entry;
  }

  void monero_wallet_light::delete_address_book_entry(uint64_t index) {  
    if (index >= m_address_book.size()) throw std::runtime_error("Index out of range: " + std::to_string(index));
    m_address_book.erase(m_address_book.begin()+index);
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
    m_wallet_listener.reset(); // wait for queued notifications
  }

  // --------------------------- PRIVATE UTILS --------------------------

  void monero_wallet_light::init_common() {
    monero_wallet_keys::init_common();

    m_is_synced = false;
    m_rescan_on_sync = false;
    m_syncing_enabled = false;
    m_sync_loop_running = false;

    m_address_info.m_locked_funds= 0;
    m_address_info.m_total_received= 0;
    m_address_info.m_total_sent= 0;
    m_address_info.m_scanned_height = 0;
    m_address_info.m_scanned_block_height = 0;
    m_address_info.m_start_height = 0;
    m_address_info.m_transaction_height = 0;
    m_address_info.m_blockchain_height = 0;

    m_address_txs.m_total_received= 0;
    m_address_txs.m_scanned_height = 0;
    m_address_txs.m_scanned_block_height = 0;
    m_address_txs.m_start_height = 0;
    m_address_txs.m_blockchain_height = 0;

    m_unspent_outs.m_per_byte_fee= 0;
    m_unspent_outs.m_fee_mask= 0;
    m_unspent_outs.m_amount= 0;

    monero_light_subaddrs subaddrs;
    m_subaddrs.m_all_subaddrs = subaddrs;
    process_subaddresses();
    set_subaddress_label(0, 0, "Primary account");
    m_wallet_listener = std::unique_ptr<monero_wallet_utils::wallet2_listener>(new monero_wallet_utils::wallet2_listener(*this));
  }

  wallet2_exported_outputs monero_wallet_light::export_outputs(bool all, uint32_t start, uint32_t count) const {
    return m_output_store.export_outputs(m_tx_store, m_generated_key_images, false, 0, count);
  }

  cryptonote::subaddress_index get_transaction_sender(const monero_light_tx &tx) {
    cryptonote::subaddress_index si = {0,0};

    for (const auto &output : tx.m_spent_outputs) {
      si.major = output.m_sender.m_maj_i;
      si.minor = output.m_sender.m_min_i;
      break;
    }

    return si;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers_aux(const monero_transfer_query& query) const {
    monero_utils::start_profile("get_transfers_aux()");

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
    std::unordered_map<uint64_t, std::shared_ptr<monero_block>> blocks;

    const uint64_t current_height = m_address_txs.m_blockchain_height.get() + 1;
    const bool view_only = is_view_only();

    for (const auto &tx : m_address_txs.m_transactions) {
      uint64_t total_sent = tx.m_total_sent.get();
      uint64_t total_received = tx.m_total_received.get();
      uint64_t fee = tx.m_fee.get();
      bool is_incoming = total_received > 0;
      bool is_outgoing = total_sent > 0;
      bool is_change = is_incoming && is_outgoing;

      if (is_change && total_sent >= total_received) total_sent -= total_received;
      else if (is_change) total_sent = 0;

      bool is_locked = tx.m_unlock_time.get() > current_height || current_height < (tx.m_height.get()) + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
      bool is_confirmed = !tx.m_mempool.get();
      bool is_miner_tx = *tx.m_coinbase == true;
      bool has_payment_id = tx.m_payment_id != boost::none && !tx.m_payment_id.get().empty() && tx.m_payment_id.get() != monero_tx::DEFAULT_PAYMENT_ID;
      std::string payment_id = has_payment_id ? tx.m_payment_id.get() : "";
      uint64_t timestamp = tx.m_timestamp.get();
      uint64_t tx_height = is_confirmed ? *tx.m_height : 0;
      uint64_t num_confirmations = is_confirmed ? current_height - tx_height : 0;
      uint64_t change_amount =  is_change ? total_received : 0;
      uint64_t input_sum = 0;
      uint64_t output_sum = 0;
      std::string tx_hash = tx.m_hash.get();
      std::shared_ptr<monero_block> block = nullptr;
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
      tx_wallet->m_is_incoming = is_incoming && !is_change;
      tx_wallet->m_is_outgoing = is_outgoing;
      tx_wallet->m_is_locked = is_locked;
      tx_wallet->m_is_relayed = true;
      tx_wallet->m_is_failed = false;
      tx_wallet->m_is_double_spend_seen = false;
      tx_wallet->m_is_confirmed = is_confirmed;
      tx_wallet->m_is_miner_tx = is_miner_tx;
      tx_wallet->m_unlock_time = *tx.m_unlock_time;
      tx_wallet->m_in_tx_pool = !is_confirmed;
      tx_wallet->m_relay = true;
      tx_wallet->m_hash = tx_hash;
      tx_wallet->m_num_confirmations = num_confirmations;
      tx_wallet->m_fee = fee;
      const auto sender = get_transaction_sender(tx);

      if (is_confirmed) {
        auto it = blocks.find(tx_height);
        if (it == blocks.end()) {
          block = std::make_shared<monero_block>();
          block->m_height = tx_height;
          block->m_timestamp = timestamp;
          blocks[tx_height] = block;
        }
        else block = it->second;

        if (is_miner_tx) block->m_miner_tx = tx_wallet;
        block->m_txs.push_back(tx_wallet);
        tx_wallet->m_block = block;
      }
      else tx_wallet->m_received_timestamp = timestamp;

      if (is_incoming) {
        for (const auto &out : m_output_store.get_by_tx_hash(tx_hash)) {
          uint64_t out_amount = out.m_amount.get();
          uint32_t out_account_idx = out.m_recipient.m_maj_i;
          uint32_t out_subaddress_idx = out.m_recipient.m_min_i;

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

            if (current_height >= TAIL_EMISSION_HEIGHT) {
              uint64_t reward = m_tx_store.get_last_block_reward();
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

            output->m_tx = tx_wallet;
            output->m_account_index = out_account_idx;
            output->m_subaddress_index = out_subaddress_idx;
            output->m_amount = out_amount;
            output->m_is_spent = out.is_spent();
            output->m_index = out.m_global_index.get();
            output->m_stealth_public_key = out.m_public_key;

            output_sum += out_amount;
          }
        }

        if (!is_outgoing && has_payment_id) tx_wallet->m_payment_id = payment_id;
      }
      
      if (is_outgoing && !view_only) {
        std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
        outgoing_transfer->m_tx = tx_wallet;
        outgoing_transfer->m_amount = total_sent >= fee ? total_sent - fee : 0;
        outgoing_transfer->m_account_index = sender.major;

        for (const auto& spent_output : tx.m_spent_outputs) {
          uint32_t account_idx = spent_output.m_sender.m_maj_i;
          uint32_t subaddress_idx = spent_output.m_sender.m_min_i;
          uint64_t out_amount = spent_output.m_amount.get();

          if (account_idx == sender.major && std::find_if(outgoing_transfer->m_subaddress_indices.begin(), outgoing_transfer->m_subaddress_indices.end(), [subaddress_idx](const uint32_t &idx) { return subaddress_idx == idx; }) == outgoing_transfer->m_subaddress_indices.end()) {
            outgoing_transfer->m_addresses.push_back(get_address(account_idx, subaddress_idx));
            outgoing_transfer->m_subaddress_indices.push_back(subaddress_idx);
          }

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

          input_sum += out_amount;
        }

        sort(outgoing_transfer->m_subaddress_indices.begin(), outgoing_transfer->m_subaddress_indices.end());

        tx_wallet->m_outgoing_transfer = outgoing_transfer;
      }

      sort(tx_wallet->m_incoming_transfers.begin(), tx_wallet->m_incoming_transfers.end(), monero_utils::incoming_transfer_before);

      if (is_confirmed && block != nullptr && !tx_query->meets_criteria(tx_wallet.get())) {
        block->m_txs.erase(std::remove(block->m_txs.begin(), block->m_txs.end(), tx_wallet), block->m_txs.end());
      }

      for (const std::shared_ptr<monero_transfer>& transfer : tx_wallet->filter_transfers(*_query)) transfers.push_back(transfer);
    }

    for (const auto &kv : m_tx_store.get_unconfirmed_txs()) {
      auto txwallet = kv.second;
      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
      txwallet->copy(txwallet, tx_wallet);
      tx_wallet->m_weight = boost::none;
      tx_wallet->m_inputs.clear();
      tx_wallet->m_outputs.clear();
      tx_wallet->m_ring_size = boost::none;
      tx_wallet->m_key = boost::none;
      tx_wallet->m_full_hex = boost::none;
      tx_wallet->m_metadata = boost::none;
      tx_wallet->m_last_relayed_timestamp = boost::none;
      for (const std::shared_ptr<monero_transfer>& transfer : tx_wallet->filter_transfers(*_query)) {
        transfers.push_back(transfer);
      }
    }
    
    monero_utils::end_profile("get_transfers_aux()");
    return transfers;
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
    std::vector<monero_light_output> outs;

    if (query.m_account_index != boost::none) {
      if (query.m_subaddress_index == boost::none) {
        outs = m_output_store.get(query.m_account_index.get());
      }
      else {
        outs = m_output_store.get(query.m_account_index.get(), query.m_subaddress_index.get());
      }
    } else outs = m_output_store.m_all;

    std::vector<std::shared_ptr<monero_output_wallet>> outputs;
    const auto block_height = m_address_txs.m_blockchain_height.get();

    // cache unique txs and blocks
    std::map<std::string, std::shared_ptr<monero_tx_wallet>> tx_map;
    std::map<uint64_t, std::shared_ptr<monero_block>> block_map;
    for (const auto &out : outs) {
      // TODO: skip tx building if output excluded by indices, etc
      std::shared_ptr<monero_tx_wallet> tx = build_tx_with_vout(m_tx_store, m_output_store, out, block_height + 1);
      monero_utils::merge_tx(tx, tx_map, block_map);
    }

    std::vector<std::shared_ptr<monero_tx_wallet>> txs;

    for (std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.begin(); tx_iter != tx_map.end(); tx_iter++) {
      txs.push_back(tx_iter->second);
    }

    sort(txs.begin(), txs.end(), monero_utils::tx_height_less_than);

    // filter and return outputs
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {

      // sort outputs
      sort(tx->m_outputs.begin(), tx->m_outputs.end(), monero_utils::vout_before);

      // collect queried outputs, erase if excluded
      for (const std::shared_ptr<monero_output_wallet>& output : tx->filter_outputs_wallet(*_query)) outputs.push_back(output);

      // remove txs without outputs
      if (tx->m_outputs.empty() && tx->m_block != boost::none) tx->m_block.get()->m_txs.erase(std::remove(tx->m_block.get()->m_txs.begin(), tx->m_block.get()->m_txs.end(), tx), tx->m_block.get()->m_txs.end()); // TODO, no way to use const_iterator?
    }

    // free query and return outputs
    monero_utils::free(tx_query);
    return outputs;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses_aux(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    // must provide subaddress indices
    std::vector<uint32_t> subaddress_idxs;
    if (subaddress_indices.empty()) {
      if (m_subaddrs.m_all_subaddrs != boost::none)
        subaddress_idxs = m_subaddrs.m_all_subaddrs->get_subaddresses_indices(account_idx);
      if (subaddress_idxs.empty()) subaddress_idxs.push_back(0);
    }
    else subaddress_idxs = subaddress_indices;

    if (subaddress_idxs.empty()) return std::vector<monero_subaddress>();

    // initialize subaddresses at indices
    return monero_wallet_keys::get_subaddresses(account_idx, subaddress_idxs);
  }

  uint64_t monero_wallet_light::get_subaddress_num_blocks_to_unlock(uint32_t account_idx, uint32_t subaddress_idx) const {
    const auto& unspent_outs = m_output_store.get(account_idx, subaddress_idx);
    return m_tx_store.calculate_num_blocks_to_unlock(unspent_outs, get_height());
  }

  bool monero_wallet_light::output_is_spent(monero_light_output &output) const {
    const auto& key_images = output.m_spend_key_images;
    const auto& rcpt = output.m_recipient;
    cryptonote::subaddress_index received_subaddr;

    received_subaddr.major = rcpt.m_maj_i;
    received_subaddr.minor = rcpt.m_min_i;
    const std::string& tx_pub_key = output.m_tx_pub_key.get();
    uint64_t output_idx = output.m_index.get();

    bool spent = false;

    for (auto& key_image : key_images) {
      if (key_image_is_ours(key_image, tx_pub_key, output_idx, received_subaddr)) {
        output.m_key_image = key_image;
        spent = true;
        break;
      }
    }

    bool checked_unconfirmed = false;

    if (!spent && !output.key_image_is_known()) {
      try {
        output.m_key_image = generate_key_image(tx_pub_key, output_idx, received_subaddr).m_hex;
        // check key image is spent in unconfirmed transactions
        spent = m_tx_store.is_key_image_spent(output.m_key_image.get());
        checked_unconfirmed = true;
      }
      catch (...) {
        return false;
      }
    }

    if (!checked_unconfirmed && !spent && output.key_image_is_known()) {
      // check key image is spent in unconfirmed transactions
      spent = m_tx_store.is_key_image_spent(output.m_key_image.get());
    }

    return spent;
  }

  bool monero_wallet_light::spend_is_real(monero_light_spend &spend) const {
    if (spend.m_key_image == boost::none) return false;
    std::string key_image = spend.m_key_image.get();
    cryptonote::subaddress_index received_subaddr = {spend.m_sender.m_maj_i,spend.m_sender.m_min_i};
    return key_image_is_ours(key_image, spend.m_tx_pub_key.get(), spend.m_out_index.get(), received_subaddr);
  }

  void monero_wallet_light::init_subaddress(monero_subaddress& subaddress) const {
    if (subaddress.m_account_index == boost::none) throw std::runtime_error("Cannot initialize subaddress: account index is none");
    if (subaddress.m_index == boost::none) throw std::runtime_error("Cannot initialize subaddress: subaddress index is none");
    uint32_t account_idx = subaddress.m_account_index.get();
    uint32_t subaddress_idx = subaddress.m_index.get();
    subaddress.m_label = get_subaddress_label(account_idx, subaddress_idx);
    subaddress.m_balance = get_balance(account_idx, subaddress_idx);
    subaddress.m_unlocked_balance = get_unlocked_balance(account_idx, subaddress_idx);
    subaddress.m_num_unspent_outputs = m_output_store.get_num_unspent(account_idx, subaddress_idx);
    subaddress.m_is_used = m_output_store.is_used(account_idx, subaddress_idx);
    subaddress.m_num_blocks_to_unlock = get_subaddress_num_blocks_to_unlock(account_idx, subaddress_idx);
  }

  void monero_wallet_light::calculate_balance() {
    m_tx_store.set(m_address_txs, m_address_info);
    m_output_store.calculate_balance(m_tx_store, get_height());
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
        catch (std::exception const& e) { MERROR("monero_wallet_light failed to background synchronize: " << e.what()); }
        catch (...) { MERROR("monero_wallet_light failed to background synchronize: unknown error"); }

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
        if (rescan) rescan_blockchain(); // infinite loop?

        // sync wallet
        result = sync_aux(start_height);
      }
    } while (!rescan && (rescan = m_rescan_on_sync.exchange(false))); // repeat if not rescanned and rescan was requested
    return result;
  }

  monero_sync_result monero_wallet_light::sync_aux(boost::optional<uint64_t> start_height) {
    MTRACE("sync_aux()");
    monero_utils::start_profile("sync_aux");

    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    // attempt to refresh which may throw exception
    try {
      result = refresh();
      if (!m_is_synced) m_is_synced = true;
      m_wallet_listener->update_listening();  // cannot unregister during sync which would segfault
    } catch (std::exception& e) {
      m_wallet_listener->on_sync_end(); // signal end of sync to reset listener's start and end heights
      monero_utils::end_profile("sync_aux");
      throw;
    }

    // notify listeners of sync end and check for updated funds
    m_wallet_listener->on_sync_end();
    LOG_PRINT_L1("Light wallet refresh done, blocks received: " << result.m_num_blocks_fetched << ", balance (all accounts): " << cryptonote::print_money(get_balance()) << ", unlocked: " << cryptonote::print_money(get_unlocked_balance()));
    monero_utils::end_profile("sync_aux");
    return result;
  }

  monero_sync_result monero_wallet_light::refresh() {
    const std::string& address = get_primary_address();
    const std::string& view_key = get_private_view_key();
    // determine sync start height
    uint64_t last_height = get_height();
    
    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    const uint64_t old_outs_amount = m_unspent_outs.m_amount.get();
    
    uint64_t blockchain_height = 1;
    auto addr_info = m_client->get_address_info(address, view_key);
    if (addr_info.m_blockchain_height != boost::none) blockchain_height = addr_info.m_blockchain_height.get() + 1;
    if (addr_info.m_start_height != boost::none) {
      uint64_t start_height = addr_info.m_start_height.get();
      if (last_height < start_height) last_height = start_height == 0 ? 0 : start_height + 1; 
    }

    // update address info height
    m_address_info.m_blockchain_height = addr_info.m_blockchain_height;
    m_address_info.m_start_height = addr_info.m_start_height;
    m_address_info.m_scanned_height = addr_info.m_scanned_height;
    m_address_info.m_scanned_block_height = addr_info.m_scanned_block_height;
    m_address_info.m_transaction_height = addr_info.m_transaction_height;
    // notify listeners of sync start
    m_wallet_listener->on_sync_start(last_height);

    if (blockchain_height == last_height) {
      return result;
    }

    boost::unique_lock<boost::recursive_mutex> lock(m_sync_data_mutex);
    
    m_address_info = addr_info;
    m_address_txs = m_client->get_address_txs(address, view_key);
    m_unspent_outs = m_client->get_unspent_outs(address, view_key, 0, 0);
    m_subaddrs = m_client->get_subaddrs(address, view_key);
    process_subaddresses();
    process_txs();
    process_outputs();
    // initialize optimized data structures
    m_output_store.set(m_tx_store, m_unspent_outs);
    m_tx_store.set(m_address_txs, addr_info);

    const uint64_t new_outs_amount = m_unspent_outs.m_amount.get();

    result.m_received_money = new_outs_amount > old_outs_amount;

    calculate_balance();
  
    lock.unlock();

    uint64_t current_height = get_height();
    uint64_t daemon_height = get_daemon_height();
    uint64_t restore_height = get_restore_height();

    if (restore_height < current_height) {
      if (last_height < restore_height) last_height = restore_height;
      uint64_t blocks_fetched = current_height - last_height;
      result.m_num_blocks_fetched = blocks_fetched;
    
      if (current_height > last_height) {
        cryptonote::block dummy;
        // notify blocks processed by lws
        for(uint64_t block_height = last_height; block_height < current_height; block_height++) {
          m_wallet_listener->on_new_block(block_height, dummy);
        }
      }
    }

    return result;
  }

  boost::optional<std::string> monero_wallet_light::get_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto subs = m_subaddress_labels.find(account_idx);
    if (subs == m_subaddress_labels.end()) return boost::none;
    auto sub = subs->second.find(subaddress_idx);
    if (sub == subs->second.end() || sub->second.empty()) return boost::none;
    return sub->second;
  }

  // --------------------------- LWS UTILS --------------------------

  void monero_wallet_light::process_txs() {
    std::vector<size_t> txs_to_remove;
    size_t tx_idx = 0;

    for(auto &tx : m_address_txs.m_transactions) {
      uint64_t tx_total_sent = tx.m_total_sent.get();
      uint64_t tx_total_received = tx.m_total_received.get();
      std::vector<size_t> outs_to_remove;
      size_t out_idx = 0;
      
      for (auto& spend : tx.m_spent_outputs) {
        if(!spend_is_real(spend)) {
          uint64_t spend_amount = spend.m_amount.get();
          if (spend_amount > tx_total_sent) throw std::runtime_error("tx total sent is negative: " + tx.m_hash.get());
          tx_total_sent -= spend_amount;
          outs_to_remove.push_back(out_idx);
        }
        out_idx++;
      }

      tx.m_total_sent = tx_total_sent;
      tx.m_total_received = tx_total_received;
      if (tx_total_received == 0 && tx_total_sent == 0) {
        txs_to_remove.push_back(tx_idx);
      }
      else for (auto it = outs_to_remove.rbegin(); it != outs_to_remove.rend(); ++it) tx.m_spent_outputs.erase(tx.m_spent_outputs.begin() + *it);

      tx_idx++;
    }

    for (auto it = txs_to_remove.rbegin(); it != txs_to_remove.rend(); ++it) m_address_txs.m_transactions.erase(m_address_txs.m_transactions.begin() + *it);
  }

  void monero_wallet_light::process_outputs() {
    auto result = m_unspent_outs;
    uint64_t real_amount = m_unspent_outs.m_amount.get();

    for (auto& output : m_unspent_outs.m_outputs) {
      if (!output_is_spent(output)) continue;
      real_amount -= output.m_amount.get();
    }

    sort(m_unspent_outs.m_outputs.begin(), m_unspent_outs.m_outputs.end(), output_before);
    m_unspent_outs.m_amount = real_amount;
  }

  void monero_wallet_light::process_subaddresses() {
    const cryptonote::account_keys &account_keys = m_account.get_keys();
    hw::device &hwdev = m_account.get_device();
    m_subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};
    if (m_subaddrs.m_all_subaddrs == boost::none) return;
    const auto& all_subaddrs = m_subaddrs.m_all_subaddrs.get();
    for (const auto& kv : all_subaddrs) {
      for (const auto& index_range : kv.second) {
        for (uint32_t i = index_range.at(0); i <= index_range.at(1); i++) {
          if (kv.first == 0 && i == 0) continue;
          const auto& subaddress_spend_pub_key = hwdev.get_subaddress_spend_public_key(account_keys, {kv.first, i});
          if (m_subaddresses.find(subaddress_spend_pub_key) == m_subaddresses.end()) m_subaddresses[subaddress_spend_pub_key] = {kv.first, i};
        }
      }
    }
  }

  void monero_wallet_light::upsert_subaddrs(const monero_light_subaddrs &subaddrs, bool get_all) {
    const auto response = m_client->upsert_subaddrs(get_primary_address(), get_private_view_key(), subaddrs, get_all);
    if (get_all) {
      m_subaddrs.m_all_subaddrs = response.m_all_subaddrs;
      process_subaddresses();
    }
  }

  void monero_wallet_light::upsert_subaddrs(uint32_t account_idx, uint32_t subaddress_idx, bool get_all) {
    if (account_idx == 0) throw std::runtime_error("subaddress major lookahead may not be zero");
    if (subaddress_idx == 0) throw std::runtime_error("subaddress minor lookahead may not be zero");

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(0, subaddress_idx - 1);
    
    for(uint32_t i = 0; i < account_idx; i++) {
      subaddrs[i] = std::vector<monero_light_index_range>();
      subaddrs[i].push_back(index_range);
    }

    upsert_subaddrs(subaddrs, get_all);
  }

  void monero_wallet_light::login(bool create_account, bool generated_locally) const {
    m_client->login(get_primary_address(), get_private_view_key(), create_account, generated_locally);
  }

  // --------------------------- STATIC WALLET UTILS --------------------------

  bool monero_wallet_light::wallet_exists(const std::string& primary_address, const std::string& private_view_key, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("monero_wallet_light::wallet_exists(" << primary_address << ")");

    monero_light_client client(std::move(http_client_factory));    
    client.set_connection(server_uri);

    try {
      client.login(primary_address, private_view_key, false);
      return true;
    }
    catch (const std::exception& ex) {
      if (std::string("Unauthorized") == std::string(ex.what())) return true;
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

    if (!config_normalized.m_seed.get().empty()) {
      if (config.m_server != boost::none && config.m_server->m_uri != boost::none) {
        if (wallet_exists(config, config.m_server->m_uri.get(), std::move(http_client_factory))) {
          throw std::runtime_error("Wallet already exists");
        }
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
    MTRACE("monero_wallet_light::create_wallet_from_seed(...)");

    // validate config
    if (config.m_is_multisig != boost::none && config.m_is_multisig.get()) throw std::runtime_error("Restoring from multisig seed not supported");
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config.m_seed == boost::none || config.m_seed.get().empty()) throw std::runtime_error("Must provide wallet seed");

    // validate mnemonic and get recovery key and language
    crypto::secret_key spend_key_sk;
    std::string language = config.m_language != boost::none ? config.m_language.get() : "";
    bool is_valid = crypto::ElectrumWords::words_to_bytes(config.m_seed.get(), spend_key_sk, language);
    if (!is_valid) throw std::runtime_error("Invalid mnemonic");
    if (language == crypto::ElectrumWords::old_language_name) language = Language::English().get_language_name();

    // validate language
    if (!crypto::ElectrumWords::is_valid_language(language)) throw std::runtime_error("Invalid language: " + language);

    // apply offset if given
    bool offset_set = config.m_seed_offset != boost::none && !config.m_seed_offset.get().empty();
    if (offset_set) spend_key_sk = cryptonote::decrypt_key(spend_key_sk, config.m_seed_offset.get());

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light(std::move(http_client_factory));
    wallet->m_account = cryptonote::account_base{};
    crypto::secret_key spend_key_val = wallet->m_account.generate(spend_key_sk, true, false);

    // initialize remaining wallet
    wallet->m_network_type = config.m_network_type.get();
    wallet->m_language = language;
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_val, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    if (offset_set && wallet->m_seed == config.m_seed) throw std::runtime_error("Expected different seed");
    wallet->init_common();
    wallet->m_is_view_only = false;

    wallet->set_daemon_connection(config.m_server);
    bool is_connected = wallet->is_connected_to_daemon();

    if (is_connected) {
      if (config.m_account_lookahead != boost::none) {
        wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      }

      if (config.m_restore_height != boost::none)
      {
        wallet->set_restore_height(config.m_restore_height.get());
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
      }

      if (config.m_restore_height != boost::none)
      {
        wallet->set_restore_height(config.m_restore_height.get());
      }
      
    } else if (config.m_restore_height != boost::none) throw std::runtime_error("Cannote restore wallet from height: wallet is not connected to lws");

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("monero_wallet_light::create_wallet_random(...)");

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
    }

    return wallet;
  }
}
