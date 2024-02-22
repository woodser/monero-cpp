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

using namespace monero;

#include <vector>
#include "daemon/monero_daemon_model.h"

namespace monero {

    struct monero_light_output {
        boost::optional<uint64_t> m_tx_id;
        boost::optional<std::string> m_amount;
        boost::optional<uint16_t> m_index;
        boost::optional<std::string> m_global_index;
        boost::optional<std::string> m_rct;
        boost::optional<std::string> m_tx_hash;
        boost::optional<std::string> m_tx_prefix_hash;
        boost::optional<std::string> m_public_key;
        boost::optional<std::string> m_tx_pub_key;
        boost::optional<std::vector<std::string>> m_spend_key_images;
        boost::optional<std::string> m_timestamp;
        boost::optional<uint64_t> m_height;

        static std::shared_ptr<monero_light_output> deserialize(const std::string& config_json);
    };

    struct monero_light_rates {
        static std::shared_ptr<monero_light_rates> deserialize(const std::string& config_json);
    };

    struct monero_light_spend {
        boost::optional<std::string> m_amount;
        boost::optional<std::string> m_key_image;
        boost::optional<std::string> m_tx_pub_key;
        boost::optional<uint16_t> m_out_index;
        boost::optional<uint32_t> m_mixin;

        static std::shared_ptr<monero_light_spend> deserialize(const std::string& config_json);
    };

    struct monero_light_transaction {
        boost::optional<uint64_t> m_id;
        boost::optional<std::string> m_hash;
        boost::optional<std::string> m_timestamp;
        boost::optional<std::string> m_total_received;
        boost::optional<std::string> m_total_sent;
        boost::optional<uint64_t> m_unlock_time;
        boost::optional<uint64_t> m_height;
        boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
        boost::optional<std::string> m_payment_id;
        boost::optional<bool> m_coinbase;
        boost::optional<bool> m_mempool;
        boost::optional<uint32_t> m_mixin;

        static std::shared_ptr<monero_light_transaction> deserialize(const std::string& config_json);
    };

    struct monero_light_random_output {
        boost::optional<std::string> m_global_index;
        boost::optional<std::string> m_public_key;
        boost::optional<std::string> m_rct;

        static std::shared_ptr<monero_light_random_output> deserialize(const std::string& config_json);
    };

    struct monero_light_random_outputs {
        boost::optional<std::string> m_amount;
        boost::optional<std::vector<monero_light_random_output>> m_outputs;

        static std::shared_ptr<monero_light_random_outputs> deserialize(const std::string& config_json);
    };

    struct monero_light_get_address_info_request {
        boost::optional<std::string> m_address;
        boost::optional<std::string> m_view_key;

        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_get_address_info_response {
        boost::optional<std::string> m_locked_funds;
        boost::optional<std::string> m_total_received;
        boost::optional<std::string> m_total_sent;
        boost::optional<uint64_t> m_scanned_height;
        boost::optional<uint64_t> m_scanned_block_height;
        boost::optional<uint64_t> m_start_height;
        boost::optional<uint64_t> m_transaction_height;
        boost::optional<uint64_t> m_blockchain_height;
        boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
        boost::optional<monero_light_rates> m_rates;
        
        static std::shared_ptr<monero_light_get_address_info_response> deserialize(const std::string& config_json);
    };

    struct monero_light_get_address_txs_request : public serializable_struct {
        boost::optional<std::string> m_address;
        boost::optional<std::string> m_view_key;

        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_get_address_txs_response {
        boost::optional<std::string> m_total_received;
        boost::optional<uint64_t> m_scanned_height;
        boost::optional<uint64_t> m_scanned_block_height;
        boost::optional<uint64_t> m_start_height;
        boost::optional<uint64_t> m_blockchain_height;
        boost::optional<std::vector<monero_light_transaction>> m_transactions;

        static std::shared_ptr<monero_light_get_address_txs_response> deserialize(const std::string& config_json);
    };

    struct monero_light_get_random_outs_request : public serializable_struct {
        boost::optional<uint32_t> m_count;
        boost::optional<std::vector<std::string>> m_amounts;
        
        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_get_random_outs_response {
        boost::optional<std::vector<monero_light_random_output>> m_amount_outs;
        
        static std::shared_ptr<monero_light_get_random_outs_response> deserialize(const std::string& config_json);
    };

    struct monero_light_get_unspent_outs_request : public serializable_struct {
        boost::optional<std::string> m_address;
        boost::optional<std::string> m_view_key;
        boost::optional<std::string> m_amount;
        boost::optional<uint32_t> m_mixin;
        boost::optional<bool> m_use_dust;
        boost::optional<std::string> m_dust_threshold;
        
        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_get_unspent_outs_response {
        boost::optional<std::string> m_per_byte_fee;
        boost::optional<std::string> m_fee_mask;
        boost::optional<std::string> m_amount;
        boost::optional<std::vector<monero_light_output>> m_outputs;
        
        static std::shared_ptr<monero_light_get_unspent_outs_response> deserialize(const std::string& config_json);
    };

    struct monero_light_import_request_request : public serializable_struct {
        boost::optional<std::string> m_address;
        boost::optional<std::string> m_view_key;
        
        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_import_request_response {
        boost::optional<std::string> m_payment_address;
        boost::optional<std::string> m_payment_id;
        boost::optional<std::string> m_import_fee;
        boost::optional<bool> m_new_request;
        boost::optional<bool> m_request_fullfilled;
        boost::optional<std::string> m_status;
        
        static std::shared_ptr<monero_light_import_request_response> deserialize(const std::string& config_json);
    };

    struct monero_light_login_request : public serializable_struct {
        boost::optional<std::string> m_address;
        boost::optional<std::string> m_view_key;
        boost::optional<bool> m_create_account;
        boost::optional<bool> m_generated_locally;
        
        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_login_response {
        boost::optional<bool> m_new_address;
        boost::optional<bool> m_generated_locally;
        boost::optional<uint64_t> m_start_height;
        
        static std::shared_ptr<monero_light_login_response> deserialize(const std::string& config_json);
    };

    struct monero_light_submit_raw_tx_request : public serializable_struct {
        boost::optional<std::string> m_tx;
        
        rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    };

    struct monero_light_submit_raw_tx_response {
        boost::optional<std::string> m_status;
        
        static std::shared_ptr<monero_light_submit_raw_tx_response> deserialize(const std::string& config_json);
    };

}