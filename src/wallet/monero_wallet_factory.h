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

#include "monero_wallet_full.h"

namespace monero
{

  struct monero_wallet_factory
  {

    static monero_wallet_factory get_default()
    {
      return monero_wallet_factory();
    }

    /**
     * Open an existing wallet from disk.
     *
     * @param path is the path to the wallet file to open
     * @param password is the password of the wallet file to open
     * @param network_type is the wallet's network type
     * @return a pointer to the wallet instance
     */
    monero_wallet_full* open_wallet(const std::string &path, const std::string &password, const monero_network_type network_type);

    /**
     * Open an in-memory wallet from existing data buffers.
     *
     * @param password is the password of the wallet file to open
     * @param network_type is the wallet's network type
     * @param keys_data contains the contents of the ".keys" file
     * @param cache_data contains the contents of the wallet cache file (no extension)
     * @param daemon_connection is connection information to a daemon (default = an unconnected wallet)
     * @param http_client_factory allows use of custom http clients
     * @return a pointer to the wallet instance
     */
    monero_wallet_full* open_wallet_data(const std::string &password, const monero_network_type, const std::string &keys_data, const std::string &cache_data, const monero_rpc_connection &daemon_connection = monero_rpc_connection(), std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    /**
     * Create a new wallet with the given configuration.
     *
     * @param config is the wallet configuration
     * @param http_client_factory allows use of custom http clients
     * @return a pointer to the wallet instance
     */
    monero_wallet_full* create_wallet(const monero_wallet_config &config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    monero_wallet_full* create_wallet_from_seed(monero_wallet_config &config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    monero_wallet_full* create_wallet_from_keys(monero_wallet_config &config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

    monero_wallet_full* create_wallet_random(monero_wallet_config &config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

  protected:
    virtual monero_wallet_full* create_origin();
  };
}