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

#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "net/http.h"
#include "daemon/monero_daemon_model.h"

/**
 * Public interface for libmonero-cpp library.
 */
namespace monero {

  /**
   * Models parameters for a request to a RPC server.
   */
  struct monero_request_params : public serializable_struct {
    monero_request_params() { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models a request to a RPC server.
   */
  struct monero_rpc_request : public serializable_struct {
    boost::optional<std::string> m_id;
    boost::optional<std::string> m_version;
    boost::optional<std::string> m_method;
    boost::optional<std::shared_ptr<serializable_struct>> m_params;

    monero_rpc_request() { }
    monero_rpc_request(const std::string& method, const std::shared_ptr<serializable_struct>& params, bool json_rpc = true);

    bool is_json_rpc() const { return m_id != boost::none && m_version != boost::none; }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models a response from a RPC server.
   */
  struct monero_rpc_response {
    boost::optional<std::string> m_jsonrpc;
    boost::optional<boost::property_tree::ptree> m_result;
    boost::optional<boost::property_tree::ptree> m_response;
    boost::optional<std::string> m_binary;
  };

  /**
   * Maintains a connection and sends requests to a Monero RPC API.
   */
  class monero_rpc_connection : public serializable_struct {
  public:
    boost::optional<std::string> m_uri;
    boost::optional<std::string> m_username;
    boost::optional<std::string> m_password;
    boost::optional<std::string> m_proxy_uri;
    boost::optional<std::string> m_zmq_uri;      // TODO implement zmq listener
    boost::optional<uint32_t> m_timeout_ms;      // RPC request timeout in milliseconds.
    boost::optional<uint64_t> m_response_time;   // automatically set by calling check_connection()
    int m_priority;                              // priority relative to other connections. 1 is highest, then priority 2, etc. Default priority is 0, lowest priority.

    static std::shared_ptr<monero_rpc_connection> from_property_tree(const boost::property_tree::ptree& node);

    /**
     * Checks RPC connection priority order.
     *
     * @param c1 first priority to compare
     * @param c2 second priority to compare
     */
    static bool compare(int p1, int p2);

    /**
     * Initialize a new RPC connection.
     *
     * @param uri RPC connection uri
     * @param username RPC connection authentication username
     * @param password RPC connection authentication password
     * @param proxy_uri RPC connection proxy uri
     * @param zmq_uri RPC connection zmq uri
     * @param priority RPC connection priority
     * @param timeout_ms RPC connection timeout in milliseconds
     */
    monero_rpc_connection(const std::string& uri = "", const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "", const std::string& zmq_uri = "", int priority = 0, const boost::optional<uint32_t>& timeout_ms = boost::none);

    /**
     * Copy a RPC connection.
     *
     * @param rpc RPC connection to copy
     */
    monero_rpc_connection(const monero_rpc_connection& rpc);

    /**
     * Indicates if the connection uri is a TOR server.
     *
     * @return true or false to indicate if connection uri is a TOR server
     */
    bool is_onion() const;

    /**
     * Indicates if the connection uri is a I2P server.
     *
     * @return true or false to indicate if connection uri is a I2P server
     */
    bool is_i2p() const;

    /**
     * Set connection credentials.
     *
     * @param username username to use in RPC authentication
     * @param password password to use in RPC authentication
     */
    void set_credentials(const std::string& username, const std::string& password);

    /**
     * Set connection attribute.
     *
     * @param key is the attribute key
     * @param val is the attribute value
     */
    void set_attribute(const std::string& key, const std::string& val);

    /**
     * Get connection attribute.
     *
     * @param key is the attribute to get the value of
     * @return key's value if set
     */
    std::string get_attribute(const std::string& key) const;

    /**
     * Indicates if the connection is online, which is set automatically by calling check_connection().
     *
     * @return true or false to indicate if online, or null if check_connection() has not been called
     */
    boost::optional<bool> is_online() const;

    /**
     * Indicates if the connection is authenticated, which is set automatically by calling check_connection().
     *
     * @return true if authenticated or no authentication, false if not authenticated, or null if not set
     */
    boost::optional<bool> is_authenticated() const;

    /**
     * Indicates if the connection is connected, which is set automatically by calling check_connection().
     *
     * @return true or false to indicate if connected, or null if check_connection() has not been called
     */
    boost::optional<bool> is_connected() const;

    /**
     * Check the connection and update online, authentication, and response time status.
     *
     * @param timeout_ms the maximum response time before considered offline
     * @return
     */
    bool check_connection(const boost::optional<uint32_t>& timeout_ms = boost::none);

    /**
     * Send a request to the RPC API.
     *
     * @param path specifies the method to request
     * @param params are the request's input parameters
     * @return the RPC API response as a map
     */
    boost::property_tree::ptree send_json_request(const std::string& path, const std::shared_ptr<serializable_struct>& params = nullptr, const boost::optional<uint32_t>& timeout_ms = boost::none) const;

    /**
     * Send a request to the RPC API.
     *
     * @param request specifies the method to request with parameters
     * @param timeout request timeout in milliseconds
     * @return the RPC API response as a map
     */
    monero_rpc_response send_json_request(const monero_rpc_request &request, const boost::optional<uint32_t>& timeout_ms = boost::none) const;

    /**
     * Send a RPC request to the given path and with the given paramters.
     *
     * E.g. "/get_transactions" with params
     *
     * @param path is the url path of the request to invoke
     * @param params are request parameters sent in the body
     * @return the RPC API response as a map
     */
    boost::property_tree::ptree send_path_request(const std::string& path, const std::shared_ptr<serializable_struct>& params = nullptr, const boost::optional<uint32_t>& timeout_ms = boost::none) const;

    /**
     * Send a RPC request to the given path and with the given paramters.
     *
     * @param request specifies the method to request with parameters
     * @param timeout request timeout in milliseconds
     * @return the request's deserialized response
     */
    monero_rpc_response send_path_request(const monero_rpc_request &request, const boost::optional<uint32_t>& timeout_ms = boost::none) const;

    /**
     * Send a binary RPC request.
     *
     * @param request specifies the method to request with paramesters
     * @param timeout request timeout in milliseconds
     * @return the request's deserialized response
     */
    monero_rpc_response send_binary_request(const monero_rpc_request &request, const boost::optional<uint32_t>& timeout_ms = boost::none) const;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;

  protected:
    // instance variables
    mutable boost::recursive_mutex m_mutex;
    boost::optional<bool> m_is_online;
    boost::optional<bool> m_is_authenticated;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    std::unordered_map<std::string, std::string> m_attributes;
    mutable std::tuple<std::string, std::string, std::string, std::string> m_applied;

    void ensure_configured() const;
    std::string invoke_post(const boost::string_ref uri, const std::string& body, const boost::optional<uint32_t>& timeout_ms = boost::none) const;
    void send_rpc_request(const boost::string_ref uri, const monero_rpc_request& request, monero_rpc_response& response, const boost::optional<uint32_t>& timeout_ms = boost::none, bool binary = false) const;
  };

}
