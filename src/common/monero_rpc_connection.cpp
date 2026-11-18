#include "monero_rpc_connection.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
#include "daemon/monero_daemon_rpc_model.h"
#include "monero_error.h"
#include "net/net_parse_helpers.h"
#include "net/zmq.h"

static const uint32_t DEFAULT_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes
static const char* ZMQ_MONITOR_ENDPOINT = "inproc://monero_zmq_subscriber_monitor";
static const int ZMQ_RECONNECT_INTERVAL_MS = 1000;

namespace monero {

  // --------------------------- MONERO REQUEST PARAMS ---------------------------

  rapidjson::Value monero_request_params::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    rapidjson::Value root(rapidjson::kObjectType);
    return root;
  }

  // --------------------------- MONERO RPC REQUEST ---------------------------

  monero_rpc_request::monero_rpc_request(const std::string& method, const std::shared_ptr<serializable_struct>& params, bool json_rpc): m_method(method), m_params(params) {
    if (params == nullptr) m_params = std::make_shared<monero_request_params>();
    if (json_rpc) {
      m_id = "0";
      m_version = "2.0";
    }
  }

  rapidjson::Value monero_rpc_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    if (!is_json_rpc()) {
      if (m_params == nullptr) throw monero_error("No params provided");
      return m_params->to_rapidjson_val(allocator);
    }

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);

    if (m_version != boost::none) monero_utils::add_json_member("jsonrpc", m_version.get(), allocator, root, value_str);
    if (m_id != boost::none) monero_utils::add_json_member("id", m_id.get(), allocator, root, value_str);
    if (m_method != boost::none) monero_utils::add_json_member("method", m_method.get(), allocator, root, value_str);
    if (m_params != nullptr) root.AddMember("params", m_params->to_rapidjson_val(allocator), allocator);

    // return root
    return root;
  }

  // --------------------------- MONERO RPC RESPONSE ---------------------------

  void raise_rpc_error(const boost::property_tree::ptree& error_node, const boost::string_ref uri, const std::string& method) {
    std::string err_message = "Unknown error";
    int err_code = -1;

    for (auto it = error_node.begin(); it != error_node.end(); ++it) {
      std::string key_err = it->first;
      if (key_err == std::string("message")) {
        if (it->second.data().empty()) {
          err_message = "Received error response from RPC request with method '" + method + "' to " + uri.to_string();
        }
        else err_message = it->second.data();
      } else if (key_err == std::string("code")) {
        try {
          err_code = it->second.get_value<int>();
        } catch (...) {
          MERROR("non-numeric error code from a malformed/unusual RPC response");
          err_code = -1;
        }
      }
    }

    throw monero_rpc_error(err_code, err_message);
  }

  // --------------------------- MONERO ZMQ SUBSCRIBER ---------------------------

  struct monero_zmq_subscriber::impl {
    net::zmq::context m_context;  // destroyed after the sockets
    net::zmq::socket m_socket;
    net::zmq::socket m_monitor;
  };

  monero_zmq_subscriber::monero_zmq_subscriber(const std::string& uri, const std::vector<std::string>& topics): m_impl(new impl()) {
    m_impl->m_context.reset(zmq_ctx_new());
    if (!m_impl->m_context) throw monero_error("Failed to create zmq context: " + net::zmq::get_error_code().message());

    m_impl->m_socket.reset(zmq_socket(m_impl->m_context.get(), ZMQ_SUB));
    if (!m_impl->m_socket) throw monero_error("Failed to create zmq subscriber: " + net::zmq::get_error_code().message());
    int linger_ms = 0;
    int reconnect_ms = ZMQ_RECONNECT_INTERVAL_MS;
    zmq_setsockopt(m_impl->m_socket.get(), ZMQ_LINGER, &linger_ms, sizeof(linger_ms));
    zmq_setsockopt(m_impl->m_socket.get(), ZMQ_RECONNECT_IVL, &reconnect_ms, sizeof(reconnect_ms));

    // connection state comes from a monitor, which must be created before connecting
    if (zmq_socket_monitor(m_impl->m_socket.get(), ZMQ_MONITOR_ENDPOINT, ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED) < 0) {
      throw monero_error("Failed to monitor zmq subscriber: " + net::zmq::get_error_code().message());
    }
    m_impl->m_monitor.reset(zmq_socket(m_impl->m_context.get(), ZMQ_PAIR));
    if (!m_impl->m_monitor) throw monero_error("Failed to create zmq monitor: " + net::zmq::get_error_code().message());
    zmq_setsockopt(m_impl->m_monitor.get(), ZMQ_LINGER, &linger_ms, sizeof(linger_ms));
    if (zmq_connect(m_impl->m_monitor.get(), ZMQ_MONITOR_ENDPOINT) < 0) {
      throw monero_error("Failed to connect zmq monitor: " + net::zmq::get_error_code().message());
    }

    for (const std::string& topic : topics) {
      if (zmq_setsockopt(m_impl->m_socket.get(), ZMQ_SUBSCRIBE, topic.c_str(), topic.size()) < 0) {
        throw monero_error("Failed to subscribe to zmq topic '" + topic + "': " + net::zmq::get_error_code().message());
      }
    }
    if (zmq_connect(m_impl->m_socket.get(), uri.c_str()) < 0) {
      throw monero_error("Failed to connect to zmq uri '" + uri + "': " + net::zmq::get_error_code().message());
    }
  }

  monero_zmq_subscriber::~monero_zmq_subscriber() { }

  boost::optional<monero_zmq_publication> monero_zmq_subscriber::wait_for_publication(int timeout_ms) {
    zmq_pollitem_t items[2] = {
      { m_impl->m_monitor.get(), 0, ZMQ_POLLIN, 0 },
      { m_impl->m_socket.get(), 0, ZMQ_POLLIN, 0 }
    };
    if (zmq_poll(items, 2, timeout_ms) < 0) {
      if (zmq_errno() == EINTR) return boost::none;
      throw monero_error("Failed to wait for zmq publication: " + net::zmq::get_error_code().message());
    }
    if (items[0].revents & ZMQ_POLLIN) read_events();
    if (!(items[1].revents & ZMQ_POLLIN)) return boost::none;

    auto message = net::zmq::receive(m_impl->m_socket.get(), ZMQ_DONTWAIT);
    if (!message) {
      if (message.error() == net::zmq::make_error_code(EAGAIN)) return boost::none;
      throw monero_error("Failed to receive zmq publication: " + message.error().message());
    }

    // "topic:json"
    size_t sep = message->find(':');
    if (sep == std::string::npos) return boost::none;
    return monero_zmq_publication{ message->substr(0, sep), message->substr(sep + 1) };
  }

  void monero_zmq_subscriber::discard_publications() {
    read_events();
    while (true) {
      zmq_msg_t msg;
      zmq_msg_init(&msg);
      int rc = zmq_msg_recv(&msg, m_impl->m_socket.get(), ZMQ_DONTWAIT);
      zmq_msg_close(&msg);
      if (rc < 0) return;
    }
  }

  void monero_zmq_subscriber::read_events() {
    while (true) {
      zmq_msg_t msg;
      zmq_msg_init(&msg);
      if (zmq_msg_recv(&msg, m_impl->m_monitor.get(), ZMQ_DONTWAIT) < 0) {
        zmq_msg_close(&msg);
        return;
      }

      // event id is in the first frame, the rest is the address
      uint16_t event = 0;
      if (zmq_msg_size(&msg) >= sizeof(event)) memcpy(&event, zmq_msg_data(&msg), sizeof(event));
      bool more = zmq_msg_more(&msg) != 0;
      zmq_msg_close(&msg);
      while (more) {
        zmq_msg_init(&msg);
        if (zmq_msg_recv(&msg, m_impl->m_monitor.get(), ZMQ_DONTWAIT) < 0) { zmq_msg_close(&msg); break; }
        more = zmq_msg_more(&msg) != 0;
        zmq_msg_close(&msg);
      }

      if (event == ZMQ_EVENT_CONNECTED) {
        MDEBUG("Connected to zmq publisher");
        m_is_connected = true;
        m_num_connections++;
      } else if (event == ZMQ_EVENT_DISCONNECTED) {
        MDEBUG("Disconnected from zmq publisher");
        m_is_connected = false;
      }
    }
  }

  // --------------------------- MONERO RPC CONNECTION ---------------------------

  bool monero_rpc_connection::compare(int p1, int p2) {
    if (p1 == p2) return false;
    // 0 alway first
    if (p1 == 0) return true;
    if (p2 == 0) return false;
    return p1 > p2;
  }

  monero_rpc_connection::monero_rpc_connection(const std::string& uri, const std::string& username, const std::string& password, const std::string& proxy_uri, const std::string& zmq_uri, int priority, const boost::optional<uint32_t>& timeout_ms) {
    if (!uri.empty()) m_uri = uri;
    else m_uri = boost::none;
    if (!proxy_uri.empty()) m_proxy_uri = proxy_uri;
    else m_proxy_uri = boost::none;
    if (!zmq_uri.empty()) m_zmq_uri = zmq_uri;
    else m_zmq_uri = boost::none;
    m_priority = priority;
    m_timeout_ms = timeout_ms;
    set_credentials(username, password);
  }

  monero_rpc_connection::monero_rpc_connection(const monero_rpc_connection& rpc) {
    boost::lock_guard<boost::recursive_mutex> src_lock(rpc.m_mutex);
    m_uri = rpc.m_uri;
    m_proxy_uri = rpc.m_proxy_uri;
    m_ssl_verify = rpc.m_ssl_verify;
    m_zmq_uri = rpc.m_zmq_uri;
    m_priority = rpc.m_priority;
    m_timeout_ms = rpc.m_timeout_ms;
    set_credentials(rpc.m_username.value_or(""), rpc.m_password.value_or(""));
    m_is_online = rpc.m_is_online;
    m_is_authenticated = rpc.m_is_authenticated;
    m_response_time = rpc.m_response_time;
    m_attributes = rpc.m_attributes;
  }

  rapidjson::Value monero_rpc_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
    if (m_username != boost::none) monero_utils::add_json_member("username", m_username.get(), allocator, root, value_str);
    if (m_password != boost::none) monero_utils::add_json_member("password", m_password.get(), allocator, root, value_str);
    if (m_proxy_uri != boost::none) monero_utils::add_json_member("proxyUri", m_proxy_uri.get(), allocator, root, value_str);
    if (m_zmq_uri != boost::none) monero_utils::add_json_member("zmqUri", m_zmq_uri.get(), allocator, root, value_str);

    // set num values
    rapidjson::Value value_num(rapidjson::kNumberType);
    monero_utils::add_json_member("priority", m_priority, allocator, root, value_num);
    if (m_timeout_ms != boost::none) monero_utils::add_json_member("timeoutMs", m_timeout_ms.get(), allocator, root, value_num);
    if (m_response_time != boost::none) monero_utils::add_json_member("responseTime", m_response_time.get(), allocator, root, value_num);

    // set bool values
    monero_utils::add_json_member("sslVerify", m_ssl_verify, allocator, root);
    if (m_is_online != boost::none) monero_utils::add_json_member("isOnline", m_is_online.get(), allocator, root);
    if (m_is_authenticated != boost::none) monero_utils::add_json_member("isAuthenticated", m_is_authenticated.get(), allocator, root);

    return root;
  }

  bool monero_rpc_connection::is_onion() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    epee::net_utils::http::url_content parsed{};
    if (!epee::net_utils::parse_url(m_uri.value_or(""), parsed)) return false;
    return parsed.host.size() >= 6 && parsed.host.compare(parsed.host.size() - 6, 6, ".onion") == 0;
  }

  bool monero_rpc_connection::is_i2p() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    epee::net_utils::http::url_content parsed{};
    if (!epee::net_utils::parse_url(m_uri.value_or(""), parsed)) return false;
    return parsed.host.size() >= 8 && parsed.host.compare(parsed.host.size() - 8, 8, ".b32.i2p") == 0;
  }

  void monero_rpc_connection::set_credentials(const std::string& username, const std::string& password) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    // disconnect http client if connected
    if (m_http_client != nullptr && m_http_client->is_connected()) m_http_client->disconnect();

    bool username_empty = username.empty();
    bool password_empty = password.empty();

    // check username and password consistency
    if (!username_empty || !password_empty) {
      if (password_empty) {
        throw monero_error("password cannot be empty because username is not empty");
      }
      if (username_empty) {
        throw monero_error("username cannot be empty because password is not empty");
      }
    }

    // check username and password changes
    bool username_equals = (m_username == boost::none && username_empty) || (m_username != boost::none && *m_username == username);
    bool password_equals = (m_password == boost::none && password_empty) || (m_password != boost::none && *m_password == password);

    // connection reset values
    if (!username_equals || !password_equals) {
      m_is_online = boost::none;
      m_is_authenticated = boost::none;
    }

    // setup username and password
    if (!username_empty && !password_empty) {
      m_username = username;
      m_password = password;
    } else {
      m_username = boost::none;
      m_password = boost::none;
    }
  }

  void monero_rpc_connection::set_attribute(const std::string& key, const std::string& val) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_attributes[key] = val;
  }

  std::string monero_rpc_connection::get_attribute(const std::string& key) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    std::unordered_map<std::string, std::string>::const_iterator i = m_attributes.find(key);
    if (i == m_attributes.end()) {
      return std::string(""); // attribute not found
    }
    return i->second;
  }

  std::unique_ptr<monero_zmq_subscriber> monero_rpc_connection::subscribe_zmq(const std::vector<std::string>& topics) const {
    std::string uri;
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      if (m_zmq_uri == boost::none || m_zmq_uri.get().empty()) throw monero_error("Connection has no zmq uri");
      uri = m_zmq_uri.get();
    }
    return std::unique_ptr<monero_zmq_subscriber>(new monero_zmq_subscriber(uri, topics));
  }

  boost::optional<bool> monero_rpc_connection::is_online() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_is_online;
  }

  boost::optional<bool> monero_rpc_connection::is_authenticated() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    return m_is_authenticated;
  }

  boost::optional<bool> monero_rpc_connection::is_connected() const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    if (m_is_online == boost::none) return boost::none;
    return m_is_online.get() && (m_is_authenticated == boost::none || m_is_authenticated.get());
  }

  bool monero_rpc_connection::check_connection(const boost::optional<uint32_t>& timeout_ms) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    boost::optional<bool> is_online_before = m_is_online;
    boost::optional<bool> is_authenticated_before = m_is_authenticated;
    boost::optional<std::chrono::high_resolution_clock::time_point> start_time = boost::none;

    try {

      // assume daemon connection
      monero_get_blocks_by_height_request request(100);
      start_time = std::chrono::high_resolution_clock::now();
      send_binary_request(request, timeout_ms);

      // set response time
      m_response_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time.get()).count();
      m_is_online = true;
      m_is_authenticated = true;
    }
    catch (const monero_rpc_error& ex) {
      m_is_online = false;
      m_is_authenticated = boost::none;
      m_response_time = boost::none;

      if (ex.code == 401 || ex.code == 404) {

        // fallback to latency check
        m_is_online = true;
        m_is_authenticated = ex.code == 404;
      }
    }
    catch (...) {
      m_is_online = false;
      m_is_authenticated = boost::none;
      m_response_time = boost::none;
    }

    if (gen_utils::bool_equals(true, m_is_online) && start_time != boost::none) {
      m_response_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time.get()).count();
    }

    return is_online_before != m_is_online || is_authenticated_before != m_is_authenticated;
  }

  boost::property_tree::ptree monero_rpc_connection::send_json_request(const std::string& path, const std::shared_ptr<serializable_struct>& params, const boost::optional<uint32_t>& timeout_ms) const {

    // send JSON-RPC request
    monero_rpc_request request(path, params);
    auto response = send_json_request(request, timeout_ms);

    // assert JSON-RPC response is defined
    if (response.m_result == boost::none) throw monero_error("Invalid Monero JSONRPC response");
    return response.m_result.get();
  }

  monero_rpc_response monero_rpc_connection::send_json_request(const monero_rpc_request &request, const boost::optional<uint32_t>& timeout_ms) const {

    // invoke JSON-RPC method
    monero_rpc_response response;
    send_rpc_request("/json_rpc", request, response, timeout_ms);

    // return JSON-RPC response
    return response;
  }

  boost::property_tree::ptree monero_rpc_connection::send_path_request(const std::string& path, const std::shared_ptr<serializable_struct>& params, const boost::optional<uint32_t>& timeout_ms) const {

    // send RPC request
    monero_rpc_request request(path, params, false);
    auto response = send_path_request(request, timeout_ms);

    // assert RPC response is defined
    if (response.m_response == boost::none) throw monero_error("Invalid Monero RPC response");
    return response.m_response.get();
  }

  monero_rpc_response monero_rpc_connection::send_path_request(const monero_rpc_request &request, const boost::optional<uint32_t>& timeout_ms) const {

    // validate parameters
    if (request.m_method == boost::none || request.m_method->empty()) throw monero_error("No RPC method set in path request");

    // invoke RPC method
    monero_rpc_response response;
    send_rpc_request(std::string("/") + request.m_method.get(), request, response, timeout_ms);

    // return RPC response
    return response;
  }

  monero_rpc_response monero_rpc_connection::send_binary_request(const monero_rpc_request &request, const boost::optional<uint32_t>& timeout_ms) const {

    // validate parameters
    if (request.m_method == boost::none || request.m_method->empty()) throw monero_error("No RPC method set in binary request");

    // invoke binary RPC method
    monero_rpc_response response;
    send_rpc_request(std::string("/") + request.m_method.get(), request, response, timeout_ms, true);

    // return binary response
    return response;
  }

  void monero_rpc_connection::ensure_configured() const {

    // create http client on first use, so constructing a connection does not require network support
    if (m_http_client == nullptr) {
      auto factory = std::make_unique<net::http::client_factory>();
      m_http_client = factory->create();
      m_http_client->set_auto_connect(true);
    }

    // only reconfigure when uri/creds/proxy/ssl changed since last apply
    std::string uri = m_uri.value_or("");
    std::string username = m_username.value_or("");
    std::string password = m_password.value_or("");
    std::string proxy_uri = m_proxy_uri.value_or("");
    auto key = std::make_tuple(uri, username, password, proxy_uri, m_ssl_verify);

    if (m_applied == key) return; // unchanged, so reuse live connection

    // setup connection credentials
    boost::optional<epee::net_utils::http::login> login;
    if(!username.empty() && !password.empty()) {
      login = epee::net_utils::http::login();
      login->username = username;
      login->password = password;
    }

    // detect ssl
    epee::net_utils::ssl_options_t ssl = uri.rfind("https", 0) == 0 ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;
    if (!m_ssl_verify) ssl.verification = epee::net_utils::ssl_verification_t::none;

    if (!m_http_client->set_proxy(proxy_uri)) throw monero_error("Could not set proxy uri: " + proxy_uri);
    if (!m_http_client->set_server(uri, login, std::move(ssl))) throw monero_error("Could not set uri: " + uri);
    if (!m_http_client->connect(std::chrono::milliseconds(DEFAULT_TIMEOUT_MS))) MWARNING("Could not connect to server: " + uri);

    // the http client only keeps host and port, so requests are sent under the path of the uri
    epee::net_utils::http::url_content parsed;
    m_path_prefix = epee::net_utils::parse_url(uri, parsed) ? parsed.m_uri_content.m_path : "";
    while (!m_path_prefix.empty() && m_path_prefix.back() == '/') m_path_prefix.pop_back();

    m_applied = key;
  }

  std::string monero_rpc_connection::invoke_post(const boost::string_ref uri, const std::string& body, const boost::optional<uint32_t>& timeout_ms) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    // request/response timeout: user-configurable, defaults to 3 minutes when not set.
    uint32_t timeout = DEFAULT_TIMEOUT_MS;
    if (timeout_ms != boost::none) timeout = timeout_ms.get();
    else if (m_timeout_ms != boost::none) timeout = m_timeout_ms.get();
    if (timeout == 0) timeout = std::numeric_limits<uint32_t>::max(); // timeout of 0 is treated as indefinite

    // ensure_configured() bounds only the first connect; epee reconnects with this request timeout
    ensure_configured();
    const epee::net_utils::http::http_response_info* pri = NULL;

    // invoke http json
    const uint64_t received_before = m_http_client->get_bytes_received();
    if (!m_http_client->invoke_post(m_path_prefix + uri.to_string(), body, std::chrono::milliseconds(timeout), std::addressof(pri))) {

      // epee never surfaces the 401 status, but a rejected login means the server answered;
      // a dead or idle-closed socket yields no response bytes at all
      bool received = m_http_client->get_bytes_received() > received_before;
      if (received && m_http_client->is_connected()) {
        throw monero_rpc_error(401, "Unauthorized");
      }

      // drop the socket: epee leaves EOF'd sockets marked connected, so without this the next
      // call reuses the poisoned socket and hits the same misdiagnosis again
      m_http_client->disconnect();
      if (m_uri == boost::none || m_uri->empty()) throw monero_error("Cannot send RPC request: uri not set.");
      throw monero_error("Network error: " + std::string(received ? "connection dropped mid-response" : "no response") + " from " + m_uri.get() + uri.to_string() + " (timeout: " + std::to_string(timeout) + "ms)");
    }
    if (!pri) throw monero_error("Could not get response info");
    if (pri->m_response_code < 200 || pri->m_response_code > 299) {
      std::string err_msg = std::to_string(pri->m_response_code) + " " + pri->m_response_comment + (pri->m_body.empty() ? "" : ": " + pri->m_body);
      throw monero_rpc_error(pri->m_response_code, err_msg);
    }

    // return response info body
    return pri->m_body;
  }

  void deserialize_rpc_response(const std::string& json, monero_rpc_response& response, const boost::string_ref uri, const std::string& method) {

    // parse json to property node
    boost::property_tree::ptree node;
    gen_utils::deserialize(json, node);

    // parse JSON-RPC response
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("error")) raise_rpc_error(it->second, uri, method);
      else if (key == std::string("jsonrpc")) response.m_jsonrpc = it->second.data();
      else if (key == std::string("result")) response.m_result = it->second;
    }

    // if not JSON-RPC, set RPC response
    if (response.m_jsonrpc == boost::none) response.m_response = node;
  }

  void monero_rpc_connection::send_rpc_request(const boost::string_ref uri, const monero_rpc_request& request, monero_rpc_response& response, const boost::optional<uint32_t>& timeout_ms, bool binary) const {
    std::string body;
    if (request.m_method == boost::none) throw monero_error("Must provide a valid request method");
    if (binary) monero_utils::json_to_binary(request.serialize(), body);
    else body = request.serialize();

    std::string result = invoke_post(uri, body, timeout_ms);
    if (binary) response.m_binary = result;
    else deserialize_rpc_response(result, response, uri, request.m_method.get());
  }

  void monero_rpc_connection::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_rpc_connection>& connection) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("uri")) connection->m_uri = it->second.data();
      else if (key == std::string("username")) connection->m_username = it->second.data();
      else if (key == std::string("password")) connection->m_password = it->second.data();
      else if (key == std::string("proxyUri") || key == std::string("proxy_uri")) connection->m_proxy_uri = it->second.data();
      else if (key == std::string("sslVerify")) connection->m_ssl_verify = it->second.get_value<bool>();
      else if (key == std::string("zmqUri")) connection->m_zmq_uri = it->second.data();
      else if (key == std::string("priority")) connection->m_priority = it->second.get_value<int>();
      else if (key == std::string("timeoutMs")) connection->m_timeout_ms = it->second.get_value<uint32_t>();
    }
  }

  std::shared_ptr<monero_rpc_connection> monero_rpc_connection::deserialize(const std::string& json) {
    return gen_utils::deserialize<monero_rpc_connection>(json);
  }

}
