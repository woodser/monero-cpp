#include "monero_light_client.h"
#include "net/http.h"

namespace monero {

  bool monero_light_client::is_connected() const {
    return m_connected;
  }

  void monero_light_client::disconnect() {
    if (m_http_client->is_connected())
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      m_http_client->disconnect();
      m_connected = false;
    }
  }

  monero_light_client::monero_light_client(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    auto credentials = std::make_shared<epee::net_utils::http::login>();
    credentials->username = std::string("");
    credentials->password = std::string("");
    m_server = std::string("");
    m_proxy = std::string("");
    m_credentials = *credentials;
    m_connected = false;

    if (http_client_factory != nullptr) m_http_client = http_client_factory->create();
    else {
      auto factory = new net::http::client_factory();
      m_http_client = factory->create();
    }
  }

  void monero_light_client::set_connection(monero_rpc_connection connection) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    if (connection.m_username != boost::none && connection.m_password != boost::none) {
      std::cout << "before set_crendetials()" << std::endl;
      set_credentials(*connection.m_username, *connection.m_password);
    }
    if (connection.m_uri != boost::none) {
      std::cout << "before set uri: " << *connection.m_uri << std::endl;
      set_server(*connection.m_uri);
    }
    else {
      std::cout << "before set uri epmty" << std::endl;
      set_server("");
    }
  }

  void monero_light_client::set_connection(boost::optional<monero_rpc_connection> connection) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    if (connection != boost::none) {
      set_connection(connection.get());
    }
    else {
      set_connection(monero_rpc_connection());
    }
  }

  monero_rpc_connection monero_light_client::get_connection() const {
    monero_rpc_connection connection;

    connection.m_uri = get_server();

    auto credentials = get_credentials();

    if (credentials != boost::none) {
      connection.m_username = credentials->username;
      epee::wipeable_string wipeablePassword = credentials->password;
      std::string password = std::string(wipeablePassword.data(), wipeablePassword.size());
      if (!password.empty()) connection.m_password = password;
    }

    return connection;
  }

  void monero_light_client::set_server(std::string uri) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    
    if (m_http_client) {
      if (m_http_client->is_connected()) {
        m_http_client->disconnect();
        m_connected = false;
      }

      if (!m_http_client->set_server(uri, m_credentials)) {
        throw std::runtime_error("Could not set light wallet server " + uri);
      }

      m_connected = m_http_client->connect(std::chrono::seconds(15));

      if (!m_connected) {
        if (!uri.empty()) std::cout << "Could not connect to light wallet server at " << uri << std::endl;
      }

      try {
        std::vector<std::string> amounts;
        amounts.push_back("0");
        get_random_outs(15, amounts);
        m_connected = true;
      } catch (...) {
        m_connected = false;
      }
    }

    m_server = uri;
  }

  void monero_light_client::set_proxy(std::string uri) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    if (m_http_client) {
      if(!m_http_client->set_proxy(uri)) {
        throw std::runtime_error("failed to set proxy address");
      }
    }

    m_proxy = uri;
  }

  void monero_light_client::set_credentials(std::string username, std::string password) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    auto credentials = std::make_shared<epee::net_utils::http::login>();

    credentials->username = username;
    credentials->password = password;

    m_credentials = *credentials;
  }

  monero_light_get_address_info_response monero_light_client::get_address_info(const std::string &address, const std::string &view_key) const {
    assert_connected();

    monero_light_wallet_request req;
    monero_light_get_address_info_response res;

    req.m_address = address;
    req.m_view_key = view_key;

    int response_code = invoke_post("/get_address_info", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not get address info");
    }

    return res;
  }

  monero_light_get_address_txs_response monero_light_client::get_address_txs(const std::string &address, const std::string &view_key) const {
    assert_connected();

    monero_light_wallet_request req;
    monero_light_get_address_txs_response res;

    req.m_address = address;
    req.m_view_key = view_key;

    int response_code = invoke_post("/get_address_txs", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not get address txs");
    }

    return res;
  }

  monero_light_get_unspent_outs_response monero_light_client::get_unspent_outs(const std::string &address, const std::string &view_key, std::string amount, uint32_t mixin, bool use_dust, std::string dust_threshold) const {
    assert_connected();

    monero_light_get_unspent_outs_request req;
    monero_light_get_unspent_outs_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_amount = amount;
    req.m_mixin = mixin;
    req.m_use_dust = use_dust;
    req.m_dust_threshold = dust_threshold;

    int response_code = invoke_post("/get_unspent_outs", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not get unspent outputs");
    }

    return res;
  }

  monero_light_get_random_outs_response monero_light_client::get_random_outs(uint32_t count, std::vector<std::string> &amounts) const {
    assert_connected();
    
    monero_light_get_random_outs_request req;
    monero_light_get_random_outs_response res;

    req.m_count = count;
    req.m_amounts = amounts;

    int response_code = invoke_post("/get_random_outs", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not get random outputs");
    }

    return res;
  }

  monero_light_get_subaddrs_response monero_light_client::get_subaddrs(const std::string &address, const std::string &view_key) const {
    assert_connected();
    
    monero_light_wallet_request req;
    monero_light_get_subaddrs_response res;

    req.m_address = address;
    req.m_view_key = view_key;

    int response_code = invoke_post("/get_subaddrs", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not get subaddresses");
    }

    return res;
  }

  monero_light_upsert_subaddrs_response monero_light_client::upsert_subaddrs(const std::string &address, const std::string &view_key, monero_light_subaddrs subaddrs, bool get_all) const {
    assert_connected();

    monero_light_upsert_subaddrs_request req;
    monero_light_upsert_subaddrs_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_subaddrs = subaddrs;
    req.m_get_all = get_all;

    int response_code = invoke_post("/upsert_subaddrs", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not upsert subaddresses");
    }

    return res;    
  }

  monero_light_provision_subaddrs_response monero_light_client::provision_subaddrs(const std::string &address, const std::string &view_key, uint32_t maj_i, uint32_t min_i, uint32_t n_maj, uint32_t n_min, bool get_all) const {
    assert_connected();

    monero_light_provision_subaddrs_request req;
    monero_light_provision_subaddrs_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_maj_i = maj_i;
    req.m_min_i = min_i;
    req.m_n_maj = n_maj;
    req.m_n_min = n_min;

    int response_code = invoke_post("/provision_subaddrs", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not provision subaddresses");
    }

    return res;
  }

  monero_light_login_response monero_light_client::login(const std::string &address, const std::string &view_key, bool create_account, bool generated_locally) const {
    assert_connected();
    std::cout << "monero_light_client::login("<< address << ", " << view_key << ")" << std::endl;

    monero_light_login_request req;
    monero_light_login_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_create_account = create_account;
    req.m_generated_locally = generated_locally;

    int response_code = invoke_post("/login", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not login on account: " + address);
    }

    return res;
  }

  monero_light_import_request_response monero_light_client::import_request(const std::string &address, const std::string &view_key, uint64_t from_height) const {
    assert_connected();
    
    monero_light_import_wallet_request req;
    monero_light_import_request_response res;

    req.m_address = address;
    req.m_view_key = view_key;
    req.m_from_height = from_height;

    int response_code = invoke_post("/import_wallet_request", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not import wallet");
    }

    return res;
  }

  monero_light_submit_raw_tx_response monero_light_client::submit_raw_tx(const std::string tx) const {
    assert_connected();
    
    monero_light_submit_raw_tx_response res;
    monero_light_submit_raw_tx_request req;

    req.m_tx = tx;

    int response_code = invoke_post("/submit_raw_tx", req, res);

    if (response_code != 200) {
      throw std::runtime_error("Could not relay tx: " + tx);
    }

    return res;
  }

}