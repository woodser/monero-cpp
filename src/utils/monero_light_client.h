#include "monero_light_model.h"
#include "daemon/monero_daemon_model.h"
#include "net/abstract_http_client.h"
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/recursive_mutex.hpp>

namespace monero {

  class monero_light_client {
    public:

      monero_light_client(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory = nullptr);

      bool is_connected() const;

      monero_light_get_address_info_response get_address_info(const std::string &address, const std::string &view_key) const;
      monero_light_get_address_txs_response get_address_txs(const std::string &address, const std::string &view_key) const;
      monero_light_get_unspent_outs_response get_unspent_outs(const std::string &address, const std::string &view_key, std::string amount, uint32_t mixin, bool use_dust = true, std::string dust_threshold = "0") const;
      monero_light_get_random_outs_response get_random_outs(uint32_t count, std::vector<std::string> &amounts) const;
      monero_light_get_subaddrs_response get_subaddrs(const std::string &address, const std::string &view_key) const;
      monero_light_upsert_subaddrs_response upsert_subaddrs(const std::string &address, const std::string &view_key, monero_light_subaddrs subaddrs, bool get_all = true) const;
      monero_light_provision_subaddrs_response provision_subaddrs(const std::string &address, const std::string &view_key, uint32_t n_maj_i = 0, uint32_t n_min_i = 0, uint32_t n_maj = 0, uint32_t n_min = 0, bool get_all = true) const;
      monero_light_login_response login(const std::string &address, const std::string &view_key, bool create_account = true, bool generated_locally = true) const;
      monero_light_import_request_response import_request(const std::string &address, const std::string &view_key) const;
      monero_light_submit_raw_tx_response submit_raw_tx(const std::string tx) const;

      void set_connection(boost::optional<monero_rpc_connection> connection);
      void set_connection(monero_rpc_connection connection);
      monero_rpc_connection get_connection() const;

      void set_server(std::string uri);
      std::string get_server() const { return m_server; };
      
      void set_proxy(std::string uri);
      std::string get_proxy() const { return m_proxy; };

      void set_credentials(std::string username, std::string password);
      boost::optional<epee::net_utils::http::login> get_credentials() const { return m_credentials; };

    protected:
      mutable boost::recursive_mutex m_mutex;
      std::string m_server;
      std::string m_proxy;
      boost::optional<epee::net_utils::http::login> m_credentials;
      std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
      bool m_connected;

      void assert_connected() const { if (!is_connected()) throw std::runtime_error("Not connected"); };

      template<class t_request, class t_response>
      inline int invoke_post(const boost::string_ref uri, const t_request& request, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15)) const {
        if (!m_http_client) throw std::runtime_error("http client not set");

        rapidjson::Document document(rapidjson::Type::kObjectType);
        rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
        rapidjson::StringBuffer sb;
        rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
        req.Accept(writer);
        std::string body = sb.GetString();

        //std::cout << "monero_light_client::invoke_post(): before invoke " << uri << ", body: " << body << std::endl;

        std::shared_ptr<epee::net_utils::http::http_response_info> _res = std::make_shared<epee::net_utils::http::http_response_info>();
        const epee::net_utils::http::http_response_info* response = _res.get();
        boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

        if (!m_http_client->invoke_post(uri, body, timeout, &response)) {
          throw std::runtime_error("Network error");
        }

        //std::cout << "monero_light_client::invoke_post(): after invoke " << uri << ", body: " << body << std::endl;

        int status_code = response->m_response_code;

        if (status_code == 200) {
          res = *t_response::deserialize(response->m_body);
        }

        return status_code;
      }
  };

}