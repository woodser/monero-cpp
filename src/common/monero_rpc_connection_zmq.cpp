#include "monero_rpc_connection.h"
#include "monero_error.h"
#include "net/zmq.h"

// kept out of monero_rpc_connection.cpp so that only builds which subscribe to zmq need libzmq

static const int ZMQ_RECONNECT_INTERVAL_MS = 1000;

namespace monero {

  // --------------------------- MONERO ZMQ SUBSCRIBER ---------------------------

  struct monero_zmq_subscriber::impl {
    net::zmq::context m_context;  // destroyed after the socket
    net::zmq::socket m_socket;
  };

  monero_zmq_subscriber::monero_zmq_subscriber(const std::string& uri, const std::vector<std::string>& topics): m_impl(new impl()) {
    m_impl->m_context.reset(zmq_ctx_new());
    if (!m_impl->m_context) throw monero_error("Failed to create zmq context: " + net::zmq::get_error_code().message());

    m_impl->m_socket.reset(zmq_socket(m_impl->m_context.get(), ZMQ_SUB));
    if (!m_impl->m_socket) throw monero_error("Failed to create zmq subscriber: " + net::zmq::get_error_code().message());
    int linger_ms = 0;
    int reconnect_ms = ZMQ_RECONNECT_INTERVAL_MS;
    int ipv6 = uri.find('[') != std::string::npos; // an ipv6 address is in brackets, a host name keeps resolving to ipv4
    zmq_setsockopt(m_impl->m_socket.get(), ZMQ_LINGER, &linger_ms, sizeof(linger_ms));
    zmq_setsockopt(m_impl->m_socket.get(), ZMQ_RECONNECT_IVL, &reconnect_ms, sizeof(reconnect_ms));
    zmq_setsockopt(m_impl->m_socket.get(), ZMQ_IPV6, &ipv6, sizeof(ipv6));

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
    zmq_pollitem_t item = { m_impl->m_socket.get(), 0, ZMQ_POLLIN, 0 };
    if (zmq_poll(&item, 1, timeout_ms) < 0) {
      if (zmq_errno() == EINTR) return boost::none;
      throw monero_error("Failed to wait for zmq publication: " + net::zmq::get_error_code().message());
    }
    if (!(item.revents & ZMQ_POLLIN)) return boost::none;

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
    while (true) {
      zmq_msg_t msg;
      zmq_msg_init(&msg);
      int rc = zmq_msg_recv(&msg, m_impl->m_socket.get(), ZMQ_DONTWAIT);
      zmq_msg_close(&msg);
      if (rc < 0) return;
    }
  }

  // --------------------------- MONERO RPC CONNECTION ---------------------------

  std::unique_ptr<monero_zmq_subscriber> monero_rpc_connection::subscribe_zmq(const std::vector<std::string>& topics) const {
    std::string uri;
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      if (m_zmq_uri == boost::none || m_zmq_uri.get().empty()) throw monero_error("Connection has no zmq uri");
      if (m_proxy_uri != boost::none && !m_proxy_uri.get().empty()) throw monero_error("Cannot subscribe to zmq through a proxy"); // zmq would connect directly
      uri = m_zmq_uri.get();
    }
    return std::unique_ptr<monero_zmq_subscriber>(new monero_zmq_subscriber(uri, topics));
  }

}
