#include "monero_rpc_connection.h"
#include "monero_error.h"
#include "net/zmq.h"

// kept out of monero_rpc_connection.cpp so that only builds which subscribe to zmq need libzmq

static const char* ZMQ_MONITOR_ENDPOINT = "inproc://monero_zmq_subscriber_monitor";
static const int ZMQ_RECONNECT_INTERVAL_MS = 1000;

namespace monero {

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

  std::unique_ptr<monero_zmq_subscriber> monero_rpc_connection::subscribe_zmq(const std::vector<std::string>& topics) const {
    std::string uri;
    {
      boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
      if (m_zmq_uri == boost::none || m_zmq_uri.get().empty()) throw monero_error("Connection has no zmq uri");
      uri = m_zmq_uri.get();
    }
    return std::unique_ptr<monero_zmq_subscriber>(new monero_zmq_subscriber(uri, topics));
  }

}
