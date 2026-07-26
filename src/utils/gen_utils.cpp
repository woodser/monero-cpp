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

#include "gen_utils.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace gen_utils;

// ------------------------- SERIALIZATION ---------------------------

std::string gen_utils::serialize(const rapidjson::Document& doc) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  return buffer.GetString();
}

std::string gen_utils::serialize(const boost::property_tree::ptree& node) {
  std::stringstream ss;
  boost::property_tree::write_json(ss, node, false);
  std::string str = ss.str();
  return str.substr(0, str.size() - 1); // strip newline
}

void gen_utils::deserialize(const std::string& json, boost::property_tree::ptree& root) {
  std::istringstream iss = json.empty() ? std::istringstream() : std::istringstream(json);
  try {
    boost::property_tree::read_json(iss, root);
  } catch (std::exception const& e) {
    throw std::runtime_error("Invalid JSON");
  }
}

// --------------------------- THREAD POLLER ---------------------------

thread_poller::thread_poller(): m_is_polling(false), m_poll_loop_running(false), m_poll_period_ms(20000) {
}

thread_poller::~thread_poller() {
  // safety net only: derived classes must stop polling in their own destructor
  // (before their members are torn down) since by the time this base destructor
  // runs, the derived part of the object is already gone and a concurrently
  // running poll() (a virtual call) would hit a partially-destructed object
  set_is_polling(false);
}

namespace {
  // stack of poller instances whose announce_scope is currently active on the current
  // thread, innermost last. Per-instance so that a callback of poller A calling into 
  // a *different* poller B's wait_for_callbacks_idle() still waits normally.
  thread_local std::vector<const thread_poller*> t_active_dispatch_stack;
}

thread_poller::announce_scope::announce_scope(thread_poller& poller): m_poller(poller) {
  t_active_dispatch_stack.push_back(&poller);
  boost::lock_guard<boost::mutex> lock(m_poller.m_announce_mutex);
  ++m_poller.m_announce_count;
}

thread_poller::announce_scope::~announce_scope() {
  {
    boost::lock_guard<boost::mutex> lock(m_poller.m_announce_mutex);
    if (--m_poller.m_announce_count == 0) m_poller.m_announce_cv.notify_all();
  }
  t_active_dispatch_stack.pop_back();
}

void thread_poller::wait_for_callbacks_idle() {
  // skip the wait only if this poller's own dispatch is active on the current thread;
  // waiting would deadlock in that case. A different poller's active dispatch must not
  // short-circuit this wait.
  for (const thread_poller* active : t_active_dispatch_stack) {
    if (active == this) return;
  }
  boost::unique_lock<boost::mutex> lock(m_announce_mutex);
  m_announce_cv.wait(lock, [&]() { return m_announce_count == 0; });
}

void thread_poller::init_common(const std::string& name) {
  m_name = name;
}

void thread_poller::request_is_polling(bool is_polling) {
  boost::lock_guard<boost::mutex> lifecycle_lock(m_lifecycle_mutex);

  if (is_polling) {
    if (m_is_polling) return;
    m_is_polling = true;
    run_poll_loop();
    return;
  }

  bool was_polling = m_is_polling.exchange(false);
  if (was_polling) {
    boost::lock_guard<boost::mutex> polling_lock(m_polling_mutex);
    m_poll_cv.notify_one();
  }
}

void thread_poller::set_is_polling(bool is_polling) {
  boost::unique_lock<boost::mutex> lifecycle_lock(m_lifecycle_mutex);

  if (is_polling) {
    if (m_is_polling) return;
    m_is_polling = true;
    run_poll_loop();
    return;
  }

  bool was_polling = m_is_polling.exchange(false);
  if (was_polling) {
    boost::lock_guard<boost::mutex> polling_lock(m_polling_mutex);
    m_poll_cv.notify_one();
  }

  if (!m_poll_loop_running) return; // loop already fully exited; nothing to wait for

  if (boost::this_thread::get_id() == m_poll_thread_id) {
    // called from the poll thread itself (e.g. a listener removed itself from within a
    // callback invoked by poll()): waiting for our own loop to exit would deadlock. Just
    // return -- the loop re-checks m_is_polling itself and will exit and clear
    // m_poll_loop_running/m_poll_thread_id on its own (see run_poll_loop).
    return;
  }

  // wait for the loop to actually finish
  m_lifecycle_cv.wait(lifecycle_lock, [&]() { return !m_poll_loop_running; });
}

void thread_poller::run_poll_loop() {
  // called with m_lifecycle_mutex held
  if (m_poll_loop_running) return; // only run one loop at a time
  m_poll_loop_running = true;

  // TODO: use global threadpool, background sync wasm wallet in c++ thread
  try {
    boost::thread([this]() {
      {
        boost::lock_guard<boost::mutex> lifecycle_lock(m_lifecycle_mutex);
        m_poll_thread_id = boost::this_thread::get_id();
      }

      while (true) {
        while (m_is_polling) {
          try { poll(); }
          catch (const std::exception& e) { MERROR(m_name << " failed to background poll: " << e.what()); }
          catch (...) { MERROR(m_name << " failed to background poll"); }

          // only wait if polling still enabled
          if (m_is_polling) {
            boost::mutex::scoped_lock lock(m_polling_mutex);
            boost::posix_time::milliseconds wait_for_ms(m_poll_period_ms.load());
            m_poll_cv.timed_wait(lock, wait_for_ms, [&]() { return !m_is_polling; });
          }
        }

        boost::unique_lock<boost::mutex> lifecycle_lock(m_lifecycle_mutex);
        if (m_is_polling) continue;
        m_poll_loop_running = false;
        m_poll_thread_id = boost::thread::id();
        m_lifecycle_cv.notify_all();
        return;
      }
    }).detach();
  } catch (...) {
    m_poll_loop_running = false;
    m_is_polling = false;
    throw;
  }
}
