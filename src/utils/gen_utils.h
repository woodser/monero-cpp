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

#ifndef gen_utils_h
#define gen_utils_h

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "rapidjson/document.h"
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <chrono>
#include <thread>
#include <atomic>
#include "include_base_utils.h"
#include "common/util.h"
#include "crypto/crypto.h"

/**
 * Collection of generic utilities.
 */
namespace gen_utils
{

  /**
   * Return a unique identifier.
   *
   * @return a unique id
   */
  static std::string get_uuid() {
    boost::uuids::random_generator generator;
    boost::uuids::uuid uuid = generator();
    return boost::uuids::to_string(uuid);
  }

  static bool is_uint64_t(const std::string& str) {
    try {
      size_t sz;
      std::stol(str, &sz);
      return sz == str.size();
    }
    catch (const std::invalid_argument&) {
      // if no conversion could be performed.
      return false;   
    }
    catch (const std::out_of_range&) {
      //  if the converted value would fall out of the range of the result type.
      return false;
    }
  }

  static uint64_t uint64_t_cast(const std::string& str) {
    if (!is_uint64_t(str)) throw std::out_of_range("String provided is not a valid uint64_t");
    uint64_t value;
    std::istringstream itr(str);
    itr >> value;
    return value;
  }

  static uint64_t timestamp_to_epoch(const std::string& iso_timestamp) {
    // ISO 8601
    std::string timestamp = boost::replace_all_copy(iso_timestamp, "T", " ");
    boost::replace_all(timestamp, "Z", "");

    boost::posix_time::ptime pt = boost::posix_time::time_from_string(timestamp);
    boost::posix_time::ptime epoch(boost::gregorian::date(1970, 1, 1));
    boost::posix_time::time_duration diff = pt - epoch;

    return static_cast<uint64_t>(diff.total_seconds());
  }

  /**
   * Wait for the given duration.
   *
   * @param duration_ms the duration to wait in milliseconds
   */
  static void wait_for(uint64_t duration_ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(duration_ms));
  }

  static bool bool_equals(bool val, const boost::optional<bool>& opt_val) {
    return opt_val == boost::none ? false : val == *opt_val;
  }

  // ------------------------- SERIALIZATION ---------------------------

  // TODO: fully switch from property trees to rapidjson

  std::string serialize(const rapidjson::Document& doc);
  std::string serialize(const boost::property_tree::ptree& node);
  void deserialize(const std::string& json, boost::property_tree::ptree& root);

  // ------------------------- VALUE RECONCILATION ----------------------------

  // TODO: refactor common template code
  template <class T, typename std::enable_if<std::is_same<T, std::string>::value, T>::type* = nullptr>
  boost::optional<T> reconcile(const boost::optional<T>& val1, const boost::optional<T>& val2, boost::optional<bool> resolve_defined, boost::optional<bool> resolve_true, boost::optional<bool> resolve_max, const std::string& err_msg = "") {

    // check for equality
    if (val1 == val2) return val1;

    // resolve one value none
    if (val1 == boost::none || val2 == boost::none) {
      if (resolve_defined != boost::none && *resolve_defined == false) return boost::none;
      else return val1 == boost::none ? val2 : val1;
    }

    throw std::runtime_error(std::string("Cannot reconcile strings: ") + boost::lexical_cast<std::string>(val1) + std::string(" vs ") + boost::lexical_cast<std::string>(val2) + (!err_msg.empty() ? std::string(". ") + err_msg : std::string("")));
  }
  template <class T, typename std::enable_if<std::is_same<T, std::string>::value, T>::type* = nullptr>
  boost::optional<T> reconcile(const boost::optional<T>& val1, const boost::optional<T>& val2, const std::string& err_msg = "") {
    return reconcile(val1, val2, boost::none, boost::none, boost::none, err_msg);
  }

  template <class T, typename std::enable_if<std::is_integral<T>::value, T>::type* = nullptr>
  boost::optional<T> reconcile(const boost::optional<T>& val1, const boost::optional<T>& val2, boost::optional<bool> resolve_defined, boost::optional<bool> resolve_true, boost::optional<bool> resolve_max, const std::string& err_msg = "") {

    // check for equality
    if (val1 == val2) return val1;

    // resolve one value none
    if (val1 == boost::none || val2 == boost::none) {
      if (resolve_defined != boost::none && *resolve_defined == false) return boost::none;
      else return val1 == boost::none ? val2 : val1;
    }

    // resolve different booleans
    if (resolve_true != boost::none) return (bool) val1 == *resolve_true ? val1 : val2; // if resolve true, return true, else return false

    // resolve different numbers
    if (resolve_max != boost::none) return *resolve_max ? std::max(*val1, *val2) : std::min(*val1, *val2);

    // cannot reconcile
    throw std::runtime_error(std::string("Cannot reconcile integrals: ") + boost::lexical_cast<std::string>(val1) + std::string(" vs ") + boost::lexical_cast<std::string>(val2) + (!err_msg.empty() ? std::string(". ") + err_msg : std::string("")));
  }
  template <class T, typename std::enable_if<std::is_integral<T>::value, T>::type* = nullptr>
  boost::optional<T> reconcile(const boost::optional<T>& val1, const boost::optional<T>& val2, const std::string& err_msg = "") {
    return reconcile(val1, val2, boost::none, boost::none, boost::none, err_msg);
  }

  template <class T>
  std::vector<T> reconcile(const std::vector<T>& v1, const std::vector<T>& v2, const std::string& err_msg = "") {

    // check for equality
    if (v1 == v2) return v1;

    // resolve one vector empty
    if (v1.empty()) return v2;
    if (v2.empty()) return v1;

    // otherwise cannot reconcile
    throw std::runtime_error("Cannot reconcile vectors" + (!err_msg.empty() ? std::string(". ") + err_msg : std::string("")));
  }

  template<typename T>
  T pop_index(std::vector<T>& vec, size_t idx) {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

    T res = std::move(vec[idx]);
    if (idx + 1 != vec.size()) vec[idx] = std::move(vec.back());
    vec.resize(vec.size() - 1);

    return res;
  }

  template<typename T>
  T pop_random_value(std::vector<T>& vec) {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    size_t idx = crypto::rand<size_t>() % vec.size();
    return pop_index(vec, idx);
  }

  // ------------------------- THREAD POLLER ----------------------------

  // WARNING: Only destroy a thread_poller from a thread other than its own pool thread.
  // (e.g. a listener callback running on the poll thread, drops the last owning reference/unique_ptr
  // to the poller.)
  class thread_poller {
  public:
    thread_poller();
    virtual ~thread_poller();

    bool is_polling() const { return m_is_polling; }
    void set_is_polling(bool is_polling);
    void request_is_polling(bool is_polling);

    void set_period_in_ms(uint64_t period_ms) { m_poll_period_ms = period_ms; }
    virtual void poll() = 0;
    void wait_for_callbacks_idle();

    class announce_scope {
    public:
      explicit announce_scope(thread_poller& poller);
      ~announce_scope();
      announce_scope(const announce_scope&) = delete;
      announce_scope& operator=(const announce_scope&) = delete;
    private:
      thread_poller& m_poller;
    };

  protected:
    std::string m_name;
    boost::recursive_mutex m_mutex;
    boost::mutex m_polling_mutex;              // guards the interruptible periodic sleep (m_poll_cv)
    boost::mutex m_lifecycle_mutex;            // guards m_poll_loop_running/m_poll_thread_id and start/stop coordination
    boost::thread::id m_poll_thread_id;        // id of the currently running loop thread; guarded by m_lifecycle_mutex
    std::atomic<bool> m_is_polling;
    bool m_poll_loop_running;                  // guarded by m_lifecycle_mutex
    std::atomic<uint64_t> m_poll_period_ms;
    boost::condition_variable m_poll_cv;       // periodic-sleep interrupt
    boost::condition_variable m_lifecycle_cv;  // notified (under m_lifecycle_mutex) when the loop actually exits
    boost::mutex m_announce_mutex;             // guards m_announce_count
    boost::condition_variable m_announce_cv;   // notified (under m_announce_mutex) when m_announce_count reaches 0
    int m_announce_count = 0;                  // number of announce_scope instances currently alive, across all threads

    void init_common(const std::string& name);
    void run_poll_loop();
  };
}
#endif /* gen_utils_h */
