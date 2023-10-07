/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2022,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NFD_DAEMON_FW_ASF_MEASUREMENTS_HPP
#define NFD_DAEMON_FW_ASF_MEASUREMENTS_HPP

#include "fw/strategy-info.hpp"
#include "table/measurements-accessor.hpp"

#include <ndn-cxx/util/rtt-estimator.hpp>

#include <unordered_map>

namespace nfd::fw::asf {

/** \brief Strategy information for each face in a namespace
*/
class FaceInfo
{
public:
  explicit
  FaceInfo(shared_ptr<const ndn::util::RttEstimator::Options> opts)
    : m_rttEstimator(std::move(opts))
  {
  }

  bool
  isTimeoutScheduled() const
  {
    return !!m_timeoutEvent;
  }

  time::nanoseconds
  scheduleTimeout(const Name& interestName, scheduler::EventCallback cb);

  void
  cancelTimeout(const Name& prefix);
  
  void
  recordThg(float thg)
  {
    m_lastThg = thg;
  }
  
  void
  recordNF(float nilai_face)
  {
    m_lastNF = nilai_face;
  }
  
  void
  recordErr(uint64_t err)
  {
    m_Err = err;
  }
  
  void
  recordProbe(uint64_t probe)
  {
    m_Probe = probe;
  }

  void
  recordRtt(time::nanoseconds rtt)
  {
    m_lastRtt = rtt;
    m_rttEstimator.addMeasurement(rtt);
  }

  void
  recordTimeout(const Name& interestName)
  {
    m_lastRtt = RTT_TIMEOUT;
    cancelTimeout(interestName);
  }

  bool
  hasTimeout() const
  {
    return getLastRtt() == RTT_TIMEOUT;
  }
  
  float 
  getLastThg() const
  {
    return m_lastThg;
  }
  
  float 
  getLastNF() const
  {
    return m_lastNF;
  }

  time::nanoseconds
  getLastRtt() const
  {
    return m_lastRtt;
  }
  
  uint64_t 
  getErr() const
  {
    return m_Err;
  }
  
  uint64_t 
  getProbe() const
  {
    return m_Probe;
  }

  time::nanoseconds
  getSrtt() const
  {
    return m_rttEstimator.getSmoothedRtt();
  }

  size_t
  getNTimeouts() const
  {
    return m_nTimeouts;
  }

  void
  setNTimeouts(size_t nTimeouts)
  {
    m_nTimeouts = nTimeouts;
  }

public:
  static constexpr time::nanoseconds RTT_NO_MEASUREMENT = -1_ns;
  static constexpr time::nanoseconds RTT_TIMEOUT = -2_ns;

private:
  ndn::util::RttEstimator m_rttEstimator;
  time::nanoseconds m_lastRtt = RTT_NO_MEASUREMENT;
  float m_lastThg = 0;
  float m_lastNF = 0;
  uint64_t m_Err = 0;
  uint64_t m_Probe = 1;
  Name m_lastInterestName;
  size_t m_nTimeouts = 0;

  // Timeout associated with measurement
  scheduler::ScopedEventId m_measurementExpiration;
  friend class NamespaceInfo;

  // RTO associated with Interest
  scheduler::ScopedEventId m_timeoutEvent;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/** \brief Stores strategy information about each face in this namespace
 */
class NamespaceInfo final : public StrategyInfo
{
public:
  static constexpr int
  getTypeId()
  {
    return 1030;
  }

  explicit
  NamespaceInfo(shared_ptr<const ndn::util::RttEstimator::Options> opts)
    : m_rttEstimatorOpts(std::move(opts))
  {
  }

  FaceInfo*
  getFaceInfo(FaceId faceId);

  FaceInfo&
  getOrCreateFaceInfo(FaceId faceId);

  void
  extendFaceInfoLifetime(FaceInfo& info, FaceId faceId);

  bool
  isProbingDue() const
  {
    return m_isProbingDue;
  }

  void
  setIsProbingDue(bool isProbingDue)
  {
    m_isProbingDue = isProbingDue;
  }

  bool
  isFirstProbeScheduled() const
  {
    return m_isFirstProbeScheduled;
  }

  void
  setIsFirstProbeScheduled(bool isScheduled)
  {
    m_isFirstProbeScheduled = isScheduled;
  }

private:
  std::unordered_map<FaceId, FaceInfo> m_fiMap;
  shared_ptr<const ndn::util::RttEstimator::Options> m_rttEstimatorOpts;
  bool m_isProbingDue = false;
  bool m_isFirstProbeScheduled = false;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/** \brief Helper class to retrieve and create strategy measurements
 */
class AsfMeasurements : noncopyable
{
public:
  explicit
  AsfMeasurements(MeasurementsAccessor& measurements);

  FaceInfo*
  getFaceInfo(const fib::Entry& fibEntry, const Name& interestName, FaceId faceId);

  FaceInfo&
  getOrCreateFaceInfo(const fib::Entry& fibEntry, const Name& interestName, FaceId faceId);

  NamespaceInfo*
  getNamespaceInfo(const Name& prefix);

  NamespaceInfo&
  getOrCreateNamespaceInfo(const fib::Entry& fibEntry, const Name& prefix);

private:
  void
  extendLifetime(measurements::Entry& me);

public:
  static constexpr time::microseconds MEASUREMENTS_LIFETIME = 5_min;

private:
  MeasurementsAccessor& m_measurements;
  shared_ptr<const ndn::util::RttEstimator::Options> m_rttEstimatorOpts;
};

} // namespace nfd::fw::asf

#endif // NFD_DAEMON_FW_ASF_MEASUREMENTS_HPP
