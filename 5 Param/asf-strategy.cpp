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

#include "asf-strategy.hpp"
#include "algorithm.hpp"
#include "common/global.hpp"
#include "common/logger.hpp"
#include <chrono>
#include <vector>

struct Error {
        long unsigned int key;
        long unsigned int value;
};

struct Send {
        long unsigned int key;
        long unsigned int value;
};

struct Load {
        long unsigned int key;
        long unsigned int value;
};

struct Popularity {
        std::string key;
        long unsigned int value;
};

std::vector<Error> errorVector;
std::vector<Send> sendVector;
std::vector<Load> loadVector;
std::vector<Popularity> popularityVector;

using namespace std::chrono;

namespace nfd::fw::asf {

NFD_LOG_INIT(AsfStrategy);
NFD_REGISTER_STRATEGY(AsfStrategy);

AsfStrategy::AsfStrategy(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder)
  , m_measurements(getMeasurements())
  , m_probing(m_measurements)
{
  ParsedInstanceName parsed = parseInstanceName(name);
  if (parsed.version && *parsed.version != getStrategyName()[-1].toVersion()) {
    NDN_THROW(std::invalid_argument(
      "AsfStrategy does not support version " + to_string(*parsed.version)));
  }

  StrategyParameters params = parseParameters(parsed.parameters);
  m_retxSuppression = RetxSuppressionExponential::construct(params);
  auto probingInterval = params.getOrDefault<time::milliseconds::rep>("probing-interval",
                                                                      m_probing.getProbingInterval().count());
  m_probing.setProbingInterval(time::milliseconds(probingInterval));
  m_nMaxTimeouts = params.getOrDefault<size_t>("max-timeouts", m_nMaxTimeouts);

  this->setInstanceName(makeInstanceName(name, getStrategyName()));

  NDN_LOG_DEBUG(*m_retxSuppression);
  NFD_LOG_DEBUG("probing-interval=" << m_probing.getProbingInterval()
                << " max-timeouts=" << m_nMaxTimeouts);
  
}


float
trapezoid(float t, float dLeft, float dLeftMiddle, float dRightMiddle, float dRight){
  if(t<=dLeft)
    return 0.0;
  else if(t<dLeftMiddle)
    return (t-dLeft)/(dLeftMiddle-dLeft);
  else if(t<=dRightMiddle)
    return 1.0;
  else if(t<dRight)
    return (dRight-t)/(dRight-dRightMiddle);
  else
    return 0.0;
};

float 
trapezoidtoinfi(float t, float dLeft, float dLeftMiddle){
  if(t<=dLeft)
    return 0.0;
  else if(t<dLeftMiddle)
    return (t-dLeft)/(dLeftMiddle-dLeft);
  else
    return 1.0;
};

float
trapezoidtomininfi(float t, float dRightMiddle, float dRight){
  if(t<=dRightMiddle)
    return 1;
  else if(t<dRight)
    return (dRight-t)/(dRight-dRightMiddle);
  else
    return 0;
};      

const Name&
AsfStrategy::getStrategyName()
{
  static const auto strategyName = Name("/localhost/nfd/strategy/asf").appendVersion(4);
  return strategyName;
}

void
AsfStrategy::afterReceiveInterest(const Interest& interest, const FaceEndpoint& ingress,
                                  const shared_ptr<pit::Entry>& pitEntry)
{
  const auto& fibEntry = this->lookupFib(*pitEntry);

  bool edited = false;
      for (size_t i = 0; i < popularityVector.size(); i++){
        if (popularityVector[i].key == interest.getName()){
                popularityVector[i].value = popularityVector[i].value+1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Popularity newPopularity;
        newPopularity.key = interest.getName();
        newPopularity.value = 1;
        popularityVector.push_back(newPopularity);
      }

      uint64_t popularity = 0.0;

      for (size_t i = 0; i < popularityVector.size(); i++){
        if (popularityVector[i].key == interest.getName()){
//                sendVector[i].value = sendVector[i].value+1;
                popularity = popularityVector[i].value * 1.0;
                break;
        }
      }
      
      NFD_LOG_DEBUG("Ade-Debug " << interest.getName() << " popularity=" << popularity);

  // Check if the interest is new and, if so, skip the retx suppression check
  if (!hasPendingOutRecords(*pitEntry)) {
    auto* faceToUse = getBestFaceForForwarding(interest, ingress.face, fibEntry, pitEntry);
    if (faceToUse == nullptr) {
      NFD_LOG_DEBUG(interest << " new-interest from=" << ingress << " no-nexthop");
      sendNoRouteNack(ingress.face, pitEntry);
    }
    else {
      NFD_LOG_DEBUG(interest << " new-interest from=" << ingress << " forward-to=" << faceToUse->getId());
      forwardInterest(interest, *faceToUse, fibEntry, pitEntry);
      sendProbe(interest, ingress, *faceToUse, fibEntry, pitEntry);
    }
    return;
  }

  auto* faceToUse = getBestFaceForForwarding(interest, ingress.face, fibEntry, pitEntry, false);
  if (faceToUse != nullptr) {
    auto suppressResult = m_retxSuppression->decidePerUpstream(*pitEntry, *faceToUse);
    if (suppressResult == RetxSuppressionResult::SUPPRESS) {
      // Cannot be sent on this face, interest was received within the suppression window
      NFD_LOG_DEBUG(interest << " retx-interest from=" << ingress
                    << " forward-to=" << faceToUse->getId() << " suppressed");
    }
    else {
      // The retx arrived after the suppression period: forward it but don't probe, because
      // probing was done earlier for this interest when it was newly received
      NFD_LOG_DEBUG(interest << " retx-interest from=" << ingress << " forward-to=" << faceToUse->getId());
      auto* outRecord = forwardInterest(interest, *faceToUse, fibEntry, pitEntry);
      if (outRecord && suppressResult == RetxSuppressionResult::FORWARD) {
        m_retxSuppression->incrementIntervalForOutRecord(*outRecord);
      }
    }
  }

  // If all eligible faces have been used (i.e., they all have a pending out-record),
  // choose the nexthop with the earliest out-record
  const auto& nexthops = fibEntry.getNextHops();
  auto it = findEligibleNextHopWithEarliestOutRecord(ingress.face, interest, nexthops, pitEntry);
  if (it == nexthops.end()) {
    NFD_LOG_DEBUG(interest << " retx-interest from=" << ingress << " no eligible nexthop");
    return;
  }
  auto& outFace = it->getFace();
  auto suppressResult = m_retxSuppression->decidePerUpstream(*pitEntry, outFace);
  if (suppressResult == RetxSuppressionResult::SUPPRESS) {
    NFD_LOG_DEBUG(interest << " retx-interest from=" << ingress
                  << " retry-to=" << outFace.getId() << " suppressed");
  }
  else {
    NFD_LOG_DEBUG(interest << " retx-interest from=" << ingress << " retry-to=" << outFace.getId());
    // sendInterest() is used here instead of forwardInterest() because the measurements info
    // were already attached to this face in the previous forwarding
    auto* outRecord = sendInterest(interest, outFace, pitEntry);
    bool edited = false;
      for (size_t i = 0; i < sendVector.size(); i++){
        if (sendVector[i].key == outFace.getId()){
                sendVector[i].value = sendVector[i].value+1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Send newSend;
        newSend.key = outFace.getId();
        newSend.value = 1;
        sendVector.push_back(newSend);
      }

    bool edited = false;
      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == outFace.getId()){
                loadVector[i].value = loadVector[i].value+1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Load newLoad;
        newLoad.key = outFace.getId();
        newLoad.value = 1;
        loadVector.push_back(newLoad);
      }

      uint64_t load = 0.0;

      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == outFace.getId()){
//                sendVector[i].value = sendVector[i].value+1;
                load = loadVector[i].value * 1.0;
                break;
        }
      }
      
      NFD_LOG_DEBUG("Ade-Debug " << outFace.getId() << " load=" << load);
    
    if (outRecord && suppressResult == RetxSuppressionResult::FORWARD) {
      m_retxSuppression->incrementIntervalForOutRecord(*outRecord);
    }
  }
}

void
AsfStrategy::beforeSatisfyInterest(const Data& data, const FaceEndpoint& ingress,
                                   const shared_ptr<pit::Entry>& pitEntry)
{

  // Check if data has Content (value_size will always check hasContent)
  size_t data_len = data.getContent().value_size();
  float data_len_final = static_cast<float>(data_len);
  NFD_LOG_DEBUG(pitEntry->getName() << " data from=" << ingress << " packet_size = " << std::to_string(data_len_final));
  
  NamespaceInfo* namespaceInfo = m_measurements.getNamespaceInfo(pitEntry->getName());
  if (namespaceInfo == nullptr) {
    NFD_LOG_DEBUG(pitEntry->getName() << " data from=" << ingress << " no-measurements");
    return;
  }

  // Record the RTT between the Interest out to Data in
  FaceInfo* faceInfo = namespaceInfo->getFaceInfo(ingress.face.getId());
  if (faceInfo == nullptr) {
    NFD_LOG_DEBUG(pitEntry->getName() << " data from=" << ingress << " no-face-info");
    return;
  }

  auto outRecord = pitEntry->getOutRecord(ingress.face);
  if (outRecord == pitEntry->out_end()) {
    NFD_LOG_DEBUG(pitEntry->getName() << " data from=" << ingress << " no-out-record");
  }
  else {
  auto start = high_resolution_clock::now();
    faceInfo->recordRtt( time::steady_clock::now() - outRecord->getLastRenewed() );
    float real_rtt = ( faceInfo->getSrtt() ).count();
    
    NFD_LOG_DEBUG(pitEntry->getName() << " Ade-Debug data from=" << ingress
                  << " rtt=" << std::to_string(real_rtt));
    
    float Thg = (((data_len_final / (real_rtt / 1000000000.0)) * 8) / 1000);
    
    NFD_LOG_DEBUG(pitEntry->getName() << " Ade-Debug data from=" << ingress
                  << " Thg=" << std::to_string(Thg));
    faceInfo->recordThg( Thg );
    
    NFD_LOG_DEBUG(pitEntry->getName() << " data from=" << ingress
                  << " rtt=" << faceInfo->getLastRtt() << " srtt=" << faceInfo->getSrtt());
                  
    long int rtt = real_rtt / 1000000;
    
    faceInfo->recordProbe(faceInfo->getProbe()+1);
    
    //uint64_t probe = faceInfo->getProbe();
    //uint64_t err = faceInfo->getErr();
    
    uint64_t probe = 0.0;
    uint64_t load = 0.0;
    uint64_t err = 0.0;

    bool edited = false;
      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == ingress.face.getId()){
                loadVector[i].value = loadVector[i].value-1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Send newSend;
        newSend.key = ingress.face.getId();
        newSend.value = 1;
        loadVector.push_back(newSend);
      }
    
      for (size_t i = 0; i < sendVector.size(); i++){
        if (sendVector[i].key == ingress.face.getId()){
//                sendVector[i].value = sendVector[i].value+1;
                probe = sendVector[i].value * 1.0;
                break;
        }
      }
      
      for (size_t i = 0; i < errorVector.size(); i++){
        if (errorVector[i].key == ingress.face.getId()){
//                sendVector[i].value = sendVector[i].value+1;
                err = errorVector[i].value * 1.0;
                break;
        }
      }

      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == ingress.face.getId()){
//                sendVector[i].value = sendVector[i].value+1;
                load = loadVector[i].value * 1.0;
                break;
        }
      }
     
      
      NFD_LOG_DEBUG("Ade-Debug " << ingress << " err=" << err << " send=" << probe << " load=" << load);
      
    float nilai_face = (trapezoidtoinfi(Thg,2100.0,2200.0) * 4.0 + trapezoid(Thg,1100.0,1200.0,2100.0,2200.0) * 3.0 + trapezoid(Thg,700.0,800.0,1100.0,1200.0) * 2.0 + trapezoidtomininfi(Thg,700.0,800.0) * 1.0) * 0.1 + (trapezoidtomininfi(rtt,300.0,400.0) * 4.0 + trapezoid(rtt,300.0,400.0,500.0,600.0) * 3.0 + trapezoid(rtt,500.0,600.0,800.0,900.0) * 2.0 + trapezoidtoinfi(rtt,800.0,900.0) * 1.0) * 0.2 + (trapezoidtomininfi((err/probe)*100.0,5.0,6.0) * 4.0 + trapezoid((err/probe)*100.0,5.0,6.0,14.0,15.0) * 3.0 + trapezoid((err/probe)*100.0,14.0,15.0,24.0,25.0) * 2.0 + trapezoidtoinfi((err/probe)*100.0,24.0,25.0) * 1.0) * 0.7;
    
    faceInfo->recordNF(nilai_face * -1.0);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<nanoseconds>(stop - start);
      
      NFD_LOG_DEBUG("Ade-Debug state face=" << ingress << " nilai_face=" << std::to_string(nilai_face) << " calc_time=" << duration.count() << " nanoseconds");
  }

  // Extend lifetime for measurements associated with Face
  namespaceInfo->extendFaceInfoLifetime(*faceInfo, ingress.face.getId());
  // Extend PIT entry timer to allow slower probes to arrive
  this->setExpiryTimer(pitEntry, 50_ms);
  faceInfo->cancelTimeout(data.getName());
}

void
AsfStrategy::afterReceiveNack(const lp::Nack& nack, const FaceEndpoint& ingress,
                              const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG(nack.getInterest() << " nack from=" << ingress << " reason=" << nack.getReason());
  onTimeoutOrNack(pitEntry->getName(), ingress.face.getId(), true);
}

pit::OutRecord*
AsfStrategy::forwardInterest(const Interest& interest, Face& outFace, const fib::Entry& fibEntry,
                             const shared_ptr<pit::Entry>& pitEntry)
{
  const auto& interestName = interest.getName();
  auto faceId = outFace.getId();

  auto* outRecord = sendInterest(interest, outFace, pitEntry);

  FaceInfo& faceInfo = m_measurements.getOrCreateFaceInfo(fibEntry, interestName, faceId);

  bool edited = false;
      for (size_t i = 0; i < sendVector.size(); i++){
        if (sendVector[i].key == outFace.getId()){
                sendVector[i].value = sendVector[i].value+1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Send newSend;
        newSend.key = outFace.getId();
        newSend.value = 1;
        sendVector.push_back(newSend);
      }

      bool edited = false;
      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == outFace.getId()){
                loadVector[i].value = loadVector[i].value+1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Load newLoad;
        newLoad.key = outFace.getId();
        newLoad.value = 1;
        loadVector.push_back(newLoad);
      }

      uint64_t load = 0.0;

      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == outFace.getId()){
//                sendVector[i].value = sendVector[i].value+1;
                load = loadVector[i].value * 1.0;
                break;
        }
      }
     
      
      NFD_LOG_DEBUG("Ade-Debug " << outFace.getId() << " load=" << load);

  // Refresh measurements since Face is being used for forwarding
  NamespaceInfo& namespaceInfo = m_measurements.getOrCreateNamespaceInfo(fibEntry, interestName);
  namespaceInfo.extendFaceInfoLifetime(faceInfo, faceId);

  if (!faceInfo.isTimeoutScheduled()) {
    auto timeout = faceInfo.scheduleTimeout(interestName,
                                            [this, name = interestName, faceId] {
                                              onTimeoutOrNack(name, faceId, false);
                                            });
    NFD_LOG_TRACE("Scheduled timeout for " << fibEntry.getPrefix() << " to=" << faceId
                  << " in " << time::duration_cast<time::milliseconds>(timeout));
  }

  return outRecord;
}

void
AsfStrategy::sendProbe(const Interest& interest, const FaceEndpoint& ingress, const Face& faceToUse,
                       const fib::Entry& fibEntry, const shared_ptr<pit::Entry>& pitEntry)
{
  if (!m_probing.isProbingNeeded(fibEntry, interest.getName()))
    return;

  Face* faceToProbe = m_probing.getFaceToProbe(ingress.face, interest, fibEntry, faceToUse);
  if (faceToProbe == nullptr)
    return;  

  Interest probeInterest(interest);
  probeInterest.refreshNonce();
  
  NFD_LOG_TRACE("Sending probe " << probeInterest << " to=" << faceToProbe->getId());
  forwardInterest(probeInterest, *faceToProbe, fibEntry, pitEntry);

  m_probing.afterForwardingProbe(fibEntry, interest.getName());
}

struct FaceStats
{
  Face* face;
  float nf;
  time::nanoseconds rtt;
  time::nanoseconds srtt;
  uint64_t cost;
};

struct FaceStatsCompare
{
  bool
  operator()(const FaceStats& lhs, const FaceStats& rhs) const
  {
    //time::nanoseconds lhsValue = getValueForSorting(lhs);
    //time::nanoseconds rhsValue = getValueForSorting(rhs);
    
    float lhsValue = getValueForSorting(lhs);
    float rhsValue = getValueForSorting(rhs);

    // Sort by RTT and then by cost
    return std::tie(lhsValue, lhs.cost) < std::tie(rhsValue, rhs.cost);
  }

private:
  //static time::nanoseconds
  static float
  getValueForSorting(const FaceStats& stats)
  {
    // These values allow faces with no measurements to be ranked better than timeouts
    // srtt < RTT_NO_MEASUREMENT < RTT_TIMEOUT
    //if (stats.rtt == FaceInfo::RTT_TIMEOUT) {
    //  return time::nanoseconds::max();
    //}
    //else if (stats.rtt == FaceInfo::RTT_NO_MEASUREMENT) {
    //  return time::nanoseconds::max() / 2;
    //}
    //else {
    //  return stats.rtt;
    //}
    
    if (stats.rtt == FaceInfo::RTT_TIMEOUT) {
      return 1.0;
    }
    else if (stats.rtt == FaceInfo::RTT_NO_MEASUREMENT) {
      return 0.0;
    }
    else {
      return stats.nf;
    }
  }
};

Face*
AsfStrategy::getBestFaceForForwarding(const Interest& interest, const Face& inFace,
                                      const fib::Entry& fibEntry, const shared_ptr<pit::Entry>& pitEntry,
                                      bool isInterestNew)
{
  std::set<FaceStats, FaceStatsCompare> rankedFaces;

  auto now = time::steady_clock::now();
  for (const auto& nh : fibEntry.getNextHops()) {
    if (!isNextHopEligible(inFace, interest, nh, pitEntry, !isInterestNew, now)) {
      continue;
    }

    const FaceInfo* info = m_measurements.getFaceInfo(fibEntry, interest.getName(), nh.getFace().getId());
    if (info == nullptr) {
      rankedFaces.insert({&nh.getFace(), 0, FaceInfo::RTT_NO_MEASUREMENT, FaceInfo::RTT_NO_MEASUREMENT, nh.getCost()});
    }
    else {
      rankedFaces.insert({&nh.getFace(), info->getLastNF(), info->getLastRtt(), info->getSrtt(), nh.getCost()});
    }
  }

  auto it = rankedFaces.begin();
  return it != rankedFaces.end() ? it->face : nullptr;
}

void
AsfStrategy::onTimeoutOrNack(const Name& interestName, FaceId faceId, bool isNack)
{
  NamespaceInfo* namespaceInfo = m_measurements.getNamespaceInfo(interestName);
  if (namespaceInfo == nullptr) {
    NFD_LOG_TRACE(interestName << " FibEntry has been removed since timeout scheduling");
    return;
  }

  FaceInfo* fiPtr = namespaceInfo->getFaceInfo(faceId);
  if (fiPtr == nullptr) {
    NFD_LOG_TRACE(interestName << " FaceInfo id=" << faceId << " has been removed since timeout scheduling");
    return;
  }

  auto& faceInfo = *fiPtr;
  size_t nTimeouts = faceInfo.getNTimeouts() + 1;
  faceInfo.setNTimeouts(nTimeouts);

  bool edited = false;
      for (size_t i = 0; i < errorVector.size(); i++){
        if (errorVector[i].key == faceId){
                errorVector[i].value = errorVector[i].value+1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Error newError;
        newError.key = faceId;
        newError.value = 1;
        errorVector.push_back(newError);
      }

  bool edited = false;
      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == faceId){
                loadVector[i].value = loadVector[i].value-1;
                edited = true;
                break;
        }
      }
      if (!edited){
        Send newSend;
        newSend.key = faceId;
        newSend.value = 1;
        loadVector.push_back(newSend);
      }

      uint64_t load = 0.0;

      for (size_t i = 0; i < loadVector.size(); i++){
        if (loadVector[i].key == faceId){
//                sendVector[i].value = sendVector[i].value+1;
                load = loadVector[i].value * 1.0;
                break;
        }
      }

      NFD_LOG_DEBUG("Ade-Debug " << faceId << " load=" << load);
  
  faceInfo.recordErr(faceInfo.getErr()+1);
  NFD_LOG_DEBUG(interestName << " Ade-Debug data from=" << faceId
                  << " error=" << std::to_string(faceInfo.getErr()));

  if (nTimeouts < m_nMaxTimeouts && !isNack) {
    NFD_LOG_TRACE(interestName << " face=" << faceId << " timeout-count=" << nTimeouts << " ignoring");
    // Extend lifetime for measurements associated with Face
    namespaceInfo->extendFaceInfoLifetime(faceInfo, faceId);
    faceInfo.cancelTimeout(interestName);
  }
  else {
    NFD_LOG_TRACE(interestName << " face=" << faceId << " timeout-count=" << nTimeouts);
    faceInfo.recordTimeout(interestName);
  }
}

void
AsfStrategy::sendNoRouteNack(Face& face, const shared_ptr<pit::Entry>& pitEntry)
{
  lp::NackHeader nackHeader;
  nackHeader.setReason(lp::NackReason::NO_ROUTE);
  this->sendNack(nackHeader, face, pitEntry);
  this->rejectPendingInterest(pitEntry);
}

} // namespace nfd::fw::asf
