/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/program_options.hpp>
#include <arpa/inet.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <mutex>
#include <thread>
#include <dirent.h>
#include "ixfr.hh"
#include "ixfrutils.hh"
#include "resolver.hh"
#include "dns_random.hh"
#include "sstuff.hh"
#include "mplexer.hh"
#include "misc.hh"
#include "iputils.hh"

/* BEGIN Needed because of deeper dependencies */
#include "arguments.hh"
#include "statbag.hh"
StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
/* END Needed because of deeper dependencies */


// For all the listen-sockets
FDMultiplexer* g_fdm;

// The domains we support
set<DNSName> g_domains;

// Map domains and their data
std::map<DNSName, ixfrinfo_t> g_soas;
std::mutex g_soas_mutex;

using namespace boost::multi_index;

namespace po = boost::program_options;
po::variables_map g_vm;
string g_workdir;
ComboAddress g_master;

bool g_verbose = false;
bool g_debug = false;

bool g_exiting = false;

#define KEEP_DEFAULT 20
uint16_t g_keep = KEEP_DEFAULT;

#define AXFRTIMEOUT_DEFAULT 20
uint16_t g_axfrTimeout = AXFRTIMEOUT_DEFAULT;

NetmaskGroup g_acl;

void handleSignal(int signum) {
  if (g_verbose) {
    cerr<<"[INFO] Got "<<strsignal(signum)<<" signal";
  }
  if (g_exiting) {
    if (g_verbose) {
      cerr<<", this is the second time we were asked to stop, forcefully exiting"<<endl;
    }
    exit(EXIT_FAILURE);
  }
  if (g_verbose) {
    cerr<<", stopping"<<endl;
  }
  g_exiting = true;
}

void usage(po::options_description &desc) {
  cerr << "Usage: ixfrdist [OPTION]... DOMAIN [DOMAIN]..."<<endl;
  cerr << desc << "\n";
}

// The compiler does not like using rfc1982LessThan in std::sort directly
bool sortSOA(uint32_t i, uint32_t j) {
  return rfc1982LessThan(i, j);
}

void cleanUpDomain(const DNSName& domain) {
  string dir = g_workdir + "/" + domain.toString();
  DIR *dp;
  dp = opendir(dir.c_str());
  if (dp == nullptr) {
    return;
  }
  vector<uint32_t> zoneVersions;
  struct dirent *d;
  while ((d = readdir(dp)) != nullptr) {
    if(!strcmp(d->d_name, ".") || !strcmp(d->d_name, "..")) {
      continue;
    }
    zoneVersions.push_back(std::stoi(d->d_name));
  }
  closedir(dp);
  if (g_verbose) {
    cerr<<"[INFO] Found "<<zoneVersions.size()<<" versions of "<<domain<<", asked to keep "<<g_keep<<", ";
  }
  if (zoneVersions.size() <= g_keep) {
    if (g_verbose) {
      cerr<<"not cleaning up"<<endl;
    }
    return;
  }
  if (g_verbose) {
    cerr<<"cleaning up the oldest "<<zoneVersions.size() - g_keep<<endl;
  }

  // Sort the versions
  std::sort(zoneVersions.begin(), zoneVersions.end(), sortSOA);

  // And delete all the old ones
  {
    // Lock to ensure no one reads this.
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    for (auto iter = zoneVersions.cbegin(); iter != zoneVersions.cend() - g_keep; ++iter) {
      string fname = dir + "/" + std::to_string(*iter);
      if (g_debug) {
        cerr<<"[DEBUG] Removing "<<fname<<endl;
      }
      unlink(fname.c_str());
    }
  }
}

static shared_ptr<SOARecordContent> getSOAFromRecords(const records_t& records) {
  for (const auto& dnsrecord : records) {
    if (dnsrecord.d_type == QType::SOA) {
      auto soa = getRR<SOARecordContent>(dnsrecord);
      if (soa == nullptr) {
        throw PDNSException("Unable to determine SOARecordContent from old records");
      }
      return soa;
    }
  }
  throw PDNSException("No SOA in supplied records");
}

static void makeIXFRDiff(const records_t& from, const records_t& to, ixfrdiff_t& diff, const shared_ptr<SOARecordContent>& fromSOA = nullptr, const shared_ptr<SOARecordContent>& toSOA = nullptr) {
  set_difference(from.cbegin(), from.cend(), to.cbegin(), to.cend(), back_inserter(diff.removals), from.value_comp());
  set_difference(to.cbegin(), to.cend(), from.cbegin(), from.cend(), back_inserter(diff.additions), from.value_comp());
  diff.oldSOA = fromSOA;
  if (fromSOA == nullptr) {
    getSOAFromRecords(from);
  }
  diff.newSOA = toSOA;
  if (toSOA == nullptr) {
    getSOAFromRecords(to);
  }
}

void updateThread() {
  std::map<DNSName, time_t> lastCheck;

  // Initialize the serials we have
  for (const auto &domain : g_domains) {
    lastCheck[domain] = 0;
    string dir = g_workdir + "/" + domain.toString();
    try {
      if (g_verbose) {
        cerr<<"[INFO] Trying to initially load domain "<<domain.toString()<<" from disk"<<endl;
      }
      auto serial = getSerialsFromDir(dir);
      shared_ptr<SOARecordContent> soa;
      {
        string fname = g_workdir + "/" + domain.toString() + "/" + std::to_string(serial);
        loadSOAFromDisk(domain, fname, soa);
        records_t records;
        if (soa != nullptr) {
          loadZoneFromDisk(records, fname, domain);
        }
        std::lock_guard<std::mutex> guard(g_soas_mutex);
        g_soas[domain].latestAXFR = records;
        g_soas[domain].soa = soa;
      }
      if (soa != nullptr) {
        if (g_verbose) {
          cerr<<"[INFO] Loaded zone "<<domain.toString()<<" with serial "<<soa->d_st.serial<<endl;
        }
        // Initial cleanup
        cleanUpDomain(domain);
      }
    } catch (runtime_error &e) {
      // Most likely, the directory does not exist.
      cerr<<"[INFO] "<<e.what()<<", attempting to create"<<endl;
      // Attempt to create it, if _that_ fails, there is no hope
      if (mkdir(dir.c_str(), 0777) == -1 && errno != EEXIST) {
        cerr<<"[ERROR] Could not create '"<<dir<<"': "<<strerror(errno)<<endl;
        exit(EXIT_FAILURE);
      }
    }
  }


  if (g_verbose) {
    cerr<<"[INFO] Update Thread started"<<endl;
  }

  while (true) {
    if (g_exiting) {
      if (g_verbose) {
        cerr<<"[INFO] UpdateThread stopped"<<endl;
      }
      break;
    }
    time_t now = time(nullptr);
    for (const auto &domain : g_domains) {
      shared_ptr<SOARecordContent> current_soa;
      {
        std::lock_guard<std::mutex> guard(g_soas_mutex);
        if (g_soas.find(domain) != g_soas.end()) {
          current_soa = g_soas[domain].soa;
        }
      }
      if ((current_soa != nullptr && now - lastCheck[domain] < current_soa->d_st.refresh) || // Only check if we have waited `refresh` seconds
          (current_soa == nullptr && now - lastCheck[domain] < 30))  {                       // Or if we could not get an update at all still, every 30 seconds
        continue;
      }
      string dir = g_workdir + "/" + domain.toString();
      if (g_verbose) {
        cerr<<"[INFO] Attempting to retrieve SOA Serial update for '"<<domain<<"' from '"<<g_master.toStringWithPort()<<"'"<<endl;
      }
      shared_ptr<SOARecordContent> sr;
      try {
        lastCheck[domain] = now;
        auto newSerial = getSerialFromMaster(g_master, domain, sr); // TODO TSIG
        if(current_soa != nullptr) {
          if (g_verbose) {
            cerr<<"[INFO] Got SOA Serial for "<<domain<<" from "<<g_master.toStringWithPort()<<": "<< newSerial<<", had Serial: "<<current_soa->d_st.serial;
          }
          if (newSerial == current_soa->d_st.serial) {
            if (g_verbose) {
              cerr<<", not updating."<<endl;
            }
            continue;
          }
          if (g_verbose) {
            cerr<<", will update."<<endl;
          }
        }
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Unable to get SOA serial update for '"<<domain<<"': "<<e.what()<<endl;
        continue;
      }
      // Now get the full zone!
      if (g_verbose) {
        cerr<<"[INFO] Attempting to receive full zonedata for '"<<domain<<"'"<<endl;
      }
      ComboAddress local = g_master.isIPv4() ? ComboAddress("0.0.0.0") : ComboAddress("::");
      TSIGTriplet tt;

      // The *new* SOA
      shared_ptr<SOARecordContent> soa;
      try {
        AXFRRetriever axfr(g_master, domain, tt, &local);
        unsigned int nrecords=0;
        Resolver::res_t nop;
        vector<DNSRecord> chunk;
        records_t records;
        time_t t_start = time(nullptr);
        time_t axfr_now = time(nullptr);
        while(axfr.getChunk(nop, &chunk, (axfr_now - t_start + g_axfrTimeout))) {
          for(auto& dr : chunk) {
            if(dr.d_type == QType::TSIG)
              continue;
            dr.d_name.makeUsRelative(domain);
            records.insert(dr);
            nrecords++;
            if (dr.d_type == QType::SOA) {
              soa = getRR<SOARecordContent>(dr);
            }
          }
          axfr_now = time(nullptr);
          if (axfr_now - t_start > g_axfrTimeout) {
            throw PDNSException("Total AXFR time exceeded!");
          }
        }
        if (soa == nullptr) {
          cerr<<"[WARNING] No SOA was found in the AXFR of "<<domain<<endl;
          continue;
        }
        if (g_verbose) {
          cerr<<"[INFO] Retrieved all zone data for "<<domain<<". Received "<<nrecords<<" records."<<endl;
        }
        writeZoneToDisk(records, domain, dir);
        if (g_verbose) {
          cerr<<"[INFO] Wrote zonedata for "<<domain<<" with serial "<<soa->d_st.serial<<" to "<<dir<<endl;
        }
        {
          std::lock_guard<std::mutex> guard(g_soas_mutex);
          ixfrdiff_t diff;
          if (!g_soas[domain].latestAXFR.empty()) {
            makeIXFRDiff(g_soas[domain].latestAXFR, records, diff, g_soas[domain].soa, soa);
            g_soas[domain].ixfrDiffs.push_back(diff);
          }
          // Clean up the diffs
          while (g_soas[domain].ixfrDiffs.size() > g_keep) {
            g_soas[domain].ixfrDiffs.erase(g_soas[domain].ixfrDiffs.begin());
          }
          g_soas[domain].latestAXFR = records;
          g_soas[domain].soa = soa;
        }
      } catch (PDNSException &e) {
        cerr<<"[WARNING] Could not retrieve AXFR for '"<<domain<<"': "<<e.reason<<endl;
      } catch (runtime_error &e) {
        cerr<<"[WARNING] Could not save zone '"<<domain<<"' to disk: "<<e.what()<<endl;
      }
      // Now clean up the directory
      cleanUpDomain(domain);
    } /* for (const auto &domain : domains) */
    sleep(1);
  } /* while (true) */
} /* updateThread */

bool checkQuery(const MOADNSParser& mdp, const ComboAddress& saddr, const bool udp = true) {
  vector<string> info_msg;

  if (g_debug) {
    cerr<<"[DEBUG] Had "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort()<<endl;
  }

  if (udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR}");
  }

  if (!udp && mdp.d_qtype != QType::SOA && mdp.d_qtype != QType::IXFR && mdp.d_qtype != QType::AXFR) {
    info_msg.push_back("QType is unsupported (" + QType(mdp.d_qtype).getName() + " is not in {SOA,IXFR,AXFR}");
  }

  {
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    if (g_domains.find(mdp.d_qname) == g_domains.end()) {
      info_msg.push_back("Domain name '" + mdp.d_qname.toLogString() + "' is not configured for distribution");
    }

    if (g_soas.find(mdp.d_qname) == g_soas.end()) {
      info_msg.push_back("Domain has not been transferred yet");
    }
  }

  if (!info_msg.empty()) {
    cerr<<"[WARNING] Ignoring "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" query from "<<saddr.toStringWithPort();
    if (g_verbose) {
      cerr<<": ";
      bool first = true;
      for (const auto& s : info_msg) {
        if (!first) {
          cerr<<", ";
          first = false;
        }
        cerr<<s;
      }
    }
    cerr<<endl;
    return false;
  }

  return true;
}

/*
 * Returns a vector<uint8_t> that represents the full response to a SOA
 * query. QNAME is read from mdp.
 */
bool makeSOAPacket(const MOADNSParser& mdp, vector<uint8_t>& packet) {
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

  pw.startRecord(mdp.d_qname, QType::SOA);
  {
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    g_soas[mdp.d_qname].soa->toPacket(pw);
  }
  pw.commit();

  return true;
}

vector<uint8_t> getSOAPacket(const MOADNSParser& mdp, const shared_ptr<SOARecordContent>& soa) {
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
  pw.getHeader()->id = mdp.d_header.id;
  pw.getHeader()->rd = mdp.d_header.rd;
  pw.getHeader()->qr = 1;

  // Add the first SOA
  pw.startRecord(mdp.d_qname, QType::SOA);
  soa->toPacket(pw);
  pw.commit();
  return packet;
}

bool makeAXFRPackets(const MOADNSParser& mdp, vector<vector<uint8_t>>& packets) {
  shared_ptr<SOARecordContent> soa;
  records_t records;
  {
    // Make copies of what we have
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    soa = g_soas[mdp.d_qname].soa;
    records = g_soas[mdp.d_qname].latestAXFR;
  }

  // Initial SOA
  packets.push_back(getSOAPacket(mdp, soa));

  for (auto const &record : records) {
    if (record.d_type == QType::SOA) {
      continue;
    }
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
    pw.getHeader()->id = mdp.d_header.id;
    pw.getHeader()->rd = mdp.d_header.rd;
    pw.getHeader()->qr = 1;
    pw.startRecord(record.d_name + mdp.d_qname, record.d_type);
    record.d_content->toPacket(pw);
    pw.commit();
    packets.push_back(packet);
  }

  // Final SOA
  packets.push_back(getSOAPacket(mdp, soa));

  return true;
}

void makeXFRPacketsFromDNSRecords(const MOADNSParser& mdp, const vector<DNSRecord>& records, vector<vector<uint8_t>>& packets) {
  for(const auto& r : records) {
    if (r.d_type == QType::SOA) {
      continue;
    }
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
    pw.getHeader()->id = mdp.d_header.id;
    pw.getHeader()->rd = mdp.d_header.rd;
    pw.getHeader()->qr = 1;
    pw.startRecord(r.d_name + mdp.d_qname, r.d_type);
    r.d_content->toPacket(pw);
    pw.commit();
    packets.push_back(packet);
  }
}

/* Produces an IXFR if one can be made according to the rules in RFC 1995 and
 * creates a SOA or AXFR packet when required by the RFC.
 */
bool makeIXFRPackets(const MOADNSParser& mdp, const shared_ptr<SOARecordContent>& clientSOA, vector<vector<uint8_t>>& packets) {
  // Get the new SOA only once, so it will not change under our noses from the
  // updateThread.
  vector<ixfrdiff_t> toSend;
  uint32_t ourLatestSerial;
  {
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    ourLatestSerial = g_soas[mdp.d_qname].soa->d_st.serial;
  }

  if (rfc1982LessThan(ourLatestSerial, clientSOA->d_st.serial) || ourLatestSerial == clientSOA->d_st.serial){
    /* RFC 1995 Section 2
     *    If an IXFR query with the same or newer version number than that of
     *    the server is received, it is replied to with a single SOA record of
     *    the server's current version, just as in AXFR.
     */
    vector<uint8_t> packet;
    bool ret = makeSOAPacket(mdp, packet);
    if (ret) {
      packets.push_back(packet);
    }
    return ret;
  }

  {
    // as we use push_back in the updater, we know the vector is sorted as oldest first
    bool shouldAdd = false;
    // Get all relevant IXFR differences
    std::lock_guard<std::mutex> guard(g_soas_mutex);
    for (const auto& diff : g_soas[mdp.d_qname].ixfrDiffs) {
      if (shouldAdd) {
        toSend.push_back(diff);
        continue;
      }
      if (diff.oldSOA->d_st.serial == clientSOA->d_st.serial) {
        toSend.push_back(diff);
        // Add all consecutive diffs
        shouldAdd = true;
      }
    }
  }

  if (toSend.empty()) {
    cerr<<"[WARNING] No IXFR available from serial "<<clientSOA->d_st.serial<<" for zone "<<mdp.d_qname<<", attempting to send AXFR"<<endl;
    return makeAXFRPackets(mdp, packets);
  }

  for (const auto& diff : toSend) {
    /* An IXFR packet's ANSWER section looks as follows:
     * SOA new_serial
     * SOA old_serial
     * ... removed records ...
     * SOA new_serial
     * ... added records ...
     * SOA new_serial
     */
    packets.push_back(getSOAPacket(mdp, diff.newSOA));
    packets.push_back(getSOAPacket(mdp, diff.oldSOA));
    makeXFRPacketsFromDNSRecords(mdp, diff.removals, packets);
    packets.push_back(getSOAPacket(mdp, diff.newSOA));
    makeXFRPacketsFromDNSRecords(mdp, diff.additions, packets);
    packets.push_back(getSOAPacket(mdp, diff.newSOA));
  }

  return true;
}

bool allowedByACL(const ComboAddress& addr) {
  return g_acl.match(addr);
}

void handleUDPRequest(int fd, boost::any&) {
  // TODO make the buffer-size configurable
  char buf[4096];
  ComboAddress saddr;
  socklen_t fromlen = sizeof(saddr);
  int res = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*) &saddr, &fromlen);

  if (res == 0) {
    cerr<<"[WARNING] Got an empty message from "<<saddr.toStringWithPort()<<endl;
    return;
  }

  if(res < 0) {
    auto savedErrno = errno;
    cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
    return;
  }

  if (!allowedByACL(saddr)) {
    cerr<<"[WARNING] UDP query from "<<saddr.toString()<<" is not allowed, dropping"<<endl;
    return;
  }

  if (saddr == ComboAddress("0.0.0.0", 0)) {
    cerr<<"[WARNING] Could not determine source of message"<<endl;
    return;
  }

  MOADNSParser mdp(true, string(buf, res));
  if (!checkQuery(mdp, saddr)) {
    return;
  }

  /* RFC 1995 Section 2
   *    Transport of a query may be by either UDP or TCP.  If an IXFR query
   *    is via UDP, the IXFR server may attempt to reply using UDP if the
   *    entire response can be contained in a single DNS packet.  If the UDP
   *    reply does not fit, the query is responded to with a single SOA
   *    record of the server's current version to inform the client that a
   *    TCP query should be initiated.
   *
   * Let's not complicate this with IXFR over UDP (and looking if we need to truncate etc).
   * Just send the current SOA and let the client try over TCP
   */
  vector<uint8_t> packet;
  makeSOAPacket(mdp, packet);
  if(sendto(fd, &packet[0], packet.size(), 0, (struct sockaddr*) &saddr, fromlen) < 0) {
    auto savedErrno = errno;
    cerr<<"[WARNING] Could not send reply for "<<mdp.d_qname<<"|"<<QType(mdp.d_qtype).getName()<<" to "<<saddr.toStringWithPort()<<": "<<strerror(savedErrno)<<endl;
  }
  return;
}

void handleTCPRequest(int fd, boost::any&) {
  ComboAddress saddr;
  int cfd = 0;

  try {
    cfd = SAccept(fd, saddr);
    setBlocking(cfd);
  } catch(runtime_error &e) {
    cerr<<"[ERROR] "<<e.what()<<endl;
    return;
  }

  if (!allowedByACL(saddr)) {
    cerr<<"[WARNING] TCP query from "<<saddr.toString()<<" is not allowed, dropping"<<endl;
    close(cfd);
    return;
  }

  if (saddr == ComboAddress("0.0.0.0", 0)) {
    cerr<<"[WARNING] Could not determine source of message"<<endl;
    return;
  }

  char buf[4096];
  ssize_t res;
  try {
    uint16_t toRead;
    readn2(cfd, &toRead, sizeof(toRead));
    toRead = std::min(ntohs(toRead), static_cast<uint16_t>(sizeof(buf)));
    res = readn2WithTimeout(cfd, &buf, toRead, 2);
  } catch (runtime_error &e) {
    cerr<<"[WARNING] Could not read message from "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
    close(cfd);
    return;
  }

  try {
    MOADNSParser mdp(true, string(buf, res));

    if (!checkQuery(mdp, saddr, false)) {
      close(cfd);
      return;
    }

    vector<vector<uint8_t>> packets;
    if (mdp.d_qtype == QType::SOA) {
    vector<uint8_t> packet;
      bool ret = makeSOAPacket(mdp, packet);
      if (!ret) {
        close(cfd);
        return;
      }
      packets.push_back(packet);
    }

    if (mdp.d_qtype == QType::AXFR) {
      if (!makeAXFRPackets(mdp, packets)) {
        close(cfd);
        return;
      }
    }

    if (mdp.d_qtype == QType::IXFR) {
      /* RFC 1995 section 3:
       *  The IXFR query packet format is the same as that of a normal DNS
       *  query, but with the query type being IXFR and the authority section
       *  containing the SOA record of client's version of the zone.
       */
      shared_ptr<SOARecordContent> clientSOA;
      for (auto &answer : mdp.d_answers) {
        // from dnsparser.hh:
        // typedef vector<pair<DNSRecord, uint16_t > > answers_t;
        if (answer.first.d_type == QType::SOA && answer.first.d_place == DNSResourceRecord::AUTHORITY) {
          clientSOA = getRR<SOARecordContent>(answer.first);
          if (clientSOA != nullptr) {
            break;
          }
        }
      } /* for (auto const &answer : mdp.d_answers) */

      if (clientSOA == nullptr) {
        cerr<<"[WARNING] IXFR request packet did not contain a SOA record in the AUTHORITY section"<<endl;
        close(cfd);
        return;
      }

      if (!makeIXFRPackets(mdp, clientSOA, packets)) {
        close(cfd);
        return;
      }
    } /* if (mdp.d_qtype == QType::IXFR) */

    for (const auto& packet : packets) {
      char sendBuf[2];
      sendBuf[0]=packet.size()/256;
      sendBuf[1]=packet.size()%256;

      ssize_t send = writen2(cfd, sendBuf, 2);
      send += writen2(cfd, &packet[0], packet.size());
    }
    shutdown(cfd, 2);
  } catch (MOADNSException &e) {
    cerr<<"[WARNING] Could not parse DNS packet from "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
  } catch (runtime_error &e) {
    cerr<<"[WARNING] Could not write reply to "<<saddr.toStringWithPort()<<": "<<e.what()<<endl;
  }
  // bye!
  close(cfd);
}

int main(int argc, char** argv) {
  try {
    po::options_description desc("IXFR distribution tool");
    desc.add_options()
      ("help", "produce help message")
      ("version", "Display the version of ixfrdist")
      ("verbose", "Be verbose")
      ("debug", "Be even more verbose")
      ("uid", po::value<string>(), "Drop privileges to this user after binding the listen sockets")
      ("gid", po::value<string>(), "Drop privileges to this group after binding the listen sockets")
      ("listen-address", po::value< vector< string>>(), "IP Address(es) to listen on")
      ("acl", po::value<vector<string>>(), "IP Address masks that are allowed access, by default only loopback addresses are allowed")
      ("server-address", po::value<string>()->default_value("127.0.0.1:5300"), "server address")
      ("work-dir", po::value<string>()->default_value("."), "Directory for storing AXFR and IXFR data")
      ("keep", po::value<uint16_t>()->default_value(KEEP_DEFAULT), "Number of old zone versions to retain")
      ("axfr-timeout", po::value<uint16_t>()->default_value(AXFRTIMEOUT_DEFAULT), "Timeout in seconds for an AXFR to complete")
      ;
    po::options_description alloptions;
    po::options_description hidden("hidden options");
    hidden.add_options()
      ("domains", po::value< vector<string> >(), "domains");

    alloptions.add(desc).add(hidden);
    po::positional_options_description p;
    p.add("domains", -1);

    po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
    po::notify(g_vm);

    if (g_vm.count("help") > 0) {
      usage(desc);
      return EXIT_SUCCESS;
    }

    if (g_vm.count("version") > 0) {
      cout<<"ixfrdist "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  } catch (po::error &e) {
    cerr<<"[ERROR] "<<e.what()<<". See `ixfrdist --help` for valid options"<<endl;
    return(EXIT_FAILURE);
  }

  bool had_error = false;

  if (g_vm.count("verbose") > 0 || g_vm.count("debug") > 0) {
    g_verbose = true;
  }

  if (g_vm.count("debug") > 0) {
    g_debug = true;
  }

  if (g_vm.count("keep") > 0) {
    g_keep = g_vm["keep"].as<uint16_t>();
  }

  if (g_vm.count("axfr-timeout") > 0) {
    g_axfrTimeout = g_vm["axfr-timeout"].as<uint16_t>();
  }

  vector<ComboAddress> listen_addresses = {ComboAddress("127.0.0.1:53")};

  if (g_vm.count("listen-address") > 0) {
    listen_addresses.clear();
    for (const auto &addr : g_vm["listen-address"].as< vector< string> >()) {
      try {
        listen_addresses.push_back(ComboAddress(addr, 53));
      } catch(PDNSException &e) {
        cerr<<"[ERROR] listen-address '"<<addr<<"' is not an IP address: "<<e.reason<<endl;
        had_error = true;
      }
    }
  }

  try {
    g_master = ComboAddress(g_vm["server-address"].as<string>(), 53);
  } catch(PDNSException &e) {
    cerr<<"[ERROR] server-address '"<<g_vm["server-address"].as<string>()<<"' is not an IP address: "<<e.reason<<endl;
    had_error = true;
  }

  if (!g_vm.count("domains")) {
    cerr<<"[ERROR] No domain(s) specified!"<<endl;
    had_error = true;
  } else {
    for (const auto &domain : g_vm["domains"].as<vector<string>>()) {
      try {
        g_domains.insert(DNSName(domain));
      } catch (PDNSException &e) {
        cerr<<"[ERROR] '"<<domain<<"' is not a valid domain name: "<<e.reason<<endl;
        had_error = true;
      }
    }
  }

  g_fdm = FDMultiplexer::getMultiplexerSilent();
  if (g_fdm == nullptr) {
    cerr<<"[ERROR] Could not enable a multiplexer for the listen sockets!"<<endl;
    return EXIT_FAILURE;
  }

  vector<string> acl = {"127.0.0.0/8", "::1/128"};
  if (g_vm.count("acl") > 0) {
    acl = g_vm["acl"].as<vector<string>>();
  }
  for (const auto &addr : acl) {
    try {
      g_acl.addMask(addr);
    } catch (const NetmaskException &e) {
      cerr<<"[ERROR] "<<e.reason<<endl;
      had_error = true;
    }
  }
  if (g_verbose) {
    cerr<<"[INFO] ACL set to "<<g_acl.toString()<<"."<<endl;
  }

  set<int> allSockets;
  for (const auto& addr : listen_addresses) {
    for (const auto& stype : {SOCK_DGRAM, SOCK_STREAM}) {
      try {
        int s = SSocket(addr.sin4.sin_family, stype, 0);
        setNonBlocking(s);
        setReuseAddr(s);
        SBind(s, addr);
        if (stype == SOCK_STREAM) {
          SListen(s, 30); // TODO make this configurable
        }
        g_fdm->addReadFD(s, stype == SOCK_DGRAM ? handleUDPRequest : handleTCPRequest);
        allSockets.insert(s);
      } catch(runtime_error &e) {
        cerr<<"[ERROR] "<<e.what()<<endl;
        had_error = true;
        continue;
      }
    }
  }

  g_workdir = g_vm["work-dir"].as<string>();

  int newgid = 0;

  if (g_vm.count("gid") > 0) {
    string gid = g_vm["gid"].as<string>();
    if (!(newgid = atoi(gid.c_str()))) {
      struct group *gr = getgrnam(gid.c_str());
      if (gr == nullptr) {
        cerr<<"[ERROR] Can not determine group-id for gid "<<gid<<endl;
        had_error = true;
      } else {
        newgid = gr->gr_gid;
      }
    }
    if(g_verbose) {
      cerr<<"[INFO] Dropping effective group-id to "<<newgid<<endl;
    }
    if (setgid(newgid) < 0) {
      cerr<<"[ERROR] Could not set group id to "<<newgid<<": "<<stringerror()<<endl;
      had_error = true;
    }
  }

  int newuid = 0;

  if (g_vm.count("uid") > 0) {
    string uid = g_vm["uid"].as<string>();
    if (!(newuid = atoi(uid.c_str()))) {
      struct passwd *pw = getpwnam(uid.c_str());
      if (pw == nullptr) {
        cerr<<"[ERROR] Can not determine user-id for uid "<<uid<<endl;
        had_error = true;
      } else {
        newuid = pw->pw_uid;
      }
    }

    struct passwd *pw = getpwuid(newuid);
    if (pw == nullptr) {
      if (setgroups(0, nullptr) < 0) {
        cerr<<"[ERROR] Unable to drop supplementary gids: "<<stringerror()<<endl;
        had_error = true;
      }
    } else {
      if (initgroups(pw->pw_name, newgid) < 0) {
        cerr<<"[ERROR] Unable to set supplementary groups: "<<stringerror()<<endl;
        had_error = true;
      }
    }

    if(g_verbose) {
      cerr<<"[INFO] Dropping effective user-id to "<<newuid<<endl;
    }
    if (pw != nullptr && setuid(pw->pw_uid) < 0) {
      cerr<<"[ERROR] Could not set user id to "<<newuid<<": "<<stringerror()<<endl;
      had_error = true;
    }
  }

  if (had_error) {
    // We have already sent the errors to stderr, just die
    return EXIT_FAILURE;
  }

  // It all starts here
  signal(SIGTERM, handleSignal);
  signal(SIGINT, handleSignal);
  signal(SIGSTOP, handleSignal);

  // Init the things we need
  reportAllTypes();

  // TODO read from urandom (perhaps getrandom(2)?
  dns_random_init("0123456789abcdef");

  cout<<"[INFO] IXFR distributor starting up!"<<endl;

  std::thread ut(updateThread);

  struct timeval now;
  for(;;) {
    gettimeofday(&now, 0);
    g_fdm->run(&now);
    if (g_exiting) {
      if (g_verbose) {
        cerr<<"[INFO] Shutting down!"<<endl;
      }
      for (const int& fd : allSockets) {
        try {
          closesocket(fd);
        } catch(PDNSException &e) {
          cerr<<"[ERROR] "<<e.reason<<endl;
        }
      }
      break;
    }
  }
  ut.join();
  if (g_verbose) {
    cerr<<"[INFO] IXFR distributor stopped"<<endl;
  }
  return EXIT_SUCCESS;
}
