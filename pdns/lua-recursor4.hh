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
#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iputils.hh"
#include "dnsname.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "filterpo.hh"
#include "ednsoptions.hh"
#include "validate.hh"
#include "lua-base4.hh"
#include <unordered_map>

#include "lua-recursor4-ffi.hh"

string GenUDPQueryResponse(const ComboAddress& dest, const string& query);
unsigned int getRecursorThreadId();

struct pdns_ffi_param
{
public:
  pdns_ffi_param(const DNSName& qname_, uint16_t qtype_, const ComboAddress& local_, const ComboAddress& remote_, const Netmask& ednssubnet_, std::vector<std::string>& policyTags_, const std::map<uint16_t, EDNSOptionView>& ednsOptions_, std::string& requestorId_, std::string& deviceId_,  bool tcp_): qname(qname_), local(local_), remote(remote_), ednssubnet(ednssubnet_), policyTags(policyTags_), ednsOptions(ednsOptions_), requestorId(requestorId_), deviceId(deviceId_), tag(0), qtype(qtype_), tcp(tcp_)
  {
  }

  const DNSName& qname;
  const ComboAddress& local;
  const ComboAddress& remote;
  const Netmask& ednssubnet;
  std::vector<std::string>& policyTags;
  const std::map<uint16_t, EDNSOptionView>& ednsOptions;
  std::string& requestorId;
  std::string& deviceId;

  unsigned int tag;
  uint16_t qtype;
  bool tcp;
};

// pdns_ffi_param_t is a lightuserdata
template<>
struct LuaContext::Pusher<pdns_ffi_param*> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, pdns_ffi_param* ptr) noexcept {
        lua_pushlightuserdata(state, ptr);
        return PushedObject{state, 1};
    }
};

class RecursorLua4 : public BaseLua4
{
public:
  RecursorLua4();
  ~RecursorLua4(); // this is so unique_ptr works with an incomplete type

  struct DNSQuestion
  {
    DNSQuestion(const ComboAddress& rem, const ComboAddress& loc, const DNSName& query, uint16_t type, bool tcp, bool& variable_, bool& wantsRPZ_): qname(query), qtype(type), local(loc), remote(rem), isTcp(tcp), variable(variable_), wantsRPZ(wantsRPZ_)
    {
    }
    const DNSName& qname;
    const uint16_t qtype;
    const ComboAddress& local;
    const ComboAddress& remote;
    const struct dnsheader* dh{nullptr};
    const bool isTcp;
    const std::vector<pair<uint16_t, string>>* ednsOptions{nullptr};
    const uint16_t* ednsFlags{nullptr};
    vector<DNSRecord>* currentRecords{nullptr};
    DNSFilterEngine::Policy* appliedPolicy{nullptr};
    std::vector<std::string>* policyTags{nullptr};
    std::unordered_map<std::string,bool>* discardedPolicies{nullptr};
    std::string requestorId;
    std::string deviceId;
    vState validationState{Indeterminate};
    bool& variable;
    bool& wantsRPZ;
    unsigned int tag{0};

    void addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name);
    void addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name);
    vector<pair<int,DNSRecord> > getRecords() const;
    boost::optional<dnsheader> getDH() const;
    vector<pair<uint16_t, string> > getEDNSOptions() const;
    boost::optional<string> getEDNSOption(uint16_t code) const;
    boost::optional<Netmask> getEDNSSubnet() const;
    vector<string> getEDNSFlags() const;
    bool getEDNSFlag(string flag) const;
    void setRecords(const vector<pair<int,DNSRecord> >& records);

    int rcode{0};
    // struct dnsheader, packet length would be great
    vector<DNSRecord> records;
    
    string followupFunction;
    string followupPrefix;

    string udpQuery;
    ComboAddress udpQueryDest;
    string udpAnswer;
    string udpCallback;
    
    LuaContext::LuaObject data;
    DNSName followupName;
  };

  unsigned int gettag(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::vector<std::string>* policyTags, LuaContext::LuaObject& data, const std::map<uint16_t, EDNSOptionView>&, bool tcp, std::string& requestorId, std::string& deviceId);
  unsigned int gettag_ffi(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::vector<std::string>* policyTags, LuaContext::LuaObject& data, const std::map<uint16_t, EDNSOptionView>&, bool tcp, std::string& requestorId, std::string& deviceId);

  bool prerpz(DNSQuestion& dq, int& ret);
  bool preresolve(DNSQuestion& dq, int& ret);
  bool nxdomain(DNSQuestion& dq, int& ret);
  bool nodata(DNSQuestion& dq, int& ret);
  bool postresolve(DNSQuestion& dq, int& ret);

  bool preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret);
  bool ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader&);

  bool needDQ() const
  {
    return (d_prerpz ||
            d_preresolve ||
            d_nxdomain ||
            d_nodata ||
            d_postresolve);
  }

  typedef std::function<std::tuple<unsigned int,boost::optional<std::unordered_map<int,string> >,boost::optional<LuaContext::LuaObject>,boost::optional<std::string>,boost::optional<std::string> >(ComboAddress, Netmask, ComboAddress, DNSName, uint16_t, const std::map<uint16_t, EDNSOptionView>&, bool)> gettag_t;
  gettag_t d_gettag; // public so you can query if we have this hooked
  typedef std::function<boost::optional<LuaContext::LuaObject>(pdns_ffi_param_t*)> gettag_ffi_t;
  gettag_ffi_t d_gettag_ffi;

protected:
  virtual void postPrepareContext() override;
  virtual void postLoad() override;
private:
  typedef std::function<bool(DNSQuestion*)> luacall_t;
  luacall_t d_prerpz, d_preresolve, d_nxdomain, d_nodata, d_postresolve, d_preoutquery, d_postoutquery;
  bool genhook(luacall_t& func, DNSQuestion& dq, int& ret);
  typedef std::function<bool(ComboAddress,ComboAddress, struct dnsheader)> ipfilter_t;
  ipfilter_t d_ipfilter;
};

