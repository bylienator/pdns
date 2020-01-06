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

#include "dnsdist.hh"

extern "C" {
#include "dnsdist-lua-ffi-interface.h"
}

// dnsdist_ffi_dnsquestion_t is a lightuserdata
template<>
struct LuaContext::Pusher<dnsdist_ffi_dnsquestion_t*> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, dnsdist_ffi_dnsquestion_t* ptr) noexcept {
        lua_pushlightuserdata(state, ptr);
        return PushedObject{state, 1};
    }
};

struct dnsdist_ffi_dnsquestion_t
{
  dnsdist_ffi_dnsquestion_t(DNSQuestion* dq_): dq(dq_)
  {
  }

  DNSQuestion* dq{nullptr};
  std::vector<dnsdist_ednsoption_t> ednsOptionsVect;
  std::vector<dnsdist_http_header> httpHeadersVect;
  std::unordered_map<std::string, std::string> httpHeaders;
  boost::optional<std::string> result{boost::none};
  boost::optional<std::string> httpPath{boost::none};
  boost::optional<std::string> httpQueryString{boost::none};
  boost::optional<std::string> httpHost{boost::none};
  boost::optional<std::string> httpScheme{boost::none};
};

const std::string& getLuaFFIWrappers();
