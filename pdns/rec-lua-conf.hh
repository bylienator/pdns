#pragma once
#include "sholder.hh"
#include "sortlist.hh"
#include "filterpo.hh"
#include "remote_logger.hh"
#include "validate.hh"

class LuaConfigItems 
{
  struct ProtobufConfig
  {
    std::shared_ptr<RemoteLogger> server{nullptr};
    uint8_t maskV4{32};
    uint8_t maskV6{128};
  };

public:
  LuaConfigItems();
  SortList sortlist;
  DNSFilterEngine dfe;
  map<DNSName,dsmap_t> dsAnchors;
  map<DNSName,std::string> negAnchors;
  ProtobufConfig protobuf;
  ProtobufConfig outgoingProtobuf;
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;
void loadRecursorLuaConfig(const std::string& fname);

