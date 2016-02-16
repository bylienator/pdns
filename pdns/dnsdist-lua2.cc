#include "dnsdist.hh"
#include "dnsdist-cache.hh"
#include "dnsrulactions.hh"
#include <thread>
#include "dolog.hh"
#include "sodcrypto.hh"
#include "base64.hh"
#include "lock.hh"
#include <map>
#include <fstream>
#include <boost/logic/tribool.hpp>

boost::tribool g_noLuaSideEffect;

/* this is a best effort way to prevent logging calls with no side-effects in the output of delta()
   Functions can declare setLuaNoSideEffect() and if nothing else does declare a side effect, or nothing
   has done so before on this invocation, this call won't be part of delta() output */
void setLuaNoSideEffect()
{
  if(g_noLuaSideEffect==false) // there has been a side effect already
    return;
  g_noLuaSideEffect=true;
}

void setLuaSideEffect()
{
  g_noLuaSideEffect=false;
}

bool getLuaNoSideEffect()
{
  return g_noLuaSideEffect==true;
}

void resetLuaSideEffect()
{
  g_noLuaSideEffect = boost::logic::indeterminate;
}

map<ComboAddress,int> filterScore(const map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan >& counts, 
				  double delta, int rate)
{
  std::multimap<unsigned int,ComboAddress> score;
  for(const auto& e : counts) 
    score.insert({e.second, e.first});

  map<ComboAddress,int> ret;
  
  double lim = delta*rate;
  for(auto s = score.crbegin(); s != score.crend() && s->first > lim; ++s) {
    ret[s->second]=s->first;
  }
  return ret;
}


typedef   map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan > counts_t;
map<ComboAddress,int> exceedRespGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Response&)> T) 
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  std::lock_guard<std::mutex> lock(g_rings.respMutex);
  for(decltype(g_rings.respRing)::const_reverse_iterator it = g_rings.respRing.rbegin(); it != g_rings.respRing.rend(); ++it) {
    if(seconds && it->when < cutoff)
      break;
    if(now < it->when)
      continue;

    T(counts, *it);
    if(it->when < mintime)
      mintime = it->when;
  }
  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}

map<ComboAddress,int> exceedQueryGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Query&)> T) 
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  ReadLock rl(&g_rings.queryLock);
  for(decltype(g_rings.queryRing)::const_reverse_iterator it = g_rings.queryRing.rbegin(); it != g_rings.queryRing.rend(); ++it) {
    if(seconds && it->when < cutoff)
      continue;
    if(now < it->when)
      continue;
    T(counts, *it);
    if(it->when < mintime)
      mintime = it->when;
  }
  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}


map<ComboAddress,int> exceedRCode(int rate, int seconds, int rcode) 
{
  return exceedRespGen(rate, seconds, [rcode](counts_t& counts, const Rings::Response& r) 
		   {
		     if(r.dh.rcode == rcode)
		       counts[r.requestor]++;
		   });
}

map<ComboAddress,int> exceedRespByterate(int rate, int seconds) 
{
  return exceedRespGen(rate, seconds, [](counts_t& counts, const Rings::Response& r) 
		   {
		     counts[r.requestor]+=r.size;
		   });
}


void moreLua(bool client)
{
  typedef NetmaskTree<DynBlock> nmts_t;
  g_lua.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });


  g_lua.writeFunction("newNMG", []() { return NetmaskGroup(); });
  g_lua.registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask)
			 {
			   nmg.addMask(mask);
			 });

  g_lua.registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  g_lua.registerFunction("size", &NetmaskGroup::size);  
  g_lua.registerFunction("clear", &NetmaskGroup::clear);  


  g_lua.writeFunction("showDynBlocks", []() {
      setLuaNoSideEffect();
      auto slow = g_dynblockNMG.getCopy();
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      boost::format fmt("%-24s %8d %8d %s\n");
      g_outputBuffer = (fmt % "Netmask" % "Seconds" % "Blocks" % "Reason").str();
      for(const auto& e: slow) {
	if(now < e->second.until)
	  g_outputBuffer+= (fmt % e->first.toString() % (e->second.until.tv_sec - now.tv_sec) % e->second.blocks % e->second.reason).str();
      }
    });

  g_lua.writeFunction("clearDynBlocks", []() {
      setLuaSideEffect();
      nmts_t nmg;
      g_dynblockNMG.setState(nmg);
    });

  g_lua.writeFunction("addDynBlocks", 
			  [](const map<ComboAddress,int>& m, const std::string& msg, boost::optional<int> seconds) { 
                           setLuaSideEffect();
			   auto slow = g_dynblockNMG.getCopy();
			   struct timespec until, now;
			   clock_gettime(CLOCK_MONOTONIC, &now);
			   until=now;
                           int actualSeconds = seconds ? *seconds : 10;
			   until.tv_sec += actualSeconds; 
			   for(const auto& capair : m) {
			     unsigned int count = 0;
                             auto got = slow.lookup(Netmask(capair.first));
                             bool expired=false;
			     if(got) {
			       if(until < got->second.until) // had a longer policy
				 continue;
			       if(now < got->second.until) // only inherit count on fresh query we are extending
				 count=got->second.blocks;
                               else
                                 expired=true;
			     }
			     DynBlock db{msg,until};
			     db.blocks=count;
                             if(!got || expired)
                               warnlog("Inserting dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg);
			     slow.insert(Netmask(capair.first)).second=db;
			   }
			   g_dynblockNMG.setState(slow);
			 });


  g_lua.registerFunction<bool(nmts_t::*)(const ComboAddress&)>("match", 
								     [](nmts_t& s, const ComboAddress& ca) { return s.match(ca); });

  g_lua.writeFunction("exceedServFails", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::ServFail);
    });
  g_lua.writeFunction("exceedNXDOMAINs", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::NXDomain);
    });



  g_lua.writeFunction("exceedRespByterate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRespByterate(rate, seconds);
    });

  g_lua.writeFunction("exceedQTypeRate", [](uint16_t type, unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [type](counts_t& counts, const Rings::Query& q) {
	  if(q.qtype==type)
	    counts[q.requestor]++;
	});
    });

  g_lua.writeFunction("exceedQRate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [](counts_t& counts, const Rings::Query& q) {
          counts[q.requestor]++;
	});
    });


  g_lua.writeFunction("topBandwidth", [](boost::optional<unsigned int> top_) {
      setLuaNoSideEffect();
      auto top = top_.get_value_or(10);
      auto res = g_rings.getTopBandwidth(top);
      boost::format fmt("%7d  %s\n");
      for(const auto& l : res) {
	g_outputBuffer += (fmt % l.first % l.second.toString()).str();
      }
    });

  g_lua.writeFunction("delta", []() {
      setLuaNoSideEffect();
      // we hold the lua lock already!
      for(const auto& d : g_confDelta) {
        struct tm tm;
        localtime_r(&d.first.tv_sec, &tm);
        char date[80];
        strftime(date, sizeof(date)-1, "# %a %b %d %Y %H:%M:%S %Z\n", &tm);
        g_outputBuffer += date;
        g_outputBuffer += d.second + "\n";
      }
    });

  g_lua.writeFunction("grepq", [](boost::variant<string, vector<pair<int,string> > > inp, boost::optional<unsigned int> limit) {
      boost::optional<Netmask>  nm;
      boost::optional<DNSName> dn;
      int msec=-1;

      vector<string> vec;
      auto str=boost::get<string>(&inp);
      if(str)
        vec.push_back(*str);
      else {
        auto v = boost::get<vector<pair<int, string> > >(inp);
        for(const auto& a: v) 
          vec.push_back(a.second);
      }
    
      for(const auto& s : vec) {
        try 
          {
            nm = Netmask(s);
          }
        catch(...) {
          if(boost::ends_with(s,"ms") && sscanf(s.c_str(), "%ums", &msec)) {
            ;
          }
          else {
            try { dn=DNSName(s); }
            catch(...) 
              {
                g_outputBuffer = "Could not parse '"+s+"' as domain name or netmask";
                return;
              }
          }
        }
      }

      decltype(g_rings.queryRing) qr;
      decltype(g_rings.respRing) rr;
      {
        ReadLock rl(&g_rings.queryLock);
        qr=g_rings.queryRing;
      }
      sort(qr.begin(), qr.end(), [](const decltype(qr)::value_type& a, const decltype(qr)::value_type& b) {
        return b.when < a.when;
      });
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
        rr=g_rings.respRing;
      }

      sort(rr.begin(), rr.end(), [](const decltype(rr)::value_type& a, const decltype(rr)::value_type& b) {
        return b.when < a.when;
      });
      
      unsigned int num=0;
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
            
      std::multimap<struct timespec, string> out;

      boost::format      fmt("%-7.1f %-47s %-12s %-5d %-25s %-5s %-6.1f %-2s %-2s %-2s %s\n");
      g_outputBuffer+= (fmt % "Time" % "Client" % "Server" % "ID" % "Name" % "Type" % "Lat." % "TC" % "RD" % "AA" % "Rcode").str();

      if(msec==-1) {
        for(const auto& c : qr) {
          bool nmmatch=true, dnmatch=true;
          if(nm)
            nmmatch = nm->match(c.requestor);
          if(dn)
            dnmatch = c.name.isPartOf(*dn);
          if(nmmatch && dnmatch) {
            QType qt(c.qtype);
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % "" % htons(c.dh.id) % c.name.toString() % qt.getName()  % "" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") %  "Question").str() )) ;
            
            if(limit && *limit==++num)
              break;
          }
        }
      }
      num=0;


      string extra;
      for(const auto& c : rr) {
        bool nmmatch=true, dnmatch=true, msecmatch=true;
        if(nm)
          nmmatch = nm->match(c.requestor);
        if(dn)
          dnmatch = c.name.isPartOf(*dn);
        if(msec != -1)
          msecmatch=(c.usec/1000 > (unsigned int)msec);

        if(nmmatch && dnmatch && msecmatch) {
          QType qt(c.qtype);
	  if(!c.dh.rcode)
	    extra=". " +std::to_string(htons(c.dh.ancount))+ " answers";
	  else 
	    extra.clear();
          if(c.usec != std::numeric_limits<decltype(c.usec)>::max())
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % c.ds.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % (c.usec/1000.0) % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str()  )) ;
          else
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % c.ds.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % "T.O" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str()  )) ;

          if(limit && *limit==++num)
            break;
        }
      }

      for(const auto& p : out) {
        g_outputBuffer+=p.second;
      }
    });

  g_lua.writeFunction("addDNSCryptBind", [](const std::string& addr, const std::string& providerName, const std::string& certFile, const std::string keyFile) {
      if (g_configurationDone) {
        g_outputBuffer="addDNSCryptBind cannot be used at runtime!\n";
        return;
      }
#ifdef HAVE_DNSCRYPT
      try {
        DnsCryptContext ctx(providerName, certFile, keyFile);
        g_dnsCryptLocals.push_back({ComboAddress(addr, 443), ctx});
      }
      catch(std::exception& e) {
        errlog(e.what());
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  g_lua.writeFunction("showDNSCryptBinds", []() {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      ostringstream ret;
      boost::format fmt("%1$-3d %2% %|25t|%3$-20.20s %|26t|%4$-8d %|35t|%5$-21.21s %|56t|%6$-9d %|66t|%7$-21.21s" );
      ret << (fmt % "#" % "Address" % "Provider Name" % "Serial" % "Validity" % "P. Serial" % "P. Validity") << endl;
      size_t idx = 0;

      for (const auto& local : g_dnsCryptLocals) {
        const DnsCryptContext& ctx = local.second;
        bool const hasOldCert = ctx.hadOldCertificate();
        const DnsCryptCert& cert = ctx.getCurrentCertificate();
        const DnsCryptCert& oldCert = ctx.getOldCertificate();

        ret<< (fmt % idx % local.first.toStringWithPort() % ctx.getProviderName() % cert.signedData.serial % DnsCryptContext::certificateDateToStr(cert.signedData.tsEnd) % (hasOldCert ? oldCert.signedData.serial : 0) % (hasOldCert ? DnsCryptContext::certificateDateToStr(oldCert.signedData.tsEnd) : "-")) << endl;
        idx++;
      }

      g_outputBuffer=ret.str();
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

    g_lua.writeFunction("generateDNSCryptProviderKeys", [](const std::string& publicKeyFile, const std::string privateKeyFile) {
        setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
        unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
        unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
        sodium_mlock(privateKey, sizeof(privateKey));

        try {
          DnsCryptContext::generateProviderKeys(publicKey, privateKey);

          ofstream pubKStream(publicKeyFile);
          pubKStream.write((char*) publicKey, sizeof(publicKey));
          pubKStream.close();

          ofstream privKStream(privateKeyFile);
          privKStream.write((char*) privateKey, sizeof(privateKey));
          privKStream.close();

          g_outputBuffer="Provider fingerprint is: " + DnsCryptContext::getProviderFingerprint(publicKey) + "\n";
        }
        catch(std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }

        sodium_memzero(privateKey, sizeof(privateKey));
        sodium_munlock(privateKey, sizeof(privateKey));
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

    g_lua.writeFunction("printDNSCryptProviderFingerprint", [](const std::string& publicKeyFile) {
        setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
        unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];

        try {
          ifstream file(publicKeyFile);
          file.read((char *) &publicKey, sizeof(publicKey));

          if (file.fail())
            throw std::runtime_error("Invalid dnscrypt provider public key file " + publicKeyFile);

          file.close();
          g_outputBuffer="Provider fingerprint is: " + DnsCryptContext::getProviderFingerprint(publicKey) + "\n";
        }
        catch(std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

    g_lua.writeFunction("generateDNSCryptCertificate", [](const std::string& providerPrivateKeyFile, const std::string& certificateFile, const std::string privateKeyFile, uint32_t serial, time_t begin, time_t end) {
        setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
        unsigned char privateKey[DNSCRYPT_PRIVATE_KEY_SIZE];
        unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
        sodium_mlock(providerPrivateKey, sizeof(providerPrivateKey));
        sodium_mlock(privateKey, sizeof(privateKey));
        sodium_memzero(providerPrivateKey, sizeof(providerPrivateKey));
        sodium_memzero(privateKey, sizeof(privateKey));

        try {
          DnsCryptPrivateKey privateKey;
          DnsCryptCert cert;
          ifstream providerKStream(providerPrivateKeyFile);
          providerKStream.read((char*) providerPrivateKey, sizeof(providerPrivateKey));
          if (providerKStream.fail()) {
            providerKStream.close();
            throw std::runtime_error("Invalid DNSCrypt provider key file " + providerPrivateKeyFile);
          }

          DnsCryptContext::generateCertificate(serial, begin, end, providerPrivateKey, privateKey, cert);

          privateKey.saveToFile(privateKeyFile);
          DnsCryptContext::saveCertFromFile(cert, certificateFile);
        }
        catch(std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }

        sodium_memzero(providerPrivateKey, sizeof(providerPrivateKey));
        sodium_memzero(privateKey, sizeof(privateKey));
        sodium_munlock(providerPrivateKey, sizeof(providerPrivateKey));
        sodium_munlock(privateKey, sizeof(privateKey));
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

    g_lua.writeFunction("showPools", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$-20.20s %|25t|%2$20s %|50t|%3%" );
        //             1        3         4
        ret << (fmt % "Name" % "Cache" % "Servers" ) << endl;

        const auto localPools = g_pools.getCopy();
        for (const auto& entry : localPools) {
          const string& name = entry.first;
          const std::shared_ptr<ServerPool> pool = entry.second;
          string cache = pool->packetCache != nullptr ? pool->packetCache->toString() : "";
          string servers;

          for (const auto& server: pool->servers) {
            if (!servers.empty()) {
              servers += ", ";
            }
            if (!server.second->name.empty()) {
              servers += server.second->name;
              servers += " ";
            }
            servers += server.second->remote.toStringWithPort();
          }

          ret << (fmt % name % cache % servers) << endl;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

    g_lua.registerFunction<void(std::shared_ptr<ServerPool>::*)(std::shared_ptr<DNSDistPacketCache>)>("setCache", [](std::shared_ptr<ServerPool> pool, std::shared_ptr<DNSDistPacketCache> cache) {
        pool->packetCache = cache;
    });
    g_lua.registerFunction("getCache", &ServerPool::getCache);

    g_lua.writeFunction("newPacketCache", [client](size_t maxEntries, boost::optional<uint32_t> maxTTL, boost::optional<uint32_t> minTTL) {
        return std::make_shared<DNSDistPacketCache>(maxEntries, maxTTL ? *maxTTL : 86400, minTTL ? *minTTL : 60);
      });
    g_lua.registerFunction("toString", &DNSDistPacketCache::toString);
    g_lua.registerFunction("isFull", &DNSDistPacketCache::isFull);
    g_lua.registerFunction("purge", &DNSDistPacketCache::purge);
    g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const DNSName& dname, boost::optional<uint16_t> qtype)>("expungeByName", [](std::shared_ptr<DNSDistPacketCache> cache, const DNSName& dname, boost::optional<uint16_t> qtype) {
        cache->expunge(dname, qtype ? *qtype : QType::ANY);
      });
    g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)()>("printStats", [](const std::shared_ptr<DNSDistPacketCache> cache) {
        g_outputBuffer="Hits: " + std::to_string(cache->getHits()) + "\n";
        g_outputBuffer+="Misses: " + std::to_string(cache->getMisses()) + "\n";
        g_outputBuffer+="Deferred inserts: " + std::to_string(cache->getDeferredInserts()) + "\n";
        g_outputBuffer+="Deferred lookups: " + std::to_string(cache->getDeferredLookups()) + "\n";
        g_outputBuffer+="Lookup Collisions: " + std::to_string(cache->getLookupCollisions()) + "\n";
        g_outputBuffer+="Insert Collisions: " + std::to_string(cache->getInsertCollisions()) + "\n";
      });

    g_lua.writeFunction("getPool", [client](const string& poolName) {
        if (client) {
          return std::make_shared<ServerPool>();
        }
        auto localPools = g_pools.getCopy();
        std::shared_ptr<ServerPool> pool = createPoolIfNotExists(localPools, poolName);
        g_pools.setState(localPools);
        return pool;
      });
}
