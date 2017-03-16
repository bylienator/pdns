#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>

#include "arguments.hh"
#include "lua-recursor4.hh"
#include "namespaces.hh"
#include "rec-lua-conf.hh"
#include "syncres.hh"
#include "validate-recursor.hh"

std::unordered_set<DNSName> g_delegationOnly;
RecursorStats g_stats;
GlobalStateHolder<LuaConfigItems> g_luaconfs;
NetmaskGroup* g_dontQuery{nullptr};
__thread MemRecursorCache* t_RC{nullptr};
SyncRes::domainmap_t* g_initialDomainMap{nullptr};
unsigned int g_numThreads = 1;

/* Fake some required functions we didn't want the trouble to
   link with */
ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

int getMTaskerTID()
{
  return 0;
}

LuaConfigItems::LuaConfigItems()
{
}

bool RecursorLua4::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret)
{
  return false;
}

int asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res)
{
  return 0;
}

/* primeHints() is only here for now because it
   was way too much trouble to link with the real one.
   We should fix this, empty functions are one thing, but this is
   bad.
*/

#include "root-addresses.hh"

void primeHints(void)
{
  vector<DNSRecord> nsset;
  if(!t_RC)
    t_RC = new MemRecursorCache();

  DNSRecord arr, aaaarr, nsrr;
  nsrr.d_name=g_rootdnsname;
  arr.d_type=QType::A;
  aaaarr.d_type=QType::AAAA;
  nsrr.d_type=QType::NS;
  arr.d_ttl=aaaarr.d_ttl=nsrr.d_ttl=time(nullptr)+3600000;

  for(char c='a';c<='m';++c) {
    static char templ[40];
    strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
    templ[sizeof(templ)-1] = '\0';
    *templ=c;
    aaaarr.d_name=arr.d_name=DNSName(templ);
    nsrr.d_content=std::make_shared<NSRecordContent>(DNSName(templ));
    arr.d_content=std::make_shared<ARecordContent>(ComboAddress(rootIps4[c-'a']));
    vector<DNSRecord> aset;
    aset.push_back(arr);
    t_RC->replace(time(0), DNSName(templ), QType(QType::A), aset, vector<std::shared_ptr<RRSIGRecordContent>>(), true); // auth, nuke it all
    if (rootIps6[c-'a'] != NULL) {
      aaaarr.d_content=std::make_shared<AAAARecordContent>(ComboAddress(rootIps6[c-'a']));

      vector<DNSRecord> aaaaset;
      aaaaset.push_back(aaaarr);
      t_RC->replace(time(0), DNSName(templ), QType(QType::AAAA), aaaaset, vector<std::shared_ptr<RRSIGRecordContent>>(), true);
    }

    nsset.push_back(nsrr);
  }
  t_RC->replace(time(0), g_rootdnsname, QType(QType::NS), nsset, vector<std::shared_ptr<RRSIGRecordContent>>(), false); // and stuff in the cache
}

/* Some helpers functions */

static void init(bool debug=false)
{
  if (debug) {
    L.setName("test");
    L.setLoglevel((Logger::Urgency)(6)); // info and up
    L.disableSyslog(true);
    L.toConsole(Logger::Info);
  }

  seedRandom("/dev/urandom");

  if (g_dontQuery)
    delete g_dontQuery;
  g_dontQuery = new NetmaskGroup();

  if (t_RC)
    delete t_RC;
  t_RC = new MemRecursorCache();

  if (g_initialDomainMap)
    delete g_initialDomainMap;
  g_initialDomainMap = new SyncRes::domainmap_t(); // new threads needs this to be setup

  SyncRes::s_maxqperq = 50;
  SyncRes::s_maxtotusec = 1000*7000;
  SyncRes::s_maxdepth = 40;
  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxcachettl = 86400;
  SyncRes::s_packetcachettl = 3600;
  SyncRes::s_packetcacheservfailttl = 60;
  SyncRes::s_serverdownmaxfails = 64;
  SyncRes::s_serverdownthrottletime = 60;
  ::arg().set("ecs-ipv4-bits", "24");
  ::arg().set("ecs-ipv6-bits", "56");
}

static void initSR(std::unique_ptr<SyncRes>& sr, bool edns0, bool dnssec)
{
  struct timeval now;
  Utility::gettimeofday(&now, 0);
  sr = std::unique_ptr<SyncRes>(new SyncRes(now));
  sr->setDoEDNS0(edns0);
  sr->setDoDNSSEC(dnssec);
  t_sstorage->domainmap = g_initialDomainMap;
}

/* Real tests */

BOOST_AUTO_TEST_SUITE(syncres_cc)

BOOST_AUTO_TEST_CASE(test_root_primed) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  t_RC->doWipeCache(g_rootdnsname, true);

  primeHints();

  /* we are primed, we should be able to resolve NS . without any query */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed) {
  std::unique_ptr<SyncRes> sr;
  init(false);
  initSR(sr, true, false);
  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      //     cerr<<"asyncresolve called to ask "<<ip.toString()<<" about "<<domain.toString()<<" / "<<QType(type).getName()<<" over "<<(doTCP ? "TCP" : "UDP")<<" (rd: "<<sendRDQuery<<", EDNS0 level: "<<EDNS0Level<<")"<<endl;
      if (domain == g_rootdnsname && type == QType::NS) {
        res->d_rcode = 0;
        res->d_aabit = true;
        res->d_tcbit = false;
        res->d_haveEDNS = true;

        res->d_records.resize(3);
        res->d_records[0].d_name = g_rootdnsname;
        res->d_records[0].d_type = QType::NS;
        res->d_records[0].d_ttl = 3600;
        res->d_records[0].d_content = std::make_shared<NSRecordContent>(DNSName("a.root-servers.net."));
        res->d_records[1].d_name = DNSName("a.root-servers.net.");
        res->d_records[1].d_type = QType::A;
        res->d_records[1].d_ttl = 3600;
        res->d_records[1].d_content = std::make_shared<ARecordContent>(ComboAddress("198.41.0.4"));
        res->d_records[2].d_name = DNSName("a.root-servers.net.");
        res->d_records[2].d_type = QType::AAAA;
        res->d_records[2].d_ttl = 3600;
        res->d_records[2].d_content = std::make_shared<ARecordContent>(ComboAddress("2001:503:ba3e::2:30"));

        return 1;
      }

      return 0;
    });

  t_RC->doWipeCache(g_rootdnsname, true);

  /* we are not primed yet, so SyncRes will have to call primeHints()
     then call getRootNS(), for which at least one of the root servers needs to answer */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
}

BOOST_AUTO_TEST_CASE(test_root_not_primed_and_no_response) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  t_RC->doWipeCache(g_rootdnsname, true);

  /* we are not primed yet, so SyncRes will have to call primeHints()
     then call getRootNS(), for which at least one of the root servers needs to answer.
     None will, so it should ServFail.
  */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("."), QType(QType::NS), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 2);
}

BOOST_AUTO_TEST_CASE(test_edns_formerr_fallback) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      if (EDNS0Level != 0) {
        res->d_rcode = RCode::FormErr;
        return 1;
      }
      if (domain == DNSName("powerdns.com") && type == QType::A && !doTCP) {
        res->d_rcode = 0;
        res->d_aabit = true;
        res->d_tcbit = false;
        res->d_haveEDNS = false;

        res->d_records.resize(1);
        res->d_records[0].d_name = domain;
        res->d_records[0].d_type = QType::A;
        res->d_records[0].d_ttl = 60;
        res->d_records[0].d_content = std::make_shared<ARecordContent>(ComboAddress("192.0.2.1"));

        return 1;
      }

      return 0;
    });

  t_RC->doWipeCache(g_rootdnsname, true);
  primeHints();

  /* fake that the root NS doesn't handle EDNS, chceck that we fallback */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
}

BOOST_AUTO_TEST_CASE(test_edns_notimpl_fallback) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      if (EDNS0Level != 0) {
        res->d_rcode = RCode::NotImp;
        return 1;
      }
      if (domain == DNSName("powerdns.com") && type == QType::A && !doTCP) {
        res->d_rcode = 0;
        res->d_aabit = true;
        res->d_tcbit = false;
        res->d_haveEDNS = false;

        res->d_records.resize(1);
        res->d_records[0].d_name = domain;
        res->d_records[0].d_type = QType::A;
        res->d_records[0].d_ttl = 60;
        res->d_records[0].d_content = std::make_shared<ARecordContent>(ComboAddress("192.0.2.1"));

        return 1;
      }

      return 0;
    });

  t_RC->doWipeCache(g_rootdnsname, true);
  primeHints();

  /* fake that the NS doesn't handle EDNS, check that we fallback */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
}

BOOST_AUTO_TEST_CASE(test_tc_fallback_to_tcp) {
  std::unique_ptr<SyncRes> sr;
  init();
  initSR(sr, true, false);

  sr->setAsyncCallback([](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, std::shared_ptr<RemoteLogger> outgoingLogger, LWResult* res) {
      if (!doTCP) {
        res->d_rcode = 0;
        res->d_tcbit = true;
        res->d_haveEDNS = false;
        return 1;
      }
      if (domain == DNSName("powerdns.com") && type == QType::A && doTCP) {
        res->d_rcode = 0;
        res->d_aabit = true;
        res->d_tcbit = false;
        res->d_haveEDNS = false;

        res->d_records.resize(1);
        res->d_records[0].d_name = domain;
        res->d_records[0].d_type = QType::A;
        res->d_records[0].d_ttl = 60;
        res->d_records[0].d_content = std::make_shared<ARecordContent>(ComboAddress("192.0.2.1"));

        return 1;
      }

      return 0;
    });

  t_RC->doWipeCache(g_rootdnsname, true);
  primeHints();

  /* fake that the NS truncates every request over UDP, we should fallback to TCP */
  vector<DNSRecord> ret;
  int res = sr->beginResolve(DNSName("powerdns.com."), QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, 0);
}

BOOST_AUTO_TEST_SUITE_END()
