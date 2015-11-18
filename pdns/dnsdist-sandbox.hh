
#if HAVE_SECCOMP
#include <seccomp.h>
#endif /* HAVE_SECCOMP */

class Sandbox
{
public:
  Sandbox()
  {
#if HAVE_SECCOMP
    seccomp_ctx = seccomp_init(SCMP_ACT_KILL);

    if (!seccomp_ctx) {
      throw PDNSError("error setting up the seccomp sandbox");
    }
#endif /* HAVE_SECCOMP */
  }

  int apply()
  {
#if HAVE_SECCOMP
    if (seccomp_ctx) {
      for (size_t idx = 0;
           idx < seccomp_rules_count;
           idx++) {
        seccomp_rule_add(seccomp_ctx, seccomp_rules[idx].action, seccomp_rules[idx].syscall, 0);
      }

      return seccomp_load(seccomp_ctx);
    }
#endif /* HAVE_SECCOMP */
    return 0;
  }
  
  ~Sandbox()
  {
#if HAVE_SECCOMP
    if (seccomp_ctx) {
      seccomp_release(seccomp_ctx);
      seccomp_ctx = 0;
    }
#endif /* HAVE_SECCOMP */
  }
  
private:
#if HAVE_SECCOMP
  scmp_filter_ctx seccomp_ctx{0};
  static const struct {
    const uint32_t action;
    const int syscall;
  } seccomp_rules[] = {
    /* receive queries */
    { SCMP_ACT_ALLOW, SCMP_SYS(recvmsg) },
    { SCMP_ACT_ALLOW, SCMP_SYS(recv) },

    /* accept TCP connections */
    { SCMP_ACT_ALLOW, SCMP_SYS(accept) },
    { SCMP_ACT_ALLOW, SCMP_SYS(setsockopt) },
    { SCMP_ACT_ALLOW, SCMP_SYS(poll) },
    { SCMP_ACT_ALLOW, SCMP_SYS(fcntl) },
    
    /* send responses */
    { SCMP_ACT_ALLOW, SCMP_SYS(sendto) },
    { SCMP_ACT_ALLOW, SCMP_SYS(send) },
    
    /* used by upCheck for health checks */
    { SCMP_ACT_ALLOW, SCMP_SYS(recvfrom) },

    /* to start the web server at runtime */
    { SCMP_ACT_ALLOW, SCMP_SYS(bind) },
    { SCMP_ACT_ALLOW, SCMP_SYS(listen) },

    /* connect to downstream servers / carbon */
    { SCMP_ACT_ALLOW, SCMP_SYS(socket) },
    { SCMP_ACT_ALLOW, SCMP_SYS(connect) },
    { SCMP_ACT_ALLOW, SCMP_SYS(close) },

    /* create new threads, synchronise */
    { SCMP_ACT_ALLOW, SCMP_SYS(clone) },
    { SCMP_ACT_ALLOW, SCMP_SYS(pipe) },
    { SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list) },
    { SCMP_ACT_ALLOW, SCMP_SYS(futex) },

    /* memory management */
    { SCMP_ACT_ALLOW, SCMP_SYS(brk) },
    { SCMP_ACT_ALLOW, SCMP_SYS(mmap) },
    { SCMP_ACT_ALLOW, SCMP_SYS(mprotect) },
    { SCMP_ACT_ALLOW, SCMP_SYS(munmap) },

    { SCMP_ACT_ALLOW, SCMP_SYS(read) },
    { SCMP_ACT_ALLOW, SCMP_SYS(write) },

    /* process */
    { SCMP_ACT_ALLOW, SCMP_SYS(exit) },
    { SCMP_ACT_ALLOW, SCMP_SYS(exit_group) },
    { SCMP_ACT_ALLOW, SCMP_SYS(nanosleep) },
    { SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime) },

    /* signals */
    { SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask) },
    { SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction) },

    /* files (/proc entries, webserver) */
    { SCMP_ACT_ALLOW, SCMP_SYS(open) },
    { SCMP_ACT_ALLOW, SCMP_SYS(stat) },
    { SCMP_ACT_ALLOW, SCMP_SYS(fstat) },
    { SCMP_ACT_ALLOW, SCMP_SYS(access) },
    { SCMP_ACT_ALLOW, SCMP_SYS(lseek) },

    /* needed for getOpenFileDescriptors */
    { SCMP_ACT_ALLOW, SCMP_SYS(getdents) },
    { SCMP_ACT_ALLOW, SCMP_SYS(getdents64) },

  };
  static const size_t seccomp_rules_count = sizeof seccomp_rules / sizeof *seccomp_rules;
#endif /* HAVE_SECCOMP */
};

  
