AC_DEFUN([PDNS_CHECK_LIBSECCOMP], [
  AC_MSG_CHECKING([whether we will be linking in libseccomp])
  AC_ARG_ENABLE([libseccomp],
    AS_HELP_STRING([--enable-libseccomp],[use libseccomp @<:@default=no@:>@]),
    [enable_libseccomp=$enableval],
    [enable_libseccomp=no],
  )
  AC_MSG_RESULT([$enable_libseccomp])

  AM_CONDITIONAL([LIBSECCOMP], [test "x$enable_libseccomp" != "xno"])

  AM_COND_IF([LIBSECCOMP], [
    PKG_CHECK_MODULES([LIBSECCOMP], [libseccomp], [
      AC_DEFINE([HAVE_SECCOMP], [1], [Define to 1 if you have libseccomp])
    ],[
      AC_MSG_ERROR([libseccomp requested but not available])
    ])
  ])
])
