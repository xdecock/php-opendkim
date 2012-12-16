dnl
dnl $Id:  $
dnl

PHP_ARG_WITH(dkim, for DKIM support,
[  --with-dkim[=DIR]    Include DKIM support (requires libopendkim)])

if test "$PHP_DKIM" != "no"; then
  PHP_SUBST(DKIM_SHARED_LIBADD)
  PHP_ADD_LIBRARY(ssl, , DKIM_SHARED_LIBADD) 
  PHP_ADD_LIBRARY(opendkim, , DKIM_SHARED_LIBADD) 
  PHP_NEW_EXTENSION(opendkim, opendkim.c, $ext_shared)
fi
