dnl
dnl $Id:  $
dnl

PHP_ARG_WITH(opendkim, for OpenDKIM support,
[  --with-opendkim[=DIR]    Include OpenDKIM support (requires libopendkim)])

if test "$PHP_OPENDKIM" != "no"; then
  if test -r $PHP_OPENDKIM/include/dkim.h; then
    OPENDKIM_DIR=$PHP_OPENDKIM
  else
    AC_MSG_CHECKING(for OpenDKIM in default path)
    for i in /usr/local /usr; do
      if test -r $i/include/opendkim/dkim.h; then
        OPENDKIM_DIR=$i
        AC_MSG_RESULT(found in $i)
        break
      fi
    done
  fi

  if test -z "$OPENDKIM_DIR"; then
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR(Please reinstall the libopendkim distribution)
  fi

  PHP_CHECK_LIBRARY(opendkim, dkim_init, 
  [
    PHP_ADD_INCLUDE($OPENDKIM_DIR/include)
    PHP_ADD_LIBRARY_WITH_PATH(opendkim, $OPENDKIM_DIR/$PHP_LIBDIR, OPENDKIM_SHARED_LIBADD)
    AC_DEFINE(HAVE_OPENDKIM,1,[ ])
  ], [
    AC_MSG_ERROR(opendkim module requires libopendkim >= 1.0.0)
  ], [
    -L$OPENDKIM_DIR/$PHP_LIBDIR
  ])

  PHP_NEW_EXTENSION(opendkim, opendkim.c, $ext_shared)
  PHP_SUBST(OPENDKIM_SHARED_LIBADD)
fi
