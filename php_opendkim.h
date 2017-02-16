/*
  ----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2007 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Xavier De Cock <void@php.net>                                |
  +----------------------------------------------------------------------+

  $Id: $
*/
#include <php.h>
#include <opendkim/dkim.h>
#ifdef ZTS
#include "TSRM.h"
#endif

#ifndef PHP_OPENDKIM_H
#define PHP_OPENDKIM_H 1

#define PHP_OPENDKIM_VERSION "0.9.1-dev-minemaz"
#define PHP_OPENDKIM_EXTNAME "opendkim"

#define BUFRSZ 1024
#define MAXADDRESS 256

#if ZEND_MODULE_API_NO >= 20151012
#define TSRMLS_DC
#define TSRMLS_CC
typedef zend_object* opendkim_zend_object;
#else
typedef zend_object_value opendkim_zend_object;
#endif

typedef struct _opendkim_object_handler {
#if ZEND_MODULE_API_NO >= 20151012
	DKIM                *handler;
	zend_object 		zo;
#else
	zend_object 		zo;
	DKIM                *handler;
#endif
} opendkim_object_handler; /* extends zend_object */

#if ZEND_MODULE_API_NO >= 20151012
#else
typedef struct _opendkim_object_pstate {
	zend_object 		zo;
} opendkim_object_pstate; /* extends zend_object */
#endif

typedef struct _opendkim_object_queryinfo {
#if ZEND_MODULE_API_NO >= 20151012
	DKIM_QUERYINFO      *queryinfo;
	zend_object 		zo;
#else
	zend_object 		zo;
	DKIM_QUERYINFO      *queryinfo;
#endif
} opendkim_object_queryinfo; /* extends zend_object */

typedef struct _opendkim_object_siginfo {
#if ZEND_MODULE_API_NO >= 20151012
	DKIM_SIGINFO        *siginfo;
	zend_object 		zo;
#else
	zend_object 		zo;
	DKIM_SIGINFO        *siginfo;
#endif
} opendkim_object_siginfo; /* extends zend_object */

static inline opendkim_object_handler *php_opendkim_obj_from_obj(zend_object *obj) {
  return (opendkim_object_handler *)((char*)(obj) - XtOffsetOf(opendkim_object_handler, zo));
}

static inline opendkim_object_queryinfo *php_opendkim_queryinfo_from_obj(zend_object *obj) {
  return (opendkim_object_queryinfo*)((char*)(obj) - XtOffsetOf(opendkim_object_queryinfo, zo));
}

void opendkim_runtime_version(char *buf);

ZEND_BEGIN_MODULE_GLOBALS(opendkim)
	DKIM_LIB *opendkim_master;
ZEND_END_MODULE_GLOBALS(opendkim)

#ifdef ZTS
#define OPENDKIM_G(v) TSRMG(opendkim_globals_id, zend_opendkim_globals *, v)
#else
#define OPENDKIM_G(v) (opendkim_globals.v)
#endif

PHP_MINIT_FUNCTION(opendkim);
PHP_MSHUTDOWN_FUNCTION(opendkim);
PHP_RINIT_FUNCTION(opendkim);
PHP_RSHUTDOWN_FUNCTION(opendkim);
PHP_MINFO_FUNCTION(opendkim);

/*** The Functions by themselves ***/
PHP_METHOD(opendkim, header);
PHP_METHOD(opendkim, body);
PHP_METHOD(opendkim, chunk);
PHP_METHOD(opendkim, eoh);
PHP_METHOD(opendkim, eom);
PHP_METHOD(opendkim, getError);
PHP_METHOD(opendkim, policySyntax);
/* End Shared Methods */
PHP_METHOD(opendkim, getCacheStats);
PHP_METHOD(opendkim, libFeature);
PHP_METHOD(opendkim, flushCache);
PHP_METHOD(opendkim, setOption);
PHP_METHOD(opendkimFree, __destruct); /* Common function */
PHP_METHOD(opendkimSign, __construct);
PHP_METHOD(opendkimSign, loadPrivateKey);
PHP_METHOD(opendkimSign, setMargin);
PHP_METHOD(opendkimSign, setSigner);
PHP_METHOD(opendkimSign, setPartial);
PHP_METHOD(opendkimSign, addQueryMethod);
PHP_METHOD(opendkimSign, addXtag);
PHP_METHOD(opendkimSign, getSignatureHeader);

PHP_METHOD(opendkimVerify, __construct);
PHP_METHOD(opendkimVerify, checkATPS);
PHP_METHOD(opendkimVerify, getDomain);
PHP_METHOD(opendkimVerify, getUser);
PHP_METHOD(opendkimVerify, getMinBodyLen);
PHP_METHOD(opendkimVerify, getARSigs);

#if ZEND_MODULE_API_NO >= 20151012
static void opendkim_object_handler_free_storage(struct _zend_object *object);
static void opendkim_object_pstate_free_storage(struct _zend_object *object);
static void opendkim_object_queryinfo_free_storage(struct _zend_object *object);
static void opendkim_object_siginfo_free_storage(struct _zend_object *object);
#else
static void opendkim_object_handler_free_storage(void *object TSRMLS_DC);
static void opendkim_object_pstate_free_storage(void *object TSRMLS_DC);
static void opendkim_object_queryinfo_free_storage(void *object TSRMLS_DC);
static void opendkim_object_siginfo_free_storage(void *object TSRMLS_DC);
#endif

extern zend_module_entry opendkim_module_entry;


#define phpext_opendkim_ptr &opendkim_module_entry

#ifdef PHP_WIN32
#define PHP_OPENDKIM_API __declspec(dllexport)
#else
# if defined(__GNUC__) && __GNUC__ >= 4
#  define PHP_OPENDKIM_API __attribute__ ((visibility("default")))
# else
#  define PHP_OPENDKIM_API
# endif
#endif

#define PHP_OPENDKIM_EXPORT(__type) PHP_OPENDKIM_API __type

#if ZEND_MODULE_API_NO >= 20151012
#  define PHP_OPENDKIM_OBJ_FROM_ZVAL(zv) php_opendkim_obj_from_obj(Z_OBJ_P(zv))->handler
#  define OPENDKIM_HANDLER_GETPOINTER(dest) dest = PHP_OPENDKIM_OBJ_FROM_ZVAL(getThis())
#  define OPENDKIM_HANDLER_SETPOINTER(source) PHP_OPENDKIM_OBJ_FROM_ZVAL(getThis())=source
#else
#  define OPENDKIM_HANDLER_GETPOINTER(dest) dest = ((opendkim_object_handler *) zend_object_store_get_object(getThis() TSRMLS_CC))->handler
#  define OPENDKIM_HANDLER_SETPOINTER(source) ((opendkim_object_handler *) zend_object_store_get_object(getThis() TSRMLS_CC))->handler=source
#endif

#if ZEND_MODULE_API_NO >= 20151012
#  define PHP_OPENDKIM_QUERYINFO_FROM_ZVAL(zv) php_opendkim_queryinfo_from_obj(Z_OBJ_P(zv))->handler
#  define OPENDKIM_QUERYINFO_GETPOINTER(dest) dest = PHP_OPENDKIM_QUERYINFO_FROM_ZVAL(getThis())
#  define OPENDKIM_QUERYINFO_SETPOINTER(source) PHP_OPENDKIM_QUERYINFO_FROM_ZVAL(getThis())=source
#else
#  define OPENDKIM_QUERYINFO_GETPOINTER(dest) dest = ((opendkim_object_queryinfo *) zend_object_store_get_object(getThis() TSRMLS_CC))->handler
#  define OPENDKIM_QUERYINFO_SETPOINTER(source) ((opendkim_object_queryinfo *) zend_object_store_get_object(getThis() TSRMLS_CC))->handler=source
#endif

#if ZEND_MODULE_API_NO >= 20151012
#  define PHP_OPENDKIM_SIGINFO_FROM_ZVAL(zv) php_opendkim_queryinfo_from_obj(Z_OBJ_P(zv))->handler
#  define OPENDKIM_SIGINFO_GETPOINTER(dest) dest = PHP_OPENDKIM_SIGINFO_FROM_ZVAL(getThis())
#  define OPENDKIM_SIGINFO_SETPOINTER(source) PHP_OPENDKIM_SIGINFO_FROM_ZVAL(getThis())=source
#else
#  define OPENDKIM_SIGINFO_GETPOINTER(dest) dest = ((opendkim_object_queryinfo *) zend_object_store_get_object(getThis() TSRMLS_CC))->handler
#  define OPENDKIM_SIGINFO_SETPOINTER(source) ((opendkim_object_queryinfo *) zend_object_store_get_object(getThis() TSRMLS_CC))->handler=source
#endif

#endif
