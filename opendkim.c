/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2012 The PHP Group                                |
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>
#include <string.h>
#include <ext/standard/info.h>
#include <opendkim/dkim.h>
#include "php_opendkim.h"

int le_opendkim;
DKIM_LIB *opendkim_master;

static zend_class_entry *opendkim_class_entry;
static zend_class_entry *opendkim_sign_class_entry;
static zend_class_entry *opendkim_verify_class_entry;

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_header, 0)
    ZEND_ARG_INFO(0, header)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_body, 0)
    ZEND_ARG_INFO(0, body)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_chunk, 0)
    ZEND_ARG_INFO(0, chunk)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_sign_set_signer, 0)
    ZEND_ARG_INFO(0, signer)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_sign_set_margin, 0)
    ZEND_ARG_INFO(0, margin)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_sign_set_partial, 0)
    ZEND_ARG_INFO(0, partial)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_opendkim_sign_add_query_method, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_sign_add_xtag, 0)
    ZEND_ARG_INFO(0, tag)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_opendkim_sign___construct, 0, 0, 3)
    ZEND_ARG_INFO(0, privateKey)
    ZEND_ARG_INFO(0, selector)
    ZEND_ARG_INFO(0, domain)
    ZEND_ARG_INFO(0, headerCanon)
    ZEND_ARG_INFO(0, bodyCanon)
    ZEND_ARG_INFO(0, signatureAlgorithm)
    ZEND_ARG_INFO(0, bodyLength)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_opendkim_lib_feature, 0)
    ZEND_ARG_INFO(0, feature)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_opendkim_verify_checkatps, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO();

static zend_function_entry opendkim_sign_class_functions[] = {
	PHP_ME(opendkim,     header,            arginfo_opendkim_header,                ZEND_ACC_PUBLIC)
	PHP_ME(opendkim,     eoh,               NULL,                                   ZEND_ACC_PUBLIC)
	PHP_ME(opendkim,     body,              arginfo_opendkim_body,                  ZEND_ACC_PUBLIC)
	PHP_ME(opendkim,     eom,               NULL,                                   ZEND_ACC_PUBLIC)
	PHP_ME(opendkim,     chunk,             arginfo_opendkim_chunk,                 ZEND_ACC_PUBLIC)
    PHP_ME(opendkim,     getError,          NULL,                                   ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, getSignatureHeader,NULL,                                   ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, loadPrivateKey,    NULL,                                   ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, setSigner,         arginfo_opendkim_sign_set_signer,       ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, setMargin,         arginfo_opendkim_sign_set_margin,       ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, setPartial,        arginfo_opendkim_sign_set_partial,      ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, addQueryMethod,    arginfo_opendkim_sign_add_query_method, ZEND_ACC_PUBLIC)
    PHP_ME(opendkimSign, addXtag,           arginfo_opendkim_sign_add_xtag,         ZEND_ACC_PUBLIC)
	PHP_ME(opendkimSign, __construct,       arginfo_opendkim_sign___construct,      ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};

static zend_function_entry opendkim_verify_class_functions[] = {
	PHP_ME(opendkimVerify, __construct,     NULL,                                   ZEND_ACC_PUBLIC)
	PHP_ME(opendkimFree, __destruct,        NULL,                                   ZEND_ACC_PUBLIC)
    PHP_ME(opendkimVerify, checkATPS,       arginfo_opendkim_verify_checkatps,      ZEND_ACC_PUBLIC)
    PHP_ME(opendkimVerify, getDomain,       NULL,                                   ZEND_ACC_PUBLIC)
    PHP_ME(opendkimVerify, getUser,         NULL,                                   ZEND_ACC_PUBLIC)
    PHP_ME(opendkimVerify, getMinBodyLen,   NULL,                                   ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};


static zend_function_entry opendkim_class_functions[] = {
    PHP_ME(opendkim,    libFeature,         arginfo_opendkim_lib_feature,           ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(opendkim,    flushCache,         NULL,                                   ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_ME(opendkim,    getCacheStats,      NULL,                                   ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    {NULL, NULL, NULL}
};

zend_module_entry opendkim_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	PHP_OPENDKIM_EXTNAME,
	NULL,
	PHP_MINIT(opendkim),
	PHP_MSHUTDOWN(opendkim),
	NULL,
	NULL,
	PHP_MINFO(opendkim),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_OPENDKIM_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OPENDKIM
ZEND_GET_MODULE(opendkim)
#endif

/* opendkim handlers */
PHP_OPENDKIM_EXPORT(zend_object_value) opendkim_object_handler_new(zend_class_entry *class_type TSRMLS_DC)
{
	zend_object_value retval;
	opendkim_object_handler *intern;


	intern = emalloc(sizeof(opendkim_object_handler));
	memset(intern, 0, sizeof(opendkim_object_handler));
	intern->handler = NULL;

	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	retval.handle = zend_objects_store_put(intern, (zend_objects_store_dtor_t) zend_objects_destroy_object, opendkim_object_handler_free_storage, NULL TSRMLS_CC);
    retval.handlers = zend_get_std_object_handlers();    

	return retval;
}

static void opendkim_object_handler_free_storage(void *object TSRMLS_DC)
{
   	zend_object *zo = (zend_object *)object;
	opendkim_object_handler *intern = (opendkim_object_handler *)object;
    DKIM *dkim;

    dkim = intern->handler;
    if (dkim) {
    	dkim_free(dkim);
    }
    intern->handler = NULL;
    zend_object_std_dtor(zo TSRMLS_CC);
    efree(intern);
}

/* opendkim query infos */
PHP_OPENDKIM_EXPORT(zend_object_value) opendkim_object_queryinfo_new(zend_class_entry *class_type TSRMLS_DC)
{
	zend_object_value retval;
	opendkim_object_queryinfo *intern;


	intern = emalloc(sizeof(opendkim_object_queryinfo));
	memset(intern, 0, sizeof(opendkim_object_queryinfo));
	intern->queryinfo = NULL;

	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	retval.handle = zend_objects_store_put(intern, (zend_objects_store_dtor_t) zend_objects_destroy_object, opendkim_object_queryinfo_free_storage, NULL TSRMLS_CC);
    retval.handlers = zend_get_std_object_handlers();    

	return retval;
}

static void opendkim_object_queryinfo_free_storage(void *object TSRMLS_DC)
{
   	zend_object *zo = (zend_object *)object;
	opendkim_object_queryinfo *intern = (opendkim_object_queryinfo *)object;
    DKIM_QUERYINFO *queryinfo;

    queryinfo = intern->queryinfo;
    if (queryinfo) {
    	efree(queryinfo);
    }
    intern->queryinfo = NULL;
    zend_object_std_dtor(zo TSRMLS_CC);
    efree(intern);
}

/* opendkim signature infos */
PHP_OPENDKIM_EXPORT(zend_object_value) opendkim_object_siginfo_new(zend_class_entry *class_type TSRMLS_DC)
{
	zend_object_value retval;
	opendkim_object_siginfo *intern;


	intern = emalloc(sizeof(opendkim_object_siginfo));
	memset(intern, 0, sizeof(opendkim_object_siginfo));
	intern->siginfo = NULL;

	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	retval.handle = zend_objects_store_put(intern, (zend_objects_store_dtor_t) zend_objects_destroy_object, opendkim_object_siginfo_free_storage, NULL TSRMLS_CC);
    retval.handlers = zend_get_std_object_handlers();    

	return retval;
}

static void opendkim_object_siginfo_free_storage(void *object TSRMLS_DC)
{
   	zend_object *zo = (zend_object *)object;
	opendkim_object_siginfo *intern = (opendkim_object_siginfo *)object;
    DKIM_QUERYINFO *siginfo;

    intern->siginfo = NULL;
    zend_object_std_dtor(zo TSRMLS_CC);
    efree(intern);
}

/* opendkim policy states */
PHP_OPENDKIM_EXPORT(zend_object_value) opendkim_object_pstate_new(zend_class_entry *class_type TSRMLS_DC)
{
	zend_object_value retval;
	opendkim_object_pstate *intern;


	intern = emalloc(sizeof(opendkim_object_pstate));
	memset(intern, 0, sizeof(opendkim_object_pstate));
	intern->pstate = NULL;

	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	retval.handle = zend_objects_store_put(intern, (zend_objects_store_dtor_t) zend_objects_destroy_object, opendkim_object_pstate_free_storage, NULL TSRMLS_CC);
    retval.handlers = zend_get_std_object_handlers();    

	return retval;
}

static void opendkim_object_pstate_free_storage(void *object TSRMLS_DC)
{
   	zend_object *zo = (zend_object *)object;
	opendkim_object_pstate *intern = (opendkim_object_pstate *) object;
    DKIM_PSTATE *pstate;

    pstate = intern->pstate;
    if (pstate) {
    	dkim_policy_state_free(pstate);
    }
    intern->pstate = NULL;
    zend_object_std_dtor(zo TSRMLS_CC);
    efree(intern);
}

/* emalloc wrapper */
void * opendkim_mallocf(void *closure, size_t nbytes) {
    return emalloc(nbytes);
}
void opendkim_freef(void *closure, void *p) {
    return efree(p);
}
/* END emalloc wrapper */

/* INIT / SHUTDOWN */
PHP_MINIT_FUNCTION(opendkim)
{
	u_int options;
	DKIM_STAT status=0;

    /* Use PHP Memory */
	opendkim_master=dkim_init(opendkim_mallocf, opendkim_freef);
	if (opendkim_master==NULL){
		return FAILURE;
	}

    /* Class Registration OpenDKIM */
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "OpenDKIM", opendkim_class_functions);
	opendkim_class_entry = zend_register_internal_class_ex(&ce, NULL, NULL TSRMLS_CC);
    /* Class Registration OpenDKIMSign */
	zend_class_entry ces;
	INIT_CLASS_ENTRY(ces, "OpenDKIMSign", opendkim_sign_class_functions);
    ces.create_object=opendkim_object_handler_new;
	opendkim_sign_class_entry = zend_register_internal_class_ex(&ces, NULL, NULL TSRMLS_CC);

    /* Class constants OpenDKIM */
    zend_declare_class_constant_long(opendkim_class_entry, "OPENSSL_VERSION",           sizeof("OPENSSL_VERSION")-1,            (long)dkim_ssl_version() TSRMLS_CC);
    /* Features block */ 
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_DIFFHEADERS",       sizeof("FEATURE_DIFFHEADERS")-1,        (long)DKIM_FEATURE_DIFFHEADERS TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_DKIM_REPUTATION",   sizeof("FEATURE_DKIM_REPUTATION")-1,    (long)DKIM_FEATURE_DKIM_REPUTATION TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_PARSE_TIME",        sizeof("FEATURE_PARSE_TIME")-1,         (long)DKIM_FEATURE_PARSE_TIME TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_QUERY_CACHE",       sizeof("FEATURE_QUERY_CACHE")-1,        (long)DKIM_FEATURE_QUERY_CACHE TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_SHA256",            sizeof("FEATURE_SHA256")-1,             (long)DKIM_FEATURE_SHA256 TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_DNSSEC",            sizeof("FEATURE_DNSSEC")-1,             (long)DKIM_FEATURE_DNSSEC TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "FEATURE_OVERSIGN",          sizeof("FEATURE_OVERSIGN")-1,           (long)DKIM_FEATURE_OVERSIGN TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_OK",                   sizeof("STAT_OK")-1,                    (long)DKIM_STAT_OK TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_BADSIG",               sizeof("STAT_BADSIG")-1,                (long)DKIM_STAT_BADSIG TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_NOSIG",                sizeof("STAT_NOSIG")-1,                 (long)DKIM_STAT_NOSIG TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_NOKEY",                sizeof("STAT_NOKEY")-1,                 (long)DKIM_STAT_NOKEY TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_CANTVRFY",             sizeof("STAT_CANTVRFY")-1,              (long)DKIM_STAT_CANTVRFY TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_SYNTAX",               sizeof("STAT_SYNTAX")-1,                (long)DKIM_STAT_SYNTAX TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_NORESOURCE",           sizeof("STAT_NORESOURCE")-1,            (long)DKIM_STAT_NORESOURCE TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_INTERNAL",             sizeof("STAT_INTERNAL")-1,              (long)DKIM_STAT_INTERNAL TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_REVOKED",              sizeof("STAT_REVOKED")-1,               (long)DKIM_STAT_REVOKED TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_NOTIMPLEMENT",         sizeof("STAT_NOTIMPLEMENT")-1,          (long)DKIM_STAT_NOTIMPLEMENT TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_KEYFAIL",              sizeof("STAT_KEYFAIL")-1,               (long)DKIM_STAT_KEYFAIL TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_CBREJECT",             sizeof("STAT_CBREJECT")-1,              (long)DKIM_STAT_CBREJECT TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_CBTRYAGAIN",           sizeof("STAT_CBTRYAGAIN")-1,            (long)DKIM_STAT_CBTRYAGAIN TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_class_entry, "STAT_CBERROR",              sizeof("STAT_CBERROR")-1,               (long)DKIM_STAT_CBERROR TSRMLS_CC);

    /* Class constants OpenDKIMSign */
    zend_declare_class_constant_long(opendkim_sign_class_entry, "CANON_RELAXED", sizeof("CANON_RELAXED")-1, (long)DKIM_CANON_RELAXED TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_sign_class_entry, "CANON_SIMPLE", sizeof("CANON_SIMPLE")-1, (long)DKIM_CANON_SIMPLE TSRMLS_CC);
    zend_declare_class_constant_long(opendkim_sign_class_entry, "ALG_RSASHA1", sizeof("ALG_RSASHA1")-1, (long)DKIM_SIGN_RSASHA1 TSRMLS_CC);
#ifdef DKIM_SIGN_RSASHA256
    zend_declare_class_constant_long(opendkim_sign_class_entry, "ALG_RSASHA256", sizeof("ALG_RSASHA256")-1, (long)DKIM_SIGN_RSASHA256 TSRMLS_CC);
#endif

    return SUCCESS;
}
/* END INIT/SHUTDOWN */

PHP_MSHUTDOWN_FUNCTION(opendkim)
{
	dkim_close(opendkim_master);
	return SUCCESS;
}

/*** Module Infos ***/
PHP_MINFO_FUNCTION(opendkim)
{
    char buf[250];
	php_info_print_table_start();
	php_info_print_table_header(2, "OpenDKIM support", "enabled");
	php_info_print_table_row(2, "OpenDKIM Extension Version", PHP_OPENDKIM_VERSION);
    opendkim_runtime_version(buf);
	php_info_print_table_row(2, "Lib OpenDKIM Version", buf);
    php_info_print_table_row(2, "Diff Headers", dkim_libfeature(opendkim_master, DKIM_FEATURE_DIFFHEADERS)?"enabled":"disabled");
    php_info_print_table_row(2, "DKIM Reputation", dkim_libfeature(opendkim_master, DKIM_FEATURE_DKIM_REPUTATION)?"enabled":"disabled");
    php_info_print_table_row(2, "Parse Time", dkim_libfeature(opendkim_master, DKIM_FEATURE_PARSE_TIME)?"enabled":"disabled");
    php_info_print_table_row(2, "Query Cache", dkim_libfeature(opendkim_master, DKIM_FEATURE_QUERY_CACHE)?"enabled":"disabled");
    php_info_print_table_row(2, "DNSSEC", dkim_libfeature(opendkim_master, DKIM_FEATURE_DNSSEC)?"enabled":"disabled");
    php_info_print_table_row(2, "Oversign", dkim_libfeature(opendkim_master, DKIM_FEATURE_OVERSIGN)?"enabled":"disabled");
    php_info_print_table_row(2, "SHA1", "enabled");
    php_info_print_table_row(2, "SHA-256", dkim_libfeature(opendkim_master, DKIM_FEATURE_SHA256)?"enabled":"disabled");
#ifdef dkim_add_querymethod
    php_info_print_table_row(2, "AddQueryMethod", "enabled");
#else
    php_info_print_table_row(2, "AddQueryMethod", "disabled");
#endif
    php_info_print_table_row(2, "Canon: Simple", "enabled");
    php_info_print_table_row(2, "Canon: Relaxed", "enabled");
	php_info_print_table_end();
}

/* LibVersion to String */
opendkim_runtime_version(char *buf) {
    int version;
    version = dkim_libversion();
    int release, major, minor, patch;
    release = (version & 0xFF000000)>>24;
    major   = (version & 0x00FF0000)>>16;
    minor   = (version & 0x0000FF00)>>8;
    patch   = (version & 0x000000FF);
    sprintf(buf, "%u.%u.%u-p%u", release, major, minor, patch);
}

/*** The Functions by themselves ***/
/* {{{ proto void OpenDKIMSign(privateKey, selector, domain[, header_canon[, body_canon[, sign_alg[, body_length]]]])
    constructor
*/
PHP_METHOD(opendkimSign, __construct)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	char *privateKey;
	int   privateKeyLen;
	char *selector;
	int   selectorLen;
	char *domain;
	int   domainLen;
	dkim_canon_t header_canon=DKIM_CANON_RELAXED, body_canon=DKIM_CANON_RELAXED;
	dkim_alg_t sign_alg=DKIM_SIGN_RSASHA1;
	long body_length=-1;
    zval *opendkim_ressource;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|llll", &privateKey, &privateKeyLen, &selector, &selectorLen, &domain, &domainLen, &header_canon, &body_canon, &sign_alg, &body_length) == FAILURE) {
        RETURN_NULL();
    }

	dkim=dkim_sign(opendkim_master, "", NULL, privateKey, selector, domain, header_canon, body_canon, sign_alg, body_length, &status);
	if (status!=DKIM_STAT_OK){
        RETURN_BOOL(0);
	} else {
        OPENDKIM_HANDLER_SETPOINTER(dkim);
    }
}/* }}} */

/* {{{ proto boolean 

/* {{{ proto boolean header(header)
 */
PHP_METHOD(opendkim, header)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	char *header;
	int   headerLen;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &header, &headerLen) == FAILURE) {
        RETURN_NULL();
    }

	status=dkim_header(dkim, header, headerLen);
	if (status!=DKIM_STAT_OK){
        RETURN_BOOL(0);
	} else {
    	RETURN_BOOL(1);
    }
}/* }}} */

/* {{{ proto boolean body(chunk)
 */
PHP_METHOD(opendkim, body)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *body;
	int   bodyLen;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &body, &bodyLen) == FAILURE) {
        RETURN_NULL();
    }

	status=dkim_body(dkim, body, bodyLen);
	if (status!=DKIM_STAT_OK){
    	RETURN_BOOL(0);
	} else {
    	RETURN_BOOL(1);
    }
}/* }}} */

/* {{{ proto boolean chunk(chunk)
 */
PHP_METHOD(opendkim, chunk)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *body=NULL;
	int   bodyLen=-1;
	zend_bool end;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &body, &bodyLen) == FAILURE) {
        RETURN_NULL();
    }
    if (bodyLen==0){
    	RETURN_BOOL(1);
    }

	if (bodyLen==-1 && body==NULL){
		status=dkim_chunk(dkim, NULL, 0);
	} else {
		status=dkim_chunk(dkim, body, bodyLen);
	}
	if (status!=DKIM_STAT_OK){
		RETURN_BOOL(0);
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto boolean eoh()
 */
PHP_METHOD(opendkim, eoh)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;

    OPENDKIM_HANDLER_GETPOINTER(dkim);

	status=dkim_eoh(dkim);
	if (status!=DKIM_STAT_OK){
		RETURN_BOOL(0);
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto int eom()
 */
PHP_METHOD(opendkim, eom)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;

    OPENDKIM_HANDLER_GETPOINTER(dkim);

	status=dkim_eom(dkim, 0);
	RETURN_LONG(status);
}/* }}} */

/* {{{ proto string getError()
 */
PHP_METHOD(opendkim, getError)
{
	zval *z_dk_ressource;
	DKIM *dkim;
    const char *error;

    OPENDKIM_HANDLER_GETPOINTER(dkim);

    error=dkim_geterror(dkim);
    if (error==NULL) {
        RETURN_BOOL(0);
    }
    RETURN_STRING(error, 1);
}/* }}} */

/* {{{ proto bool loadPrivateKey() 
 */
PHP_METHOD(opendkimSign, loadPrivateKey)
{
	zval *z_dk_ressource;
	DKIM *dkim;
    DKIM_STAT status;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
    
    status = dkim_privkey_load(dkim);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    } else {
        RETURN_BOOL(1);
    }
} /* }}} */

/* {{{ proto bool setSigner(signer) 
 */
PHP_METHOD(opendkimSign, setSigner)
{
	zval *z_dk_ressource;
	DKIM *dkim;
	char *signer;
	int   signerLen;
    DKIM_STAT status;
    const char *signer2;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &signer, &signerLen) == FAILURE) {
        RETURN_NULL();
    }
    status=dkim_set_signer(dkim, signer);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
} /* }}} */

/* {{{ proto bool setMargin(margin) 
 */
PHP_METHOD(opendkimSign, setMargin)
{
	zval *z_dk_ressource;
	DKIM *dkim;
    long margin;
    DKIM_STAT status;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &margin) == FAILURE) {
        RETURN_NULL();
    }

    status=dkim_set_margin(dkim, margin);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
} /* }}} */

/* {{{ proto bool setPartial(partial) 
 */
PHP_METHOD(opendkimSign, setPartial)
{
	zval *z_dk_ressource;
	DKIM *dkim;
	zend_bool partial = 0;
    DKIM_STAT status;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &partial) == FAILURE) {
        RETURN_NULL();
    }

    status=dkim_setpartial(dkim, partial);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
} /* }}} */

/* {{{ proto bool addQueryMethod(method[, options]) 
 */
PHP_METHOD(opendkimSign, addQueryMethod)
{
#ifndef dkim_add_querymethod
    RETURN_BOOL(0);
#else
	zval *z_dk_ressource;
	DKIM *dkim;
	char *method;
	int   methodLen;
	char *options;
	int   optionsLen = -1;
    DKIM_STAT status;
    
    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &method, &methodLen, &options, &optionsLen) == FAILURE) {
        RETURN_NULL();
    }

    if (optionsLen==-1) {
        status=dkim_add_querymethod(dkim, method, NULL);
    } else {
        status=dkim_add_querymethod(dkim, method, options);
    }
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
#endif
} /* }}} */

/* {{{ proto bool addXtag(tag, value)
 */
PHP_METHOD(opendkimSign, addXtag)
{
	zval *z_dk_ressource;
	DKIM *dkim;
	char *tag;
	int   tagLen;
	char *value;
	int   valueLen = -1;
    DKIM_STAT status;
    
    OPENDKIM_HANDLER_GETPOINTER(dkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &tag, &tagLen, &value, &valueLen) == FAILURE) {
        RETURN_NULL();
    }

    status=dkim_add_xtag(dkim, tag, value);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
}

/* {{{ proto string getSignatureHeader()
 */
PHP_METHOD(opendkimSign, getSignatureHeader)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
#ifndef dkim_getsighdr_d 
	char buffer[4096]="";
#else
    char *buffer;
    size_t blen;
#endif

    OPENDKIM_HANDLER_GETPOINTER(dkim);

#ifdef dkim_getsighdr_d 
    status=dkim_getsighdr_d(dkim, 16, &buffer, &blen);
#else
#if OPENDKIM_LIB_VERSION<0x02060000
	status=dkim_getsighdr(dkim, buffer, 4096, 75, 16);
#else
	status=dkim_getsighdr(dkim, buffer, 4096, 16);
#endif
#endif
	if (status!=DKIM_STAT_OK){
		RETURN_BOOL(0);
	}
#ifdef dkim_getsighdr_d 
	RETURN_STRINGL(buffer, blen, 1);
#else
	RETURN_STRING(buffer, 1);
#endif
}/* }}} */

/* OpenDKIMVerify */
/* {{{ proto void OpenDKIMVerify()
    constructor
 */
PHP_METHOD(opendkimVerify, __construct)
{
	DKIM *dkim;
	DKIM_STAT status=0;
    zval *opendkim_ressource;

	dkim=dkim_verify(opendkim_master, "", NULL, &status);
	if (status!=DKIM_STAT_OK){
        RETURN_BOOL(0);
	} else {
        OPENDKIM_HANDLER_SETPOINTER(dkim);
    }
}/* }}} */

/* {{{ proto checkATPS([timeout])
 */
PHP_METHOD(opendkimVerify, checkATPS) 
{
	DKIM *dkim;
	DKIM_STAT status=0;
    DKIM_SIGINFO *sig;
    long timeout = -1;
    struct timeval tval;
    dkim_atps_t res;

    OPENDKIM_HANDLER_GETPOINTER(dkim);
 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &timeout) == FAILURE) {
        RETURN_NULL();
    }
    if (timeout != -1) {
        tval.tv_sec=floor(timeout/1000);
        tval.tv_usec=((timeout%1000)*1000);
        status = dkim_atps_check(dkim, sig, &tval, &res);
    } else {
        status = dkim_atps_check(dkim, sig, NULL, &res);
    }
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_LONG(status);
}/* }}} */

/* {{{ proto string openDKIMVerify::getDomain()
 */
PHP_METHOD(opendkimVerify, getDomain)
{
	DKIM *dkim;
	char *domain;
    OPENDKIM_HANDLER_GETPOINTER(dkim);
    domain = dkim_getdomain(dkim);
    if (domain == NULL) {
        RETURN_BOOL(0);
    }
    RETURN_STRING(domain, 1);
}/* }}} */

/* {{{ proto string openDKIMVerify::getUser()
 */
PHP_METHOD(opendkimVerify, getUser)
{
	DKIM *dkim;
	char *user;
    OPENDKIM_HANDLER_GETPOINTER(dkim);
    user = dkim_getuser(dkim);
    if (user == NULL) {
        RETURN_BOOL(0);
    }
    RETURN_STRING(user, 1);
}/* }}} */

/* {{{ proto string openDKIMVerify::getMinBodyLen()
 */
PHP_METHOD(opendkimVerify, getMinBodyLen)
{
	DKIM *dkim;
	unsigned long bodylen;
    OPENDKIM_HANDLER_GETPOINTER(dkim);
    bodylen = dkim_minbody(dkim);
    RETURN_LONG(bodylen);
}/* }}} */

/* End OpenDKIMSigner */

/* Static object utils */ 

/* {{{ proto int openDKIM::flushCache()
 */
PHP_METHOD(opendkim, flushCache)
{
    int status;
	status=dkim_flush_cache(opendkim_master);
    if (status>0) {
        RETURN_LONG(status);
    } else {
        RETURN_BOOL(0);
    }
}/* }}} */

/* {{{ proto int openDKIM::libFeature()
 */
PHP_METHOD(opendkim, libFeature)
{
    int status;
    long feature;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &feature) == FAILURE) {
        RETURN_NULL();
    }
    if (dkim_libfeature(opendkim_master, (u_int)feature)) {
        RETURN_BOOL(1);
    } else {
        RETURN_BOOL(0);
    }
}/* }}} */

/* {{{ proto int openDKIM::getCacheStats()
 */
PHP_METHOD(opendkim, getCacheStats)
{
    DKIM_STAT status;
    u_int queries, hits, expired;
	status=dkim_getcachestats(&queries, &hits, &expired);
    if (status != DKIM_STAT_OK) {
        RETURN_BOOL(0);
    } else {
        array_init(return_value);
        add_assoc_long(return_value, "queries", queries);
        add_assoc_long(return_value, "hits",    hits);
        add_assoc_long(return_value, "expired", expired);
    }
}/* }}} */

/* {{{ proto bool openDKIM::setOption(option, value)
 */
PHP_METHOD(opendkim, setOption)
{
} /* }}} */


