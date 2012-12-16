/*
  +----------------------------------------------------------------------+
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>
#include <string.h>
#include <ext/standard/info.h>
#ifndef bool
    typedef int bool;
#   define false	0
#   define true		1
#endif
#include <opendkim/dkim.h>
#include <openssl/evp.h>
#include "php_opendkim.h"

int le_opendkim;
DKIM_LIB *opendkim_master;

static zend_class_entry *opendkim_sign_class_entry;
static zend_function_entry opendkim_sign_class_functions[] = {
	PHP_FALIAS(header, opendkim_header, NULL)
	PHP_FALIAS(eoh, opendkim_eoh, NULL)
	PHP_FALIAS(body, opendkim_body, NULL)
	PHP_FALIAS(eom, opendkim_eom, NULL)
	PHP_FALIAS(chunk, opendkim_chunk, NULL)
    PHP_FALIAS(getSignatureHeader, opendkim_getsighdr, NULL)
    PHP_FALIAS(getError, opendkim_geterror, NULL)
    PHP_FALIAS(loadPrivateKey, opendkim_privkey_load, NULL)
    PHP_FALIAS(setSigner, opendkim_set_signer, NULL)
    PHP_FALIAS(setMargin, opendkim_set_margin, NULL)
    PHP_FALIAS(setPartial, opendkim_setpartial, NULL)
	PHP_ME(opendkim_sign, __construct, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(opendkim_free, __destruct, NULL, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};

static zend_function_entry opendkim_functions[] = {
    PHP_FE(opendkim_flush_cache, NULL)
	{NULL, NULL, NULL}
};

zend_module_entry opendkim_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	PHP_OPENDKIM_EXTNAME,
	opendkim_functions,
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

#ifdef COMPILE_DL_DKIM
ZEND_GET_MODULE(opendkim)
#endif

/* Destructors */
ZEND_RSRC_DTOR_FUNC(php_opendkim_dtor)
{
    DKIM *dkim = (DKIM *)rsrc->ptr;
    if (dkim) {
    	dkim_free(dkim);
    }
    rsrc->ptr = NULL;
}
/* End destructors */
/* INIT / SHUTDOWN */
PHP_MINIT_FUNCTION(opendkim)
{
	u_int options;
	DKIM_STAT status=0;

	opendkim_master=dkim_init(NULL, NULL);
	if (opendkim_master==NULL){
		return FAILURE;
	}

    /* OpenDKIM Ressource Destructor */
    le_opendkim = zend_register_list_destructors_ex(php_opendkim_dtor, NULL, PHP_OPENDKIM_RES_NAME, module_number);

    /* Class Registration */
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "OpenDKIMSign", opendkim_sign_class_functions);
	opendkim_sign_class_entry = zend_register_internal_class_ex(&ce, NULL, NULL TSRMLS_CC);
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
	php_info_print_table_start();
	php_info_print_table_header(2, "OpenDKIM support", "enabled");
	php_info_print_table_row(2, "OpenDKIM Extension Version", PHP_OPENDKIM_VERSION);
	php_info_print_table_end();
}

/*** The Functions by themselves ***/
/* {{{ proto void OpenDKIMSigner(privateKey, selector, domain[, header_canon[, body_canon[, sign_alg[, body_length]]]])
    constructor
*/
PHP_METHOD(opendkim_sign, __construct)
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
    	ALLOC_INIT_ZVAL(opendkim_ressource);
        ZEND_REGISTER_RESOURCE(opendkim_ressource, dkim, le_opendkim);
    	add_property_zval(this_ptr, "descriptor", opendkim_ressource);
    }
}/* }}} */

/* {{{ proto void ~OpenDKIMSign() and ~OpenDKIMVerify
   destructor
   */
PHP_METHOD(opendkim_free, __destruct)
{
	zval **data;
	
	if (SUCCESS == zend_hash_find(HASH_OF(this_ptr), "descriptor",
					sizeof("descriptor"), (void**)&data)) {
		zval_ptr_dtor(data);
	}
}
/* }}} end ~OpenDKIMSign / ~OpenDKIMVerify Destructor */

/* {{{ proto boolean 

/* {{{ proto boolean header(header)
 */
PHP_FUNCTION(opendkim_header)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *header;
	int   headerLen;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &header, &headerLen) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_header(dkim, header, headerLen);
	if (status!=DKIM_STAT_OK){
        RETURN_BOOL(0);
	} else {
    	RETURN_BOOL(1);
    }
}/* }}} */

/* {{{ proto boolean body(chunk)
 */
PHP_FUNCTION(opendkim_body)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *body;
	int   bodyLen;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &body, &bodyLen) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_body(dkim, body, bodyLen);
	if (status!=DKIM_STAT_OK){
    	RETURN_BOOL(0);
	} else {
    	RETURN_BOOL(1);
    }
}/* }}} */

/* {{{ proto boolean chunk(chunk)
 */
PHP_FUNCTION(opendkim_chunk)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *body=NULL;
	int   bodyLen=-1;
	zend_bool end;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &body, &bodyLen) == FAILURE) {
        RETURN_NULL();
    }
    if (bodyLen==0){
    	RETURN_BOOL(1);
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);
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
PHP_FUNCTION(opendkim_eoh)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);

	status=dkim_eoh(dkim);
	if (status!=DKIM_STAT_OK){
		RETURN_BOOL(0);
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto boolean eom()
 */
PHP_FUNCTION(opendkim_eom)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_eom(dkim, 0);
	if (status!=DKIM_STAT_OK){
		RETURN_BOOL(0);
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto string getsighdr()
 */
PHP_FUNCTION(opendkim_getsighdr)
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
    OPENDKIM_GETRESSOURCE(z_dk_ressource);
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);
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

/* {{{ proto string getError()
 */
PHP_FUNCTION(opendkim_geterror)
{
	zval *z_dk_ressource;
	DKIM *dkim;
    const char *error;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);

    error=dkim_geterror(dkim);
    if (error==NULL) {
        RETURN_BOOL(0);
    }
    RETURN_STRING(error, 1);
}/* }}} */

/* {{{ proto bool loadPrivateKey() 
 */
PHP_FUNCTION(opendkim_privkey_load)
{
	zval *z_dk_ressource;
	DKIM *dkim;
    DKIM_STAT status;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);
    
    status = dkim_privkey_load(dkim);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    } else {
        RETURN_BOOL(1);
    }
} /* }}} */

/* {{{ proto bool setSigner(signer) 
 */
PHP_FUNCTION(opendkim_set_signer)
{
	zval *z_dk_ressource;
	DKIM *dkim;
	char *signer;
	int   signerLen;
    DKIM_STAT status;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &signer, &signerLen) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);

    status=dkim_set_signer(dkim, signer);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
} /* }}} */

/* {{{ proto bool setMargin(margin) 
 */
PHP_FUNCTION(opendkim_set_margin)
{
	zval *z_dk_ressource;
	DKIM *dkim;
    long margin;
    DKIM_STAT status;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &margin) == FAILURE) {
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
PHP_FUNCTION(opendkim_setpartial)
{
	zval *z_dk_ressource;
	DKIM *dkim;
	char *partial;
	int   partialLen;
    DKIM_STAT status;

    OPENDKIM_GETRESSOURCE(z_dk_ressource);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &partial, &partialLen) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);

    status=dkim_setpartial(dkim, partial);
    if (status!=DKIM_STAT_OK) {
        RETURN_BOOL(0);
    }
    RETURN_BOOL(1);
} /* }}} */

/* {{{ proto bool addQueryMethod(method[, options]) 
 */
PHP_FUNCTION(opendkim_add_querymethod)
{
	zval *z_dk_ressource;
	DKIM *dkim;
	char *method;
	int   methodLen;
	char *options;
	int   optionsLen = -1;
    DKIM_STAT status;
    
    OPENDKIM_GETRESSOURCE(z_dk_ressource);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &method, &methodLen, &options, &optionsLen) == FAILURE) {
        RETURN_NULL();
    }

} /* }}} */

/* {{{ proto int opendkim_flush_cache()
 */
PHP_FUNCTION(opendkim_flush_cache)
{
    int status;
	status=dkim_flush_cache(opendkim_master);
    if (status>0) {
        RETURN_LONG(status);
    } else {
        RETURN_BOOL(0);
    }
}/* }}} */

