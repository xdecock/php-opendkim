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

static zend_function_entry opendkim_functions[] = {
	PHP_FE(opendkim_sign,		NULL)
	PHP_FE(opendkim_header,		NULL)
	PHP_FE(opendkim_body,		NULL)
	PHP_FE(opendkim_chunk,		NULL)
	PHP_FE(opendkim_eoh,		NULL)
	PHP_FE(opendkim_eom,		NULL)
	PHP_FE(opendkim_getsighdr,	NULL)
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

	/*options=DKIM_LIBFLAGS_ZTAGS|DKIM_LIBFLAGS_FIXCRLF;
	(void) dkim_options(dkim_master, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                    &options, sizeof options);
*/
    le_opendkim = zend_register_list_destructors_ex(php_opendkim_dtor, NULL, PHP_OPENDKIM_RES_NAME, module_number);
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
/* {{{ proto resource opendkim_sign(privateKey, selector, domain[, header_canon[, body_canon[, sign_alg[, body_length]]]])
*/
PHP_FUNCTION(opendkim_sign)
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

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|llll", &privateKey, &privateKeyLen, &selector, &selectorLen, &domain, &domainLen, &header_canon, &body_canon, &sign_alg, &body_length) == FAILURE) {
        RETURN_NULL();
    }

	dkim=dkim_sign(opendkim_master, "", NULL, privateKey, selector, domain, header_canon, body_canon, sign_alg, body_length, &status);
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_sign");
	}
	/*status=dkim_set_margin(dkim, 0);
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "An error occured in dkim_sign, unable to drop wraping");
	}*/

    ZEND_REGISTER_RESOURCE(return_value, dkim, le_opendkim);
}/* }}} */

/* {{{ proto boolean opendkim_header(dkim_res, header)
 */
PHP_FUNCTION(opendkim_header)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *header;
	int   headerLen;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &z_dk_ressource, &header, &headerLen) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_header(dkim, header, headerLen);
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_header");
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto boolean dkim_body(dkim_res, chunk)
 */
PHP_FUNCTION(opendkim_body)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *body;
	int   bodyLen;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &z_dk_ressource, &body, &bodyLen) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_body(dkim, body, bodyLen);
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_body");
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto boolean dkim_chunk(dkim_res, chunk)
 */
PHP_FUNCTION(opendkim_chunk)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char *body=NULL;
	int   bodyLen=-1;
	zend_bool end;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|s", &z_dk_ressource, &body, &bodyLen) == FAILURE) {
 		if (status!=DKIM_STAT_OK){
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_chunk [A]");
		}
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
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_chunk [B]");
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto boolean dkim_eoh(dkim_res)
 */
PHP_FUNCTION(opendkim_eoh)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &z_dk_ressource) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_eoh(dkim);
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_eoh");
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto boolean dkim_eom(dkim_res)
 */
PHP_FUNCTION(opendkim_eom)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &z_dk_ressource) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);


	status=dkim_eom(dkim, 0);
	if (status==DKIM_STAT_INVALID){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_eom [I]");
	}
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_eom ");
	}
	RETURN_BOOL(1);
}/* }}} */

/* {{{ proto string dkim_getsighdr(dkim_res)
 */
PHP_FUNCTION(opendkim_getsighdr)
{
	DKIM *dkim;
	DKIM_STAT status=0;
	zval *z_dk_ressource;
	char buffer[4096]="";

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &z_dk_ressource) == FAILURE) {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE(dkim, DKIM *, &z_dk_ressource, -1, PHP_OPENDKIM_RES_NAME, le_opendkim);

#if OPENDKIM_LIB_VERSION<0x02060000
	status=dkim_getsighdr(dkim, buffer, 4096, 75, 16);
#else
	status=dkim_getsighdr(dkim, buffer, 4096, 16);
#endif
	if (status!=DKIM_STAT_OK){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An error occured in dkim_getsighdr");
	}
	RETURN_STRING(buffer,1);
	free(buffer);

}/* }}} */
