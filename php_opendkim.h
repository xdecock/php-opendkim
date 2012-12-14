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
#ifndef PHP_OPENDKIM_H
#define PHP_OPENDKIM_H 1

#define PHP_OPENDKIM_VERSION "0.9-dev"
#define PHP_OPENDKIM_EXTNAME "opendkim"

PHP_MINIT_FUNCTION(opendkim);
PHP_MSHUTDOWN_FUNCTION(opendkim);
PHP_MINFO_FUNCTION(opendkim);

/*** The Functions by themselves ***/
PHP_FUNCTION(opendkim_sign);
PHP_FUNCTION(opendkim_header);
PHP_FUNCTION(opendkim_body);
PHP_FUNCTION(opendkim_chunk);
PHP_FUNCTION(opendkim_eoh);
PHP_FUNCTION(opendkim_eom);
PHP_FUNCTION(opendkim_getsighdr);

extern zend_module_entry opendkim_module_entry;
#define phpext_opendkim_ptr &opendkim_module_entry

#define PHP_OPENDKIM_RES_NAME "OpenDKIM Keys resource"

#endif
