#include "mod_papi_private.h"

#ifndef __MOD_PAPI_COOKIE_HANDLER_H__
#define __MOD_PAPI_COOKIE_HANDLER_H__

static int papi_cookie_test (request_rec *r, papi_dir_config *d);
static int papi_cookie_login (request_rec *r, papi_dir_config *d);
static int papi_cookie_logout (request_rec *r, papi_dir_config *d);
static int papi_cookie_check (request_rec *r, papi_dir_config *d);
static int papi_cookie_checked (request_rec *r, papi_dir_config *d);
static int papi_send_file (request_rec *r, const char *filename);
static int papi_send_file_with_cookies (request_rec *r, const char *filename, const char *lcook);
static int papi_redirect_error_url (request_rec *r, papi_dir_config *d, const char *uri, const char *data);
static char *papi_gen_user_data (request_rec *r, papi_dir_config *d, char *poa, char *code);
static char *papi_encrypt_gen_code (request_rec *r, papi_dir_config *d, const char *assert, int valid_date, const char *data);

#endif // __MOD_PAPI_COOKIE_HANDLER_H__
