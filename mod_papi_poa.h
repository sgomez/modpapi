#include "mod_papi_private.h"

#ifndef __MOD_PAPI_POA_H__
#define __MOD_PAPI_POA_H__

static char *papi_request_get_cookie (apr_pool_t *p, const apr_table_t *src, const char *name);
static char **papi_split_assertion (request_rec *r, const char *str, const char token, int n);
static int papi_test_filters (request_rec *r, papi_dir_config *d, char* assert);
static char *papi_user_data_rewrite (request_rec *r, papi_dir_config *d, char *assert);
static int papi_test_as (request_rec *r, papi_dir_config *d, char *as);
static apr_dbd_t *papi_dbd_open (request_rec* r, papi_dir_config *d, const apr_dbd_driver_t *driver);


#endif // __MOD_PAPI_POA_H__
