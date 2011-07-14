#ifndef __MOD_PAPI_PRIVATE_H__
#define __MOD_PAPI_PRIVATE_H__

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_log.h>
#include <http_config.h>
#include <http_request.h>
#include <mod_core.h>
#include <util_md5.h>
#include <apr_strings.h>
#include <apr_optional.h>
#include <apr_base64.h>
#include <apr_dbd.h>
#include <ctype.h>
#include <curl/curl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pcre.h>
#include <openssl/rand.h>

#ifndef UNSET
#define UNSET (-1)
#endif

#ifndef MAX_SIZE
#define MAX_SIZE 8192
#endif

#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6

#define SMALL_KEY       128
#define MEDIUM_KEY      192
#define BIG_KEY         256

#define MODNAME "mod_papi: "

#define PAPI_LOGIN		1
#define PAPI_LOGOUT		2
#define PAPI_TEST		3
#define PAPI_CHECK		4
#define PAPI_CHECKED	5

#define APACHE_LOG(level, ...) \
  ap_log_rerror(APLOG_MARK, level, 0, r, MODNAME __VA_ARGS__)

#define papi_return_if_fail(expr)                               \
     if (expr) { } else                                         \
       {                                                        \
         APACHE_LOG (APLOG_DEBUG,                              \
                "assertion `%s' failed",                        \
                #expr);                                         \
         return;                                                \
       };

#define papi_return_val_if_fail(expr, val)                      \
     if (expr) { } else                                         \
       {                                                        \
         APACHE_LOG (APLOG_DEBUG,                              \
                "assertion `%s' failed",                        \
                #expr);                                         \
         return (val);                                          \
       };

#ifndef UNSET
#define UNSET (-1)
#endif

#define ARRAY(x,y)                      (((x##_t *) d->x->elts)+i)
#define DEFAULT_ARRAY_TYPE(type)	apr_array_make (pool, 5, sizeof (type))
#define DEFAULT_DOMAIN				r->server->server_hostname
#define DEFAULT_AUTH_LOCATION		"/PAPI/cookie_handler.cgi"
#define DEFAULT_WAYF				"built-in"
#define DEFAULT_LCOOK_TIMEOUT		3600
#define DEFAULT_LCOOK_MAX_TIMEOUT	3600
#define DEFAULT_URL_TIMEOUT			3600
#define DEFAULT_HASH_USER_DATA		FALSE
#define DEFAULT_CLIENT_ADDR_TOKEN	FALSE
#define DEFAULT_GPOA_HASH_USER_DATA	FALSE
#define DEFAULT_REMOTE_USER_ATTRIB  "uid"
#define DEFAULT_ATTRIBUTE_SEPARATOR	','
#define DEFAULT_VALUE_SEPARATOR		'='
#define DEFAULT_LAZY_SESSION		FALSE

#define SET_DEFAULT_IF_NULL(var,val)  if (var == NULL) var=val
#define SET_DEFAULT_IF_UNSET(var,val) if (var == UNSET) var=val

typedef struct {
	const pcre *pcre_re;
	const char *pattern;
} papi_regex_t;

typedef struct {
	papi_regex_t *re;
} pass_url_pattern_t;

typedef struct {
	papi_regex_t *re;
} cookie_reject_t;

typedef struct {
	papi_regex_t *re;
	const char *url;
} signoff_location_t;

typedef struct {
	papi_regex_t *re;
	int accept;
} papi_filter_t;

typedef struct {
	const char *name;
	const char *url;
	const char *description;
} papi_as_t;

typedef struct {
	papi_regex_t *re;
	const char *rs;
} user_data_rewrite_t;

typedef struct {
	papi_regex_t *poa_re;
	papi_regex_t *re;
	const char *rs;
} gpoa_rewrite_t;

typedef struct {
	apr_table_t *headers_in;
	const char  *method;
	const char  *uri;
	const char  *args;
	const char  *filename;
	const char  *post;
} poa_request_t;

typedef struct {
	const char *key;
	const char *value;
} attribute_list_t;

typedef struct {
	char* loc;
	apr_array_header_t *attribute_list;
	// Configuration data
	char* lkey;
	char* service_id;
	const char* accept_file;
	const char* reject_file;
	const char* keys_path;
	char* domain;
	char* auth_location;
	apr_array_header_t *signoff_location;
	apr_array_header_t *pass_url_pattern;
	int lcook_timeout;
	int lcook_max_timeout;
	int url_timeout;
	int max_ttl;
	apr_array_header_t *papi_as;
	char *wayf;
	apr_array_header_t *papi_filter;
	apr_array_header_t *cookie_reject;
	int hash_user_data;
	user_data_rewrite_t *user_data_rewrite;
	int client_address_in_tokens;
	char *remote_user_attrib;
	char attribute_separator;
	char value_separator;
	const char* gpoa_url;
	char* req_db;
	const char* req_dir;
	char* gpoa_privkey;
	apr_array_header_t *gpoa_rewrite;
	int gpoa_hash_user_data;
	int lazy_session;
} papi_dir_config;

// mod_papi_config

const char* papi_set_parameters (request_rec* r, papi_dir_config* dir);
const char* papi_set_file_slot (cmd_parms *parms, void *config, const char *arg);
const char* papi_set_path_slot (cmd_parms *parms, void *config, const char *arg);
const char* papi_set_signoff_location_slot (cmd_parms *parms, void *config, const char *re, const char *url);
const char* papi_set_pass_url_pattern_slot (cmd_parms *parms, void *config, const char *re);
const char* papi_set_papi_filter_slot (cmd_parms *parms, void *config, const char *re, const char *accept);
const char* papi_set_cookie_reject_slot (cmd_parms *parms, void *config, const char *re);
const char* papi_set_user_data_rewrite_slot (cmd_parms *parms, void *config, const char *re, const char *rs);
const char* papi_set_papi_as_slot (cmd_parms *parms, void *config, const char *args);
const char* papi_set_gpoa_url_slot (cmd_parms *parms, void *config, const char *id, const char *url);
const char* papi_set_attribute_slot (cmd_parms *parms, void *config, const char *separator);
const char* papi_set_value_slot (cmd_parms *parms, void *config, const char *separator);
const char* papi_set_gpoa_rewrite_slot (cmd_parms *parms, void *config, const char *poa_re, const char *re, const char *rs);

// mod_papi_crypt

char *papi_encrypt_AES (request_rec* r, char* input, char* _key, int keylenbits);
char *papi_decrypt_AES (request_rec* r, char* _input, char* _key, int keylenbits);
char *papi_encrypt_priv_RSA (request_rec* r, char* rsa_in, char* keyfile);
char *papi_decrypt_pub_RSA (request_rec* r, char* in, char* keyfile);

// mod_papi_utils

char *papi_escape_string (apr_pool_t *pool, const char *str);
int   papi_get_action (request_rec *r);
char *papi_md5_base64 (request_rec *r, char *str);
char *papi_unescape_string (apr_pool_t *pool, const char *str);
char *papi_uri_add_arg (apr_pool_t *pool, const char *uri, const char *key, const char *value);
char *papi_uri_get_arg (apr_pool_t *pool, const char *src, const char *name);
papi_regex_t *papi_regex_new (apr_pool_t *p, const char *pattern);
int papi_regex_match (papi_regex_t *re, const char *string);
char *papi_regex_replace (apr_pool_t *p, papi_regex_t *re, const char* string, const char* replace);
char **papi_string_split (apr_pool_t *p, char *string, char *token, int limit);
char* papi_file_stat (request_rec *r, papi_dir_config *d, const char *path, apr_filetype_e type);

// mod_papi_poa

const char* papi_build_attrList (request_rec *r, papi_dir_config *d, char *assert);
char* papi_test_url (request_rec *r, papi_dir_config *d, int *valid_data);
char* papi_test_gpoa_url (request_rec *r, papi_dir_config *d, char **code, int *valid_date);
char* papi_pub_keyfile (request_rec *r, papi_dir_config *d, const char *as);
char* papi_priv_keyfile (apr_pool_t *p, papi_dir_config *d, const char *as);
char* papi_gen_lcook (request_rec* r, papi_dir_config* d, int init, const char* code);
char* papi_test_lcook (request_rec* r, papi_dir_config* d, int *init);
char* papi_gen_logout_lcook_cookie (request_rec *r, papi_dir_config *d);
poa_request_t *papi_load_request (request_rec* r, papi_dir_config *d, char* request_id);
char* papi_save_request (request_rec* r, papi_dir_config *d);

// mod_papi_cookie_handler
int papi_cookie_handler (request_rec *r, papi_dir_config *d);
int papi_redirect_with_cookies (request_rec *r, const char *uri, const char *lcook);
int papi_redirect_url (request_rec *r, const char *uri);

// mod_papi_redirectgpoa
int papi_redirect_gpoa (request_rec *r, papi_dir_config *d);

// mod_papi_post_handler
int papi_post_handler (request_rec *r, papi_dir_config *d, const char *post);
int papi_read_body (request_rec *r, char **buffer);

#endif // __MOD_PAPI_PRIVATE_H__
