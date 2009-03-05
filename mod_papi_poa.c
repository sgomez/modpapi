#include "mod_papi_poa.h"

/**
 * Split an assertion.
 * @param p      the pool
 * @param src	 the header table to search for the cookie
 * @param name   the name of the cookie
 * @return       the value of the cookie
 */
static char *papi_request_get_cookie (apr_pool_t *p, const apr_table_t *src, const char *name)
{
	const char *cookies;
	const char *start_cookie;
	
	if ((cookies = apr_table_get(src, "Cookie"))) {
		for (start_cookie = ap_strstr_c(cookies, name); start_cookie;
			 start_cookie = ap_strstr_c(start_cookie + 1, name)) {
				 if (start_cookie == cookies ||
					 start_cookie[-1] == ';' ||
					 start_cookie[-1] == ',' ||
					 isspace(start_cookie[-1])) {
						 
						 start_cookie += strlen(name);
						 while(*start_cookie && isspace(*start_cookie))
							 ++start_cookie;
						 if (*start_cookie == '=' && start_cookie[1]) {
							 /*
							   * Session cookie was found, get it's value
							   */
							 char *end_cookie, *cookie;
							 ++start_cookie;
							 cookie = apr_pstrdup(p, start_cookie);
							 if ((end_cookie = strchr(cookie, ';')) != NULL)
								 *end_cookie = '\0';
							 if((end_cookie = strchr(cookie, ',')) != NULL)
								 *end_cookie = '\0';
							 return papi_unescape_string (p, cookie);
						 }
					 }
			 }
	}
	return NULL;
}

/**
 * Split an assertion.
 * @param r      the request
 * @param str    the assertion
 * @param token  the token to split with
 * @param n      the number of elements
 * @return       a char** with the elements
 */
static char **papi_split_assertion (request_rec *r, const char *str, const char token, int n)
{
	papi_return_val_if_fail (str, NULL);

	char **split = apr_palloc (r->pool, sizeof(char *)*n);
	char *buf = apr_pstrdup (r->pool, str);
	int i;
	for (i=n-1; i > 0; i--) {
		char *ptr = strrchr (buf, token);
		if (ptr == NULL)
			return NULL;
		split[i] = apr_pstrdup (r->pool, ptr+1);
		*ptr = '\0';
	}
	split[i] = apr_pstrdup (r->pool, buf);
	
	return split;
}


/** 
 * Check if the assertion is accepted or not.
 * 
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @param assert the assertion send by the AS
 * @return       1 (accepted) or 0 (rejected)
 */
static int papi_test_filters (request_rec *r, papi_dir_config *d, char* assert)
{
	papi_return_val_if_fail(assert, 1);
	
	// PAPI_Filter directives are evaluated first
	int i;
	for (i=0; i < d->papi_filter->nelts; i++) {
		papi_filter_t *papi_filter = ((papi_filter_t *) d->papi_filter->elts)+i;
		if (papi_regex_match (papi_filter->re, assert)) {
			APACHE_LOG (APLOG_INFO, "Filter /%s/ matches for %s: %s",
						   papi_filter->re->pattern,
						   assert,
						   (papi_filter->accept?"accept":"reject"));
			return papi_filter->accept;
		}
	}
	// TODO: SPOCP
	return 1;
}

/**
 * Build the attributes list from an assertion.
 *
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @param assert the assertion send by the AS
 * @return       the asid (id from AS)
 */

const char *papi_build_attrList (request_rec *r, papi_dir_config *d, char *assert)
{
	papi_return_if_fail (assert);
	
	const char *pair;
	const char *ptr = strrchr (assert, '@');
	const char *asid = apr_pstrdup (r->pool, ptr+1);
	const char *src = apr_pstrndup (r->pool, assert, ptr-assert);

	while (*src && (pair = ap_getword (r->pool, &src, d->attribute_separator))) {
		const char *name;
		attribute_t *attr;
		
		name = ap_getword (r->pool, &pair, d->value_separator);
		attr = (attribute_t *) apr_array_push (d->attribute_list);
		attr->key = papi_unescape_string (r->pool, name);
		attr->value = papi_unescape_string (r->pool, pair);
	}
	
	return asid;
}

/**
 * Transform an assert which PAPIGPoARewrite rules.
 *
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @param assert the assertion send by the AS
 * @return       the new assertion
 */

static char *papi_user_data_rewrite (request_rec *r, papi_dir_config *d, char *assert)
{
	papi_return_val_if_fail (assert, NULL);
	
	if (d->user_data_rewrite->re == NULL)
		return assert;
	
	char *nua = papi_regex_replace (r->pool, d->user_data_rewrite->re, assert, d->user_data_rewrite->rs);
	
	return nua;
}

/**
 * Check if the AS is valid.
 *
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @param as     the name of AS to search for in d->papi_as array
 * @return       true if the AS exists
 */

static int papi_test_as (request_rec *r, papi_dir_config *d, char *as)
{
	papi_return_val_if_fail (as, 0);
	
	int i;	
	for (i=0; i < d->papi_as->nelts; i++) {
		papi_as_t *papi_as = ((papi_as_t *) d->papi_as->elts)+i;
		if (apr_strnatcmp (papi_as->name, as) == 0)
			return 1;
	}
	
	return 0;
}

/**
 * Test the signed URL from AS.
 *
 * @param r          the request
 * @param d          the configuration of the PoA/GPoA
 * @param valid_data return the connection timeout
 * @return           the assertion
 */

char* papi_test_url (request_rec *r, papi_dir_config *d, int *valid_data)
{
	*valid_data = 0;
	char *as    = papi_uri_get_arg (r->pool, r->args, "AS");
	char *data  = papi_uri_get_arg (r->pool, r->args, "DATA");
	
	if ( papi_test_as (r, d, as) == 0 ) {
		APACHE_LOG (APLOG_WARNING, "Authentication server %s not defined for this PoA",
					   as);
		return NULL;
	}
	
	char *key_file = papi_pub_keyfile (r, d, as);
	char *linea = papi_decrypt_pub_RSA (r, data, key_file);
	
	if (!linea || apr_strnatcmp (linea, "ERRORCRYPT") == 0) {
		APACHE_LOG (APLOG_WARNING, "Error in verifying signed URL");
		return NULL;
	}
	
	if (apr_strnatcmp (linea, "ERRORFILE") == 0) {
		APACHE_LOG (APLOG_WARNING, "Error reading public key file (%s)",
					   key_file);
		return NULL;
	}
	
	char **elem = papi_split_assertion (r, linea, ':', 5);
	if (!elem) {
		APACHE_LOG (APLOG_WARNING, "Error in verifying signed URL");
		return NULL;
	}
	
	char *service = elem[4];
	int timeout = atoi (elem[2]);
	int then = atoi (elem[1]);
	char *assertion = elem[0];
		
	int now = time(NULL);
	if (now > timeout + d->url_timeout) {
		APACHE_LOG (APLOG_WARNING, "URL timeout expired %d > %d + %d",
					   now, timeout, d->url_timeout);
		return NULL;
	}
	
	if (now > then) {
		APACHE_LOG (APLOG_WARNING, "Validation date field in URL is wrong");
		return NULL;
	}
	
	if (apr_strnatcmp (service, d->service_id)) {
		APACHE_LOG (APLOG_WARNING, "Invalid service ID %s in URL",
					 service);
		return NULL;
	}
	
	char *assert = apr_pstrcat (r->pool, assertion, "@", as, NULL);
	if (papi_test_filters (r, d, assert) == 0) {
		return NULL;
	}
	
	assertion = papi_user_data_rewrite (r, d, assertion);
	
	if (d->hash_user_data) {
		char *nua;
		nua = papi_md5_base64 (r, assertion);
		APACHE_LOG (APLOG_INFO, "User assertion %s transformed into %s",
					   assertion, nua);
		assertion = nua;
	}
	
	if (d->max_ttl != UNSET) {
		int maxt = timeout + d->max_ttl;
		if (then > maxt) {
			APACHE_LOG (APLOG_WARNING, "Requested TTL of %d reduced to %d (%d + %d)",
						   then, maxt, timeout, d->max_ttl);
			then=maxt;
		}
	}
	
	*valid_data=then;
	assert = apr_pstrcat (r->pool, assertion, "@", as, NULL);
	return assert;
}

/**
 * Test the signed URL from a GPoA.
 *
 * @param r          the request
 * @param d          the configuration of the PoA/GPoA
 * @param code		 the assertion
 * @param valid_date return the connection timeout
 * @return           the connection id
 */

char* papi_test_gpoa_url (request_rec *r, papi_dir_config *d, char **code, int *valid_date)
{
	*code = NULL;
	*valid_date = 0;
	
	char *gid   = papi_uri_get_arg (r->pool, r->args, "AS");
	char *data  = papi_uri_get_arg (r->pool, r->args, "DATA");	
	
	if (!data) {
		APACHE_LOG (APLOG_ERR, "Signed GPoA/AS URL without DATA field");
		return NULL;
	}
	
	if (!strncmp (data, "ERROR", 5)) {
		APACHE_LOG (APLOG_ERR, "Signed GPoA/AS URL without valid DATA field (%s)", data);
		return NULL;
	}
	
	if (gid == NULL) 
		gid = apr_pstrdup (r->pool, "_GPoA");
	
	char *key_file = papi_pub_keyfile (r, d, gid);
	char *linea = papi_decrypt_pub_RSA (r, data, key_file);
	
	if (!linea || apr_strnatcmp (linea, "ERRORCRYPT") == 0) {
		APACHE_LOG (APLOG_WARNING, "Error in verifying signed URL from GPoA/AS");
		return NULL;
	}

	if (apr_strnatcmp (linea, "ERRORFILE") == 0) {
		APACHE_LOG (APLOG_WARNING, "Error reading public key file (%s)",
					   key_file);
		return NULL;
	}
	
	APACHE_LOG (APLOG_DEBUG, "Decrypted GPoA_URL: %s", linea);
	
	char **elem = papi_split_assertion (r, linea, ':', 4);
	if (!elem) {
		APACHE_LOG (APLOG_WARNING, "Error in verifying signed URL");
		return NULL;
	}
	char *id_req = elem[3];
	int timeout = atoi(elem[2]);
	int ttl = atoi (elem[1]);
	char *assertion = elem[0];
	int now = time (NULL);
	
	if (id_req == NULL) {
		APACHE_LOG (APLOG_WARNING, "Signed GPoA/AS URL without Id_Req");
		return NULL;
	}

	if (apr_strnatcmp (assertion, "ERROR") == 0) {
		APACHE_LOG (APLOG_WARNING, "Authentication ERROR received from GPoA (%s)",
					   d->gpoa_url);
		return id_req;
	}
	
	if (now > timeout + d->url_timeout) {
		APACHE_LOG (APLOG_WARNING, "GPoA/AS URL timeout expired: %d > %d",
					   now, timeout + d->url_timeout);
		return id_req;
	}
	
	if (now > ttl) {
		APACHE_LOG (APLOG_WARNING, "Validation date field in GPoA/AS URL is wrong");
		return id_req;
	}
	
	if (papi_test_filters (r, d, assertion) == 0) {
		return id_req;
	}
	
	char *ptr = strrchr (assertion, '@');
	char *as = apr_pstrdup (r->pool, ptr+1);
	*ptr = '\0';
	
	assertion = papi_user_data_rewrite (r, d, assertion);
	
	if (d->hash_user_data) {
		char *nua;
		nua = papi_md5_base64 (r, assertion);
		APACHE_LOG (APLOG_WARNING, "User assertion %s transformed into %s",
					   assertion, nua);
		assertion = nua;
	}
	
	if (d->max_ttl != UNSET) {
		int maxt = timeout + d->max_ttl;
		if (ttl > maxt) {
			APACHE_LOG (APLOG_WARNING, "Requested TTL of %d reduced to %d (%d + %d)",
						   ttl, maxt, timeout, d->max_ttl);
			ttl=maxt;
		}
	}
	
	*valid_date=ttl;
	*code = apr_pstrcat (r->pool, assertion, "@", as, NULL);
	
	return 	id_req;
}

/** 
 * Return the AS keyfile path.
 *
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @param as     the as name
 * @return       the keyfile path
 */

char* papi_pub_keyfile (request_rec *r, papi_dir_config *d, const char *as) {

	papi_return_val_if_fail (as, NULL);
	
	return apr_pstrcat (r->pool, d->pubkeys_path, as, "_pubkey.pem", NULL);
}

/**
 * Generate the LCook.
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @param code   the assert
 * @return       the cookie
 */

char* papi_gen_lcook (request_rec* r, papi_dir_config* d, int init, const char* code) {
	
	papi_return_val_if_fail (code, NULL);
	
	char *aes_in = NULL;
	if (d->client_address_in_tokens) {
		aes_in = apr_psprintf (r->pool, "%d:%d:%s:%s:%s%%%s%%",
							   init,
							   (int)time(NULL),
							   d->loc,
							   d->service_id,
							   code,
							   r->connection->remote_ip);
	} else {
		aes_in = apr_psprintf (r->pool, "%d:%d:%s:%s:%s",
                               init,
							   (int)time(NULL),
							   d->loc,
							   d->service_id,
							   code);
	}
	
	APACHE_LOG (APLOG_DEBUG, "aes_in lcook: %s", aes_in);
	
	char *safe = papi_encrypt_AES (r, aes_in, d->lkey, 128);
	
	char *cookie = apr_psprintf (r->pool, "Lcook=%s;path=%s;domain=%s",
								 papi_escape_string (r->pool, safe),
								 d->loc,
								 d->domain);
	
	return cookie;
}

/**
 * Check the LCook.
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @return       the assertion
 */

char* papi_test_lcook (request_rec* r, papi_dir_config* d, int *init) {

	char *lcook = papi_request_get_cookie (r->pool, r->headers_in, "Lcook");
	
	if (!lcook) {
		APACHE_LOG (APLOG_WARNING, "Lcook is empty");
		return NULL;	
	}
	
	char *lcookdes = papi_decrypt_AES (r, lcook, d->lkey, 128);
	
	if (!lcookdes) {
		APACHE_LOG (APLOG_WARNING, "After decrypting Lcook is empty");
		return NULL;
	}
	
	char **re = papi_string_split (r->pool, lcookdes, ":", 5);
	
	// Check split
	int i;
	for (i=0; re[i] != NULL; i++);
	if (i < 5) {
		APACHE_LOG (APLOG_WARNING, "Lcook invalid (%s)", lcookdes);
		return NULL;
	}
	
	*init = (int)apr_atoi64 (re[1]);
	if (apr_strnatcmp (re[2], d->loc) != 0) {
		APACHE_LOG (APLOG_WARNING, "Location parameter of Lcook is not valid. "
					   "Loc of Lcook (%s), Loc of PoA (%s)",
					   re[2], d->loc);
		return NULL;
	}
	
	if (apr_strnatcmp (re[3], d->service_id) != 0) {
		APACHE_LOG (APLOG_WARNING, "PAPIServiceID parameter of Lcook is not valid. "
					   "Serv of Lcook (%s), Serv of Poa (%s)",
					   re[3], d->service_id);
		return NULL;
	}

	if ((int)apr_atoi64(re[0]) + d->lcook_max_timeout < time (NULL)) {
		APACHE_LOG (APLOG_WARNING, "Lcook MaxTime expired for %s",
					   re[4]);
		return NULL;
	}	

	if (*init + d->lcook_timeout < time (NULL)) {
		APACHE_LOG (APLOG_WARNING, "Lcook expired for %s",
					   re[4]);
		return NULL;
	}
	
	char *code = apr_pstrdup (r->pool, re[4]);
	char *key = code;
	
	if (d->client_address_in_tokens) {
		re = papi_string_split (r->pool, code, "%", 3);
		if ( apr_strnatcmp (re[1], r->connection->remote_ip) != 0 ) {
			APACHE_LOG (APLOG_WARNING, "**COLLISION**: Lcook received from address %s when it was assigned to %s",
						   r->connection->remote_ip,
						   re[1]);
			
			return NULL;
		}
		key = apr_pstrdup (r->pool, re[0]);
	}
	
	for (i=0; i < d->cookie_reject->nelts; i++) {
		cookie_reject_t *cr = ((cookie_reject_t *) d->cookie_reject->elts)+i;
		if (papi_regex_match (cr->re, key)) {
			APACHE_LOG (APLOG_WARNING, "%s matches rejection cookie filter %s",
						   key, cr->re->pattern);
			return NULL;
		}
	}
	
	return code;			
}

/**
 * Generate an expired LCook.
 * @param r      the request
 * @param d      the configuration of the PoA/GPoA
 * @return       the cookie
 */

char* papi_gen_logout_lcook_cookie (request_rec *r, papi_dir_config *d) {
	return apr_psprintf (r->pool, "Lcook=D;expires=0;path=%s;domain=%s",
						 d->loc,
						 d->domain);
}

poa_request_t *papi_load_request (request_rec* r, papi_dir_config *d, char* request_id) {
	const apr_dbd_driver_t *driver = NULL;
#ifdef APR_DBD_SQLITE3
	apr_dbd_prepared_t *req_statement = NULL;
	apr_dbd_prepared_t *del_statement = NULL;
	apr_dbd_prepared_t *header_statement = NULL;
	const char *req_s = "SELECT method, uri, args, filename, post FROM Request WHERE id = %s";
	const char *req_q = "DELETE FROM Request WHERE id = %s";
	const char *header_s = "SELECT key, value FROM Header WHERE id = %s";
#else
	char *req_statement = NULL;
	char *del_statement = NULL;
	char *header_statement = NULL;
	const char *req_s = "SELECT method, uri, args, filename, post FROM Request WHERE id = '%s'";
	const char *req_q = "DELETE FROM Request WHERE id = '%s'";
	const char *header_s = "SELECT key, value FROM Header WHERE id = '%s'";
#endif
	apr_dbd_results_t *res = NULL;
	apr_dbd_row_t *row = NULL;
	apr_dbd_t *handle = NULL;
	apr_status_t status;
	poa_request_t *request = NULL;
	int nrows = 0;
	
	request = apr_palloc (r->pool, sizeof (poa_request_t));
	
	if (apr_dbd_init (r->pool) != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to init apr_dbd");
		return NULL;
	}
	
	if (apr_dbd_get_driver (r->pool, "sqlite3", &driver) != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to fetch sqlite3 driver");
		return NULL;
	}
	
	handle = papi_dbd_open (r, d, driver);
	if (handle == NULL) {
		APACHE_LOG (APLOG_ERR, "failed to open database");
		return NULL;
	}

#ifdef APR_DBD_SQLITE3	
	status = apr_dbd_prepare (driver, r->pool, handle, req_s, NULL, &req_statement);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare req_s statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	status = apr_dbd_prepare (driver, r->pool, handle, header_s, NULL, &header_statement);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare header_s statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	status = apr_dbd_prepare (driver, r->pool, handle, req_q, NULL, &del_statement);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare req_q statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
#else
	req_statement = apr_psprintf (r->pool, req_s, request_id);
	header_statement = apr_psprintf (r->pool, header_s, request_id);
	del_statement = apr_psprintf (r->pool, req_q, request_id);
#endif

#ifdef APR_DBD_SQLITE3
	status = apr_dbd_pvselect (driver, r->pool, handle, &res, req_statement, FALSE,
							   request_id);
#else
	status = apr_dbd_select (driver, r->pool, handle, &res, req_statement, FALSE);
#endif
	
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to select req_s statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	nrows = 0;
	for (status = apr_dbd_get_row(driver, r->pool, res, &row, -1);
		 status == 0;
		 status = apr_dbd_get_row(driver, r->pool, res, &row, -1), nrows++) {
			 request->method = apr_dbd_get_entry (driver, row, 0);
			 request->uri = apr_dbd_get_entry (driver, row, 1);
			 request->args = apr_dbd_get_entry (driver, row, 2);
			 request->filename = apr_dbd_get_entry (driver, row, 3);
			 request->post = apr_dbd_get_entry (driver, row, 4);
		 }
	if (nrows == 0) {
		APACHE_LOG (APLOG_ERR, "failed to select %s, reload?", request_id);
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
#ifdef APR_DBD_SQLITE3
	status = apr_dbd_pvselect (driver, r->pool, handle, &res, header_statement, FALSE,
							   request_id);
#else
	status = apr_dbd_select (driver, r->pool, handle, &res, header_statement, FALSE);
#endif
	
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to select header_s statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	request->headers_in = apr_table_make (r->pool, apr_dbd_num_tuples (driver, res));
	
	for (status = apr_dbd_get_row(driver, r->pool, res, &row, -1);
		 status == 0;
		 status = apr_dbd_get_row(driver, r->pool, res, &row, -1)) {
			 apr_table_set (request->headers_in, 
							apr_dbd_get_entry (driver, row, 0),
							apr_dbd_get_entry (driver, row, 1));
		 }
	
#ifdef APR_DBD_SQLITE3
	status = apr_dbd_pvquery (driver, r->pool, handle, &nrows, del_statement,
							  request_id);
#else
	status = apr_dbd_query (driver, handle, &nrows, del_statement);
#endif
	
	if (status != APR_SUCCESS)
		APACHE_LOG (APLOG_WARNING, "req id=%s not deleted: %s", 
					   request_id, apr_dbd_error (driver, handle, status));
	
	apr_dbd_close (driver, handle);
	
	return request;
}

char* papi_save_request (request_rec* r, papi_dir_config *d) {
	const apr_dbd_driver_t *driver = NULL;
#ifdef APR_DBD_SQLITE3
	apr_dbd_prepared_t *req_statement = NULL;
	apr_dbd_prepared_t *header_statement = NULL;
	const char *req_q = "INSERT INTO Request VALUES (%s, %s, %s, %s, %s, %s, %s)";
	const char *header_q = "INSERT INTO Header VALUES (%s, %s, %s)";
#else
	char *req_statement = NULL;
	char *header_statement = NULL;
	const char *req_q = "INSERT INTO Request VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s')";
	const char *header_q = "INSERT INTO Header VALUES ('%s', '%s', '%s')";
#endif
	apr_dbd_t *handle = NULL;
	apr_status_t status;
	char *post, *key;
	int nrows, i, now, errn;
	const apr_array_header_t *headers_in;

	now = (int)time(NULL);
	if (apr_dbd_init (r->pool) != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to init apr_dbd");
		return NULL;
	}
	
	if (apr_dbd_get_driver (r->pool, "sqlite3", &driver) != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to fetch sqlite3 driver");
		return NULL;
	}
	
	if (r->method_number == M_POST) {
		errn = papi_read_body (r, &post);
		if (errn != OK) {
			APACHE_LOG (APLOG_ERR, "failed to save post");
			return NULL;
		}
	} else {
		post = apr_pstrdup (r->pool, "");
	}
	
	handle = papi_dbd_open (r, d, driver);
	
	if (handle == NULL) {
		APACHE_LOG (APLOG_ERR, "failed to open database");
		return NULL;
	}
#ifdef APR_DBD_SQLITE3
	status = apr_dbd_prepare (driver, r->pool, handle, req_q, "req_q", &req_statement);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare req_q statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	status = apr_dbd_prepare (driver, r->pool, handle, header_q, "header_q", &header_statement);
	if ( status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare header_q statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
#endif
	key = ap_md5 (r->pool, (unsigned char*) apr_psprintf (r->pool, "%d%d", now, getpid()));
	
#ifdef APR_DBD_SQLITE3
	status = apr_dbd_pvquery (driver, r->pool, handle, &nrows, req_statement,
					 key, r->method, r->uri, r->args?r->args:"", r->filename,
					 post, "");
#else
	req_statement = apr_psprintf (r->pool, req_q, 
								  key, r->method, r->uri, r->args?r->args:"", 
								  r->filename, post, "");
	status = apr_dbd_query (driver, handle, &nrows, req_statement);
#endif
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to exec req_q statement: %s",
					apr_dbd_error (driver, handle, status));
		return NULL;
	}

	headers_in = apr_table_elts (r->headers_in);
	
	for (i=0; i < headers_in->nelts; i++) {
		apr_table_entry_t *header_in;
		header_in = ((apr_table_entry_t*) headers_in->elts)+i;
#ifdef APR_DBD_SQLITE3
		status = apr_dbd_pvquery (driver, r->pool, handle, &nrows, header_statement,
								  key, header_in->key, header_in->val);
#else
		header_statement = apr_psprintf (r->pool, header_q, 
										 key, header_in->key, header_in->val);
		status = apr_dbd_query (driver, handle, &nrows, header_statement);
#endif
		if (status != APR_SUCCESS) {
			APACHE_LOG (APLOG_ERR, "failed to exec header_q statement: %s",
						   apr_dbd_error (driver, handle, status));
			return NULL;
		}
		
	}
		
	apr_dbd_close (driver, handle);
		
	return key;
}

static apr_dbd_t *papi_dbd_open (request_rec* r, papi_dir_config *d, const apr_dbd_driver_t *driver) {
	apr_dbd_t *handle = NULL;
	apr_status_t status;
	
	const char *table1 = 
		"CREATE TABLE Request ("
		"id TEXT NOT NULL, "
		"method CHAR(5) NOT NULL, "
		"uri TEXT NOT NULL, "
		"args TEXT NOT NULL, "
		"filename TEXT NOT NULL, "
		"post TEXT, "
		"timeEnter DATE, "
		"primary key (id))";
	const char *table2 =
		"CREATE TABLE Header ("
		"id TEXT NOT NULL, " 
		"key TEXT NOT NULL, "
		"value TEXT NOT NULL)";
	const char *trigger1 = 
		"CREATE TRIGGER insert_Request_timeEnter AFTER INSERT ON Request "
		"BEGIN "
		"  UPDATE Request SET timeEnter = DATETIME('NOW','LOCALTIME') WHERE id = new.id;"
		"END ";
	const char *trigger2 =
		"CREATE TRIGGER Request_on_Delete_Cascade BEFORE DELETE ON Request "
		"FOR EACH ROW BEGIN "
		"  DELETE FROM Header WHERE id = OLD.id; "
		"END";
	int nrows = 0;
	
	int build = FALSE;
	apr_finfo_t finfo;
	status = apr_stat(&finfo, d->req_db, APR_FINFO_USER, r->pool);
	if (status != APR_SUCCESS) {
		build = TRUE;
	}
	
	status = apr_dbd_open (driver, r->pool, d->req_db, &handle);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to open database");
		return NULL;
	}
	
	if (!build) {
		return handle;
	}
		
	status = apr_dbd_query (driver, handle, &nrows, table1);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare table1 statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	status = apr_dbd_query (driver, handle, &nrows, table2);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare table2 statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	status = apr_dbd_query (driver, handle, &nrows, trigger1);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare trigger1 statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	status = apr_dbd_query (driver, handle, &nrows, trigger2);
	if (status != APR_SUCCESS) {
		APACHE_LOG (APLOG_ERR, "failed to prepare trigger2 statement: %s",
					   apr_dbd_error (driver, handle, status));
		apr_dbd_close (driver, handle);
		return NULL;
	}
	
	return handle;	
}

	
