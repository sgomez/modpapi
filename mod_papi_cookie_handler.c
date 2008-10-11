#include "mod_papi_cookie_handler.h"

/** Action array function pointer.
 */
static int (* action_function[]) (request_rec *, papi_dir_config *) =
{
	NULL,
	papi_cookie_login,
	papi_cookie_logout,
	papi_cookie_test,
	papi_cookie_check,
	papi_cookie_checked
};

int papi_cookie_handler (request_rec *r, papi_dir_config *d)
{
	int action = papi_get_action (r);
	char *data = papi_uri_get_arg (r->pool, r->args, "DATA");
	char *target = papi_uri_get_arg (r->pool, r->args, "target");
	
	if (d->lazy_session && target) {
		if (d->gpoa_url) {
			return papi_redirect_gpoa (r, d);
		} else {
			return OK;
		}
	}
	
	if (!action) {
		APACHE_LOG (APLOG_WARNING, "Signed URL without valid ACTION field");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	if (!data) {
		APACHE_LOG (APLOG_WARNING, "Signed URL without DATA field");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	return action_function[action](r,d);
}

static int papi_cookie_test (request_rec *r, papi_dir_config *d)
{
	char *lcook = papi_test_lcook (r, d);
	char *aurl  = papi_uri_get_arg (r->pool, r->args, "AURL");
	char *rurl  = papi_uri_get_arg (r->pool, r->args, "RURL");

	if (lcook) {
		if (aurl)
			return papi_redirect_url (r, aurl);
		else
			return papi_send_file (r, d->accept_file);
	} else {
		if (rurl)
			return papi_redirect_url (r, rurl);
		else
			return papi_send_file (r, d->reject_file);
	}
}

static int papi_cookie_login (request_rec *r, papi_dir_config *d)
{
	int valid_date;
	char *aurl  = papi_uri_get_arg (r->pool, r->args, "AURL");
	char *rurl  = papi_uri_get_arg (r->pool, r->args, "RURL");
	
	char *code = papi_test_url (r, d, &valid_date);
	if (valid_date == 0) {
		APACHE_LOG (APLOG_WARNING, "Error validating URL from AS %s",
					 papi_uri_get_arg (r->pool, r->args, "AS"));
		if (rurl)
			return papi_redirect_url (r, rurl);
		else
			return papi_send_file (r, d->reject_file);
	}
	char *lcook = papi_gen_lcook (r, d, code);

	if (aurl)
		return papi_redirect_with_cookies (r, aurl, lcook);
	else
		return papi_send_file_with_cookies (r, d->accept_file, lcook);
}

static int papi_cookie_logout (request_rec *r, papi_dir_config *d)
{
	char *lcook = papi_test_lcook (r, d);
	char *aurl  = papi_uri_get_arg (r->pool, r->args, "AURL");
	char *rurl  = papi_uri_get_arg (r->pool, r->args, "RURL");

	if (lcook) {
		APACHE_LOG (APLOG_INFO, "Logging out %s", lcook);
		lcook = papi_gen_logout_lcook_cookie (r, d);
		if (aurl)
			return papi_redirect_with_cookies (r, aurl, lcook);
		else
			return papi_send_file_with_cookies (r, d->accept_file, lcook);
	} else {
		APACHE_LOG (APLOG_WARNING, "Error trying to LOGOUT");
		if (rurl)
			return papi_redirect_url (r, rurl);
		else
			return papi_send_file (r, d->reject_file);
	}				
}

static int papi_cookie_check (request_rec *r, papi_dir_config *d)
{
	char *lcook = papi_test_lcook (r, d);
	char *url   = papi_uri_get_arg (r->pool, r->args, "URL");
	char *data  = papi_uri_get_arg (r->pool, r->args, "DATA");

	if (!lcook) {
		if (d->gpoa_url) {
			return papi_redirect_gpoa (r, d);
		} else {
			APACHE_LOG (APLOG_WARNING, 
						 "Error testing authZ tokens at GPoA for %s", url);
			return papi_redirect_error_url (r, d, url, data);
		}
	}
	
	int now = (int)time(NULL);
	int gpoa_vdate = now + d->lcook_timeout;
	
	char *userdata = papi_gen_user_data (r, d, url, lcook);
	char *rdata = papi_encrypt_gen_code (r, d, userdata, gpoa_vdate, data);
	url = papi_uri_add_arg (r->pool, url, "ACTION", "CHECKED");
	url = papi_uri_add_arg (r->pool, url, "DATA", rdata);
	lcook = papi_gen_lcook (r, d, lcook);
	APACHE_LOG (APLOG_DEBUG, "Main: New Lcook: %s", lcook);
	
	return papi_redirect_with_cookies (r, url, lcook);
}

static int papi_cookie_checked (request_rec *r, papi_dir_config *d)
{
	int valid_date;
	char *code;
	poa_request_t *request = NULL;
	
	char *req_id = papi_test_gpoa_url (r, d, &code, &valid_date);
	if (req_id) {
		request = papi_load_request (r, d, req_id);
	}
	
	if (request == NULL) {
		char *redir = apr_pstrcat (r->pool, "http://",
								   r->hostname,
								   d->loc, NULL);
		APACHE_LOG (APLOG_ERR, "Invalid requestID received from GPoA/AS");
		return papi_redirect_url (r, redir);
	}
	
	char *url  = papi_uri_get_arg (r->pool, request->args, "URL");
	char *data = papi_uri_get_arg (r->pool, request->args, "DATA");
	
	if (valid_date == 0) {
		APACHE_LOG (APLOG_WARNING, "Invalid GPoA/AS answer for %s",
					 ap_construct_url (r->pool, r->unparsed_uri, r));
		return papi_redirect_error_url (r, d, url, data);
	}
	
	char *userdata = papi_gen_user_data (r, d, url, code);
	char *rdata = papi_encrypt_gen_code (r, d, userdata, valid_date, data);
	url = papi_uri_add_arg (r->pool, url, "ACTION", "CHECKED");
	url = papi_uri_add_arg (r->pool, url, "DATA", rdata);
	
	if (valid_date > 1) {
		char *lcook = papi_gen_lcook (r, d, code);
		APACHE_LOG (APLOG_DEBUG, "(%s:%d) New Lcook: %s", 
					 __FILE__, __LINE__, lcook);
		return papi_redirect_with_cookies (r, url, lcook);
	}
	
	return papi_redirect_url (r, url);
}

static int papi_send_file (request_rec *r, const char *filename)
{	
	request_rec *rs = ap_sub_req_lookup_file (filename, r, NULL);
	ap_set_content_type (r, rs->content_type);
	int err = ap_run_sub_req (rs);
	if (err != OK)
		APACHE_LOG (APLOG_ERR, "Cookie_Handler: Exception handling %s (%d)",
					   filename, err);
	ap_destroy_sub_req (rs);
	return err;
}

static int papi_send_file_with_cookies (request_rec *r, const char *filename, const char *lcook)
{
	
	request_rec *rs = ap_sub_req_lookup_file (filename, r, NULL);
	apr_table_set (r->err_headers_out, "Set-cookie", lcook);
	ap_set_content_type (r, rs->content_type);
	int err = ap_run_sub_req (rs);
	if (err != OK)
		APACHE_LOG (APLOG_ERR, "Cookie_Handler: Exception handling %s", filename);
	ap_destroy_sub_req (rs);
	return err;
}	

int papi_redirect_with_cookies (request_rec *r, const char *uri, const char *lcook)
{
	apr_table_set (r->err_headers_out, "Location", uri);
	apr_table_add (r->err_headers_out, "Set-cookie", lcook);
	return HTTP_MOVED_TEMPORARILY;
}

static int papi_redirect_error_url (request_rec *r, papi_dir_config *d, const char *uri, const char *data)
{
	char *rdata = papi_encrypt_gen_code (r, d, "ERROR", 0, data);
	char *poaURL = papi_uri_add_arg (r->pool, uri, "ACTION", "CHECKED");
	poaURL = papi_uri_add_arg (r->pool, poaURL, "DATA", rdata);
	
	return papi_redirect_url (r, poaURL);
}

int papi_redirect_url (request_rec *r, const char *uri)
{
	apr_table_set (r->err_headers_out, "Location", uri);
	return HTTP_MOVED_TEMPORARILY;
}

static char *papi_encrypt_gen_code (request_rec *r, papi_dir_config *d, const char *assert, int valid_date, const char *data)
{
	int now = valid_date == 0 ? 0 : (int)time(NULL);
	
	char *rsa_in = apr_psprintf (r->pool, "%s:%d:%d:%s",
						   assert,
						   valid_date,
						   now,
						   data);
	if (d->keys_path) {
		d->gpoa_privkey = apr_pstrcat (r->pool, d->keys_path, d->service_id, "_privkey.pem", NULL);
		apr_finfo_t finfo;
		int status = apr_stat(&finfo, d->gpoa_privkey, APR_FINFO_USER, r->pool);
		if (status != APR_SUCCESS) {
			APACHE_LOG (APLOG_ERR, "could not stat private gpoa keyfile %s", d->gpoa_privkey);
			return NULL;
		}
	}

	
	return papi_encrypt_priv_RSA (r, rsa_in, d->gpoa_privkey);
}

static char *papi_gen_user_data (request_rec *r, papi_dir_config *d, char *poa, char *code)
{
	int i;	
	char *ptr = strrchr (code, '@');
	char *asid = apr_pstrdup (r->pool, ptr+1);
	char *uas = apr_pstrndup (r->pool, code, ptr-code);
	
	for (i=0; i < d->gpoa_rewrite->nelts; i++) {
		gpoa_rewrite_t *poarw;

		poarw = ((gpoa_rewrite_t *) d->gpoa_rewrite->elts)+i;
		if (papi_regex_match (poarw->poa_re, poa)) {
			uas = papi_regex_replace (r->pool, poarw->re, uas, poarw->rs);
		}
	}
	
	uas = d->hash_user_data ? papi_md5_base64 (r, uas) : uas;	
	return apr_pstrcat (r->pool, uas, "@", asid, NULL);
}
