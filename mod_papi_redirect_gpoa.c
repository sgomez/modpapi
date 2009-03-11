#include "mod_papi_private.h"

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

static int papi_is_https (request_rec *r)
{
	const char* uri = ap_construct_url (r->pool, r->unparsed_uri, r);
	return strncmp (uri, "https", 5) == 0;
}

static void papi_no_cache (request_rec *r)
{
	r->no_cache = 1;
	apr_table_add(r->headers_out, "Cache-Control", "no-cache");
	apr_table_add(r->headers_out, "Pragma", "no-cache");
}

static int papi_builtin_wayf (request_rec *r, papi_dir_config *d)
{
	char *action = papi_uri_get_arg (r->pool, r->args, "NEXTURL");
	char *poaref = papi_uri_get_arg (r->pool, r->args, "PAPIPOAREF");
	char *poaurl = papi_uri_get_arg (r->pool, r->args, "PAPIPOAURL");
	char *noofas = papi_uri_get_arg (r->pool, r->args, "NOOFAS");
	char *body;
	int i;
	int asn;
	
	papi_no_cache (r);
	
	if (noofas == NULL) {
		APACHE_LOG (APLOG_ERR, "papi_builtin_wayf : NOOFAS is NULL");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	asn = atoi (noofas);
	
	if (asn == 1) {
		char *id;
		char *url;
		
		id  = papi_uri_get_arg (r->pool, r->args, "ASID0");
		url = papi_uri_add_arg (r->pool, action, "PAPIPOAREF", poaref);
		url = papi_uri_add_arg (r->pool, url, "PAPIPOAURL", poaurl);
		url = papi_uri_add_arg (r->pool, url, "ASID", id);
		
		return papi_redirect_url (r, url);
	}
	
	body = apr_pstrcat (r->pool,
						"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n"
						"<html><head><title>PAPI Internal Location Service</title></head>"
						"<body><form method=\"GET\" action=\"", action, "\">"
						"<h3>PAPI Internal Location Service</h3>"
						"<p>Please select your Authentication Server from the following "
						"list and press the <b>Authenticate</b> button.</p>"
						"<input type=\"hidden\" name=\"PAPIPOAREF\" value=\"", poaref, "\">"
						"<input type=\"hidden\" name=\"PAPIPOAURL\" value=\"", poaurl, "\">"
						"<select name=\"ASID\">", NULL);
	
	for (i=0; i < asn; i++) {
		char *as_name;
		char *as_desc;
		
		as_name = apr_psprintf (r->pool, "ASID%d", i);
		as_desc = apr_psprintf (r->pool, "ASDESC%d", i);
		
		body = apr_pstrcat (r->pool,
							body,
							"<option value=\"", papi_uri_get_arg (r->pool, r->args, as_name), "\">", 
							  papi_uri_get_arg (r->pool, r->args, as_desc),
							"</option>", NULL);
	}
	
	body = apr_pstrcat (r->pool,
						body,
						"<p><input type=\"submit\" value=\"Authenticate\">"
						"</form></body></html>", NULL);
	
	ap_set_content_type (r, "text/html");
	ap_rputs (body, r);
	
	return DONE;
}

int papi_redirect_gpoa (request_rec *r, papi_dir_config *d)
{
	char *poa_uri;
	
	if (d->lazy_session) {
		poa_uri = papi_uri_get_arg (r->pool, r->args, "target");
                if (poa_uri == NULL) {
                    APACHE_LOG (APLOG_ERR, "No target in lazy session");
                    return 1;
                }
                char *ptr = strstr(r->uri, d->auth_location);
                if (ptr) *ptr='\0';
                char *src = ptr;
                if (strncmp (r->args, "target=", 7) == 0) {
                    ptr = r->args;
                    src = strchrnul (r->args, '&');
                    if (*src == '&') src ++;
                } else {
                    ptr = strstr(r->args, "&target=");
                    src = strchrnul (ptr+1, '&');
                }
                memcpy (ptr, src, strlen(src)+1);

	} else {
		poa_uri = ap_construct_url (r->pool, r->unparsed_uri, r);
	}
	char *poa_url = ap_getword_nc (r->pool, &poa_uri, '?');
	const char *poa_scheme = papi_is_https (r) ? "https" : "http";
	const char *poa_server = ap_get_server_name (r);
	int poa_port = ap_get_server_port (r);
	
	if (((poa_port != 80) && (strcmp (poa_scheme, "http") == 0)) ||
		((poa_port != 443) && (strcmp (poa_scheme, "https") == 0)))
		poa_server = apr_psprintf (r->pool, "%s:%d", poa_server, poa_port);
	
	char *key = papi_save_request (r, d);
	
	if (strncmp (d->gpoa_url, "wayf:", 5) == 0) {
		// Using a wayf
		char *argstr, *nexturl, *fas, *wayfurl;
		int i;		

		wayfurl = strchr (d->gpoa_url, ':')+1;
		if (strncmp (wayfurl, "http", 4) == 0) {
			// External WAYF
			wayfurl = papi_uri_add_arg (r->pool, wayfurl, "PAPIPOAREF", key);
			wayfurl = papi_uri_add_arg (r->pool, wayfurl, "PAPIPOAURL", poa_url);
	
			return papi_redirect_url (r, wayfurl);
		}

		nexturl = apr_pstrcat (r->pool,
							   poa_scheme, "://", poa_server, d->loc, 
							   d->auth_location, "/PAPIASRedirector", NULL);
		fas = apr_psprintf (r->pool, "%d", d->papi_as->nelts);
		
		argstr = papi_uri_add_arg (r->pool, "", "PAPIPOAREF", key);
		argstr = papi_uri_add_arg (r->pool, argstr, "PAPIPOAURL", poa_url);
		argstr = papi_uri_add_arg (r->pool, argstr, "NEXTURL", nexturl);
		argstr = papi_uri_add_arg (r->pool, argstr, "NOOFAS", fas);
		
		for (i=0; i < d->papi_as->nelts; i++) {
			papi_as_t *papi_as;
			
			papi_as = ((papi_as_t *) d->papi_as->elts)+i;
			
			argstr = papi_uri_add_arg (r->pool, argstr, apr_psprintf (r->pool, "ASID%d", i), papi_as->name);
			argstr = papi_uri_add_arg (r->pool, argstr, apr_psprintf (r->pool, "ASDESC%d", i), papi_as->description);
			argstr = papi_uri_add_arg (r->pool, argstr, apr_psprintf (r->pool, "ASURL%d", i), papi_as->url);
		}
		
		argstr++; // argstr stars with '?'
		
		if (strcmp (wayfurl, "built-in") == 0) {
			// Built-in WAYF
			
			APACHE_LOG (APLOG_DEBUG, "(%s:%d) Redirecting to built-in WAYF:%s", 
						   __FILE__, __LINE__, wayfurl);
			r->args = argstr; 
			return papi_builtin_wayf (r, d);
			
		} else {
			// Internal WAYF
			
			request_rec *sr;
			int err;
			
			APACHE_LOG (APLOG_DEBUG, "(%s:%d) Redirecting to internal WAYF:%s", 
						   __FILE__, __LINE__, wayfurl);
			
			sr = ap_sub_req_lookup_file (wayfurl, r, NULL);
			sr->args = argstr;
			papi_no_cache (sr);
			err = ap_run_sub_req (sr);
			ap_destroy_sub_req (sr);
			
			return err;
		}
		
	} else { 
		// Redirect to a normal GPoA
		char *rurl;
		
		rurl = papi_uri_add_arg (r->pool, d->gpoa_url, "ACTION", "CHECK");
		rurl = papi_uri_add_arg (r->pool, rurl, "DATA", key);
		rurl = papi_uri_add_arg (r->pool, rurl, "URL", poa_url);
		
		APACHE_LOG (APLOG_DEBUG, "(%s:%d) Redirecting to %s", 
					 __FILE__, __LINE__, rurl);
		
		return papi_redirect_url (r, rurl);						   
	}
}


