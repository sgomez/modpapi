#include "mod_papi_private.h"
#include <ctype.h>

/**
 * Encode in base a md5 checksum from a string.
 *
 * @param r      the request
 * @param str    the assertion
 * @return       the base64 encoded md5 checksum
 */
char *papi_md5_base64 (request_rec *r, char *str)
{	
	papi_return_val_if_fail (str, NULL);
	
	char *md5 = ap_md5 (r->pool, (unsigned char*) str);
	char *base64 = apr_palloc (r->pool, apr_base64_encode_len (strlen (md5)));
	apr_base64_encode (base64, md5, strlen (md5));
	return base64;
}

char *papi_escape_string (apr_pool_t *p, const char *str)
{		
	char *tmp = curl_easy_escape (NULL, str, 0);
	apr_pool_cleanup_register (p, tmp, (void *)free, apr_pool_cleanup_null);
	return tmp;
}

char *papi_unescape_string (apr_pool_t *p, const char *str)
{
	char *tmp = curl_easy_unescape (NULL, str, 0, NULL);
	apr_pool_cleanup_register (p, tmp, (void *)free, apr_pool_cleanup_null);
	return tmp;
}

char *papi_uri_get_arg (apr_pool_t *p, const char *src, const char *name)
{
	const char *queries;
	const char *start_query;
	
	if ((queries = src)) {
		for (start_query = ap_strstr_c(queries, name); start_query;
			 start_query = ap_strstr_c(start_query + 1, name)) {
				 if (start_query == queries ||
					 start_query[-1] == '&') {
						 
						 start_query += strlen(name);
						 
						 if (*start_query == '=' && start_query[1]) {
							 /*
							   * query param was found, get it's value
							   */
							 char *end_query, *query;
							 ++start_query;
							 query = apr_pstrdup(p, start_query);
							 if ((end_query = strchr(query, '&')) != NULL)
								 *end_query = '\0';
							 return papi_unescape_string (p, query);
						 }
					 }
			 }
	}
	return NULL;
}

char *papi_uri_add_arg (apr_pool_t *pool, const char *uri, const char *key, const char *value)
{
	char *sep;
	char *newuri;
	
	if (uri == NULL)
		return NULL;
	
	if (key == NULL || value == NULL || pool == NULL) 
		return apr_pstrdup (pool, uri);
	
	sep = strchr (uri, '?') ? "&" : "?";
	
	newuri = apr_pstrcat (pool,
						  uri, sep, 
						  key , "=", 
						  papi_escape_string (pool, value), NULL);
	
	return newuri;
}

int papi_get_action (request_rec *r)
{
	const char *action = papi_uri_get_arg (r->pool, r->args, "ACTION");
	
	if (!action) return 0;
	
	if (!strcmp (action, "CHECK"))
		return PAPI_CHECK;
	else if (!strcmp (action, "CHECKED"))
		return PAPI_CHECKED;
	else if (!strcmp (action, "LOGIN"))
		return PAPI_LOGIN;
	else if (!strcmp (action, "LOGOUT"))
		return PAPI_LOGOUT;
	else if (!strcmp (action, "TEST"))
		return PAPI_TEST;
	else
		return 0;
}

papi_regex_t *papi_regex_new (apr_pool_t *p, const char *pattern)
{
	papi_regex_t *re = apr_palloc (p, sizeof (papi_regex_t));
	
	const char *error;
	int erroroffset;
		
	re->pcre_re = pcre_compile (pattern, 0, &error, &erroroffset, NULL);
	if (re->pcre_re == NULL) {
		// APACHE_LOG (APLOG_DEBUG, "Error compiling regex %s: %s", pattern, error);
		return NULL;
	}
	apr_pool_cleanup_register (p, re->pcre_re, (void *) pcre_free, apr_pool_cleanup_null);
	re->pattern = pattern;
	
	return re;
}

int papi_regex_match (papi_regex_t *re, const char *string)
{
	int ovector[3];
	int length = strlen (string);
	int rc = pcre_exec (re->pcre_re, NULL, string, length, 0, 0, ovector, 3);
	
	return rc>0?TRUE:FALSE;
}

char *papi_regex_replace (apr_pool_t *p, papi_regex_t *re, const char* string, const char* replace)
{
	int ovector[3];
	int length = strlen (string);
	int rc = pcre_exec (re->pcre_re, NULL, string, length, 0, 0, ovector, 3);
	
	if (rc < 0) {
		return NULL;
	}
	
	if (rc == 0) {
		return apr_pstrdup (p, string);
	}
	
	// string = part_a + replace + part_b
	int string_a_length = ovector[0];
	int string_b_length = length - ovector[1];
	
	char *replaced = apr_psprintf (p, "%.*s%s%.*s",
								   string_a_length,
								   string,
								   replace,
								   string_b_length,
								   string+ovector[1]);
	
	return replaced;
}

char **papi_string_split (apr_pool_t *p, char *string, char *token, int limit)
{	
	if (limit < 1) return NULL;
	
	char **array = apr_pcalloc (p, sizeof(char*) * (limit+1));
	
	char *buffer = apr_pstrdup (p, string);
	int i;
	
	for (i=0; i<limit-1 && buffer; i++)
	{
		array[i] = strsep (&buffer, token);
	}
	array[i] = buffer;
	
	return array;
}

char* papi_file_stat (request_rec *r, papi_dir_config *d, const char *path, apr_filetype_e type) {
        apr_finfo_t finfo;
        apr_status_t status;
        
        status = apr_stat(&finfo, path, APR_FINFO_OWNER|APR_FINFO_PROT|APR_FINFO_TYPE, r->pool);
        papi_return_val_if_fail (status==APR_SUCCESS,
                apr_psprintf(r->pool, "Error file %s not found in Location %s", path, d->loc));
        papi_return_val_if_fail (finfo.filetype == type,
                apr_psprintf(r->pool, "Error PAPI expected another type of file (%s) in Location %s", path, d->loc));

        papi_return_val_if_fail (type == APR_DIR && ((finfo.user  == geteuid() && finfo.protection&S_IWUSR) ||
                                     (finfo.group == getegid() && finfo.protection&S_IWGRP) ||
                                     (finfo.protection&S_IWOTH)),
                apr_psprintf(r->pool, "Error PAPI can't write on directory %s in Location %s", path, d->loc));

        papi_return_val_if_fail (type == APR_REG && ((finfo.user  == geteuid() && finfo.protection&S_IRUSR) ||
                                     (finfo.group == getegid() && finfo.protection&S_IRGRP) ||
                                     (finfo.protection&S_IROTH)),
                apr_psprintf(r->pool, "Error PAPI can't read file %s in Location %s", path, d->loc));
        return NULL;

}
