#include "mod_papi_private.h"

typedef struct {
	char *data;
	size_t size;
} papi_post_data_t;

static size_t papi_post_read_data (void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	papi_post_data_t *mem = (papi_post_data_t *)data;
		
	mem->data = (char *)realloc(mem->data, mem->size + realsize + 1);
	if (mem->data) {
		memcpy(&(mem->data[mem->size]), ptr, realsize);
		mem->size += realsize;
		mem->data[mem->size] = 0;
	}
	return realsize;
}


int papi_post_handler (request_rec *r, papi_dir_config *d, const char *post)
{
	char *uri = ap_construct_url (r->pool, r->unparsed_uri, r);
	char *ptr = strchr (uri, '?');
	if (ptr) *ptr = '\0';

	papi_post_data_t *papi_post_data = apr_pcalloc (r->pool, sizeof (papi_post_data_t));
	
	curl_global_init (CURL_GLOBAL_ALL);
	CURL *curl = curl_easy_init();
	curl_easy_setopt (curl, CURLOPT_URL, uri);
	curl_easy_setopt (curl, CURLOPT_POST, 1);
	curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, papi_post_read_data);
	curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)papi_post_data);
	
	// Copy saved header in request.
	int i;
	const apr_array_header_t *headers_in = apr_table_elts (r->headers_in);
	struct curl_slist *headers_out = NULL;
	for (i=0; i < headers_in->nelts; i++) {
		apr_table_entry_t *entry = ((apr_table_entry_t *)headers_in->elts)+i;
		char *header;
		if (!strcmp (entry->key, "Content-Length")) {
			header = apr_psprintf (r->pool, "Content-Length: %d", (int)strlen(post));
		} else {
			header = apr_pstrcat (r->pool, entry->key, ": ", entry->val, NULL);
		}
		headers_out = curl_slist_append (headers_out, header);
	}
	
	curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers_out);
	curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post);
	int res = curl_easy_perform (curl);
	if (res == CURLE_OK) {
		char *ct;
		curl_easy_getinfo (curl, CURLINFO_CONTENT_TYPE, &ct);
		ap_set_content_type (r, apr_pstrdup (r->pool, ct));
	}
	curl_easy_cleanup (curl);
	curl_global_cleanup();
	
	ap_rputs (papi_post_data->data, r);
	free (papi_post_data->data);
	
	return DONE;
}

int papi_read_body (request_rec *r, char **buffer)
{
	char buf[MAX_SIZE+1];
	size_t bytes, count = 0;
	
	*buffer = apr_pstrdup (r->pool, "");
	
	if (ap_setup_client_block (r, REQUEST_CHUNKED_DECHUNK) != OK) {
		APACHE_LOG (APLOG_ERR, "Bad request body!");
		return HTTP_BAD_REQUEST;
	}
	
	if (ap_should_client_block (r)) {
		for (bytes = ap_get_client_block (r, buf, MAX_SIZE); 
			 bytes > 0;
			 bytes = ap_get_client_block (r, buf, MAX_SIZE)) {
				 buffer[bytes-1] = '\0';
				 *buffer = apr_pstrcat (r->pool, *buffer, buf, NULL);
				 count += bytes;
			 }
	} else {
		APACHE_LOG (APLOG_WARNING, "No request body.");
	}
	buffer[count-1] = '\0';

	return OK;
}

