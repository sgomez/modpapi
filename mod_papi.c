#include "mod_papi_private.h"
#include "mod_papi.h"

/**
 * Generate a random lkey
 *
 * @param p     Apache memory pool
 * @return      A random lkey
 */

static char *papi_generate_lkey(apr_pool_t *p) {    
    unsigned char rnd[256];
    if (RAND_bytes(rnd, 256) == 0) {
        RAND_pseudo_bytes (rnd, 256);
    }
    return ap_md5_binary(p, rnd, 256);
}

/**
 * Test if a URL pass PAPIPassURLPattern filters.
 *
 * @param r     the request
 * @param d     the configuration of the PoA/GPoA
 * @param curl  url to check
 * @return      true is the url matches one filter
 */
static int papi_test_pass_url_pattern(request_rec *r, papi_dir_config *d, const char *curl) {
    papi_return_val_if_fail(curl, 0);

    int i;
    for (i = 0; i < d->pass_url_pattern->nelts; i++) {
        pass_url_pattern_t *pass_url_pattern = ARRAY(pass_url_pattern, i);
        if (papi_regex_match(pass_url_pattern->re, curl)) {
            APACHE_LOG(APLOG_INFO,
                    "Request for %s matches passtrhought filter %s. Access granted",
                    curl, pass_url_pattern->re->pattern);
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Default PAPI config
 *
 * @param p     Apache memory pool
 * @param loc   Location
 * @return      Apache Config
 */
static void* create_papi_dir_config(apr_pool_t* pool, char *loc) {
    papi_dir_config* dir = apr_pcalloc(pool, sizeof (papi_dir_config));

    dir->accept_file = NULL;
    dir->attribute_list = DEFAULT_ARRAY_TYPE(attribute_list_t);
    dir->attribute_separator = UNSET;
    dir->auth_location = NULL;
    dir->cookie_reject = DEFAULT_ARRAY_TYPE(cookie_reject_t);
    dir->client_address_in_tokens = UNSET;
    dir->domain = NULL;
    dir->gpoa_hash_user_data = UNSET;
    dir->gpoa_privkey = NULL;
    dir->gpoa_rewrite = DEFAULT_ARRAY_TYPE(gpoa_rewrite_t);
    dir->gpoa_url = NULL;
    dir->hash_user_data = UNSET;
    dir->keys_path = NULL;
    dir->lazy_session = UNSET;
    dir->lcook_max_timeout = UNSET;
    dir->lcook_timeout = UNSET;
    dir->lkey = papi_generate_lkey(pool);
    dir->loc = loc;
    dir->max_ttl = UNSET;
    dir->papi_as = DEFAULT_ARRAY_TYPE(papi_as_t);
    dir->papi_filter = DEFAULT_ARRAY_TYPE(papi_filter_t);
    dir->pass_url_pattern = DEFAULT_ARRAY_TYPE(pass_url_pattern_t);
    dir->reject_file = NULL;
    dir->remote_user_attrib = NULL;
    dir->req_db = NULL;
    dir->req_dir = NULL;
    dir->service_id = NULL;
    dir->signoff_location = DEFAULT_ARRAY_TYPE(signoff_location_t);
    dir->url_timeout = UNSET;
    dir->user_data_rewrite = apr_palloc(pool, sizeof (user_data_rewrite_t));
    dir->user_data_rewrite->re = NULL;
    dir->user_data_rewrite->rs = NULL;
    dir->value_separator = UNSET;
    dir->wayf = NULL;

    return (void *) dir;
}

static void* create_papi_merge_dir_config(apr_pool_t* pool, void* _base, void* _add) {
    papi_dir_config* base = _base;
    papi_dir_config* add = _add;
    papi_dir_config* mrg = apr_pcalloc(pool, sizeof (papi_dir_config));
    mrg->user_data_rewrite = apr_palloc(pool, sizeof (user_data_rewrite_t));

    cfgMergeString  (accept_file);
    cfgMergeArray   (attribute_list);
    cfgMergeChar    (attribute_separator);
    cfgMergeString  (auth_location);
    cfgMergeArray   (cookie_reject);
    cfgMergeBool    (client_address_in_tokens);
    cfgMergeString  (domain);
    cfgMergeBool    (gpoa_hash_user_data);
    cfgMergeArray   (gpoa_rewrite);
    cfgCopy         (gpoa_url);
    cfgMergeBool    (hash_user_data);
    cfgMergeString  (keys_path);
    cfgMergeBool    (lazy_session);
    cfgMergeInt     (lcook_max_timeout);
    cfgMergeInt     (lcook_timeout);
    cfgCopy         (lkey);
    cfgMergeString  (loc);
    cfgMergeInt     (max_ttl);
    cfgMergeArray   (papi_as);
    cfgMergeArray   (papi_filter);
    cfgMergeArray   (pass_url_pattern);
    cfgMergeString  (reject_file);
    cfgMergeString  (remote_user_attrib);
    cfgMergeString  (req_dir);
    cfgCopy         (service_id);
    cfgMergeArray   (signoff_location);
    cfgMergeInt     (url_timeout);
    cfgMergeString  (user_data_rewrite->re);
    cfgMergeString  (user_data_rewrite->rs);
    cfgMergeChar    (value_separator);
    cfgCopy         (wayf);

    return (void *) mrg;
}

static int papi_auth_hook(request_rec *r) {
    int i;
    const char *type = ap_auth_type(r);
    if (!type || strcasecmp(type, "PAPI")) {
        return DECLINED;
    }

    // Configure POA
    papi_dir_config *d = ap_get_module_config(r->per_dir_config, &papi_module);
    const char *err = papi_set_parameters(r, d);
    if (err) {
        APACHE_LOG(APLOG_ERR, "Error configuring %s: %s", d->loc, err);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    char *curl = ap_construct_url(r->pool, r->unparsed_uri, r);
    char *ptr = strchr(curl, '?');
    char *url = apr_pstrndup(r->pool, curl, ptr - curl);

    APACHE_LOG(APLOG_DEBUG, "Processing request: %s", curl);

    // Check wether the request matches passthrough filters
    if (papi_test_pass_url_pattern(r, d, curl)) return OK;

    if ((strstr(r->uri, d->auth_location))) {
        // Redirection to an AS to reauthenticate user
        if ((strstr(r->uri, "PAPIASRedirector"))) {
            char *as = papi_uri_get_arg(r->pool, r->args, "ASID");
            if (as == NULL) {
                return HTTP_FORBIDDEN;
            }

            char *asurl = NULL;
            for (i = 0; i < d->papi_as->nelts; i++) {
                papi_as_t *papi_as = ARRAY(papi_as, i);
                if (apr_strnatcmp(papi_as->name, as) == 0) {
                    asurl = apr_pstrdup(r->pool, papi_as->url);
                    break;
                }
            }

            if (asurl == NULL) {
                return HTTP_FORBIDDEN;
            }

            char *poaurl = papi_uri_get_arg(r->pool, r->args, "PAPIPOAURL");
            char *poaref = papi_uri_get_arg(r->pool, r->args, "PAPIPOAREF");
            asurl = papi_uri_add_arg(r->pool, asurl, "ATTREQ", d->service_id);
            asurl = papi_uri_add_arg(r->pool, asurl, "PAPIPOAREF", poaref);
            asurl = papi_uri_add_arg(r->pool, asurl, "PAPIPOAURL", poaurl);

            return papi_redirect_url(r, asurl);
        } else {
            // A request for cookies coming from an AS
            return papi_cookie_handler(r, d);
        }
    }

    // Processing actions
    APACHE_LOG(APLOG_DEBUG, "Main processing request %s", curl);

    char *code = NULL;
    if (papi_get_action(r) == PAPI_CHECKED) { // Answer from a GPoA

        // Check from an answer of ans AS to an ATTREQ
        int valid_date;
        char *req_id = papi_test_gpoa_url(r, d, &code, &valid_date);

        if (req_id == NULL) {
            APACHE_LOG(APLOG_WARNING, "Invalid GPoA/AS answer for %s",
                    r->uri);
            return HTTP_FORBIDDEN;
        }

        poa_request_t *request = papi_load_request(r, d, req_id);
        // If no request found, asssume this is a old visit (reload)
        if (request == NULL) {
            const char *data = r->args;
            const char *pair;

            if (data != NULL) {
                while (*data && (pair = ap_getword(r->pool, &data, '&'))) {
                    const char *name;
                    name = ap_getword(r->pool, &pair, '=');
                    if (strcmp(name, "ACTION") && strcmp(name, "DATA") && strcmp(name, "AS")) {
                        url = papi_uri_add_arg(r->pool, url, name, pair);
                    }
                }
            }
            return papi_redirect_url(r, url);
        }

        if (valid_date == 0) {
            APACHE_LOG(APLOG_WARNING, "Invalid GPoA/AS answer for %s",
                    r->uri);
            return HTTP_FORBIDDEN;
        }

        char *lcook = papi_gen_lcook(r, d, (int) time(NULL), code);
        apr_table_add(r->err_headers_out, "Set-Cookie", lcook);
        APACHE_LOG(APLOG_DEBUG, "New Lcook: %s", lcook);

        // Copy saved header in request.
        const apr_array_header_t *headers_in = apr_table_elts(request->headers_in);
        for (i = 0; i < headers_in->nelts; i++) {
            apr_table_entry_t *entry = ((apr_table_entry_t *) headers_in->elts) + i;
            if (!strcmp(entry->key, "Content-Length")) continue;
            apr_table_set(r->headers_in, entry->key, entry->val);
        }

        // Remove lcook in request.
        char *cookie = NULL;
        const char *data = apr_table_get(request->headers_in, "Cookie");
        const char *pair;
        if (cookie != NULL) {
            while (*data && (pair = ap_getword(r->pool, &data, ';'))) {
                if (strncmp("Lcook=", pair, 6)) {
                    if (cookie) {
                        cookie = apr_pstrcat(r->pool, cookie, ";", pair, NULL);
                    } else {
                        cookie = apr_pstrdup(r->pool, pair);
                    }
                }
            }
            apr_table_set(r->headers_in,
                    "Cookie",
                    cookie);
        }

        // Restore the others request elements
        r->method = apr_pstrdup(r->pool, request->method);
        r->method_number = ap_method_number_of(r->method);
        r->uri = apr_pstrdup(r->pool, request->uri);
        r->args = apr_pstrdup(r->pool, request->args);
        r->filename = apr_pstrdup(r->pool, request->filename);
        if (r->method_number == M_POST) {
            cookie = apr_pstrcat(r->pool, lcook, ";", apr_table_get(r->headers_in, "Cookie"), NULL);
            apr_table_set(r->headers_in, "Cookie", cookie);
            APACHE_LOG(APLOG_DEBUG, "Main: POST request");
            return papi_post_handler(r, d, request->post);
        }

    } else { // Normal request
        APACHE_LOG(APLOG_DEBUG, "Processing request %s", r->uri);

        int init = UNSET;
        code = papi_test_lcook(r, d, &init);
        if (code == NULL) {
            if (d->lazy_session) {
                return OK;
            } else {
                if (d->gpoa_url) {
                    return papi_redirect_gpoa(r, d);
                } else {
                    return HTTP_FORBIDDEN;
                }
            }
        } else {
            apr_table_add(r->err_headers_out, "Set-Cookie",
                    papi_gen_lcook(r, d, init, code));
            APACHE_LOG(APLOG_DEBUG, "Lcook OK: %s", code);
        }
    }

    APACHE_LOG(APLOG_INFO, "Access OK to %s: %s %s",
            d->service_id, code, url);
    // Signoff request
    for (i = 0; i < d->signoff_location->nelts; i++) {

        signoff_location_t *so = ARRAY(signoff_location, i);
        if (papi_regex_match(so->re, curl)) {
            APACHE_LOG(APLOG_ERR, "Signoff request through %s. Tokens invalidated and request redirected to %s",
                    curl, so->url);
            char *lcook = papi_gen_logout_lcook_cookie(r, d);
            return papi_redirect_with_cookies(r, so->url, lcook);
        }

    }

    // Pass user attribute information
    if (d->attribute_list->nelts == 0) {
        const char *asid;
        asid = papi_build_attrList(r, d, code);
        if (asid != NULL) {
            apr_table_add(r->notes,
                    apr_pstrdup(r->pool,
                    "PAPI-ASID"),
                    asid);
            apr_table_add(r->headers_in,
                    apr_pstrdup(r->pool,
                    "X-PAPI-ASID"),
                    asid);
        }
    }

    for (i = 0; i < d->attribute_list->nelts; i++) {

        attribute_list_t *attr = ARRAY(attribute_list, i);
        apr_table_add(r->notes,
                apr_pstrcat(r->pool,
                "PAPIAttr-", attr->key, NULL),
                attr->value);
        apr_table_add(r->headers_in,
                apr_pstrcat(r->pool,
                "X-PAPIAttr-", attr->key, NULL),
                attr->value);
        if (strcmp(attr->key, d->remote_user_attrib) == 0) {
            APACHE_LOG(APLOG_DEBUG, "Remote user is %s", attr->value);
            r->user = apr_pstrdup(r->pool, attr->value);
        }
    }

    return OK;
}

static command_rec papi_cmds [] =
{
    AP_INIT_TAKE1(
    "PAPILKey",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, lkey),
    RSRC_CONF | OR_AUTHCFG,
    "PAPILKey string: Defines encryption key for the Lcook tokens."
    ),
    AP_INIT_TAKE1(
    "PAPIServiceID",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, service_id),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIServiceID serviceName: Name used to identify a PoA"
    ),
    AP_INIT_TAKE1(
    "PAPIAcceptFile",
    papi_set_file_slot,
    (void *) APR_OFFSETOF(papi_dir_config, accept_file),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIAcceptFile filename: File holding the default object "
    "to be sent to the user's browser when an action is accepted."
    ),
    AP_INIT_TAKE1(
    "PAPIRejectFile",
    papi_set_file_slot,
    (void *) APR_OFFSETOF(papi_dir_config, reject_file),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIRejectFile filename: File holding the default object "
    "to be sent to the user's browser when an action is rejected."
    ),
    AP_INIT_TAKE1(
    "PAPIKeysPath",
    papi_set_path_slot,
    (void *) APR_OFFSETOF(papi_dir_config, keys_path),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIPubkeysPath directoryName: Directory where public keys of "
    "the authentication servers are stored."
    ),
    AP_INIT_TAKE1(
    "PAPIDomain",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, domain),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIDomain domainName: Name of the web server this PoA belongs to."
    ),
    AP_INIT_TAKE1(
    "PAPIAuthLocation",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, auth_location),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIAuthLocation location: URI for dealing with direct "
    "connections between the PoA and PAPI authentication servers."
    ),
    AP_INIT_TAKE2(
    "PAPISignoffLocation",
    papi_set_signoff_location_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPISignoffLocation regularExpression URL: Requests that "
    "fire a sign-off process."
    ),
    AP_INIT_TAKE1(
    "PAPIPassURLPattern",
    papi_set_pass_url_pattern_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIPassURLPattern regularExpression: If the expression "
    "matches, the PAPI access checkings are not performed and "
    "access is automatically granted."
    ),
    AP_INIT_TAKE1(
    "PAPILcookTimeout",
    ap_set_int_slot,
    (void *) APR_OFFSETOF(papi_dir_config, lcook_timeout),
    RSRC_CONF | OR_AUTHCFG,
    "PAPILcookTimeout seconds: Period of time during which Lcook "
    "tokens are valid."
    ),
    AP_INIT_TAKE1(
    "PAPILcookMaxTimeout",
    ap_set_int_slot,
    (void *) APR_OFFSETOF(papi_dir_config, lcook_timeout),
    RSRC_CONF | OR_AUTHCFG,
    "PAPILcookMaxTimeout seconds: Period of time during which Lcook "
    "can be renewed."
    ),
    AP_INIT_TAKE1(
    "PAPIURLTimeout",
    ap_set_int_slot,
    (void *) APR_OFFSETOF(papi_dir_config, url_timeout),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIURLTimeout seconds: Period of time during which a signed "
    "URL generated by an authentication server is valid."
    ),
    AP_INIT_TAKE1(
    "PAPIMaxTTL",
    ap_set_int_slot,
    (void *) APR_OFFSETOF(papi_dir_config, max_ttl),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIMaxTTL seconds: Maximum time-to-live for tokens generated at the PoA"
    ),
    AP_INIT_RAW_ARGS(
    "PAPIAS",
    papi_set_papi_as_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIAS ASName ASURL ASDescription: Definition of a PAPI "
    "authentication server that is valid for this PoA."
    ),
    AP_INIT_TAKE1(
    "PAPIWAYF",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, wayf),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIWAYF uri: A reference to a WAYF service."
    ),
    AP_INIT_TAKE2(
    "PAPIFilter",
    papi_set_papi_filter_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIFilter (regex) [accept|reject]: The filter is a regular "
    "expression to be matched against the assertion about the user "
    "that the PoA is going to receive from Authentication Servers."
    ),
    AP_INIT_TAKE1(
    "PAPICookieReject",
    papi_set_cookie_reject_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPICookieReject (regex): Definition of a cookie reject filter "
    "applicable to this PoA."
    ),
    AP_INIT_FLAG(
    "PAPIHashUserData",
    ap_set_flag_slot,
    (void *) APR_OFFSETOF(papi_dir_config, hash_user_data),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIHashUserData [1|0]: If set to 1, the user data received from "
    "the AS is transformed through a hash function."
    ),
    AP_INIT_TAKE2(
    "PAPIUserDataRewrite",
    papi_set_user_data_rewrite_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIUserDataRewrite (regex) (newstring): With this directive, the "
    "assertion received for a certain access request can be rewritten in "
    "order to be stored inside the access tokens."
    ),
    AP_INIT_FLAG(
    "PAPIClientAdressInTokens",
    ap_set_flag_slot,
    (void *) APR_OFFSETOF(papi_dir_config, client_address_in_tokens),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIClientAdressInTokens [1|0]: If set to 1, client IP address is "
    "included into user data inside access tokens, and verified upon "
    "reception. A mismatch makes access to be denied."
    ),
    AP_INIT_TAKE1("PAPIRemoteUserAttribute",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, remote_user_attrib),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIRemoteUserAttribute attribute"
    ),
    AP_INIT_TAKE1(
    "PAPIAttributeSeparator",
    papi_set_attribute_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIAttributeSeparator (char): The string defines the characters "
    "that will be used by the PoA to identify each individual attribute "
    "inside an assertion. Blanks are always included in the list of "
    "separators. By default, it takes the value ','"
    ),
    AP_INIT_TAKE1(
    "PAPIValueSeparator",
    papi_set_value_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIValueSeparator (char): The string defines the characters that will "
    "be used by the PoA to identify the attribute names and values for each "
    "individual attribute inside an assertion. Blanks are always included in "
    "the list of separators. By default, it takes the value '='."
    ),
    AP_INIT_TAKE2(
    "PAPIGPoA",
    papi_set_gpoa_url_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIGPoA URL: The URL for accessing the authorization procedures "
    "of the GPoA this PoA is associated with."
    ),
    AP_INIT_TAKE1(
    "PAPIReqDB",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(papi_dir_config, req_db),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIReqDB filename: File (in SQLITE database format) where this PoA is "
    "going to record the parameters received for requests redirected through the GPoA."
    ),
    AP_INIT_TAKE1(
    "PAPIReqDBPath",
    papi_set_path_slot,
    (void *) APR_OFFSETOF(papi_dir_config, req_dir),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIReqDBDir dirname: Directory where this PoA is going to create "
    "the file described in PAPIReqDB. You can configure PAPIReqDBPath only "
    "and the filename will be taken automatically from the service name."
    ),
    AP_INIT_TAKE1(
    "PAPIGPoAPrivKey",
    papi_set_file_slot,
    (void *) APR_OFFSETOF(papi_dir_config, gpoa_privkey),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIGPoAPrivKey filename: The file where the private key for this "
    "GPoA is stored (using PEM format)."
    ),
    AP_INIT_TAKE3(
    "PAPIGPoARewrite",
    papi_set_gpoa_rewrite_slot,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "PAPIGPoARewrite PoARegExp regExp replacementString: This directive "
    "allows the GPoA to control the information it sends to its subordinated "
    "PoAs. When a PoA with and identifier matching PoARegExp requests user "
    "data to the GPoA, the assertion that GPoAs has received is matched "
    "against regExp, and the replacement is performed if necessary."
    ),
    AP_INIT_FLAG(
    "PAPIGPoAHashUserData",
    ap_set_flag_slot,
    (void *) APR_OFFSETOF(papi_dir_config, gpoa_hash_user_data),
    RSRC_CONF | OR_AUTHCFG,
    "PAPIGPoAHashUserData [1|0]: If set to 1, user data is transformed "
    "through a hash function prior to sending it to the subordinated PoA."
    ),
    AP_INIT_FLAG(
    "PAPILazySession",
    ap_set_flag_slot,
    (void *) APR_OFFSETOF(papi_dir_config, lazy_session),
    RSRC_CONF | OR_AUTHCFG,
    "PAPILazySession [1|0]"
    ),
    {NULL}
};

static void papi_hooks(apr_pool_t *pool) {
    ap_hook_check_user_id(papi_auth_hook, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA papi_module = {
    STANDARD20_MODULE_STUFF,
    create_papi_dir_config,
    create_papi_merge_dir_config,
    NULL,
    NULL,
    papi_cmds,
    papi_hooks
};

