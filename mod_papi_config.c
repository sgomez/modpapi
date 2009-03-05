#include "mod_papi_private.h"

const char* papi_set_parameters(request_rec *r,
        papi_dir_config *d) {
    if (!d->service_id) {
        return "PAPIServiceID parameter is empty";
    }

    if (!d->keys_path) {
        return "PAPIKeysPath parameters are empties";
    }

    if (!d->accept_file) {
        return "PAPIAcceptFile parameter is empty";
    }

    if (!d->reject_file) {
        return "PAPIRejectFile parameter is empty";
    }

    if (d->wayf && !d->gpoa_url) {
        d->gpoa_url = apr_pstrcat(r->pool, "wayf:", d->wayf, NULL);
    }

    if (!d->req_db && d->gpoa_url) {
        if (d->req_dir == NULL) {
            return "PAPIReqDB and PAPIRedDBDir parameters are empties";
        } else {
            d->req_db = apr_pstrcat(r->pool,
                    d->req_dir, d->service_id, ".db", NULL);
        }
    }

    // Configuring default parameters values

    SET_DEFAULT_IF_NULL(d->domain, DEFAULT_DOMAIN);
    SET_DEFAULT_IF_NULL(d->auth_location, DEFAULT_AUTH_LOCATION);
    SET_DEFAULT_IF_UNSET(d->lcook_timeout, DEFAULT_LCOOK_TIMEOUT);
    SET_DEFAULT_IF_UNSET(d->lcook_max_timeout, DEFAULT_LCOOK_MAX_TIMEOUT);
    SET_DEFAULT_IF_UNSET(d->url_timeout, DEFAULT_URL_TIMEOUT);
    SET_DEFAULT_IF_UNSET(d->hash_user_data, DEFAULT_HASH_USER_DATA);
    SET_DEFAULT_IF_UNSET(d->client_address_in_tokens, DEFAULT_CLIENT_ADDR_TOKEN);
    SET_DEFAULT_IF_UNSET(d->gpoa_hash_user_data, DEFAULT_GPOA_HASH_USER_DATA);
    SET_DEFAULT_IF_NULL(d->remote_user_attrib, DEFAULT_REMOTE_USER_ATTRIB);
    SET_DEFAULT_IF_UNSET(d->attribute_separator, DEFAULT_ATTRIBUTE_SEPARATOR);
    SET_DEFAULT_IF_UNSET(d->value_separator, DEFAULT_VALUE_SEPARATOR);
    SET_DEFAULT_IF_UNSET(d->lazy_session, DEFAULT_LAZY_SESSION);

    apr_table_add(r->notes, "PAPIid", d->service_id);

    int i;
    for (i = 0; i < d->papi_as->nelts; i++) {
        papi_as_t *as = ((papi_as_t *) d->papi_as->elts) + i;
        char *path = papi_pub_keyfile(r, d, as->name);
        apr_finfo_t finfo;
        int status = apr_stat(&finfo, path, APR_FINFO_USER, r->pool);
        if (status != APR_SUCCESS) {
            return apr_pstrcat(r->pool, "could not stat public AS keyfile ", path, NULL);
        }
    }

    return NULL;
}

const char* papi_set_file_slot(cmd_parms *parms,
        void *config,
        const char *arg) {
    apr_finfo_t finfo;
    int status = apr_stat(&finfo, arg, APR_FINFO_USER, parms->pool);
    if (status != APR_SUCCESS) {
        return apr_pstrcat(parms->pool, "could not stat file ", arg, NULL);
    }

    int offset = (int) (long) parms->info;
    *(const char **) ((char *) config + offset) = arg;

    return NULL;
}

const char* papi_set_path_slot(cmd_parms *parms,
        void *config,
        const char *arg) {
    int last = strlen(arg) - 1;
    if (last < 0) return NULL;

    int offset = (int) (long) parms->info;

    if (arg[last] != '/') {
        *(const char **) ((char *) config + offset) = apr_pstrcat(parms->pool, arg, "/", NULL);
    } else {
        *(const char **) ((char *) config + offset) = arg;
    }

    return NULL;
}

const char* papi_set_papi_as_slot(cmd_parms *parms,
        void *config,
        const char *args) {
    papi_dir_config *d = (papi_dir_config *) config;
    papi_as_t *new = (papi_as_t *) apr_array_push(d->papi_as);
    new->name = ap_getword_conf(parms->pool, &args);
    new->url = ap_getword_conf(parms->pool, &args);
    new->description = ap_getword_conf(parms->pool, &args);

    const char *arg = ap_getword_conf(parms->pool, &args);

    while (apr_strnatcmp(arg, "")) {
        new->description = apr_pstrcat(parms->pool, new->description, " ", arg, NULL);
        arg = ap_getword_conf(parms->pool, &args);
    }

    return NULL;
}

const char* papi_set_gpoa_url_slot(cmd_parms *parms,
        void *config,
        const char *id,
        const char *url) {
    papi_dir_config *d = (papi_dir_config *) config;
    d->gpoa_url = url;
    d->gpoa_privkey = papi_priv_keyfile (parms->pool, d, id);

    return NULL;
}
const char* papi_set_signoff_location_slot(cmd_parms *parms,
        void *config,
        const char *re,
        const char *url) {
    papi_dir_config *d = (papi_dir_config *) config;
    signoff_location_t *new;

    new = (signoff_location_t *) apr_array_push(d->signoff_location);
    new->re = papi_regex_new(parms->pool, re);
    if (new->re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", re);
    }
    new->url = url;

    return NULL;
}

const char* papi_set_pass_url_pattern_slot(cmd_parms *parms,
        void *config,
        const char *re) {
    papi_dir_config* d = (papi_dir_config *) config;
    pass_url_pattern_t *new = (pass_url_pattern_t *) apr_array_push(d->pass_url_pattern);
    new->re = papi_regex_new(parms->pool, re);
    if (new->re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", re);
    }

    return NULL;
}

const char* papi_set_papi_filter_slot(cmd_parms *parms,
        void *config,
        const char *re,
        const char *accept) {
    papi_dir_config *d = (papi_dir_config *) config;
    papi_filter_t *new;

    new = (papi_filter_t *) apr_array_push(d->papi_filter);
    new->re = papi_regex_new(parms->pool, re);
    if (new->re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", re);
    }
    new->accept = apr_strnatcasecmp(accept, "accept") == 0 ? TRUE : FALSE;

    return NULL;
}

const char* papi_set_cookie_reject_slot(cmd_parms *parms,
        void *config,
        const char *re) {
    papi_dir_config* d = (papi_dir_config *) config;
    cookie_reject_t *new = (cookie_reject_t *) apr_array_push(d->cookie_reject);
    new->re = papi_regex_new(parms->pool, re);
    if (new->re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", re);
    }

    return NULL;
}

const char* papi_set_user_data_rewrite_slot(cmd_parms *parms,
        void *config,
        const char *re,
        const char *rs) {
    papi_dir_config *d = (papi_dir_config *) config;
    user_data_rewrite_t *new;

    new = (user_data_rewrite_t *) apr_array_push(d->papi_filter);
    new->re = papi_regex_new(parms->pool, re);
    if (new->re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", re);
    }
    new->rs = rs;

    return NULL;
}

const char* papi_set_attribute_slot(cmd_parms *parms,
        void *config,
        const char *separator) {
    papi_dir_config* dir = (papi_dir_config *) config;

    if (strlen(separator) > 1) {
        return "PAPIAttributeSeparator must be one character.";
    }

    dir->attribute_separator = separator[0];

    return NULL;
}

const char* papi_set_value_slot(cmd_parms *parms,
        void *config,
        const char *value) {
    papi_dir_config* dir = (papi_dir_config *) config;

    if (strlen(value) > 1) {
        return "PAPIValueSeparator must be one character.";
    }

    dir->value_separator = value[0];

    return NULL;
}

const char* papi_set_gpoa_rewrite_slot(cmd_parms *parms,
        void *config,
        const char *poa_re,
        const char *re,
        const char *rs) {
    papi_dir_config *d = (papi_dir_config *) config;
    gpoa_rewrite_t *new;

    new = (gpoa_rewrite_t *) apr_array_push(d->papi_filter);
    new->poa_re = papi_regex_new(parms->pool, poa_re);
    if (new->poa_re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", poa_re);
    }
    new->re = papi_regex_new(parms->pool, re);
    if (new->re == NULL) {
        return apr_psprintf(parms->pool, "Error compiling regex pattern: %s", re);
    }
    new->rs = rs;


    return NULL;
}
