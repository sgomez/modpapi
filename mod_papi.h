#ifndef __MOD_PAPI_H__
#define __MOD_PAPI_H__

module AP_MODULE_DECLARE_DATA papi_module;

#define cfgCopy(el)         mrg->el = add->el
#define cfgMerge(el,unset)  mrg->el = (add->el == (unset)) ? base->el : add->el
#define cfgMergeArray(el)   mrg->el = apr_array_append(pool, add->el, base->el)
#define cfgMergeString(el)  cfgMerge(el, NULL)
#define cfgMergeBool(el)    cfgMerge(el, UNSET)
#define cfgMergeInt(el)     cfgMerge(el, UNSET)
#define cfgMergeChar(el)    cfgMerge(el, UNSET)

#endif  /* __MOD_PAPI_H__ */

