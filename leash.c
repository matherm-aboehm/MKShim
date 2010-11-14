#include "heim.h"
#include<mit-leashwin.h>
#include<mit-leasherr.h>

DWORD
Leash_get_default_lifetime(void)
{
    krb5_error_code     code;
    krb5_context        context = 0;
    krb5_deltat         lifetime = 10 * 60 * 60;

    code = krb5_init_context(&context);
    if (code == 0) {
        lifetime = krb5_config_get_time_default(context, NULL, lifetime,
                                                "libdefaults", "ticket_lifetime", NULL);
        krb5_free_context(context);
    }

    return lifetime / 60;       /* Return value should be in
                                 * minutes */
}

DWORD
Leash_get_default_renew_till(void)
{
    krb5_error_code     code;
    krb5_context        context = 0;
    krb5_deltat         renew_lifetime = 7 * 24 * 60 * 60;

    code = krb5_init_context(&context);
    if (code == 0) {
        renew_lifetime = krb5_config_get_time_default(context, NULL, renew_lifetime,
                                                      "libdefaults", "renew_lifetime",
                                                      NULL);
        krb5_free_context(context);
    }

    return renew_lifetime / 60;
}

DWORD
Leash_get_default_forwardable(void)
{
    krb5_error_code     code;
    krb5_context        context = 0;
    krb5_boolean        forwardable = TRUE;

    code = krb5_init_context(&context);
    if (code == 0) {
        forwardable = krb5_config_get_bool_default(context, NULL, forwardable,
                                                   "libdefaults", "forwardable",
                                                   NULL);
        krb5_free_context(context);
    }

    return forwardable;
}

DWORD
Leash_get_default_renewable(void)
{
    krb5_error_code     code;
    krb5_context        context = 0;
    krb5_boolean        renewable = TRUE;

    code = krb5_init_context(&context);
    if (code == 0) {
        renewable = krb5_config_get_bool_default(context, NULL, renewable,
                                                 "libdefaults", "renewable",
                                                 NULL);
        krb5_free_context(context);
    }

    return renewable;
}

DWORD
Leash_get_default_noaddresses(void)
{
    krb5_error_code     code;
    krb5_context        context = 0;
    krb5_boolean        noaddresses = TRUE;

    code = krb5_init_context(&context);
    if (code == 0) {
        noaddresses = krb5_config_get_bool_default(context, NULL, noaddresses,
                                                   "libdefaults", "noaddresses",
                                                   NULL);
        krb5_free_context(context);
    }

    return noaddresses;
}

DWORD
Leash_get_default_proxiable(void)
{
    krb5_error_code     code;
    krb5_context        context = 0;
    krb5_boolean        proxiable = FALSE;

    code = krb5_init_context(&context);
    if (code == 0) {
        proxiable = krb5_config_get_bool_default(context, NULL, proxiable,
                                                 "libdefaults", "proxiable",
                                                 NULL);
        krb5_free_context(context);
    }

    return proxiable;
}

DWORD
Leash_get_default_publicip(void)
{
    return 0;
}

DWORD
Leash_get_default_life_min(void)
{
    return 5;
}

DWORD
Leash_get_default_life_max(void)
{
    return 1440;
}

DWORD
Leash_get_default_renew_min(void)
{
    return 600;
}

DWORD
Leash_get_default_renew_max(void)
{
    return 60 * 24 * 30;
}
