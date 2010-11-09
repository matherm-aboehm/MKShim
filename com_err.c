#include "heim.h"

#include <com_err.h>
#include <Heimdal/gkrb5_err.h>
#include <Heimdal/wind_err.h>
#include <Heimdal/krb_err.h>
#include <Heimdal/hx509_err.h>

static void
init_error_tables(void * context)
{
    struct et_list ** et_list = (struct et_list **) context;

    initialize_asn1_error_table_r(et_list);
    initialize_gk5_error_table_r(et_list);
    initialize_wind_error_table_r(et_list);
    initialize_krb5_error_table_r(et_list);
    initialize_krb_error_table_r(et_list);
    initialize_k524_error_table_r(et_list);
    initialize_heim_error_table_r(et_list);
    initialize_hx_error_table_r(et_list);
}

static void
mshim_init_error_tables(struct et_list **et_list)
{
    static dispatch_once_t once;

    dispatch_once_f(&once, (void *) et_list, init_error_tables);
}

const char *
mit_error_message(errcode_t code)
{
    static struct et_list *et_list = NULL;
    static char buffer[1024];
    const char *str;

    mshim_init_error_tables(&et_list);

    str = heim_com_right_r(et_list, code, buffer, sizeof(buffer));
    if (str == NULL) {
#ifdef HAVE_STRSAFE
        StringCbPrintfA(buffer, sizeof(buffer), "Unknown error %d", (int)code);
#else
	snprintf(buffer, sizeof(buffer), "Unknown error %d", (int)code);
#endif
	str = buffer;
    }
    return str;
}

void
mit_com_err(const char *progname, errcode_t code, const char *format, ...)
{
    va_list args;

    va_start(args, format);

    heim_com_err_va(progname, code, format, args);
}

void
mit_com_err_va(const char *progname, errcode_t code, const char *format, va_list args)
{
    heim_com_err_va(progname, code, format, args);
}

#if defined(_WIN32) && !defined(_WIN64)

static volatile com_err_handler_t com_err_handler = NULL;

static void KRB5_CALLCONV
err_handler_thunk(const char * pname, long code, const char * format, va_list args)
{
    com_err_handler_t h = com_err_handler;

    if (h != NULL)
        (*h)(pname, code, format, args);
}
                                            

com_err_handler_t
mit_set_com_err_hook(com_err_handler_t handler)
{
    com_err_handler_t prev = NULL;

#ifdef HAVE_INTERLOCKED

    prev = com_err_handler;

    do {
        com_err_handler_t t;

        t = InterlockedCompareExchangePointer(&com_err_handler,
                                              handler, prev);
        if (t == prev)
            break;
        prev = t;

    } while (TRUE);

#else

    prev = com_err_handler;
    com_err_handler = handler;

#endif

    heim_set_com_err_hook(err_handler_thunk);

    return prev;
}

com_err_handler_t
mit_reset_com_err_hook(void)
{
    com_err_handler_t prev;

#ifdef HAVE_INTERLOCKED

    prev = com_err_handler;

    do {
        com_err_handler_t t;

        t = InterlockedCompareExchangePointer(&com_err_handler,
                                              NULL, prev);
        if (t == prev)
            break;
        prev = t;

    } while (TRUE);

#else

    prev = com_err_handler;
    com_err_handler = NULL;

#endif

    heim_reset_com_err_hook();

    return prev;
}

#elif defined(_WIN64)

com_err_handler_t
mit_set_com_err_hook(com_err_handler_t handler)
{
    return heim_set_com_err_hook(handler);
}

com_err_handler_t
mit_reset_com_err_hook(void)
{
    return heim_reset_com_err_hook();
}

#endif
