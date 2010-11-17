#include "heim.h"
#include <mit-krb5.h>
#include <roken.h>

mit_krb5_error_code KRB5_CALLCONV
mit_krb5_timestamp_to_sfstring (mit_krb5_timestamp ts, char *buffer,
                                size_t buflen, char *pad)
{
    size_t      c = 0;
    struct tm   tm;
    time_t      timestamp = ts;
    int         i;

    static const char * const formats[] = {
	"%c",
	"%d %b %Y %T",
	"%x %X",
	"%d/%m/%Y %R"
    };

    localtime_r(&timestamp, &tm);

    for (i=0; i < sizeof(formats)/sizeof(formats[0]); i++) {
        c = strftime(buffer, buflen, formats[i], &tm);
        if (c > 0 && c < buflen)
            break;
    }

    if (c == 0 || c >= buflen)
        return ENOMEM;

    if (c < buflen - 1 && pad != NULL) {
        memset(buffer + c, *pad, (buflen - 1) - c);
        buffer[buflen - 1] = '\0';
    }

    return 0;
}

mit_krb5_error_code KRB5_CALLCONV
mit_krb5_timestamp_to_string (mit_krb5_timestamp ts, char *buffer, size_t buflen)
{
    size_t      c;
    time_t      timestamp = ts;
    struct tm   tm;

    localtime_r(&timestamp, &tm);

    c = strftime(buffer, buflen, "%c", &tm);
    if (c == 0 || c >= buflen)
        return ENOMEM;
    return 0;
}

mit_krb5_error_code KRB5_CALLCONV
mit_krb5_string_to_deltat(char *str, mit_krb5_deltat *t)
{
    krb5_error_code ret;
    krb5_deltat ht;

    ret = heim_krb5_string_to_deltat(str, &ht);
    if (ret)
	return ret;
    *t = ht;
    return 0;
}

mit_krb5_error_code KRB5_CALLCONV
mit_krb5_enctype_to_string(mit_krb5_enctype enctype,
                           char *str,
                           size_t size)
{
#ifdef HAVE_STRSAFE
    StringCchPrintfA(str, size, "enctype-%d", enctype);
#else
    snprintf(str, size, "enctype-%d", enctype);
#endif
    return 0;
}
