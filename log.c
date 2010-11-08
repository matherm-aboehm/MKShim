/*
 * Copyright (c) 2008-2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2008-2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "heim.h"

static int do_log = 0;

#ifdef __APPLE__

#include <dispatch/dispatch.h>

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>

static void
init_log(void)
{
    static dispatch_once_t once = 0;
    dispatch_once(&once, ^{
	    CFBooleanRef b;
	    b = CFPreferencesCopyAppValue(CFSTR("EnableDebugging"),
					  CFSTR("com.apple.MITKerberosShim"));
	    if (b && CFGetTypeID(b) == CFBooleanGetTypeID())
		do_log = CFBooleanGetValue(b);
    });
}


void
mshim_log_entry(const char *msg, ...)
{
    init_log();

    if (do_log) {
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
    }
}

int
mshim_failure(const char *func, int error, const char *subsystem)
{
    init_log();

    if (do_log && error)
	syslog(LOG_DEBUG, "%s failed with %d for '%s'", func, error, subsystem);
    return error;
}

#elseif defined(_WIN32)

void
mshim_log_entry(const char *msg, ...)
{

}

int
mshim_failure(const char *func, int error, const char *subsystem)
{
    if (error)
	mshim_log_entry("%s failed with %d for '%s'", func, error, subsystem);
    return error;
}

void
mshim_log_lasterror(const char * func, const char * msg)
{
    DWORD       lastError = GetLastError();
    DWORD       len;
    char        *errstr = NULL;

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, lastError, 0, &errstr,
                        0, NULL);
    if (len == 0)
        return;

    mshim_log_entry("%s:%s", msg, errstr);

    if (errstr)
        LocalFree(errstr);
}

#endif

