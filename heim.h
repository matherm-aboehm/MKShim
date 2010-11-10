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

#ifndef _WIN32

/* override heimdals own prototypes */
#define __krb5_protos_h__

#define KRB5_LIB_VARIABLE
#define KRB5_LIB_FUNCTION
#define KRB5_LIB_CALL
#define GSSAPI_LIB_FUNCTION
#define GSSAPI_LIB_CALL

#else

#define KRB5_LIB_VARIABLE
#define KRB5_LIB_FUNCTION
#define KRB5_LIB_CALL __stdcall
#define GSSAPI_LIB_FUNCTION
#define GSSAPI_LIB_CALL __stdcall

#define __attribute__(x)

#include "rename-heim.h"
#define heim_gsskrb5_extract_authz_data_from_sec_context gsskrb5_extract_authz_data_from_sec_context
#define heim_gss_import_name gss_import_name

#endif

#include <Heimdal/krb5.h>

extern krb5_context milcontext;

#include "mit-krb5.h"

#ifdef _WIN32

#define LOG_UNIMPLEMENTED() mshim_log_function_missing(__FUNCTION__)
#define LOG_ENTRY() mshim_log_entry("MITKerberosShim: %s entered", __FUNCTION__)
#define LOG_FAILURE(_r, _s) mshim_failure(__FUNCTION__, _r, _s)
#define LOG_LASTERROR(_s) mshim_log_lasterror(__FUNCTION__, _s);

#define HAVE_STRSAFE 1
#define HAVE_INTERLOCKED 1

#include <strsafe.h>
#include "dispatch_once.h"

#else

#include <syslog.h>

#define LOG_UNIMPLEMENTED() mshim_log_function_missing(__func__)
#define LOG_ENTRY() mshim_log_entry("MITKerberosShim: %s entered", __func__)
#define LOG_FAILURE(_r, _s) mshim_failure(__func__, _r, _s)

#endif

#ifdef __APPLE__

#define HAVE_DISPATCH_ONCE
#define HAVE_COMMONCRYPTO_COMMONDIGEST_H

#endif

void
mshim_log_entry(const char *func, ...);

int
mshim_failure(const char *func, int error, const char *subsystem);

void
mshim_log_lasterror(const char * func, const char * msg);

/* this might not work, lets try it out, if anyone uses krb5_build_principal_va we are smoked */
struct comb_principal {
    struct mit_krb5_principal_data mit;
    krb5_principal heim;
};

#define HC(x) ((krb5_context)x)

struct mshim_map_flags {
    unsigned long in;
    unsigned long out;
};

unsigned long
	mshim_remap_flags(unsigned long, const struct mshim_map_flags *);


void	mshim_log_function_missing(const char *);
void	mshim_init_context(void);

/* mapping functions */
void	mshim_mcred2hcred(krb5_context, mit_krb5_creds *, krb5_creds *);
void	mshim_hcred2mcred(krb5_context, krb5_creds *, mit_krb5_creds *);
mit_krb5_principal
	mshim_hprinc2mprinc(krb5_context, krb5_principal);
krb5_error_code
	mshim_hdata2mdata(const krb5_data *, mit_krb5_data *);
krb5_error_code
	mshim_mdata2hdata(const mit_krb5_data *m, krb5_data *h);
void
	mshim_hkeyblock2mkeyblock(const krb5_keyblock *, mit_krb5_keyblock *);

void	mshim_haprepencpart2maprepencpart(const krb5_ap_rep_enc_part *,
					  mit_krb5_ap_rep_enc_part *);
void	mshim_herror2merror(krb5_context, const krb5_error *, mit_krb5_error *);
void	mshim_hreplay2mreplay(const krb5_replay_data *, mit_krb5_replay_data *);
void *	mshim_malloc(size_t);



enum {
    klPromptMechanism_Autodetect = 0,
    klPromptMechanism_GUI = 1,
    klPromptMechanism_CLI = 2,
    klPromptMechanism_None = 0xFFFFFFFF
};

#ifndef _WIN32
#include "heim-protos.h"

/* krb5-protos.h + sed */
const char *
com_right (struct et_list * /*list*/,
	   long /*code*/);

const char *
heim_com_right_r(struct et_list * /*list*/,
		 long /*code*/,
		 char * /*str*/,
		 size_t /*len*/);

#endif
