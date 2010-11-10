#include "dummy.h"
#include <mit-gssapi.h>
#include <mit-gssapi_krb5.h>

dummyk5(gss_krb5_ui, OM_uint32,
        (OM_uint32 * minor, OM_uint32 flag), 0);

dummyk5(gss_str_to_oid, OM_uint32,
        (OM_uint32 * minor, gss_buffer_t oid_str, gss_OID * oid), 0);

dummyk5(gss_krb5_get_tkt_flags, OM_uint32,
        (OM_uint32 *minor_status, gss_ctx_id_t context_handle,
         krb5_flags *ticket_flags), 0);

dummyk5(gss_sign, OM_uint32,
        (OM_uint32 * minor, gss_ctx_id_t ctx, int qop_req,
         gss_buffer_t msg, gss_buffer_t buf), 0);

dummyk5(gss_inquire_mechs_for_name, OM_uint32,
        (OM_uint32 * minor, const gss_name_t inp, gss_OID_set * s), 0);

dummyk5(gss_verify, OM_uint32,
        (OM_uint32 * minor, gss_ctx_id_t ctx, gss_buffer_t msg,
         gss_buffer_t tok, int *r), 0);
