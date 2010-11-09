#include "dummy.h"

dummy(cc_close, cc_int32,
      (apiCB *in_context, ccache_p **ioCCache), 0);

dummy(cc_create, cc_int32,
      (apiCB *in_context, const char *in_name, const char *in_principal,
       cc_int32 in_version, cc_uint32 in_flags, ccache_p **out_ccache), 0);

dummy(cc_destroy, cc_int32,
      (apiCB *in_context, ccache_p **io_ccache), 0);

dummy(cc_free_NC_info, cc_int32,
      (apiCB *in_context, infoNC ***io_info), 0);

dummy(cc_free_creds, cc_int32,
      (apiCB *in_context, cred_union **io_cred_union), 0);

dummy(cc_free_name, cc_int32,
      (apiCB *in_context, char **io_name), 0);

dummy(cc_free_principal, cc_int32,
      (apiCB *in_context, char **io_principal), 0);

dummy(cc_get_NC_info, cc_int32,
      (apiCB *in_context, infoNC ***out_info), 0);

dummy(cc_get_change_time, cc_int32,
      (apiCB *in_context, cc_time_t *out_change_time) ,0);

dummy(cc_get_cred_version, cc_int32,
      (apiCB *in_context, ccache_p *in_ccache, cc_int32 *out_version), 0);

dummy(cc_get_name, cc_int32,
      (apiCB *in_context, ccache_p *in_ccache, char **out_name), 0);

dummy(cc_get_principal, cc_int32,
      (apiCB *in_context, ccache_p *in_ccache, char **out_principal), 0);

dummy(cc_open, cc_int32,
      (apiCB *in_context, const char *in_name, cc_int32 in_version,
       cc_uint32 in_flags, ccache_p **out_ccache), 0);

dummy(cc_remove_cred, cc_int32,
      (apiCB *in_context, ccache_p *in_ccache, cred_union in_credentials), 0);

dummy(cc_seq_fetch_NCs_begin, cc_int32,
      (apiCB *in_context, ccache_cit **out_nc_iterator), 0);

dummy(cc_seq_fetch_NCs_end, cc_int32,
      (apiCB *in_context, ccache_cit **io_nc_iterator), 0);

dummy(cc_seq_fetch_NCs_next, cc_int32,
      (apiCB *in_context, ccache_p **out_ccache, ccache_cit *in_nc_iterator), 0);

dummy(cc_seq_fetch_creds_begin, cc_int32,
      (apiCB *in_context, const ccache_p *in_ccache, ccache_cit **out_ccache_iterator), 0);

dummy(cc_seq_fetch_creds_end, cc_int32,
      (apiCB *in_context, ccache_cit **io_ccache_iterator), 0);

dummy(cc_seq_fetch_creds_next, cc_int32,
      (apiCB *in_context, cred_union **out_cred_union, ccache_cit *in_ccache_iterator), 0);

dummy(cc_set_principal, cc_int32,
      (apiCB    *in_context, ccache_p *in_ccache, cc_int32  in_version, char     *in_principal), 0);

dummy(cc_shutdown, cc_int32,
      (apiCB **io_context), 0);

dummy(cc_store, cc_int32,
      (apiCB      *in_context, ccache_p   *in_ccache, cred_union  in_credentials), 0);

