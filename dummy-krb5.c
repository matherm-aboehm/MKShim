
#define KRB5_OLD_CRYPTO

#include "dummy.h"
#include <mit-krb5.h>

#ifndef _WIN32

dummy(encode_krb5_as_req, 0);

dummy(krb5_get_krbhst, KRB5_REALM_UNKNOWN);

dummy(krb5_free_krbhst, 0);

dummy(krb524_convert_creds_kdc, 0);

#endif

dummyk5(krb5_425_conv_principal, mit_krb5_error_code,
	(mit_krb5_context context, const char *name, const char *instance,
         const char *realm, mit_krb5_principal *princ), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_524_conv_principal, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_const_principal princ, 
         char *name, char *inst, char *realm), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_524_convert_creds, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_creds *v5creds,
	 struct credentials *v4creds), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_address_compare, mit_krb5_boolean,
	(mit_krb5_context context, const mit_krb5_address *a, const mit_krb5_address *b),
        0);

dummyk5(krb5_address_order, int,
        (mit_krb5_context context, const mit_krb5_address *a, const mit_krb5_address *b), 0);

dummyk5(krb5_address_search, mit_krb5_boolean,
	(mit_krb5_context context, const mit_krb5_address *a,
         mit_krb5_address * const *b), 0);

dummyk5(krb5_aname_to_localname, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_const_principal p, int i, char *s),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5v(krb5_appdefault_boolean,
        (mit_krb5_context context, const char *appname, const mit_krb5_data *realm,
         const char *option, int default_value, int *ret_value));

dummyk5v(krb5_appdefault_string,
         (mit_krb5_context context, const char *appname, const mit_krb5_data *realm,
         const char *option, const char *default_value, char ** ret_value));

dummyk5(krb5_auth_con_get_checksum_func, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac,
         krb5_mk_req_checksum_func *f, void **v), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_getrecvsubkey, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_keyblock **k),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_getsendsubkey, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_keyblock **k),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_initivector, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_auth_context ac), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_set_checksum_func, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac,
         krb5_mk_req_checksum_func f, void *v), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_setrecvsubkey, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_keyblock *k),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_setsendsubkey, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_keyblock *k),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_auth_con_setuseruserkey, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_keyblock *k),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_build_principal_alloc_va, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_principal *p, unsigned int i, const char *s,
         va_list l), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_build_principal_va, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_principal p, unsigned int i, const char *s,
         va_list l), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_block_size, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_enctype enctype, size_t *blocksize),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_checksum_length, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_cksumtype cksumtype, size_t *length),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_decrypt, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_keyblock *key,
         mit_krb5_keyusage usage, const mit_krb5_data *cipher_state,
         const mit_krb5_enc_data *input, mit_krb5_data *output), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_encrypt, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_keyblock *key,
         mit_krb5_keyusage usage, const mit_krb5_data *cipher_state,
         const mit_krb5_data *input, mit_krb5_enc_data *output), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_encrypt_length, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_enctype enctype,
         size_t inputlen, size_t *length), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_enctype_compare, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_enctype e1, mit_krb5_enctype e2,
         mit_krb5_boolean *similar), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_free_state, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_keyblock *key, mit_krb5_data *state),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_init_state, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_keyblock *key, mit_krb5_keyusage usage,
         mit_krb5_data *new_state), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_is_coll_proof_cksum, mit_krb5_boolean,
	(mit_krb5_cksumtype ctype), 0);

dummyk5(krb5_c_is_keyed_cksum, mit_krb5_boolean,
	(mit_krb5_cksumtype ctype), 0);

dummyk5(krb5_c_keyed_checksum_types, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_enctype enctype,
         unsigned int *count, mit_krb5_cksumtype **cksumtypes), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_make_checksum, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_cksumtype cksumtype,
         const mit_krb5_keyblock *key, mit_krb5_keyusage usage,
         const mit_krb5_data *input, mit_krb5_checksum *cksum), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_make_random_key, mit_krb5_error_code,
    (mit_krb5_context context, mit_krb5_enctype enctype,
     mit_krb5_keyblock *k5_random_key), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_prf, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_keyblock *k,
         mit_krb5_data *in, mit_krb5_data *out), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_prf_length, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_enctype e, size_t *outlen), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_random_add_entropy, mit_krb5_error_code,
        (mit_krb5_context context, unsigned int  randsource_id,
         const mit_krb5_data *data), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_random_make_octets, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_data *data), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_random_os_entropy, mit_krb5_error_code,
        (mit_krb5_context context, int strong, int *success), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_random_seed, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_data *data), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_string_to_key_with_params, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_enctype enctype,
         const mit_krb5_data *string, const mit_krb5_data *salt,
         const mit_krb5_data *params, mit_krb5_keyblock *key), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_c_valid_cksumtype, mit_krb5_boolean,
        (mit_krb5_cksumtype ctype), 1);

dummyk5(krb5_c_valid_enctype, mit_krb5_boolean,
        (mit_krb5_enctype ktype), 1);

dummyk5(krb5_c_verify_checksum, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_keyblock *key, mit_krb5_keyusage usage,
         const mit_krb5_data *data, const mit_krb5_checksum *cksum,
         mit_krb5_boolean *valid), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_calculate_checksum, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_cksumtype ctype, mit_krb5_const_pointer in,
         size_t in_length, mit_krb5_const_pointer seed, size_t seed_length,
         mit_krb5_checksum * outcksum), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_cc_last_change_time, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_ccache ccache,
         mit_krb5_timestamp *change_time), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_cc_lock, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_ccache ccache), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_cc_set_config, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_ccache cache,
         mit_krb5_const_principal principal,
         const char *s, mit_krb5_data *d), MIT_KRB5KRB_ERR_GENERIC);

quietdummyk5(krb5_cc_set_flags, mit_krb5_error_code,
             (mit_krb5_context context, mit_krb5_ccache cache, mit_krb5_flags flags), 0);

dummyk5(krb5_cc_unlock, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_ccache ccache), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_cccol_last_change_time, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_timestamp *change_time),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_cccol_lock, mit_krb5_error_code,
        (mit_krb5_context context), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_cccol_unlock, mit_krb5_error_code,
        (mit_krb5_context context), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_change_password, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_creds *creds, char *newpw,
         int *result_code, mit_krb5_data *result_code_string,
         mit_krb5_data *result_string), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_checksum_size, size_t,
	(mit_krb5_context context, mit_krb5_cksumtype ctype), 0);

dummyk5(krb5_cksumtype_to_string, mit_krb5_error_code,
        (mit_krb5_cksumtype type, char *s, size_t sz), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_copy_addresses, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_address * const * addr,
         mit_krb5_address *** ret), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_copy_authdata, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_authdata * const * in,
         mit_krb5_authdata *** out), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_copy_authenticator, mit_krb5_error_code,
	(mit_krb5_context context, const mit_krb5_authenticator * in,
         mit_krb5_authenticator ** out), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_copy_checksum, mit_krb5_error_code,
	(mit_krb5_context context, const mit_krb5_checksum *in,
         mit_krb5_checksum **out), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_copy_context, mit_krb5_error_code,
	(mit_krb5_context in, mit_krb5_context *out), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_copy_ticket, mit_krb5_error_code,
	(mit_krb5_context context, const mit_krb5_ticket *in, mit_krb5_ticket **out),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_decrypt, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_const_pointer inptr, mit_krb5_pointer outptr,
         size_t size, mit_krb5_encrypt_block * eblock, mit_krb5_pointer ivec),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_deltat_to_string, mit_krb5_error_code,
	(mit_krb5_deltat d, char *s, size_t sz), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_eblock_enctype, mit_krb5_enctype,
        (mit_krb5_context context, const mit_krb5_encrypt_block * eblock), 0);

dummyk5(krb5_encrypt, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_const_pointer inptr,
         mit_krb5_pointer outptr, size_t size, mit_krb5_encrypt_block * eblock,
         mit_krb5_pointer ivec), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_encrypt_size, size_t,
	(size_t length, mit_krb5_enctype crypto), 0);

dummyk5(krb5_finish_key, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_encrypt_block * eblock),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_finish_random_key, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_encrypt_block * eblock,
         mit_krb5_pointer * ptr), MIT_KRB5KRB_ERR_GENERIC);

dummyk5v(krb5_free_authenticator,
         (mit_krb5_context context, mit_krb5_authenticator *a));

dummyk5v(krb5_free_checksum,
         (mit_krb5_context context, mit_krb5_checksum *c));

dummyk5v(krb5_free_checksum_contents,
         (mit_krb5_context c, mit_krb5_checksum *s));

dummyk5v(krb5_free_cksumtypes,
         (mit_krb5_context c, mit_krb5_cksumtype *s));

dummyk5v(krb5_free_tgt_creds,
         (mit_krb5_context context, mit_krb5_creds **c));

dummyk5(krb5_fwd_tgt_creds, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_auth_context ac, char *s,
         mit_krb5_principal p, mit_krb5_principal p2, mit_krb5_ccache cc, int forwardable,
         mit_krb5_data *c), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_get_credentials_renew, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_flags f, mit_krb5_ccache cc, mit_krb5_creds *c,
         mit_krb5_creds **cr), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_get_credentials_validate, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_flags f, mit_krb5_ccache cc, mit_krb5_creds *c,
         mit_krb5_creds **cr),MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_get_in_tkt, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_flags f, mit_krb5_address * const * a,
         mit_krb5_enctype *e, mit_krb5_preauthtype *p,
         mit_krb5_error_code ( *cb)(mit_krb5_context, mit_krb5_enctype, mit_krb5_data *,
                                    mit_krb5_const_pointer, mit_krb5_keyblock **),
         mit_krb5_const_pointer cbd,
         mit_krb5_error_code ( *ecb)(mit_krb5_context, const mit_krb5_keyblock *,
                                     mit_krb5_const_pointer, mit_krb5_kdc_rep *),
         mit_krb5_const_pointer ecbd, mit_krb5_creds *cr, mit_krb5_ccache cc,
         mit_krb5_kdc_rep **rep), KRB5_KT_NOTFOUND);

dummyk5(krb5_get_in_tkt_with_keytab, mit_krb5_error_code,
        (krb5_context context, krb5_flags f,
         krb5_address * const *a, krb5_enctype *e, krb5_preauthtype *pa,
         krb5_keytab kt, krb5_ccache cc, krb5_creds *c, krb5_kdc_rep **rep),
        KRB5_KT_NOTFOUND);

dummyk5(krb5_get_in_tkt_with_skey, mit_krb5_error_code,
        (krb5_context context, krb5_flags f, krb5_address * const * a, krb5_enctype *e,
         krb5_preauthtype *pa, const krb5_keyblock *kb, krb5_ccache cc, krb5_creds *c,
         krb5_kdc_rep **rep), KRB5_KT_NOTFOUND);

quietdummyk5v(krb5_get_init_creds_opt_set_change_password_prompt,
              (mit_krb5_get_init_creds_opt *opt, int prompt));

dummyk5(krb5_get_init_creds_opt_set_pa, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_get_init_creds_opt *opt,
         const char *attr, const char *value), MIT_KRB5KRB_ERR_GENERIC);

dummyk5v(krb5_get_init_creds_opt_set_salt,
         (mit_krb5_get_init_creds_opt *opt, mit_krb5_data *salt));

dummyk5(krb5_get_permitted_enctypes, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_enctype **e), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_get_profile, mit_krb5_error_code,
        (mit_krb5_context c, struct _profile_t **p), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_get_time_offsets, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_timestamp *t, mit_krb5_int32 *i),
        MIT_KRB5KRB_ERR_GENERIC);

// dummyk5(krb5_gss_use_kdc_context, MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_init_keyblock, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_enctype enctype, size_t length,
         mit_krb5_keyblock **out), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_init_random_key, mit_krb5_error_code,
	(mit_krb5_context context, const mit_krb5_encrypt_block * eblock,
         const mit_krb5_keyblock * keyblock, mit_krb5_pointer * ptr),
        MIT_KRB5KRB_ERR_GENERIC);

//quietdummyk5(krb5_ipc_client_clear_target, 0);
//quietdummyk5(krb5_ipc_client_set_target_uid, 0);

dummyk5(krb5_is_config_principal, mit_krb5_boolean,
        (mit_krb5_context context, mit_krb5_const_principal princ), 0);

dummyk5(krb5_is_referral_realm, mit_krb5_boolean,
        (const mit_krb5_data * d), 0);

dummyk5(krb5_is_thread_safe, mit_krb5_boolean,
        (void), 0);

dummyk5(krb5_kuserok, mit_krb5_boolean,
	(mit_krb5_context context, mit_krb5_principal p, const char *s), 0);

dummyk5(krb5_mk_1cred, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_creds *c,
         mit_krb5_data **d, mit_krb5_replay_data *rd), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_mk_error, mit_krb5_error_code,
	(mit_krb5_context context, const mit_krb5_error *e, mit_krb5_data *d),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_mk_ncred, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_creds **c,
         mit_krb5_data **d, mit_krb5_replay_data *rd), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_mk_rep, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_data *d),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_parse_name_flags, mit_krb5_error_code,
	(mit_krb5_context context, const char *s, int i, mit_krb5_principal *p),
        MIT_KRB5KRB_ERR_GENERIC);

//dummyk5(krb5_pkinit_get_client_cert, 0);
//dummyk5(krb5_pkinit_get_client_cert_db, 0);
//dummyk5(krb5_pkinit_get_kdc_cert, 0);
//dummyk5(krb5_pkinit_get_kdc_cert_db, 0);
//dummyk5(krb5_pkinit_have_client_cert, 0);
//dummyk5(krb5_pkinit_release_cert, 0);
//dummyk5(krb5_pkinit_release_cert_db, 0);
//dummyk5(krb5_pkinit_set_client_cert, 0);

dummyk5(krb5_process_key, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_encrypt_block * eblock,
         const mit_krb5_keyblock * key), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_random_key, mit_krb5_error_code,
	(mit_krb5_context context, const mit_krb5_encrypt_block * eblock,
         mit_krb5_pointer ptr, mit_krb5_keyblock ** keyblock), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_rd_cred, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_auth_context ac, mit_krb5_data *d,
         mit_krb5_creds ***c, mit_krb5_replay_data *rd), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_rd_error, mit_krb5_error_code,
	(mit_krb5_context c, const mit_krb5_data *d, mit_krb5_error **e),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_rd_rep, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_auth_context ac, const mit_krb5_data *d,
         mit_krb5_ap_rep_enc_part **e), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_read_password, mit_krb5_error_code,
	(mit_krb5_context context, const char *s, const char *r, char *g,
         unsigned int *h), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_salttype_to_string, mit_krb5_error_code,
        (mit_krb5_int32 i, char *s, size_t sz), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_server_decrypt_ticket_keytab, mit_krb5_error_code,
  	(mit_krb5_context context, const mit_krb5_keytab kt, mit_krb5_ticket  *ticket),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_set_password, mit_krb5_error_code,
        (mit_krb5_context context, mit_krb5_creds *creds, char *newpw,
         mit_krb5_principal change_password_for, int *result_code,
         mit_krb5_data *result_code_string, mit_krb5_data *result_string),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_set_principal_realm, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_principal p, const char *r), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_string_to_cksumtype, mit_krb5_error_code,
        (char *s, mit_krb5_cksumtype *r), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_string_to_enctype, mit_krb5_error_code,
        (char *s, mit_krb5_enctype *r), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_string_to_key, mit_krb5_error_code,
        (mit_krb5_context context, const mit_krb5_encrypt_block * eblock,
         mit_krb5_keyblock * keyblock, const mit_krb5_data * data,
         const mit_krb5_data * salt), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_string_to_salttype, mit_krb5_error_code,
	(char *s, mit_krb5_int32 *st), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_unparse_name_ext, mit_krb5_error_code,
	(mit_krb5_context c, mit_krb5_const_principal cp, char **s,
         unsigned int *r), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_unparse_name_flags, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_const_principal cp, int f, char **r),
        MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_unparse_name_flags_ext, mit_krb5_error_code,
        (mit_krb5_context c, mit_krb5_const_principal cp, int f, char **r,
         unsigned int *v), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_use_enctype, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_encrypt_block * eblock,
         mit_krb5_enctype enctype), MIT_KRB5KRB_ERR_GENERIC);

dummyk5(krb5_verify_checksum, mit_krb5_error_code,
	(mit_krb5_context context, mit_krb5_cksumtype ctype,
         const mit_krb5_checksum * cksum, mit_krb5_const_pointer in,
         size_t in_length, mit_krb5_const_pointer seed, size_t seed_length),
        MIT_KRB5KRB_ERR_GENERIC);

struct _krb5int_access;

dummyk5(krb5int_accessor, mit_krb5_error_code,
        (struct _krb5int_access *a, mit_krb5_int32 i), MIT_KRB5KRB_ERR_GENERIC);

//dummyk5(krb5int_freeaddrinfo, 0);
//dummyk5(krb5int_gai_strerror, 0);
//dummyk5(krb5int_getaddrinfo, 0);

dummyk5(krb5int_gmt_mktime, time_t,
        (struct tm *t), 0);

dummyk5(krb5int_init_context_kdc, mit_krb5_error_code,
        (mit_krb5_context *pctx), MIT_KRB5KRB_ERR_GENERIC);

//dummyk5(krb5int_pkinit_auth_pack_decode, 0);
//dummyk5(krb5int_pkinit_create_cms_msg, 0);
//dummyk5(krb5int_pkinit_pa_pk_as_rep_encode, 0);
//dummyk5(krb5int_pkinit_pa_pk_as_req_decode, 0);
//dummyk5(krb5int_pkinit_parse_cms_msg, 0);
//dummyk5(krb5int_pkinit_reply_key_pack_encode, 0);
