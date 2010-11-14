#include "dummy.h"
#include <mit-leashwin.h>

typedef LPSTR (*err_func)(int, long);

dummy(Leash_kinit_dlg, int, (HWND hParent, LPLSH_DLGINFO lpdlginfo), -1);
dummy(Leash_kinit_dlg_ex, int, (HWND hParent, LPLSH_DLGINFO_EX lpdlginfoex), -1);
dummy(Leash_changepwd_dlg, int, (HWND hParent, LPLSH_DLGINFO lpdlginfo), -1);
dummy(Leash_changepwd_dlg_ex, int, (HWND hParent, LPLSH_DLGINFO_EX lpdlginfo), -1);
dummy(Leash_checkpwd, long, (char *principal, char *password), -1);
dummy(Leash_changepwd, long, (char *principal, char *password, char *newpassword,
                              char** result_string), -1);
dummy(Leash_kinit, long, (char *principal, char *password, int lifetime), EINVAL);
dummy(Leash_kinit_ex, long, (char * principal, char * password, int lifetime,
                             int forwardable, int proxiable, int renew_life,
                             int addressless, unsigned long publicIP), EINVAL);
dummy(Leash_klist, long, (HWND hlist, TICKETINFO *ticketinfo), KFAILURE);
dummy(Leash_kdestroy, long, (void), 0);
dummy(Leash_get_lsh_errno, long, ( LONG *err_val), 0);
dummy(Leash_renew, long, (void), 0);
dummy(Leash_importable, long, (void), FALSE);
dummy(Leash_import, long, (void), 0);
dummy(Leash_set_help_file, BOOL, ( char *szHelpFile ), 0);
dummy(Leash_get_help_file, LPSTR, (void), NULL);
dummyv(Leash_reset_defaults, (void));
dummy(Leash_set_default_lifetime, DWORD, (DWORD minutes), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_lifetime, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_renew_till, DWORD, (DWORD minutes), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_renew_till, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_renewable, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_renewable, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_forwardable, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_forwardable, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_noaddresses, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_noaddresses, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_proxiable, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_proxiable, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_publicip, DWORD, (DWORD ipv4addr), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_publicip, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_get_default_use_krb4, DWORD, (void), 0);
dummy(Leash_set_default_use_krb4, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_use_krb4, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_get_hide_kinit_options, DWORD, (void), 0);
dummy(Leash_set_hide_kinit_options, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_hide_kinit_options, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_life_min, DWORD, (DWORD minutes), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_life_min, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_life_max, DWORD, (DWORD minutes), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_life_max, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_renew_min, DWORD, (DWORD minutes), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_renew_min, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_set_default_renew_max, DWORD, (DWORD minutes), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_renew_max, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_get_lock_file_locations, DWORD, (void), 0);
dummy(Leash_set_lock_file_locations, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_lock_file_locations, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_get_default_uppercaserealm, DWORD, (void), 0);
dummy(Leash_set_default_uppercaserealm, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_uppercaserealm, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_get_default_mslsa_import, DWORD, (void), 0);
dummy(Leash_set_default_mslsa_import, DWORD, (DWORD onoffmatch), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_mslsa_import, DWORD, (void), ERROR_NOT_SUPPORTED);
dummy(Leash_get_default_preserve_kinit_settings, DWORD, (void), 0);
dummy(Leash_set_default_preserve_kinit_settings, DWORD, (DWORD onoff), ERROR_NOT_SUPPORTED);
dummy(Leash_reset_default_preserve_kinit_settings, DWORD, (void), ERROR_NOT_SUPPORTED);
dummyv(Leash_initialize_kadm_error_table, (HANDLE *__et_list));
dummyv(Leash_initialize_krb_error_func, (err_func func, HANDLE * __et_list));
dummyv(initialize_lsh_error_table, (HANDLE *__et_list));
dummyv(Leash_load_com_err_callback, (FARPROC ce, FARPROC em, FARPROC etn));
dummy(Leash_timesync, LONG, (int m), 0);
dummy(Leash_krb_err_func, LPSTR, (int offset, long code), NULL);
dummy(lsh_com_err_proc, int, (LPSTR whoami, long code, LPSTR fmt, va_list args), IDOK);
