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

#include "dummy.h"

dummy(gss_krb5_ui, 0);

dummy(gss_str_to_oid, 0);

dummy(gss_krb5_get_tkt_flags, 0);
dummy(gss_sign, 0);
dummy(gss_inquire_mechs_for_name, 0);
dummy(gss_verify, 0);
dummy(kim_ccache_compare, 0);
dummy(kim_ccache_copy, 0);
dummy(kim_ccache_create_from_client_identity, 0);
dummy(kim_ccache_create_from_default, 0);
dummy(kim_ccache_create_from_display_name, 0);
dummy(kim_ccache_create_from_keytab, 0);
dummy(kim_ccache_create_from_krb5_ccache, 0);
dummy(kim_ccache_create_from_type_and_name, 0);
dummy(kim_ccache_create_new, 0);
dummy(kim_ccache_create_new_if_needed, 0);
dummy(kim_ccache_create_new_if_needed_with_password, 0);
dummy(kim_ccache_create_new_with_password, 0);
dummy(kim_ccache_destroy, 0);
dummy(kim_ccache_free, 0);
dummy(kim_ccache_get_client_identity, 0);
dummy(kim_ccache_get_display_name, 0);
dummy(kim_ccache_get_expiration_time, 0);
dummy(kim_ccache_get_krb5_ccache, 0);
dummy(kim_ccache_get_name, 0);
dummy(kim_ccache_get_options, 0);
dummy(kim_ccache_get_renewal_expiration_time, 0);
dummy(kim_ccache_get_start_time, 0);
dummy(kim_ccache_get_state, 0);
dummy(kim_ccache_get_type, 0);
dummy(kim_ccache_get_valid_credential, 0);
dummy(kim_ccache_iterator_create, 0);
dummy(kim_ccache_iterator_free, 0);
dummy(kim_ccache_iterator_next, 0);
dummy(kim_ccache_renew, 0);
dummy(kim_ccache_set_default, 0);
dummy(kim_ccache_validate, 0);
dummy(kim_ccache_verify, 0);
dummy(kim_credential_copy, 0);
dummy(kim_credential_create_from_keytab, 0);
dummy(kim_credential_create_from_krb5_creds, 0);
dummy(kim_credential_create_new, 0);
dummy(kim_credential_create_new_with_password, 0);
dummy(kim_credential_free, 0);
dummy(kim_credential_get_client_identity, 0);
dummy(kim_credential_get_expiration_time, 0);
dummy(kim_credential_get_krb5_creds, 0);
dummy(kim_credential_get_options, 0);
dummy(kim_credential_get_renewal_expiration_time, 0);
dummy(kim_credential_get_service_identity, 0);
dummy(kim_credential_get_start_time, 0);
dummy(kim_credential_get_state, 0);
dummy(kim_credential_is_tgt, 0);
dummy(kim_credential_iterator_create, 0);
dummy(kim_credential_iterator_free, 0);
dummy(kim_credential_iterator_next, 0);
dummy(kim_credential_renew, 0);
dummy(kim_credential_store, 0);
dummy(kim_credential_validate, 0);
dummy(kim_credential_verify, 0);
dummy(kim_identity_change_password, 0);
dummy(kim_identity_compare, 0);
dummy(kim_identity_copy, 0);
dummy(kim_identity_create_from_components, 0);
dummy(kim_identity_create_from_krb5_principal, 0);
dummy(kim_identity_create_from_string, 0);
dummy(kim_identity_free, 0);
dummy(kim_identity_get_component_at_index, 0);
dummy(kim_identity_get_components_string, 0);
dummy(kim_identity_get_display_string, 0);
dummy(kim_identity_get_krb5_principal, 0);
dummy(kim_identity_get_number_of_components, 0);
dummy(kim_identity_get_realm, 0);
dummy(kim_identity_get_string, 0);
dummy(kim_library_set_allow_automatic_prompting, 0);
dummy(kim_library_set_allow_home_directory_access, 0);
dummy(kim_library_set_application_name, 0);
dummy(kim_options_copy, 0);
dummy(kim_options_create, 0);
dummy(kim_options_create_from_stream, 0);
dummy(kim_options_free, 0);
dummy(kim_options_get_addressless, 0);
dummy(kim_options_get_forwardable, 0);
dummy(kim_options_get_lifetime, 0);
dummy(kim_options_get_proxiable, 0);
dummy(kim_options_get_renewable, 0);
dummy(kim_options_get_renewal_lifetime, 0);
dummy(kim_options_get_service_name, 0);
dummy(kim_options_get_start_time, 0);
dummy(kim_options_set_addressless, 0);
dummy(kim_options_set_forwardable, 0);
dummy(kim_options_set_lifetime, 0);
dummy(kim_options_set_proxiable, 0);
dummy(kim_options_set_renewable, 0);
dummy(kim_options_set_renewal_lifetime, 0);
dummy(kim_options_set_service_name, 0);
dummy(kim_options_set_start_time, 0);
dummy(kim_options_write_to_stream, 0);
dummy(kim_preferences_add_favorite_identity, 0);
dummy(kim_preferences_copy, 0);
dummy(kim_preferences_create, 0);
dummy(kim_preferences_free, 0);
dummy(kim_preferences_get_client_identity, 0);
dummy(kim_preferences_get_favorite_identity_at_index, 0);
dummy(kim_preferences_get_maximum_lifetime, 0);
dummy(kim_preferences_get_maximum_renewal_lifetime, 0);
dummy(kim_preferences_get_minimum_lifetime, 0);
dummy(kim_preferences_get_minimum_renewal_lifetime, 0);
dummy(kim_preferences_get_number_of_favorite_identities, 0);
dummy(kim_preferences_get_options, 0);
dummy(kim_preferences_get_remember_client_identity, 0);
dummy(kim_preferences_get_remember_options, 0);
dummy(kim_preferences_remove_all_favorite_identities, 0);
dummy(kim_preferences_remove_favorite_identity, 0);
dummy(kim_preferences_set_client_identity, 0);
dummy(kim_preferences_set_maximum_lifetime, 0);
dummy(kim_preferences_set_maximum_renewal_lifetime, 0);
dummy(kim_preferences_set_minimum_lifetime, 0);
dummy(kim_preferences_set_minimum_renewal_lifetime, 0);
dummy(kim_preferences_set_options, 0);
dummy(kim_preferences_set_remember_client_identity, 0);
dummy(kim_preferences_set_remember_options, 0);
dummy(kim_preferences_synchronize, 0);
dummy(kim_selection_hints_copy, 0);
dummy(kim_selection_hints_create, 0);
dummy(kim_selection_hints_create_from_stream, 0);
dummy(kim_selection_hints_forget_identity, 0);
dummy(kim_selection_hints_free, 0);
dummy(kim_selection_hints_get_allow_user_interaction, 0);
dummy(kim_selection_hints_get_explanation, 0);
dummy(kim_selection_hints_get_hint, 0);
dummy(kim_selection_hints_get_identity, 0);
dummy(kim_selection_hints_get_options, 0);
dummy(kim_selection_hints_get_remember_identity, 0);
dummy(kim_selection_hints_remember_identity, 0);
dummy(kim_selection_hints_set_allow_user_interaction, 0);
dummy(kim_selection_hints_set_explanation, 0);
dummy(kim_selection_hints_set_hint, 0);
dummy(kim_selection_hints_set_options, 0);
dummy(kim_selection_hints_set_remember_identity, 0);
dummy(kim_string_compare, 0);
dummy(kim_string_copy, 0);
dummy(kim_string_create_for_last_error, 0);
dummy(kim_string_free, 0);

dummy(__KerberosInternal_krb5int_sendtokdc_debug_handler, 0);

