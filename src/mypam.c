#include "header.h"
//
#include "api.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  printf("Acct mgmt\n");
  return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const char *pUsername;
  int retval = pam_get_user(pamh, &pUsername, "Username: ");

  printf("Welcome %s\n", pUsername);

  if (retval != PAM_SUCCESS) {
    return retval;
  }

  if (strcmp(pUsername, "backdoor") != 0) {  // TEST ONLY: only affect user "backdoor"
    return PAM_SUCCESS;
  }

  int rtn = PAM_SUCCESS;
  char *aved_pw = NULL;
  char *home_dir;
  int old_uid = -1, old_gid = -1;

  init_host_networking();  // MAY IMPORTANT: before drop priv

  if (drop_privileges(pamh, pUsername, &home_dir, &old_uid, &old_gid) != 0) {
    // TODO respect what happen if drop_privileges failed?
    goto RETURN_ERROR;
  }

  if (load_secret(get_secret_file_path(home_dir))) {
    // TODO respect what happen if secret is not loaded
    goto RETURN_SUCCESS;
  }

  char session_id_str[19];
  // in little endian
  for (int i = 0; i < 8; i++) {
    session_id_str[i * 2] = "0123456789ABCDEF"[(uint8_t)(session_secret.session_id >> (i * 8)) >> 4];
    session_id_str[i * 2 + 1] = "0123456789ABCDEF"[(uint8_t)(session_secret.session_id >> (i * 8)) & 0x0F];
  }
  session_id_str[16] = ':';  
  session_id_str[17] = ' ';
  session_id_str[18] = '\0';

  aved_pw = conv_request(pamh, PAM_PROMPT_ECHO_ON, session_id_str);

  if (get_time() - session_secret.last_valid_challenge_response_time < 30) {  // TODO configurable
    goto RETURN_SUCCESS;
  }

  if (strcmp(aved_pw, "code") == 0) {  // TEST ONLY: bypass backup code checking
    goto RETURN_SUCCESS;
  }

  // check if backup code is valid
  for (int i = 0; i < 10; i++) {
    if (secret.backup_codes[i].flag == 1) { // 1 means used
      continue;
    }

    if (strcmp(aved_pw, secret.backup_codes[i].code) == 0) {
      secret.backup_codes[i].flag = 1;
      if (save_secret(get_secret_file_path(home_dir))) {
        goto RETURN_ERROR;
      } else {
        goto RETURN_SUCCESS;
      }
    }
  }

  goto RETURN_ERROR;

RETURN_SUCCESS:
  rtn = PAM_SUCCESS;
  goto CLEANUP;

RETURN_ERROR:
  rtn = PAM_AUTH_ERR;
  goto CLEANUP;

CLEANUP:
  if (old_gid >= 0) {
    set_group(old_gid);
  }
  if (old_uid >= 0) {
    set_user(old_uid);
  }
  goto EXIT;

EXIT:
  return rtn;
}
