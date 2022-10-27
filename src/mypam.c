#include "utils.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  printf("Acct mgmt\n");
  return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  int retval;

  const char *pUsername;
  retval = pam_get_user(pamh, &pUsername, "Username: ");

  printf("Welcome %s\n", pUsername);

  if (retval != PAM_SUCCESS) {
    return retval;
  }

  if (strcmp(pUsername, "backdoor") != 0) {  // TEST ONLY: only affect user "backdoor"
    return PAM_SUCCESS;
  }

  // const char* aved_pw = request_pass(pamh, PAM_PROMPT_ECHO_ON, "hello:");

#define UNUSED(x) (void)(x)
  // UNUSED(aved_pw);

  return PAM_AUTH_ERR;
}
