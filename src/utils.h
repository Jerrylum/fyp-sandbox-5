#pragma once

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#ifdef sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif

#define UNUSED(x) (void)(x)

#include "api.h"

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (PAM_CONST void **)&conv); // Jerry Lum: void*
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

// Show error message to the user.
static void conv_error(pam_handle_t *pamh, const char *text) {
  PAM_CONST struct pam_message msg = {
      .msg_style = PAM_ERROR_MSG,
      .msg = text,
  };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  const int retval = converse(pamh, 1, &msgs, &resp);

  free(resp);
}

static char *conv_request(pam_handle_t *pamh, int echo_code, PAM_CONST char *prompt) {
  // Query user for verification code
  PAM_CONST struct pam_message msg = {
      .msg_style = echo_code,
      .msg = prompt,
  };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;

  if (retval == PAM_SUCCESS && resp && resp->resp) {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}
