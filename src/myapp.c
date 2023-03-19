#include "header.h"
//
#include "api.h"

void print_help_message() {
  printf("Usage: ./myapp [command]\n");
  printf("Commands:\n");
  printf("  new: create a new secret, session secret, and backup code\n");
  printf("  renew-backup-code: create a new backup code\n");
  printf("  help: print help message\n");
}

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: ./myapp [command]\n");
    return 1;
  }

  char* command = argv[1];
  if (strcmp(command, "new") == 0) {
    new_secret();
    // save_secret(NULL); // test only

    init_host_networking();

    show_secret_QRcode();

    goto WAIT_FOR_BACKUP_CODE;
  } else if (strcmp(command, "renew-backup-code") == 0) {
    if (load_secret(NULL) != 0) {
      printf("No secret found\n");
      return 1;
    }
    init_host_networking();

WAIT_FOR_BACKUP_CODE:

    // loop all backup codes, set all flag to 1
    for (int i = 0; i < 10; i++) {
      secret.backup_codes[i].flag = 1;
    }

    printf("Session ID: ");
    uint64_t session_id = session_secret.session_id;
    for (int i = 0; i < 8; i++) {
      printf("%02X ", (uint8_t)(session_id >> (i * 8)));
    }

    printf("\nWaiting for device to response\n");

    while (1) {
      uint8_t any_used = 0;
      for (int i = 0; i < 10; i++) {
        if (secret.backup_codes[i].flag == 1) {
          any_used = 1;
          break;
        }
      }

      if (any_used == 0) {
        break;
      }
      sleep(1);
    }

    printf("Device responded\n");
    save_secret(NULL);
    printf("Saved secret\n");

    // print all backup codes
    printf("Backup codes:\n");
    for (int i = 0; i < 10; i++) {
      printf("%s\n", secret.backup_codes[i].code);
    }
  } else if (strcmp(command, "help") == 0) {
    print_help_message();
  } else {
    printf("Unknown command: %s\n", command);
    print_help_message();
    return 1;
  }

  return 0;
}
