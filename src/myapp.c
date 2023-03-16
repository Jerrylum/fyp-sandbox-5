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
    // save_secret(); // test only

    init_host_networking();

    show_secret_QRcode();

    printf("Master key: ");
    for (int i = 0; i < 32; i++) {
      printf("%02x ", secret.master_key[i]);
    }

    printf("\nWaiting for device to response\n");

    while (session_secret.last_valid_challenge_response_time == 0) {
      // wait for device to response
      sleep(1);
    }

    printf("Device responded\n");
    save_secret();
    printf("Saved secret\n");
  } else if (strcmp(command, "renew-backup-code") == 0) {
    load_secret();
    init_host_networking();

    // loop all backup codes, set all flag to 1
    for (int i = 0; i < 10; i++) {
      secret.backup_codes[i].flag = 1;
    }

    printf("Master key: ");
    for (int i = 0; i < 32; i++) {
      printf("%02x ", secret.master_key[i]);
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
    }

    printf("Device responded\n");
    save_secret();
    printf("Saved secret\n");
  } else if (strcmp(command, "help") == 0) {
    print_help_message();
  } else {
    printf("Unknown command: %s\n", command);
    print_help_message();
    return 1;
  }

  return 0;
}
