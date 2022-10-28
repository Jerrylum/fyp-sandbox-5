#include "utils.h"

int main(int argc, char **argv) {
  // hello world
  printf("Hello world\n");

  // for every second, print the current time
  while (1) {
    uint64_t unix_time = get_time();
    uint64_t now = get_time_count_value(unix_time, secret.time_offset,
                                        secret.time_duration);
    printf("Current time: %lu %lu\n", unix_time, now);

    renew_time_slots();

    // print all time slots
    struct time_slot *ts = secret.slots;
    while (ts != NULL) {
      printf("%lu ", ts->time_count);
      ts = ts->next;
    }
    printf("\n");

    sleep(1);
  }

  return 0;
}
