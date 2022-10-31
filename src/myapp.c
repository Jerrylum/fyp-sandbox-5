#include "utils.h"

int main(int argc, char** argv) {
  // hello world
  printf("Hello world\n");

  // print master key
  printf("Master key: ");
  for (int i = 0; i < 32; i++) {
    printf("%02x ", secret.master_key[i]);
  }

  ///////////////////////

  uint8_t frame[128];
  uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);

  ///////////////////////
  renew_time_slots(time_count_now);
  ///////////////////////

  printf("\nfeedback: %d\n", create_frame_challenge(frame, time_count_now));

  ///////////////////////
  create_frame_challenge_response(frame, time_count_now, session_secret.session_id);
  ///////////////////////

  handle_frame(frame);

  return 0;
}

// int main(int argc, char** argv) {
//   // hello world
//   printf("Hello world\n");

//   // print master key
//   printf("Master key: ");
//   for (int i = 0; i < 32; i++) {
//     printf("%02x ", secret.master_key[i]);
//   }

//   ///////////////////////

//   uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);

//   ///////////////////////
//   renew_time_slots(time_count_now);
//   ///////////////////////

//   uint8_t plain[55] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};  // plaintext example

//   uint8_t frame[128];
//   printf("\nfeedback: %d\n", create_frame_packet(frame, time_count_now, 0x00, plain));

//   ///////////////////////

//   handle_frame(frame);

//   return 0;
// }

// int main(int argc, char **argv) {
//   // hello world
//   printf("Hello world\n");

//   // for every second, print the current time
//   while (1) {
//     uint64_t unix_time = get_time();
//     uint64_t now = get_time_count_value(unix_time, secret.time_offset,
//                                         secret.time_duration);
//     printf("Current time: %lu %lu\n", unix_time, now);

//     renew_time_slots();

//     // print all time slots
//     struct time_slot *ts = session_secret.slots;
//     while (ts != NULL) {
//       printf("%lu ", ts->time_count);
//       ts = ts->next;
//     }
//     printf("\n");

//     sleep(1);
//   }

//   return 0;
// }
