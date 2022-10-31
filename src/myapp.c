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

  uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);

  ///////////////////////
  renew_time_slots(time_count_now);
  ///////////////////////

  struct time_slot* slot = get_slot(time_count_now);
  if (slot == NULL) {
    printf("\nSlot not found\n");
    return 1;
  }

  uint8_t plain[64] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};  // plaintext example

  uint8_t frame[128];
  encrypt_packet(frame + 32, slot->packet_key, secret.master_iv, plain);
  memcpy(frame, slot->frame_header, 32);

  ///////////////////////

  struct time_slot* slot2 = find_slot_by_frame_header(frame);
  if (slot2 == NULL) {
    printf("\nSlot2 not found\n");
    return 1;
  }

  uint8_t decrypted[64];
  decrypt_packet(decrypted, slot2->packet_key, secret.master_iv, frame + 32);

  ///////////////////////

  printf("\nDecrypted: ");
  for (int i = 0; i < 64; i++) {
    printf("%02x ", decrypted[i]);
  }

  return 0;
}

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
