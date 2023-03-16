#include "header.h"
//
#include "api.h"

static uint8_t client_handle_frame(uint8_t* frame) {
  struct time_slot* slot = find_slot_by_frame_header(frame);
  if (slot == NULL) {
    return UNKNOWN_HEADER_ERR;
  }

  uint8_t packet_buffer[64];
  decrypt_packet(packet_buffer, slot->packet_key, secret.master_iv, frame + 32);
  uint8_t type = packet_buffer[0];

  if (type == PACKET_CHECKSUM_INVALID_ERR) {
    return PACKET_CHECKSUM_INVALID_ERR;
  }

  uint64_t session_id = 0;
  memcpy(&session_id, packet_buffer + 1, 8);

  // device doesn't have its own session id
  // if (session_id != session_secret.session_id) {
  //   return SESSION_ID_MISMATCH_ERR;
  // }

  uint8_t payload_55[55];
  memcpy(payload_55, packet_buffer + 9, 55);

  // DEBUG
  printf("\nDecrypted: ");
  for (int i = 0; i < 64; i++) {
    printf("%02x ", packet_buffer[i]);
  }

  switch (type) {
    case PACKET_TYPE_CHALLENGE:
      printf("\nChallenge received\n");

      uint8_t response_frame[128];
      create_frame_challenge_response(response_frame, slot->time_count, session_id);
      int ret = sendto(udp_to_host_fd, response_frame, 128, 0, (struct sockaddr*)&udp_to_host_addr, sizeof(udp_to_host_addr));
      printf("Sned result %d\n", ret);
      break;
    default:
      /* ignore */
      break;
  }

  return type;
}

int main(int argc, char** argv) {
  load_secret();

  // hello world
  printf("Hello world\n");

  if (init_udp_broadcast_socket(&udp_to_host_fd, &udp_to_host_addr, UDP_TO_HOST_PORT)) return 0;
  if (init_udp_broadcast_socket(&udp_to_device_fd, &udp_to_device_addr, UDP_TO_DEVICE_PORT)) return 0;

  uint8_t buffer[128];
  int read_size;

  while (1) {
    read_size = recv(udp_to_device_fd, buffer, 128, 0);
    if (read_size != 128) continue;

    uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);
    renew_time_slots(time_count_now);
  
    client_handle_frame(buffer);
  }

  return 0;
}

// int main(int argc, char** argv) {
//   // hello world
//   printf("Hello world\n");

//   if (init_udp_broadcast_socket(&udp_to_host_fd, &udp_to_host_addr, UDP_TO_HOST_PORT)) return 0;
//   if (init_udp_broadcast_socket(&udp_to_device_fd, &udp_to_device_addr, UDP_TO_DEVICE_PORT)) return 0;

//   int addr_len = sizeof(struct sockaddr_in);

//   uint8_t buffer[128];
//   getrandom(buffer, 128, 0);

//   int ret = sendto(udp_to_host_fd, buffer, 128, 0, (struct sockaddr*)&udp_to_host_addr, addr_len);
//   printf("Hello %d\n", ret);

//   int read_size = recv(udp_to_device_fd, buffer, 128, 0);
//   printf("Received %d\n", read_size);
  

//   sleep(1);

//   // save_secret();
//   return 0;
// }

// int main(int argc, char** argv) {
//   // hello world
//   printf("Hello world\n");

//   // load_secret();
//   new_secret();

//   // print master key
//   printf("Master key: ");
//   for (int i = 0; i < 32; i++) {
//     printf("%02x ", secret.master_key[i]);
//   }
//   printf("\n");

//   show_secret_QRcode();

//   // save_secret();
//   return 0;
// }

// int main(int argc, char** argv) {
//   // hello world
//   printf("Hello world\n");

//   // print master key
//   printf("Master key: ");
//   for (int i = 0; i < 32; i++) {
//     printf("%02x ", secret.master_key[i]);
//   }

//   // using capital letters are fine
//   struct backup_code codes[10] = {
//     {.code = "A0B6123456"},
//     {.code = "A1B6123456"},
//     {.code = "A2B6123456"},
//     {.code = "A3B6123456"},
//     {.code = "A4B6123456"},
//     {.code = "A5B6123456"},
//     {.code = "A6B6123456"},
//     {.code = "A7B6123456"},
//     {.code = "A8B6123456"},
//     {.code = "A9B6123456"},
//   };

//   ///////////////////////

//   uint8_t frame[128];
//   uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);

//   ///////////////////////
//   renew_time_slots(time_count_now);
//   ///////////////////////

//   printf("\nfeedback: %d\n", create_frame_renew_backup_code(frame, time_count_now, codes));

//   handle_frame(frame);

//   for (int i = 0; i < 10; i++) {
//     printf("code %d: %s\n", i, secret.backup_codes[i].code);
//   }

//   return 0;
// }

// int main(int argc, char** argv) {
//   // hello world
//   printf("Hello world\n");

//   ///////////////////////

//   uint8_t frame[128];
//   uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);

//   ///////////////////////
//   renew_time_slots(time_count_now);
//   ///////////////////////

//   printf("\nfeedback: %d\n", create_frame_challenge(frame, time_count_now));

//   ///////////////////////
//   create_frame_challenge_response(frame, time_count_now, session_secret.session_id);
//   ///////////////////////

//   handle_frame(frame);

//   return 0;
// }

// int main(int argc, char** argv) {
//   // hello world
//   printf("Hello world\n");

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
