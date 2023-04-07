#include "header.h"
//
#include "api.h"

int client_tcp_fd;

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

  uint8_t payload_55[55];
  memcpy(payload_55, packet_buffer + 9, 55);

  // DEBUG
  // printf("\nDecrypted: ");
  // for (int i = 0; i < 64; i++) {
  //   printf("%02x ", packet_buffer[i]);
  // }

  switch (type) {
    case PACKET_TYPE_CHALLENGE:
      printf("\nChallenge received\n");

      uint8_t response_frame[128];
      create_frame_challenge_response(response_frame, slot->time_count, session_id);
      
      struct backup_code codes[10] = {
        {.code = "A0B6123456"},
        {.code = "A1B6123456"},
        {.code = "A2B6123456"},
        {.code = "A3B6123456"},
        {.code = "A4B6123456"},
        {.code = "A5B6123456"},
        {.code = "A6B6123456"},
        {.code = "A7B6123456"},
        {.code = "A8B6123456"},
        {.code = "A9B6123456"},
      };
      // create_frame_renew_backup_code(response_frame, slot->time_count, session_id, codes);

      int ret = sendto(udp_to_host_fd, response_frame, 128, 0, (struct sockaddr*)&udp_to_host_addr, sizeof(udp_to_host_addr));
      // int ret = 0;

      uint8_t tcp_response_frame[129];
      tcp_response_frame[0] = 0x00; // send
      memcpy(tcp_response_frame + 1, response_frame, 128);
      int ret2 = send(client_tcp_fd, tcp_response_frame, 129, 0);
      
      printf("Challenge response sent %d %d\n", ret, ret2);
      break;
    default:
      /* ignore */
      break;
  }

  return type;
}

int main(int argc, char** argv) {
  load_secret(NULL);

  // hello world
  printf("Hello world\n");

  printf("Master key: ");
  for (int i = 0; i < 32; i++) {
    printf("%02x ", secret.master_key[i]);
  }
  printf("\n");

  init_host_networking();

  sleep(3);

  printf("Client listening\n");

  const int port = 25000;

  uint8_t* message = malloc(1 + secret.minimum_slots * 32);

BEGIN:
  sleep(1);

  printf("Connecting to exchange server...\n");

  struct hostent* host = gethostbyname("0.0.0.0");

  struct sockaddr_in sendSockAddr;
  bzero((char*)&sendSockAddr, sizeof(sendSockAddr));
  sendSockAddr.sin_family = AF_INET;
  sendSockAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
  sendSockAddr.sin_port = htons(port);

  client_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);

  int status = connect(client_tcp_fd, (struct sockaddr*)&sendSockAddr, sizeof(sendSockAddr));
  if (status < 0) goto BEGIN;

  printf("Connected to exchange server\n");

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(client_tcp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

  uint64_t existed_time_count_now = 0;

  while (1) {
    uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);
    if (time_count_now != existed_time_count_now) {
      existed_time_count_now = time_count_now;

      renew_time_slots(time_count_now);

      message[0] = 0x01; // listen 32 bytes header

      struct time_slot* slot = session_secret.slots;
      int i = 0;
      while (slot != NULL) {
        memcpy(message + 1 + i * 32, slot->frame_header, 32);
        slot = slot->next;
        i++;
      }

      send(client_tcp_fd, message, 1 + secret.minimum_slots * 32, 0);
    }

    uint8_t buffer[128];
    int read_size = recv(client_tcp_fd, buffer, 128, 0);
    if (read_size == 128) {
      client_handle_frame(buffer);
    } else if (read_size == 0) {
      goto CLOSE;
    } else if (read_size < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // ignore
      } else {
        goto CLOSE;
      }
    }
  }

CLOSE:
  printf("Closing connection to exchange server...\n");
  close(client_tcp_fd);
  goto BEGIN;

  return 0;
}

// int main(int argc, char** argv) {
//   load_secret(NULL);

//   // hello world
//   printf("Hello world\n");

//   printf("Master key: ");
//   for (int i = 0; i < 32; i++) {
//     printf("%02x ", secret.master_key[i]);
//   }
//   printf("\n");

//   if (init_udp_broadcast_socket(&udp_to_host_fd, &udp_to_host_addr, UDP_TO_HOST_PORT)) return 0;
//   if (init_udp_broadcast_socket(&udp_to_device_fd, &udp_to_device_addr, UDP_TO_DEVICE_PORT)) return 0;

//   uint8_t buffer[128];
//   int read_size;

//   while (1) {
//     read_size = recv(udp_to_device_fd, buffer, 128, 0);
//     if (read_size != 128) continue;

//     uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);
//     renew_time_slots(time_count_now);
  
//     client_handle_frame(buffer);
//   }

//   return 0;
// }

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
