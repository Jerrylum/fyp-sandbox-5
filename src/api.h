#pragma once

#include "header.h"

// ignore warning
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#pragma pack(push) /* push current alignment to stack */
#pragma pack(1)    /* set alignment to 1 byte boundary */

static struct secret_storage {
  uint8_t master_key[32];
  uint8_t master_iv[16];
  uint64_t time_offset;   // The time offset in seconds
  uint8_t time_duration;  // The length of time in seconds that the key is valid for
  uint8_t minimum_slots;  // The minimum number of slots at any given time, should be at least 1
  struct backup_code backup_codes[10];
} secret = {
    .master_key = {},
    .master_iv = {},
    .time_offset = 0,
    .time_duration = 60,
    .minimum_slots = 3,
    .backup_codes =
        {
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
            {.code = {}, .flag = 1},
        },
};

#pragma pack(pop) /* restore original alignment from stack */

static struct session_storage {
  uint64_t session_id;
  uint64_t last_valid_challenge_response_time;
  struct time_slot* slots;

} session_secret = {
    .session_id = 0,
    .last_valid_challenge_response_time = 0,
    .slots = NULL,
};

static enum { QR_NONE, QR_ANSI, QR_UTF8 } qr_mode = QR_UTF8;

/**
 * Global access: secret
 * @brief Allocates a new time slot
 *
 * @param time_count The time count value
 *
 * @return struct time_slot* The new time slot
 */
static struct time_slot* new_slot(uint64_t time_count) {
  struct time_slot* slot = (struct time_slot*)malloc(sizeof(struct time_slot));
  if (slot == NULL) {
    return NULL;
  }

  slot->time_count = time_count;
  get_packet_encryption_key(slot->packet_key, secret.master_key, time_count);
  sha3_256(slot->frame_header, slot->packet_key, 32);
  slot->next = NULL;

  return slot;
}

/**
 * Global access: session_secret
 * @brief Gets the time slot from session_secret for the given time count value
 *
 * @param time_count The time count value
 *
 * @return struct time_slot* The time slot, or NULL if it doesn't exist
 */
static struct time_slot* get_slot(uint64_t time_count) {
  struct time_slot* slot = session_secret.slots;

  while (slot != NULL) {
    if (slot->time_count == time_count) {
      return slot;
    }

    slot = slot->next;
  }

  return NULL;
}

/**
 * Global access: session_secret
 * @brief Gets the time slot from session_secret for the given frame header
 *
 * @param frame_header The frame header, must be 32 bytes
 *
 * @return struct time_slot* The time slot, or NULL if it doesn't exist
 */
static struct time_slot* find_slot_by_frame_header(uint8_t* frame_header) {
  struct time_slot* slot = session_secret.slots;

  while (slot != NULL) {
    if (memcmp(slot->frame_header, frame_header, 32) == 0) {
      return slot;
    }

    slot = slot->next;
  }

  return NULL;
}

/**
 * Global access: secret, session_secret
 * @brief Renew the session_secret.slots list by the given time count value
 *
 * @param time_count The current time count value
 */
static void renew_time_slots(uint64_t time_count_now) {
  uint8_t s_half = secret.minimum_slots / 2;
  uint64_t s_min = time_count_now - s_half;
  uint64_t s_max = time_count_now + s_half - ((secret.minimum_slots + 1) % 2);

  // Remove slots that are too old
  while (session_secret.slots != NULL && session_secret.slots->time_count != s_min) {
    struct time_slot* slot = session_secret.slots;
    session_secret.slots = session_secret.slots->next;
    free(slot);
  }

  // Add new slots up to s_max
  struct time_slot* slot = session_secret.slots;
  if (slot == NULL) {
    session_secret.slots = slot = new_slot(s_min);
  }

  // Add new slots up to s_max, s_half must be at least 1
  while (slot->time_count != s_max && s_half != 0) {
    if (slot->next == NULL) {
      slot->next = new_slot(slot->time_count + 1);
    }
    slot = slot->next;
  }
}

/**
 * @brief Create new frame with encrypted packet
 *
 * @param dst The destination buffer, must be 128 bytes
 * @param slot The time slot to use
 * @param packet_buffer The packet to encrypt
 */
static void create_frame(uint8_t* dst, struct time_slot* slot, uint8_t* packet_buffer) {
  encrypt_packet(dst + 32, slot->packet_key, secret.master_iv, packet_buffer);
  memcpy(dst, slot->frame_header, 32);
}

/**
 * Global access: session secret
 * @brief Create new frame with encrypted packet
 *
 * @param dst The destination buffer, must be 128 bytes
 * @param time_count_now The current time count value
 * @param type The packet type to encrypt
 * @param payload_55 The packet payload with padding, must be 55 bytes
 *
 * @return uint8_t 0 = success, 1 = error
 */
static uint8_t create_frame_packet(uint8_t* dst, uint64_t time_count_now, uint8_t type, uint8_t* payload_55) {
  struct time_slot* slot = get_slot(time_count_now);
  if (slot == NULL) {
    return 1;
  }

  uint8_t packet_buffer[64];
  packet_buffer[0] = type;

  getrandom(&session_secret.session_id, sizeof(session_secret.session_id), 0);
  memcpy(packet_buffer + 1, &session_secret.session_id, 8);

  memcpy(packet_buffer + 9, payload_55, 55);

  create_frame(dst, slot, packet_buffer);

  return 0;
}

/**
 * Global access: session_secret
 * @brief Create new frame with encrypted packet: Challenge
 *
 * @param dst The destination buffer, must be 128 bytes
 * @param time_count_now The current time count value
 *
 * @return uint8_t 0 = success, 1 = error
 */
static uint8_t create_frame_challenge(uint8_t* dst, uint64_t time_count_now) {
  uint8_t full_padding[55] = {};
  return create_frame_packet(dst, time_count_now, PACKET_TYPE_CHALLENGE, full_padding);
}

/**
 * Global access: session_secret
 * @brief Create new frame with encrypted packet: Challenge Response as Device
 *
 * @param dst The destination buffer, must be 128 bytes
 * @param time_count_now The current time count value
 * @param session_id The challenge
 *
 * @return uint8_t 0 = success, 1 = error
 */
static uint8_t create_frame_challenge_response(uint8_t* dst, uint64_t time_count_now, uint64_t session_id) {
  struct time_slot* slot = get_slot(time_count_now);
  if (slot == NULL) {
    return 1;
  }

  uint8_t packet_buffer[1 + 8 + 55] = {};
  packet_buffer[0] = PACKET_TYPE_CHALLENGE_RESPONSE;
  memcpy(packet_buffer + 1, &session_id, 8);
  create_frame(dst, slot, packet_buffer);

  return 0;
}

/**
 * Global access: session_secret
 * @brief Create new frame with encrypted packet: Renew Backup Code as Device
 *
 * @param dst The destination buffer, must be 128 bytes
 * @param time_count_now The current time count value
 * @param backup_code The backup_code array, must be 10 entries
 *
 * @return uint8_t 0 = success, 1 = error
 */
static uint8_t create_frame_renew_backup_code(uint8_t* dst, uint64_t time_count_now, uint64_t session_id, struct backup_code* backup_code) {
  struct time_slot* slot = get_slot(time_count_now);
  if (slot == NULL) {
    return 1;
  }

  uint8_t packet_buffer[1 + 8 + 55] = {};
  packet_buffer[0] = PACKET_TYPE_RENEW_BACKUP_CODE;
  memcpy(packet_buffer + 1, &session_id, 8);
  uint8_t* full_padding = packet_buffer + 9;

  for (int i = 0; i < 10; i++) {
    for (uint8_t j = 0; j < 5; j++) {
      uint8_t char1 = backup_code[i].code[j * 2];
      uint8_t char2 = backup_code[i].code[j * 2 + 1];

      uint8_t hex1 = char1 >= '0' && char1 <= '9' ? char1 - '0' : char1 - 'a' + 10;
      uint8_t hex2 = char2 >= '0' && char2 <= '9' ? char2 - '0' : char2 - 'a' + 10;

      full_padding[i * 5 + j] = hex1 << 4 | hex2;
    }
  }

  create_frame(dst, slot, packet_buffer);
}

/**
 * Global access: session secret
 * @brief Handle decrypted packet: packet challenge response
 * @param payload_55 The packet payload with padding, must be 55 bytes
 */
static void handle_packet_challenge_response(uint8_t* payload_55) {
  // check if the padding is zero
  uint8_t zero_padding[55] = {};
  if (memcmp(payload_55, zero_padding, 55) != 0) {
    return;
  }

  session_secret.last_valid_challenge_response_time = get_time();
  printf("\nReceived valid challenge\n");
}

/**
 * Global access: secret
 * @brief Handle decrypted packet: renew backup code
 * @param payload_55 The packet payload with padding, must be 55 bytes
 */
static void handle_packet_renew_backup_code(uint8_t* payload_55) {
  for (uint8_t i = 0; i < 10; i++) {
    for (uint8_t j = 0; j < 5; j++) {
      uint8_t byte = payload_55[i * 5 + j];

      uint8_t hex_char1 = byte >> 4;
      hex_char1 = hex_char1 < 10 ? hex_char1 + '0' : hex_char1 - 10 + 'a';
      uint8_t hex_char2 = byte & 0x0f;
      hex_char2 = hex_char2 < 10 ? hex_char2 + '0' : hex_char2 - 10 + 'a';

      secret.backup_codes[i].code[j * 2] = hex_char1;
      secret.backup_codes[i].code[j * 2 + 1] = hex_char2;
    }
    secret.backup_codes[i].flag = 0;
  }

  printf("\nReceived valid renew backup code\n");
}

/**
 * Global access: session secret
 * @brief Handle frame decryption as Host
 * @param frame The frame to decrypt
 *
 * @return uint8_t packet type
 */
static uint8_t handle_frame(uint8_t* frame) {
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

  if (session_id != session_secret.session_id) {
    return SESSION_ID_MISMATCH_ERR;
  }

  uint8_t payload_55[55];
  memcpy(payload_55, packet_buffer + 9, 55);

  // DEBUG
  printf("\nDecrypted: ");
  for (int i = 0; i < 64; i++) {
    printf("%02x ", packet_buffer[i]);
  }

  switch (type) {
    case PACKET_TYPE_CHALLENGE_RESPONSE:
      handle_packet_challenge_response(payload_55);
      break;
    case PACKET_TYPE_RENEW_BACKUP_CODE:
      handle_packet_renew_backup_code(payload_55);
      break;
    default:
      /* ignore */
      break;
  }

  return type;
}

static char* get_secret_file_path(char* home) { // accept NULL
  if (home == NULL) {
    home = getenv("HOME");
  }
  if (!home || *home != '/') {
    return NULL;
  }

  char* path = malloc(strlen(home) + strlen(SECRET) + 1);
  if (!path) {
    return NULL;
  }

  strcat(strcpy(path, home), SECRET);
  return path;
}

static uint8_t save_secret(char *secret_file_path) {
  uint8_t rtn = 0;

  if (secret_file_path == NULL) {
    secret_file_path = get_secret_file_path(NULL);
  }
  if (secret_file_path == NULL) {
    goto ERROR_EXIT;
  }

  char* temp_path = malloc(strlen(secret_file_path) + 2);
  strcat(strcpy(temp_path, secret_file_path), "~");

  int fd = open(temp_path, O_WRONLY | O_EXCL | O_CREAT | O_NOFOLLOW | O_TRUNC, 0400);
  if (fd < 0) {
    goto ERROR_EXIT;  // Failed to create temp file
  }

  size_t secret_size = sizeof(struct secret_storage);
  if (write(fd, &secret, secret_size) != (ssize_t)secret_size || rename(temp_path, secret_file_path)) {
    unlink(secret_file_path);  // Failed to write new secret
    goto ERROR_EXIT;
  }

  goto CLEANUP;

ERROR_EXIT:
  rtn = 1;

CLEANUP:
  if (fd > 0) {
    close(fd);
  }

  free(secret_file_path);
  free(temp_path);

  return rtn;
}

static uint8_t load_secret(char* secret_file_path) {
  uint8_t rtn = 0;

  if (secret_file_path == NULL) {
    secret_file_path = get_secret_file_path(NULL);
  }
  if (secret_file_path == NULL) {
    goto ERROR_EXIT;
  }

  int fd = open(secret_file_path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) {
    goto ERROR_EXIT;  // Failed to open secret file
  }

  size_t secret_size = sizeof(struct secret_storage);
  if (read(fd, &secret, secret_size) != (ssize_t)secret_size) {
    goto ERROR_EXIT;  // Failed to read secret file
  }

  goto CLEANUP;

ERROR_EXIT:
  rtn = 1;

CLEANUP:
  if (fd > 0) {
    close(fd);
  }

  free(secret_file_path);

  return rtn;
}

static void new_secret() {
  getrandom(secret.master_key, 32, 0);
  getrandom(secret.master_iv, 16, 0);
}

#define UDP_TO_HOST_PORT 25001
#define UDP_TO_DEVICE_PORT 25002

static pthread_t udp_thread;
static int udp_to_host_fd = -1;
static int udp_to_device_fd = -1;
static struct sockaddr_in udp_to_host_addr;
static struct sockaddr_in udp_to_device_addr;
static char udp_thread_running = 0;

static int init_udp_broadcast_socket(int* fd, struct sockaddr_in* addr, uint16_t port) {
  *fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (*fd < 0) return -1;

  int broadcast = 1;
  if (setsockopt(*fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) return -1;
  if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &broadcast, sizeof(broadcast)) < 0) return -1;

  (*addr).sin_family = AF_INET;
  (*addr).sin_port = htons(port);
  (*addr).sin_addr.s_addr = htonl(INADDR_BROADCAST);

  if (bind(*fd, (struct sockaddr*)addr, sizeof(*addr)) < 0) return -1;

  return 0;
}

static void* host_udp_recv_thread_func(void* arg) {
  udp_thread_running = 1;

  int addr_len = sizeof(struct sockaddr_in);

  uint8_t buffer[128];
  int read_size;

  while (1) {
    read_size = recv(udp_to_host_fd, buffer, 128, 0);
    if (read_size != 128) continue;
    handle_frame(buffer);
  }
}

static void* host_udp_send_thread_func(void* arg) {
  int addr_len = sizeof(struct sockaddr_in);

  uint8_t frame[128];
  uint64_t existed_time_count_now = 0;

  while (1) {
    sleep(1);

    uint64_t time_count_now = get_time_count_value(get_time(), secret.time_offset, secret.time_duration);
    if (time_count_now != existed_time_count_now) {
      existed_time_count_now = time_count_now;

      renew_time_slots(time_count_now);
      if (create_frame_challenge(frame, time_count_now)) continue;
    }

    printf("e\n");
    sendto(udp_to_device_fd, frame, 128, 0, (struct sockaddr*)&udp_to_device_addr, addr_len);
  }
}

static void init_host_networking() {
  if (init_udp_broadcast_socket(&udp_to_host_fd, &udp_to_host_addr, UDP_TO_HOST_PORT)) return;
  if (init_udp_broadcast_socket(&udp_to_device_fd, &udp_to_device_addr, UDP_TO_DEVICE_PORT)) return;

  pthread_create(&udp_thread, NULL, host_udp_recv_thread_func, NULL);
  pthread_create(&udp_thread, NULL, host_udp_send_thread_func, NULL);
}

#define ANSI_RESET "\x1B[0m"
#define ANSI_BLACK_ON_GREY "\x1B[30;47;27m"
#define ANSI_WHITE "\x1B[27m"
#define ANSI_BLACK "\x1B[7m"
#define UTF8_BOTH "\xE2\x96\x88"
#define UTF8_TOP_HALF "\xE2\x96\x80"
#define UTF8_BOTTOM_HALF "\xE2\x96\x84"

static void show_secret_QRcode() {
  // 6 bytes header + secret without backup codes
  size_t buf_size = 6 + 32 + 16 + 8 + 1 + 1;
  uint8_t qr_buffer[buf_size];
  memcpy(qr_buffer, "MYPAM:", 6);
  memcpy(qr_buffer + 6, secret.master_key, 32);
  memcpy(qr_buffer + 6 + 32, secret.master_iv, 16);
  memcpy(qr_buffer + 6 + 32 + 16, &secret.time_offset, 8);
  qr_buffer[buf_size - 2] = secret.time_duration;
  qr_buffer[buf_size - 1] = secret.minimum_slots;

  QRcode* qrcode = QRcode_encodeData(buf_size, (uint8_t*)&qr_buffer, 0, QR_ECLEVEL_L);

#define PRINT_BORDER(c)                         \
  printf(ANSI_BLACK_ON_GREY);                   \
  for (int i = 0; i < qrcode->width + 4; i++) { \
    printf(c);                                  \
  }                                             \
  puts(ANSI_RESET);

  // From google authenticator pam with some modifications

  if (qr_mode == QR_ANSI) {
    // Output QRCode using ANSI colors. Instead of black on white, we
    // output black on grey, as that works independently of whether the
    // user runs their terminal in a black on white or white on black color
    // scheme.
    // But this requires that we print a border around the entire QR Code.
    // Otherwise readers won't be able to recognize it.
    PRINT_BORDER("  ");
    PRINT_BORDER("  ");

    const char* ptr = (char*)qrcode->data;
    for (int y = 0; y < qrcode->width; ++y) {
      printf(ANSI_BLACK_ON_GREY "    ");
      int isBlack = 0;
      for (int x = 0; x < qrcode->width; ++x) {
        if (*ptr++ & 1) {
          if (!isBlack) {
            printf(ANSI_BLACK);
          }
          isBlack = 1;
        } else {
          if (isBlack) {
            printf(ANSI_WHITE);
          }
          isBlack = 0;
        }
        printf("  ");
      }
      if (isBlack) {
        printf(ANSI_WHITE);
      }
      puts("    " ANSI_RESET);
    }

    PRINT_BORDER("  ");
    PRINT_BORDER("  ");
  } else if (qr_mode == QR_UTF8) {
    // Drawing the QRCode with Unicode block elements is desirable as
    // it makes the code much smaller, which is often easier to scan.
    // Unfortunately, many terminal emulators do not display these
    // Unicode characters properly.
    PRINT_BORDER(" ");

    for (int y = 0; y < qrcode->width; y += 2) {
      printf(ANSI_BLACK_ON_GREY "  ");
      for (int x = 0; x < qrcode->width; ++x) {
        const int top = qrcode->data[y * qrcode->width + x] & 1;
        int bottom = 0;
        if (y + 1 < qrcode->width) {
          bottom = qrcode->data[(y + 1) * qrcode->width + x] & 1;
        }
        if (top) {
          printf(bottom ? UTF8_BOTH : UTF8_TOP_HALF);
        } else {
          printf(bottom ? UTF8_BOTTOM_HALF : " ");
        }
      }
      puts("  " ANSI_RESET);
    }

    PRINT_BORDER(" ");
  } else {
    // TODO
  }
  QRcode_free(qrcode);

#undef PRINT_BORDER
}
