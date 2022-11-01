#pragma once

#include "header.h"


static struct secret_storage {
  uint8_t master_key[32];
  uint8_t master_iv[16];
  uint64_t time_offset;   // The time offset in seconds
  uint8_t time_duration;  // The length of time in seconds that the key is valid for
  uint8_t minimum_slots;  // The minimum number of slots at any given time, should be at least 1
  struct backup_code backup_codes[10];
} secret = {
    .master_key = {0x12},
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

static struct session_storage {
  uint64_t session_id;
  uint64_t last_valid_challenge_response_time;
  struct time_slot* slots;

} session_secret = {
    .session_id = 0,
    .last_valid_challenge_response_time = 0,
    .slots = NULL,
};


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
static uint8_t create_frame_renew_backup_code(uint8_t* dst, uint64_t time_count_now, struct backup_code* backup_code) {
  uint8_t full_padding[55] = {};
  for (int i = 0; i < 10; i++) {
    for (uint8_t j = 0; j < 5; j++) {
      uint8_t char1 = backup_code[i].code[j * 2];
      uint8_t char2 = backup_code[i].code[j * 2 + 1];

      uint8_t hex1 = char1 >= '0' && char1 <= '9' ? char1 - '0' : char1 - 'a' + 10;
      uint8_t hex2 = char2 >= '0' && char2 <= '9' ? char2 - '0' : char2 - 'a' + 10;

      full_padding[i * 5 + j] = hex1 << 4 | hex2;
    }
  }
  return create_frame_packet(dst, time_count_now, PACKET_TYPE_RENEW_BACKUP_CODE, full_padding);
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
