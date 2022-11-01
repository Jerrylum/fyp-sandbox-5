#pragma once

#include "header.h"

#ifdef sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif

#define UNUSED(x) (void)(x)

#define SESSION_ID_MISMATCH_ERR 253
#define PACKET_CHECKSUM_INVALID_ERR 254
#define UNKNOWN_HEADER_ERR 255

#define PACKET_TYPE_CHALLENGE 0
#define PACKET_TYPE_CHALLENGE_RESPONSE 1
#define PACKET_TYPE_RENEW_BACKUP_CODE 2

struct time_slot {
  uint64_t time_count;  // or slot id
  uint8_t packet_key[32];
  uint8_t frame_header[32];

  struct time_slot* next;
};

struct backup_code {  // 10 codes in total
  uint8_t code[10];   // 10 HEX digits
  uint8_t flag;       // 0 = not used, 1 = used
};

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

/**
 * @brief Get the current unix time in seconds
 *
 * @return uint64_t
 */
static uint64_t get_time() { return (unsigned long)time(NULL); }

/**
 * @brief Get the time counter value for the current time
 *
 * @param time The current time
 * @param time_offset The time offset
 * @param time_duration The time duration
 *
 * @return uint64_t
 */
static uint64_t get_time_count_value(uint64_t time, uint64_t time_offset, uint8_t time_duration) {
  return (time + time_offset) / time_duration;
}

/**
 * @brief Sha3-256
 *
 * @param dst The destination buffer, must be at least 32 bytes long
 * @param plain The plain text
 * @param plain_length The length of the plain text
 */
static void sha3_256(uint8_t* dst, uint8_t* input, size_t input_length) {
  sha3_context sc;
  uint8_t* hash;

  sha3_Init256(&sc);
  sha3_Update(&sc, input, input_length);
  hash = (uint8_t*)sha3_Finalize(&sc);

  memcpy(dst, hash, 32);
}

/**
 * @brief Generates the packet key from the master key and the current time
 *
 * @param dst The destination buffer, must be 32 bytes long
 * @param key The master key
 * @param time_count_value The current time counter value
 */
static void get_packet_encryption_key(uint8_t* dst, uint8_t* key, uint64_t time_count_value) {
  uint8_t buffer[32 + 8];
  memcpy(buffer, key, 32);
  memcpy(buffer + 32, &time_count_value, 8);

  sha3_256(dst, buffer, 32 + 8);
}

/**
 * @brief Encrypts the packet using AES-256-CBC
 *
 * @param dst The encrypted packet in the form of a 96 byte array
 * @param packet_key The key to encrypt the packet with, must be 32 bytes
 * @param iv The initialization vector, must be 16 bytes
 * @param packet_buffer The packet to encrypt, must be 64 bytes
 */
static void encrypt_packet(uint8_t* dst, uint8_t* packet_key, uint8_t* iv, uint8_t* packet_buffer) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, packet_key, iv);

  memcpy(dst, packet_buffer, 64);

  sha3_256(dst + 64, packet_buffer, 64);

  AES_CBC_encrypt_buffer(&ctx, dst, 96);
}

/**
 * @brief Decrypts the packet using AES-256-CBC
 *
 * The first byte of the packet is the packet type, PACKET_CHECKSUM_INVALID_ERR if the packet is invalid
 *
 * @param dst The decrypted packet in the form of a 64 byte array
 * @param packet_key The key to decrypt the packet with, must be 32 bytes
 * @param iv The initialization vector, must be 16 bytes
 * @param enc The packet to decrypt, must be 96 bytes
 */
static void decrypt_packet(uint8_t* dst, uint8_t* packet_key, uint8_t* iv, uint8_t* enc) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, packet_key, iv);

  AES_CBC_decrypt_buffer(&ctx, enc, 96);

  uint8_t hash[32];
  sha3_256(hash, enc, 64);

  if (memcmp(hash, enc + 64, 32) != 0) {
    dst[0] = PACKET_CHECKSUM_INVALID_ERR;
  } else {
    memcpy(dst, enc, 64);
  }
}

/**
 * @brief Releases all the memory used by this time slot and all time slots after it
 *
 * @param slot The time slot to start from
 */
static void release_slots(struct time_slot* slot) {
  if (slot == NULL) {
    return;
  }

  release_slots(slot->next);
  free(slot);
}
