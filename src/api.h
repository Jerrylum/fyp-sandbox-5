#pragma once

#include "sha3.h"
#include "utils.h"

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
static uint64_t get_time_count_value(uint64_t time, uint64_t time_offset, uint64_t time_duration) {
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

struct time_slot {
  uint64_t time_count;  // or slot id
  uint8_t packet_key[32];
  uint8_t frame_header[32];

  struct time_slot* next;
};

static struct {
  uint8_t master_key[32];
  uint8_t master_iv[16];
  uint64_t time_offset;  // The time offset in seconds
  uint64_t time_duration;  // The length of time in seconds that the key is valid for
  uint8_t minimum_slots;  // The minimum number of slots at any given time
  struct time_slot* slots;
} secret = {
    .master_key = {},
    .master_iv = {},
    .time_offset = 0,
    .time_duration = 30,
    .minimum_slots = 3,
    .slots = NULL,
};

static void release_slots(struct time_slot* slot) {
  if (slot == NULL) {
    return;
  }

  release_slots(slot->next);
  free(slot);
}

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

static void renew_ime_slots() {
  
}
