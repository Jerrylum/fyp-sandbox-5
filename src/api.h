#pragma once

#include "utils.h"
#include "sha3.h"

/**
 * @brief Get the current unix time in seconds
 *
 * @return uint64_t
 */
static uint64_t get_time() {
    return (unsigned long)time(NULL);
}

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


struct time_slot {
    long time;
};
