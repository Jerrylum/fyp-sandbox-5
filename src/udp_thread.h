#pragma once

#include "utils.h"

static pthread_t udp_thread;
static char udp_thread_running = 0;

void* udp_thread_func(void* arg) {
  udp_thread_running = 1;

  // setup UDP broadcast socket
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  int broadcast = 1;
  int ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

  

}

static void do_init_udp_thread() {
  pthread_create(&udp_thread, NULL, udp_thread_func, NULL);
}