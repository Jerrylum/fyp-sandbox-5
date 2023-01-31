#include "header.h"
//
#include "api.h"

int main(int argc, char** argv) {
  init_networking();

  // hello world
  printf("Hello world\n");

  // sleep 3 seconds
  while (1) sleep(3);

  return 0;
}
