#pragma once

// Include system libraries

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/in.h>
#include <pthread.h>
#include <pwd.h>
#include <qrencode.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

// Include local libraries

#include "aes.h"
#include "sha3.h"

// Start defining constants and essential functions

#include "essentials.h"
