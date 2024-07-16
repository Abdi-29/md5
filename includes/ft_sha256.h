#ifndef FT_SHA256_H

#define FT_SHA256_H

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

#endif