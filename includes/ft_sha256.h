#ifndef FT_SHA256_H

#define FT_SHA256_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "ft_util.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

typedef struct {
    uint32_t state[8];
    unsigned char buffer[SHA256_BLOCK_SIZE];
    uint32_t datalen;
    uint64_t bitlen;
} sha256_ctx;

void sha256_string(const char *input, t_hash_algo *algo);
void sha256_init(sha256_ctx *ctx);
void sha256_transform(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *input, unsigned int input_len);
void sha256_pad(sha256_ctx *ctx);
void sha256_final(sha256_ctx *ctx, uint8_t *hash);
void sha256_process(int fd, const char *source, t_hash_algo *algo);
void sha256_command(int argc, char **argv);
void sha256_process_stdin(t_hash_algo *algo);

#endif