#include "ft_ssl.h"
#include "ft_sha256.h"

const uint32_t sha256_hash_init[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

void sha256_command(int argc, char **argv) {
    
}

void sha256_init(sha256_ctx *ctx) {
    ctx->count = 0;
    memcpy(ctx->state, sha256_hash_init, sizeof(ctx->state));
}

