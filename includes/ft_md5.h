#ifndef FT_MD5_H

#define FT_MD5_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ft_util.h"

#define FLAG_P 0x01
#define FLAG_Q 0x08
#define FLAG_R 0x04

typedef unsigned char uint1;

#define F(B, C, D) ((B & C) | (~B & D))
#define G(B, C, D) ((D & B) | (~D & C))
#define H(B, C, D) (B ^ C ^ D)
#define I(B, C, D) (C ^ (B | ~D))

#define rotate_left(x, n) ((x << n) | (x >> (32 - n)))


typedef struct {
    uint1 buffer[64];
    uint1 digest[16];
    uint32_t count[2];
    uint32_t state[4];
} t_ctx;

void md5_tranform(t_ctx *ctx, uint1 *buffer);
void md5_init(t_ctx *ctx);
void md5_update(t_ctx *ctx, uint1 buffer[], uint32_t len);
void md5_final(t_ctx *ctx, uint1 hash[16]);
void md5_string(const char *input, t_hash_algo *algo);

void md5_encode(uint1 output[], const uint32_t input[], uint32_t count);
void md5_decode(uint32_t output[], const uint1 input[], unsigned int len);
uint32_t left_rotate(uint32_t x, int n);
void md5_process(int fd, const char *source, t_hash_algo *algo);
void md5_process_stdin(t_hash_algo *algo);


#endif