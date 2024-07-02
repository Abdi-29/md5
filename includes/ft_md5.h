#ifndef FT_MD5_H

#define FT_MD5_H
#include <stdlib.h>
#include <string.h>

#define FLAG_P 0x01
#define FLAG_Q 0x08
#define FLAG_R 0x04

typedef unsigned char uint1;
typedef unsigned int uint4;

#define F(B, C, D) ((B & C) | (~B & D))
#define G(B, C, D) ((B & D) | (C & ~D))
#define H(B, C, D) (B ^ C ^ D)
#define I(B, C, D) (C ^ (B | ~D))

typedef struct {
    uint1 buffer[64];
    uint1 digest[16];
    uint4 count[2];
    uint4 state[4];
} t_ctx;

void md5_tranform(t_ctx *ctx, uint1 buffer[]);
void md5_init(t_ctx *ctx);
void md5_update(t_ctx *ctx,  uint1 buffer[], uint4 len);
void md5_final(t_ctx *ctx, uint1 hash[]);
void md5_string(const char *input, int flag);

void md5_encode(uint1 output[], const uint4 input[], uint4 count);
void md5_decode(uint4 output[], const uint1 input[], unsigned int len);
void print_hash(uint1 hash[], const char *input, const char *source, int flag);
uint4 left_rotate(uint4 x, uint4 offset);
void parse_flag(int *flag, int argc, char **argv);

#endif