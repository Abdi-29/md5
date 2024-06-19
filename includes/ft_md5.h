#ifndef FT_MD5_H

#define FT_MD5_H
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
typedef unsigned int WORD;

#define F(B, C, D) ((B & C) | (~B & D))
#define G(B, C, D) ((B & D) | (C & ~D))
#define H(B, C, D) (B ^ C ^ D)
#define I(B, C, D) (C ^ (B | ~D))

typedef struct {
    BYTE data[64];
    WORD data_len;
    unsigned long long bit_len;
    WORD state[4];
} t_ctx;

void md5_tranform(t_ctx *ctx, const BYTE data[]);
void md5_init(t_ctx *ctx);
void md5_update(t_ctx *ctx, const BYTE data[], size_t len);
void md5_final(t_ctx *ctx, BYTE hash[]);

#endif