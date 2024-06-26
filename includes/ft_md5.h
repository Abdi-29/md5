#ifndef FT_MD5_H

#define FT_MD5_H
#include <stdlib.h>
#include <string.h>

#define FLAG_P 0x01
#define FLAG_Q 0x08
#define FLAG_R 0x04

typedef unsigned char BYTE;
typedef unsigned int WORD;

#define F(B, C, D) ((B & C) | (~B & D))
#define G(B, C, D) ((B & D) | (C & ~D))
#define H(B, C, D) (B ^ C ^ D)
#define I(B, C, D) (C ^ (B | ~D))

typedef struct {
    BYTE buffer[64];
    BYTE digest[16];
    WORD count[2];
    WORD state[4];
} t_ctx;

void md5_tranform(t_ctx *ctx, const BYTE buffer[]);
void md5_init(t_ctx *ctx);
void md5_update(t_ctx *ctx, const BYTE buffer[], size_t len);
void md5_final(t_ctx *ctx, BYTE hash[]);
void md5_string(const char *input, int flag);

#endif