#ifndef FT_UTIL_H

#define FT_UTIL_H

#define FLAG_P 0x01
#define FLAG_Q 0x08
#define FLAG_R 0x04

#include <stdio.h>

extern unsigned int g_hash_len;
void print_hash(unsigned char hash[], const char *input, const char *source, int flag);

#endif