#include "ft_util.h"

void print_hash(unsigned char *hash, const char *input, const char *source, int flag) {
    if (flag & FLAG_Q) {
        for (int i = 0; i < g_hash_len; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else if (flag & FLAG_R) {
        for (int i = 0; i < g_hash_len; i++) {
            printf("%02x", hash[i]);
        }
        if (source) {
            printf(" %s\n", source);
        } else if (input) {
            printf(" \"%s\"\n", input);
        } else {
            printf("\n");
        }
    } else {
        if (source) {
            printf("MD5 (%s) = ", source);
        } else if (input) {
            printf("MD5 (\"%s\") = ", input);
        }
        for (int i = 0; i < g_hash_len; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    }
}