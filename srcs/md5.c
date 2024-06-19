#include "ft_ssl.h"
#include "ft_md5.h"

const int k_table[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

const int s_table[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

void md5_command(int argc, char **argv) {

}

void md5_init(t_ctx *ctx) {
    ctx->data_len = 0;
    ctx->bit_len = 0;
    ctx->state[0] = 0x67425301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

void md5_tranform(t_ctx *ctx, const BYTE data[]) {
    WORD a, b, c, d, m[16], i, j;

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    md5_decode(data, m);

    for(i = 0; i < 64; i++) {
        WORD f, g;
        if(i < 16) {
            f = F(b, c, d);
            g = i;
        } else if(i < 32) {
            f = G(b, c, d);
            g = (5 * i + 1) % 16;
		} else if (i < 48) {
			f = H(b, c, d);
			g = (3 * i + 5) % 16;
		} else {
			f = I(b, c, d);
			g = (7 * i) % 16;
		}
        WORD temp = d;
        d = c;
        c = b;
        b = b + ((a + f + k_table[i] + m[g]) << s_table[i] | (a + f + k_table[i] + m[g]) >> (32 - s_table[i]));
        a = temp;
    }

    ctx->state[0] = a;
    ctx->state[1] = b;
    ctx->state[2] = c;
    ctx->state[3] = d;
}

void md_update(t_ctx *ctx, const BYTE input[], WORD length) {
    WORD index, i, first_part;

    index = ctx->data_len / 8 % 64;
    first_part = 64 - index;

    if((ctx->data_len += (length << 3)) < (length << 3)) {
        ctx->bit_len++;
    }
    ctx->bit_len += (length >> 29);

    if(length >= first_part) {
        memcpy(ctx->data, input, first_part);
        md5_tranform(ctx, )
    }

}

void md5_decode(const BYTE output[], WORD input[]) {
    WORD i, j;

    for(i = 0, j = 0; i < 16; i++, j += 4) {
        input[i] = (output[j]) | (output[j + 1] << 8) | (output[j + 1] << 16) | (output[j + 1] << 24);
    }
}

void md5_encode(const BYTE output[], WORD input[]) {
    WORD i, j;

    for(i = 0, j = 0; i < 16; i++, j += 4) {
        input[j] = output[i] & 0xff;
        input[j + 1] = (output[i] >> 8) & 0xff;
        input[j + 2] = (output[i] >> 16) & 0xff;
        input[j + 3] = (output[i] >> 24) & 0xff;
    }
}