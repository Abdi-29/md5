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

const unsigned char	padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md5_command(int argc, char **argv) {
    t_ctx ctx;
    char *input;
    int flag;

    parse_flag(&flag, argc, argv);
}

void parse_flag(int *flag, int argc, char **argv) {
    for(int i = 1; i + 1 < argc; i++) {
        if(argv[i][0] == '-') {
            if(strcmp(argv[i], "-p") == 0) {
                *flag |= FLAG_P;
            } else if(strcmp(argv[i], "-q") == 0) {
                *flag |= FLAG_Q;
            } else if(strcmp(argv[i], "-r") == 0) {
                *flag |= FLAG_R;
            } else if(strcmp(argv[i], "-s") == 0) {
                if(i + 1 < argc) {
                // printf("hellooooo");
                    md5_string(argv[++i], *flag);
                }
            } else {
                printf("Error: ft_ssl: md5: %s", argv[i]);
            }
        }
    }
}

void md5_init(t_ctx *ctx) {
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->state[0] = 0x67425301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
     memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void md5_tranform(t_ctx *ctx, BYTE buffer[]) {
    WORD a, b, c, d, m[16], i, j;

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    md5_decode(buffer, ctx->count, 8);

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
        f = f + a + k_table[i] + m[g];
        a = d;
        d = c;
        c = b;
        b = b + left_rotate(f, s_table[i]);
    }

    ctx->state[0] = a;
    ctx->state[1] = b;
    ctx->state[2] = c;
    ctx->state[3] = d;
}

WORD left_rotate(WORD x, WORD offset) {
    return (x << offset) | (x >> (32 - offset));
}

void	md5_update(t_ctx *context, unsigned char *input, WORD input_len)
{
	unsigned int	i;
	int		index;
	unsigned int	part_len;

	index = ((context->count[0] >> 3) & 0x3F);
	if ((context->count[0] += (input_len << 3)) < (input_len << 3))
		context->count[1]++;
	context->count[1] += (input_len >> 29);
	part_len = 64 - index;
	if (input_len >= part_len)
	{
		memcpy(&context->buffer[index], input, part_len);
		md5_tranform(context, context->buffer);
		i = part_len;
		while (i + 63 < input_len)
		{
			md5_tranform(context, &input[i]);
			i += 64;
		}
		index = 0;
	}
	else
		i = 0;
	memcpy(&context->buffer[index], &input[i], input_len - i);
}

void md5_final(t_ctx *ctx) {
    unsigned char bits[8];
    unsigned int index;
    unsigned int pad_len;

    md5_encode(bits, ctx->count, 8);
    index = ctx->count[0] / 8 % 64;
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, (unsigned char *)padding, pad_len);
    md5_update(ctx, bits, 8);
    // md5_encode(ctx->digest, ctx->state, 16);
    // bzero(ctx, sizeof(*ctx));
}

void md5_string(const char *input, int flag) {
    t_ctx ctx;
    unsigned int len;

    printf("hello: ");
    len = strlen(input);
    md5_init(&ctx);
    md5_update(&ctx, (BYTE *)input, len);
    md5_final(&ctx);
}

void print_hash(BYTE hash[], const char *input, const char *source, int flag) {
    if(flag & FLAG_Q) {
        for(int i = 0; i < 16; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else if(flag & FLAG_R) {
        for(int i = 0; i < 16; i++) {
            printf("%02x", hash[i]);
        }
        if(source) {
            printf(" %s\n", source);
        } else if(input) {
            printf(" \"%s\"\n", input);
        } else {
            printf("\n");
        }
    } else {
        if(source) {
            printf(" %s", source);
        } else if(input) {
            printf("MD5 (\"%s\") = ", input);
        }
        for(int i = 0; i < 16; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    }
}

void md5_decode(const BYTE output[], WORD input[], WORD count) {
    WORD i, j;

    for(i = 0, j = 0; i < count; i++, j += 4) {
        input[i] = (output[j]) | (output[j + 1] << 8) | (output[j + 1] << 16) | (output[j + 1] << 24);
    }
}

void md5_encode(BYTE output[], const WORD input[], WORD count) {
    WORD i, j;
    printf("input: %d", input[0]);

    for(i = 0, j = 0; j < count; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}