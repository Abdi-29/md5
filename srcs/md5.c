#include "ft_ssl.h"
#include "ft_md5.h"
#include "../libft/includes/libft.h"
#include "../libft/includes/ft_printf.h"

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

void md5_process_stdin(t_hash_algo *algo) {
    t_ctx ctx;
    uint1 buffer[1024];
    uint32_t ret;
    uint1 hash[16];
    char input[1024];
    int input_len = 0;

    md5_init(&ctx);

    while ((ret = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
        if (input_len + ret < sizeof(input)) {
            ft_memcpy(input + input_len, buffer, ret);
            input_len += ret;
        }
        md5_update(&ctx, buffer, ret);
    }
    
    if (ret < 0) {
        ft_printf("Error reading from stdin");
        return;
    }

    if (input_len > 0 && input[input_len - 1] == '\n') {
        input_len--;
    }

    md5_final(&ctx, hash);

    if (algo->flag & FLAG_P) {
        ft_putstr_fd("(\"", 1);
        for (int i = 0; i < input_len && input[i] != '\0'; i++) {
            ft_putchar_fd(input[i], 1);
        }
        ft_putstr_fd("\")= ", 1);
    }
    print_hash(hash, NULL, NULL, algo);
}



void md5_command(int argc, char **argv) {
    t_ctx ctx;

    t_hash_algo md5_algo = {
        .process_fn = md5_process,
        .process_stdin = md5_process_stdin,
        .process_string = md5_string,
        .hash_len = 16,
        .type = "MD5",
        .flag = 0
    };
    parse_flag(argc, argv, &md5_algo);
}
void md5_process(int fd, const char *source, t_hash_algo *algo) {
    t_ctx ctx;
    uint1 buffer[1024];
    uint32_t ret;
    uint1 hash[16];

    md5_init(&ctx);
    while ((ret = read(fd, buffer, 1024)) > 0) {
        md5_update(&ctx, buffer, ret);
    }
    if (ret < 0) {
        ft_printf("Error reading file %s\n", source);
        return;
    }
    md5_final(&ctx, hash);
    print_hash(hash, NULL, source, algo);
}

void md5_init(t_ctx *ctx) {  
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}


void md5_tranform(t_ctx *ctx, uint1 *buffer) {
    uint32_t x[16];
    unsigned int a, b, c, d;

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    md5_decode(x, buffer, 64);

    for(unsigned int i = 0; i < (unsigned int)64; i++) {
        unsigned int f, g;
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
        f = f + a + k_table[i] + x[g];
        a = d;
        d = c;
        c = b;
        b = b + left_rotate(f, s_table[i]);
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ft_memset(x, 0, sizeof x);
}

uint32_t left_rotate(uint32_t x, int offset) {
    return (x << offset) | (x >> (32 - offset));
}

void md5_update(t_ctx *context, unsigned char *input, uint32_t input_len) {
    unsigned int i;
    uint32_t index;
    unsigned int part_len;

    index = (unsigned int)(context->count[0] >> 3) & 0x3f;
    if ((context->count[0] += (input_len << 3)) < (input_len << 3))
        context->count[1]++;
    context->count[1] += (input_len >> 29);
    part_len = 64 - index;
    if (input_len >= part_len) {
        ft_memcpy(&context->buffer[index], input, part_len);
        md5_tranform(context, context->buffer);
        for (i = part_len; i + 64 <= input_len; i += 64) {
            md5_tranform(context, &input[i]);
        }
        index = 0;
    }
    else {
        i = 0;  
    }
    ft_memcpy(&context->buffer[index], &input[i], input_len - i);
}

void md5_final(t_ctx *ctx, uint1 *hash) {
    unsigned char bits[8];
    uint32_t index;
    unsigned int pad_len;

    const unsigned char	padding[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    md5_encode(bits, ctx->count, 8);
    index = (unsigned int)(ctx->count[0] >> 3) & 0x3f;
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, (unsigned char *)padding, pad_len);
    md5_update(ctx, bits, 8);
    md5_encode(hash, ctx->state, 16);
    ft_memset(ctx, 0, sizeof(*ctx));
}

void md5_string(const char *input, t_hash_algo *algo) {
    t_ctx ctx;
    uint1 hash[16];
    unsigned int len;

    len = ft_strlen(input);
    md5_init(&ctx);
    md5_update(&ctx, (uint1 *)input, len);
    md5_final(&ctx, hash);
    print_hash(hash, input, NULL, algo);
}

void md5_encode(uint1 output[], const uint32_t input[], unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (uint1)(input[i] & 0xff);
        output[j + 1] = (uint1)((input[i] >> 8) & 0xff);
        output[j + 2] = (uint1)((input[i] >> 16) & 0xff);
        output[j + 3] = (uint1)((input[i] >> 24) & 0xff);
    }
}

void md5_decode(uint32_t output[], const uint1 input[], unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) |
                    (((uint32_t)input[j + 1]) << 8) |
                    (((uint32_t)input[j + 2]) << 16) |
                    (((uint32_t)input[j + 3]) << 24);
    }
}
