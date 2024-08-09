#include "ft_ssl.h"
#include "ft_sha256.h"

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t sha256_hash_init[] = {
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
    sha256_ctx ctx;
    char *input;
    int flag;

    g_hash_len = 32;
    sha256_parse_flag(&flag, argc, argv);
    if (flag & FLAG_P) {
        sha256_process(STDIN_FILENO, NULL, flag);
    }
}

void sha256_parse_flag(int *flag, int argc, char **argv) {
    int i;
    for (i = 2; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-p") == 0) {
                *flag |= FLAG_P;
                sha256_process_stdin(*flag);
            } else if (strcmp(argv[i], "-q") == 0) {
                *flag |= FLAG_Q;
            } else if (strcmp(argv[i], "-r") == 0) {
                *flag |= FLAG_R;
            } else if (strcmp(argv[i], "-s") == 0) {
                if (i + 1 < argc) {
                    sha256_string(argv[++i], *flag);
                } else {
                    printf("ft_ssl: sha256: -s: No such file or directory\n");
                    return;
                }
            } else {
                printf("ft_ssl: sha256: %s: No such file or directory\n", argv[i]);
                return;
            }
        } else {
            break;
        }
    }

    for (; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd == -1) {
            printf("ft_ssl: sha256: %s: No such file or directory\n", argv[i]);
            continue;
        }
        sha256_process(fd, argv[i], *flag);
        close(fd);
    }
}

void sha256_process_stdin(int flag) {
    sha256_ctx ctx;
    unsigned char buffer[1024];
    unsigned int ret;
    unsigned char hash[32];
    char input[1024];
    int input_len = 0;

    sha256_init(&ctx);

    while ((ret = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
        if (input_len + ret < sizeof(input)) {
            memcpy(input + input_len, buffer, ret);
            input_len += ret;
        }
        sha256_update(&ctx, buffer, ret);
    }
    
    if (ret < 0) {
        perror("Error reading from stdin");
        return;
    }

    if (input_len > 0 && input[input_len - 1] == '\n') {
        input_len--;
    }

    sha256_final(&ctx, hash);

    if (flag & FLAG_P) {
        printf("(\"%.*s\")= ", input_len, input);
    }
    print_hash(hash, NULL, NULL, flag);
}


void sha256_process(int fd, const char *source, int flag) {
    sha256_ctx ctx;
    unsigned char buffer[1024];
    unsigned int ret;
    unsigned char hash[32];

    sha256_init(&ctx);
    while ((ret = read(fd, buffer, 1024)) > 0) {
        sha256_update(&ctx, buffer, ret);
    }
    if (ret < 0) {
        printf("Error reading file %s\n", source);
        return;
    }
    sha256_final(&ctx, hash);
    print_hash(hash, NULL, source, flag);
}

void sha256_string(const char *input, int flag) {
    sha256_ctx ctx;
    unsigned char hash[32];
    unsigned int len;

    len = strlen(input);
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char *)input, len);
    sha256_final(&ctx, hash);
    print_hash(hash, input, NULL, flag);
}

void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    memcpy(ctx->state, sha256_hash_init, sizeof(sha256_hash_init));
}

void sha256_transform(sha256_ctx *ctx) {
    uint32_t state[8], m[64];
    int i, j;

    for(i = 0; i < 8; i++) {
        state[i] = ctx->state[i];
    }

    for (i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = (ctx->buffer[j] << 24) | (ctx->buffer[j + 1] << 16) | (ctx->buffer[j + 2] << 8) | (ctx->buffer[j + 3]);
    }

    for (; i < 64; i++) {
        m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
    }

    for (i = 0; i < 64; i++) {
        uint32_t tmp1 = state[7] + SIGMA1(state[4]) + Ch(state[4], state[5], state[6]) + k[i] + m[i];
        uint32_t tmp2 = SIGMA0(state[0]) + Maj(state[0], state[1], state[2]);
        state[7] = state[6];
        state[6] = state[5];
        state[5] = state[4];
        state[4] = state[3] + tmp1;
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = tmp1 + tmp2;
    }

    for (i = 0; i < 8; i++) {
        ctx->state[i] += state[i];
    }
}

void sha256_update(sha256_ctx *ctx, const uint8_t *input, unsigned int input_len) {
    for (unsigned int i = 0; i < input_len; i++) {
        ctx->buffer[ctx->datalen] = input[i] & 0xFF;
        ctx->datalen++;
        if (ctx->datalen == SHA256_BLOCK_SIZE) {
            ctx->bitlen += 512;
            sha256_transform(ctx);
            // ctx->datalen = 0;
        }
    }
}

void sha256_pad(sha256_ctx *ctx) {
    uint64_t bit_len = ctx->bitlen;
    size_t pad_len = (ctx->datalen < 56) ? 56 - ctx->datalen : 120 - ctx->datalen;
    uint8_t pad[64] = {0x80};


    for (size_t i = 1; i < pad_len; i++) {
        pad[i] = 0x00;
    }
    sha256_update(ctx, pad, pad_len);
    for (int i = 0; i < 8; i++) {
        ctx->buffer[63 - i] = (bit_len >> (i * 8)) & 0xff;
    }
    sha256_transform(ctx);
}


void sha256_final(sha256_ctx *ctx, uint8_t *hash) {
    // Increase the bit length
    ctx->bitlen += ctx->datalen * 8;

    // Pad the message
    sha256_pad(ctx);

    // Produce the final hash value in big-endian order
    for (int i = 0; i < 8; ++i) {
        hash[(i * 4) + 0] = (ctx->state[i] >> 24) & 0xff;
        hash[(i * 4) + 1] = (ctx->state[i] >> 16) & 0xff;
        hash[(i * 4) + 2] = (ctx->state[i] >> 8) & 0xff;
        hash[(i * 4) + 3] = ctx->state[i] & 0xff;
    }
}


