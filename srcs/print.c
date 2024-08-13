#include "ft_util.h"
#include "../libft/includes/libft.h"
#include "../libft/includes/ft_printf.h"

void print_hash(unsigned char *hash, const char *input, const char *source, t_hash_algo *algo) {
    if (algo->flag & FLAG_Q) {
        for (int i = 0; i < algo->hash_len; i++) {
            // printf("%02x", hash[i]);
            print_hex(hash[i], 2);
        }
        ft_printf("\n");
    } else if (algo->flag & FLAG_R) {
        for (int i = 0; i < algo->hash_len; i++) {
            print_hex(hash[i], 2);
        }
        if (source) {
            ft_printf(" %s\n", source);
        } else if (input) {
            ft_printf(" \"%s\"\n", input);
        } else {
            ft_printf("\n");
        }
    } else {
        if (source) {
            ft_printf("%s (%s) = ", algo->type, source);
        } else if (input) {
            ft_printf("%s (\"%s\") = ", algo->type, input);
        }
        for (int i = 0; i < algo->hash_len; i++) {
            print_hex(hash[i], 2);
        }
        ft_printf("\n");
    }
}

void	print_hex(unsigned int value, int width) {
    const char hex_digits[] = "0123456789abcdef";
    char hex[width + 1];

    for (int i = width - 1; i >= 0; i--) {
        hex[i] = hex_digits[value & 0x0F];
        value >>= 4;
    }
    hex[width] = '\0';
    ft_putstr_fd(hex, 1);
}

void parse_flag(int argc, char **argv, t_hash_algo *algo) {
    int i;
    int processed = 0;

    for (i = 2; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-p") == 0) {
                algo->flag |= FLAG_P;
                algo->process_stdin(algo);
            } else if (strcmp(argv[i], "-q") == 0) {
                algo->flag |= FLAG_Q;
            } else if (strcmp(argv[i], "-r") == 0) {
                algo->flag |= FLAG_R;
            } else if (strcmp(argv[i], "-s") == 0) {
                if (i + 1 < argc) {
                    algo->process_string(argv[++i], algo);
                    processed = 1;
                } else {
                    ft_printf("ft_ssl: %s: -s: No such file or directory\n", algo->type);
                    return;
                }
            } else {
                ft_printf("ft_ssl: %s: %s: No such file or directory\n", algo->type, argv[i]);
                return;
            }
        } else {
            break;
        }
    }

    for (; i < argc; i++) {
        processed = 1;
        int fd = open(argv[i], O_RDONLY);
        if (fd == -1) {
            printf("ft_ssl: %s: %s: No such file or directory\n", algo->type, argv[i]);
            continue;
        }
        algo->process_fn(fd, argv[i], algo);
        close(fd);
    }
    if (i == argc && !(algo->flag & FLAG_P) && !processed) {
        algo->process_stdin(algo);
    }
}