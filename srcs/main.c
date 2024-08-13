#include "ft_ssl.h"
#include "../libft/includes/ft_printf.h"

unsigned int g_hash_len;

void print_usage() {
    ft_printf("usage: ft_ssl command [flags] [file/string]\n");
}

int main(int argc, char **argv) {
    if(argc < 2) {
        print_usage();
        return 1;
    }

    t_command command[] = {
        {"md5", &md5_command},
        {"sha256", &sha256_command},
        {NULL, NULL}
    };
    for(int i = 0; command[i].name != NULL; i++) {
        if(strcmp(argv[1], command[i].name) == 0) {
            command[i].func(argc, argv);
            return 0;
        }
    }

    ft_printf("ft_ssl: Error: '%s' is an invalid command.\n", argv[1]);
    print_usage();
    return 1;
}