#ifndef FT_SSL_H

#include <stdio.h>
#include <string.h>

typedef void(*command_function)(int, char **);
typedef struct s_type {
    const char *name;
    command_function func;
} t_command;

void md5_command(int argc, char **argv);
void sha256_command(int argc, char **argv);

#endif