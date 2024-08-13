#ifndef FT_UTIL_H

#define FT_UTIL_H

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#define FLAG_P 0x01
#define FLAG_Q 0x08
#define FLAG_R 0x04

#include <stdio.h>

typedef struct s_hash_algo t_hash_algo;

typedef void (*t_process_fn)(int, const char *, t_hash_algo *);
typedef void (*t_process_stdin)(t_hash_algo *);
typedef void(*t_process_string)(const char *, t_hash_algo *);

typedef struct s_hash_algo{
    t_process_fn    process_fn;
    t_process_stdin process_stdin;
    t_process_string    process_string;
    int     hash_len;
    int     flag;
    const char *type;
} t_hash_algo;

void print_hash(unsigned char hash[], const char *input, const char *source, t_hash_algo *algo);
void parse_flag(int argc, char **argv, t_hash_algo *algo);
void	print_hex(unsigned int value, int width);

#endif