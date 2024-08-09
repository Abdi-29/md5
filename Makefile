NAME = ft_ssl
CC = gcc
CFLAGS = -Wall -Wextra -Werror
OBJ_DIR = obj
INCLUDE = -I includes
SRC_DIR = srcs

SRC_FILES = main.c md5.c sha256.c print.c
OBJ = $(patsubst %,$(OBJ_DIR)/%,$(SRC:.c=.o))
SRC = $(addprefix $(SRC_DIR)/, $(SRC_FILES))

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(FLAGS) $(INCLUDE) -c -o $@ $<

clean:
	rm -rf $(OBJ_DIR)

fclean:	clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re	
