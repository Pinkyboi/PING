
NAME = ft_ping

CC = gcc


# CFLAGS = -Wall -Werror -Wextra
CFLAGS = 

SRC_PATH = ./src
OBJ_PATH = ./obj
INC_PATH = ./inc

LIBFT_PATH = ./libft
LIBFT_INC = $(addprefix $(LIBFT_PATH)/, inc)

HDR_FILES = ping.h
SRC_FILES = main.c\
			create_hdrs.c\
			errors.c\
			maths.c\
			net_tools.c\
			time.c\

OBJ_FILES = $(SRC_FILES:.c=.o)

HDR = $(addprefix $(INC_PATH)/,$(HDR_FILES))
SRC = $(addprefix $(SRC_PATH)/,$(SRC_FILES))
OBJ = $(addprefix $(OBJ_PATH)/,$(OBJ_FILES))

LIBS = -L$(LIBFT_PATH) -lft

INC = -I$(INC_PATH) -I$(LIBFT_INC)

.PHONY: all clean fclean re

all : libft_all $(NAME)


libft_all :
	@make -C $(LIBFT_PATH)

$(NAME) : $(OBJ)
	@$(CC) $^ $(LIBS) -o $@

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c $(HDR)| $(OBJ_PATH)
	@$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(OBJ_PATH) :
	@mkdir -p $(OBJ_PATH)

clean :
	@make -C $(LIBFT_PATH) clean
	@rm -rf $(OBJ_PATH)

fclean : clean
	@make -C $(LIBFT_PATH) fclean
	@rm -f $(NAME)

re: fclean all