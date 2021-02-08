BUILD_DIR = build

C_SOURCES = \
  ../cube/User/Src/sha256.c \
  sink20169.c

C_INCLUDES = \
  -I../cube/User/Inc

CC = gcc
CFLAGS = $(C_INCLUDES) -Wall -Werror
LDFLAGS =

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/sink20169: $(OBJECTS) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@