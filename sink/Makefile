BUILD_DIR = build

C_SOURCES = \
../cube/User/Src/sha256.c \
sink20169.c \
logging.c \
receiver.c


C_INCLUDES = \
-I. \
-I../cube/User/Inc

CC = gcc
CFLAGS = $(C_INCLUDES) -Wall -Werror -std=c99
LDFLAGS = -lconfig
TARGET = sink20169

all: $(BUILD_DIR)/$(TARGET)

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/$(TARGET): $(OBJECTS) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR):
	mkdir $@

.phony: clean
clean:
	-rm -rf $(BUILD_DIR)
