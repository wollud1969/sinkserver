BUILD_DIR = build

C_SOURCES = \
sha256.c \
sink20169.c \
logging.c

VERSION ?= $(shell git rev-parse --short=8 HEAD)
UNAME_S := $(shell uname -s)

CC = gcc
CFLAGS = $(shell pkg-config --cflags libpq libconfig) -I. \
         -Wall -Werror -std=c99 \
		 -D$(UNAME_S)=1 -DVERSION="\"$(VERSION)\""
LDFLAGS = $(shell pkg-config --libs libpq libconfig)
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
