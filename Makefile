# Variables
CC		:= gcc
PKG		:= gtk+-3.0
SRC_DIR	:= src
BUILD_SIR := build
BIN_DIR	:= bin

# Find all .c files
SRC 	:= $(shell find $(SRC_DIR) -name '*.c')
OBJ      := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))

TARGET	:= $(BIN_DIR)/app

# compiler flags from pkg-config
CFLAGS	:= -g -Wall $(shell pkg-config --cflags $(PKG))
# linker flags from pkg-config
LDFLAGS	:= $(shell pkg-config --libs $(PKG))

.PHONY: all dirs

all: dirs $(TARGET)

# Link target binary
$(TARGET): $(OBJ)
	@echo "[LD] $@"
	$(CC) $^ -o $@ $(LDFLAGS)

# Compile each .c to .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Create bin and build dirs if missing
dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

clean:
	@echo "[CLEAN]"
	rm -rf $(BUILD_DIR) $(BIN_DIR)