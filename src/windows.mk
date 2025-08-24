# windows.mk

# Compiler settings
CC = gcc
LDFLAGS = -lbcrypt

# Source and target files
SRC = main.c
OUT = Perks.exe

# Build rule
all: $(OUT)

$(OUT): $(SRC)
	$(CC) -o $(OUT) $(SRC) $(LDFLAGS)

# Clean rule
clean:
	del /Q $(OUT)
