# vim:ft=make
SHELL := /bin/bash
CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic -g
LDFLAGS := -lm

TARGET := mqtt-client

OBJ := lib/mqtt.o lib/connack.o src/client.o 

.PHONY: all clean valgrind

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJ)

# Run valgrind with the default options and send the output to a file
valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./$(TARGET) 0

