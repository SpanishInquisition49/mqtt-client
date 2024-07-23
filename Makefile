# vim:ft=make
SHELL := /bin/bash
CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic -g
LDFLAGS := -lm

TARGET := mqtt-client

OBJ := lib/mqtt.o src/client.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJ)

