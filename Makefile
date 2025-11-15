CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -pedantic
LDLIBS = -lssl -lcrypto

SRCS = server.c net.c tls.c handler.c
OBJS = $(SRCS:.c=.o)
TARGET = server

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)
