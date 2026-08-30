CC = gcc
CFLAGS = -Wall -Wextra
THREAD_FLAGS = -pthread

all: server client test_cipher

server: server.c
	$(CC) $(CFLAGS) $(THREAD_FLAGS) server.c -o server

client: client.c
	$(CC) $(CFLAGS) $(THREAD_FLAGS) client.c -o client

test_cipher: test_cipher.c
	$(CC) $(CFLAGS) test_cipher.c -o test_cipher

clean:
	rm -f server client test_cipher
