CC = gcc
CFLAGS = -O2 -Wall -static -pthread -D_GNU_SOURCE
SRC = exploit.c

all: exploit

exploit: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o exploit

clean:
	rm -f exploit
