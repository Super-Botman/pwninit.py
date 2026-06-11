CC = zig cc
CFLAGS = -target x86_64-linux-musl -static -Os -g -no-pie -o exploit.debug -ffunction-sections -fdata-sections -flto
CFLAGS = -O2 -Wall -static -pthread -D_GNU_SOURCE
SRC = exploit.c

all: exploit

exploit: $(SRC)
	$(CC) $(SRC) $(CFLAGS)
	cp exploit.debug exploit
	strip exploit

clean:
	rm -f exploit
