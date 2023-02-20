CC=gcc

LIBS=-lpthread
CFLAGS=-Wall -Werror -O0 -g

TESTS=fork_app readv


all: $(TESTS)

.PHONY: clean

%.o: %.c
	$(CC) -c $^

$(TESTS): %: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o $(TESTS)
