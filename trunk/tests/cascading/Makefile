CC=gcc

LIBS=-lpthread
CFLAGS=-Wall -Werror -O0 -g

TESTS=sender_tcp_oob receiver_tcp_oob sender_tcp_oob_inline \
	receiver_tcp_oob_inline sender_fastsend receiver_no_rp \
	sender_no_rp_1write receiver_no_rp_1read sender_crash \
	receiver_varied_size_writes receiver_varied_size_writes2 \
	receiver_varied_size_writes3 receiver_varied_size_writes4 \
	receiver_varied_size_writes5 sender_slowsend



all: $(TESTS)

.PHONY: clean

%.o: %.c
	$(CC) -c $^

$(TESTS): %: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o $(TESTS)
