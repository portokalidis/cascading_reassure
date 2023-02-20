CC=gcc

LIBS=-lpthread
CFLAGS=-Wall -Werror -O0 -g

TESTS=steps_crashes steps_returns ret_overwrite step_repeated \
      fib_threaded_crashes fib_threaded_returns fib_thread_stretch \
      fib_thread_test fib_block_test steps_threaded_crashes versionseq_app \
      very_long_rp very_long_rp_crash steps_threaded unaligned_crash


all: $(TESTS)
	cd tools && make
	cd cascading && make
	cd misc && make

.PHONY: clean tools cascading misc

%.o: %.c
	$(CC) -c $^

$(TESTS): %: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	cd tools && make clean
	cd cascading && make clean
	cd misc && make clean
	rm -f *.o $(TESTS)
