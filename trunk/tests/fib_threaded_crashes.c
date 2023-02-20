#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

unsigned long long fib_n = 1, fib_val = 1;

static void *run_fib(void *opaque)
{
	unsigned long long f_n_1, f_n_2, f_n, n;

	// For n = 2 
	f_n_2 = 0;
	f_n_1 = 1;

	for (n = 2; 1; n++) {
		f_n = f_n_1 + f_n_2;

		fib_n = n;
		fib_val = f_n;

		f_n_2 = f_n_1;
		f_n_1 = f_n;
	}

	return NULL;
}

static void get_fib_str(char *mybuf) {
	char buf[40];

	printf("I should return: F(%llu) = %llu\n", fib_n, fib_val);
	sprintf(buf, "F(%llu) = %llu", fib_n, fib_val);
	memcpy(mybuf, buf, sizeof(buf));
}

static void print_fib(void) {
	char buf[40];
	void (*fptr)() = NULL;

	get_fib_str(buf);
	printf(buf);
	putchar('\n');
	if ((rand() % 4) == 0) {
		printf("Calling weird function\n");
		(*fptr)();
	}
}


int main(void)
{
	pthread_attr_t tattr;
	pthread_t fib_thread;

	pthread_attr_init(&tattr);
	pthread_create(&fib_thread, &tattr, run_fib, NULL);

	srand(time(NULL));

	while (1) {
		print_fib();
		sleep(1);
	}

	return 0;
}
