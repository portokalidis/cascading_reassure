#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 1024

unsigned long long fib_n = 1, fib_val = 1;

static void *run_fib(void *opaque)
{
	unsigned long long f_n_1, f_n_2, f_n, n;
	//int i;

	// For n = 2 
	f_n_2 = 0;
	f_n_1 = 1;

	for (n = 2; 1; n++) {
		f_n = f_n_1 + f_n_2;

		fib_n = n;
		fib_val = f_n;

		f_n_2 = f_n_1;
		f_n_1 = f_n;
		//for (i = 0; i < 103090930; i++)
			//;
		usleep(1000);
	}

	return NULL;
}

static void get_fib_str(char *mybuf) {
	char buf[BUFSZ];

	snprintf(buf, BUFSZ, "F(%llu) = %llu", fib_n, fib_val);
	memcpy(mybuf, buf, BUFSZ);
}

static void print_fib(void) {
	char buf[BUFSZ];

	get_fib_str(buf);
	printf("1->%s\n", buf);

	//usleep(100000);

	get_fib_str(buf);
	printf("2->%s\n\n", buf);
}


int main(void)
{
	pthread_attr_t tattr;
	pthread_t fib_thread;

	pthread_attr_init(&tattr);
	pthread_create(&fib_thread, &tattr, run_fib, NULL);

	while (1) {
		print_fib();
		sleep(1);
	}

	return 0;
}
