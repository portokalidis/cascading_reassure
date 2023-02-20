#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 1024

static __thread unsigned long long fib_n = 1, fib_val = 1;

static void *run_fib(void *opaque)
{
	unsigned long long f_n_1, f_n_2, f_n, n;
	int threadno = (int)opaque;

	// For n = 2 
	f_n_2 = 0;
	f_n_1 = 1;

	for (n = 2; 1; n++) {
		f_n = f_n_1 + f_n_2;

		fib_n = n;
		fib_val = f_n;

		f_n_2 = f_n_1;
		f_n_1 = f_n;
		printf("%4d: %10llu=%llu\n", threadno, n, f_n);
	}

	return NULL;
}

#define THREAD_NUM 20

int main(void)
{
	int i;
	pthread_attr_t tattr;
	pthread_t tarray[THREAD_NUM];

	pthread_attr_init(&tattr);

	for (i = 0; i < THREAD_NUM; i++) {
		pthread_create(tarray + i, &tattr, run_fib, (void *)i);
		usleep(1000);
	}

	return 0;
}
