#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 1024

static unsigned long long fib_n = 1, fib_val = 1;

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

static void *do_nothing(void *opaque)
{
	printf("Thread %d does nothing\n", (int)opaque);
	pause();
	return NULL;
}

static void *needs_saving(void *opaque)
{
	fib_n = 100000;
	fib_val = 111111;
	return NULL;
}



#define THREAD_NUM 20

int main(void)
{
	int i;
	pthread_attr_t tattr;
	pthread_t tarray[THREAD_NUM + 1];

	pthread_attr_init(&tattr);
	pthread_create(tarray + THREAD_NUM, &tattr, run_fib, (void *)0);

	for (i = 0; i < (THREAD_NUM - 1); i++) {
		pthread_create(tarray + i, &tattr, do_nothing, (void *)i);
		usleep(1000);
	}

	usleep(10000);
	pthread_create(tarray + THREAD_NUM - 1, &tattr, needs_saving, NULL);

	sleep(10);
	return 0;
}
