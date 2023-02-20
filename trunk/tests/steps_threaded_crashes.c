#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

/* Writing in stdout uses a lock through futex.
 * As a result, even when non-blocking RPs are used, we can get in a deadlock
 * because the futex lock may be updated concurrently by multiple threads */

#define THREADS_NO 5

static pthread_t threads[THREADS_NO];

static int step3(int counter, int tid)
{
	char tmp[8];

	counter += 4;
	sprintf(tmp, "[%d] This is the 3rd step %d", tid, counter);
	printf("%s\n", tmp);
	return 0;
}

static int step2(int counter, int tid)
{
	counter += 2;
	printf("[%d] This is the 2nd step %d\n", tid, counter);
	return step3(counter, tid);
}

static int step1(int counter, int tid)
{
	printf("[%d] This is the 1st step %d\n", tid, ++counter);
	return step2(counter, tid);
}



static void *run_thread(void *opaque)
{
	int tid, r, counter = 0;

	tid = (int)opaque;

	r  = step1(counter, tid);
	//printf("[%d] returned %d\n", tid, r);

	return (void *)r;
}

static int start_thread(int tid)
{
	pthread_attr_t tattr;

	pthread_attr_init(&tattr);
	return pthread_create(threads + tid, &tattr, 
			run_thread, (void *)tid);
}



int main(void)
{
	int i;
	void *retval;

	for (i = 0; i < THREADS_NO; i++) {
		if (start_thread(i) != 0) {
			perror("cannot start thread");
			exit(1);
		}
	}

	//printf("[F] Joining threads\n");

	for (i = 0; i < THREADS_NO; i++) {
		pthread_join(threads[i], &retval);
		//printf("[%d] returned %d\n", i, (int)retval);
	}

	return 0;
}
