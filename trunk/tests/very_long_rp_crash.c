#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

typedef long mytype;
#define REPETITIONS (100 * 1024)
//#define REPETITIONS 2000

void long_rp(mytype *array, int len)
{
	int i, j, *p;
	unsigned long long counter;

	counter = 0;
	for (j = 0; j < len; j++) {
		for (i = 0; i < REPETITIONS; i++) {
			array[j] = i * j;
			counter++;
		}
	}
	printf("Writes %llu\n", counter);
	p = (int *)0; //0xC0000000;
	*p = 1000;
	printf("Bug triggered\n");
}

int main(int argc, char **argv)
{
	mytype *buf, *start;
	struct timeval t1, t2;

	buf = malloc((1024) * sizeof(mytype));
	printf("Buffer is at %8p\n", buf);
	gettimeofday(&t1, NULL);
	long_rp(buf, 1024);
	gettimeofday(&t2, NULL);
	if (t2.tv_sec > t1.tv_sec) {
		printf("%lus%luus\n", t2.tv_sec - t1.tv_sec,
				1000000 - t1.tv_usec + t2.tv_usec);
	} else {
		printf("0s%luus\n", t2.tv_usec - t1.tv_usec);
	}

	for (start = buf; start < (buf + 1024); start++)
		if (*start) {
			printf("Unclear buffer, improper exit\n");
			return 1;
		}

	printf("Proper exit\n");
	return 0;
}
