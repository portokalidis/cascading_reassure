#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <malloc.h>
#include <string.h>

#define REPETITIONS (100 * 1024)

void long_rp(unsigned char *array, int len)
{
	unsigned short *wordp;
	unsigned long *longp;
	unsigned long long *quadp;
	int *p;
	

	array[0] = 'A'; // Byte accesses are always aligned

	 // Unaligned word access
	wordp = (unsigned short *)(array + 1);
	*wordp = 10;
	wordp = (unsigned short *)(array + 6);
	*wordp = 20;
	wordp = (unsigned short *)(array + 11); 
	*wordp = 30; // This should actually trigger our code


	 // Unaligned long access
	longp = (unsigned long *)(array + 17);
	*longp = 100;
	longp = (unsigned long *)(array + 22);
	*longp = 200;

	 // Unaligned quad access
	quadp = (unsigned long long *)(array + 29);
	*quadp = 1000;
	quadp = (unsigned long long *)(array + 43);
	*quadp = 2000;

	p = (int *)0xd0000000;
	*p = 1000;

	printf("Bug triggered\n");
}

int main(int argc, char **argv)
{
	unsigned char *buf, *start;
	struct timeval t1, t2;

	buf = memalign(4096, 4096);
	memset(buf, 0, 4096);
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

	for (start = buf; start < (buf + 4096); start++)
		if (*start) {
			printf("Unclear buffer, improper exit\n");
			return 1;
		}

	printf("Proper exit\n");
	return 0;
}
