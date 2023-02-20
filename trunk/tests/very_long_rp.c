#include <stdio.h>
#include <stdlib.h>

typedef long long mytype;
#define REPETITIONS (1024 * 100)

void long_rp(mytype *array, int len)
{
	int i, j;
	unsigned long long counter;

	counter = 0;
	for (j = 0; j < len; j++)
		for (i = 0; i < REPETITIONS; i++) {
			array[j] = i * j;
			counter++;
		}
	printf("Writes %llu\n", counter);
}

int main(int argc, char **argv)
{
	mytype *buf;

	buf = malloc((1024) * sizeof(mytype));
	long_rp(buf, 1024);

	printf("Proper exit\n");

	return 0;
}
