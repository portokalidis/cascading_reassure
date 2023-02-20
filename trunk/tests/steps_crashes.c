#include <stdio.h>
#include <string.h>

static int counter = 0;


static int step3(char *msg, size_t len)
{
	char tmp[8];

	counter += 4;
	sprintf(tmp, "This is the 3rd step %d", counter);
	printf("%s\n", tmp);
	return 0;
}

static int step2(char *msg, size_t len)
{
	counter += 2;
	sprintf(msg, "This is the 2nd step %d", counter);
	printf("%s\n", msg);
	step3(msg, sizeof(msg));
	return 0;
}

static int step1(char *msg, size_t len)
{
	sprintf(msg, "This is the 1st step %d", ++counter);
	printf("%s\n", msg);
	step2(msg, sizeof(msg));
	return 0;
}

int main(void)
{
	int r;
	char msg[80];

	//sprintf(msg, "I am starting now\n");
	//printf("%s\n", msg);

	r = step1(msg, sizeof(msg));
	printf("Returned %d\n", r);

	return 0;
}
