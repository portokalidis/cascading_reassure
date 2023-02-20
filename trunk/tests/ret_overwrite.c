#include <stdio.h>

static int good_function(void)
{
	printf("I am a good function\n");
	return 0;
}

int main(void)
{
	int test;

	test = good_function();

	printf("It seems the function is %d\n", test);

	return 0;
}
