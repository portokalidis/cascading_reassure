#include <stdio.h>

void test1(void)
{
	printf("Test1\n");
}

void test2(void)
{
	printf("Test2\n");
}

int main(void)
{
	test1();
	test2();
	test1();
	test2();
	test1();
	test2();
	return 0;
}
