#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	int c;

	if ((c = fork()) < 0) {
		perror("Could not fork");
		return 1;
	} else if (c == 0) {
		printf("Child me=%d\n", getpid());
		return 0;
	} else {
		int state;

		printf("Parent me=%d, child=%d\n", getpid(), c);
		wait(&state);
		return 0;
	}
	return 0;
}
