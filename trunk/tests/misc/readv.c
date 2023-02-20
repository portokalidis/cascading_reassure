#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	struct iovec iov[2];
	char buf1[10], buf2[512];
	int r, i;

	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));

	iov[0].iov_base = buf1;
	iov[0].iov_len = sizeof(buf1);
	iov[1].iov_base = buf2;
	iov[1].iov_len = sizeof(buf2);

	r = readv(STDIN_FILENO, iov, 2);
	if (r < 0) {
		perror("readv failed");
		return EXIT_FAILURE;
	}

	printf("Read %d bytes in total\n", r);
	for (i = 0; i < 2; i++) {
		printf("[%d] %u bytes -> %s\n", i, 
				iov[i].iov_len, iov[i].iov_base);
	}

	return EXIT_SUCCESS;
}
