#include <stdio.h>
#include <unistd.h>		/* for exit() */
#include <stdlib.h>		/* for exit() */
#include <string.h>		/* for memset() */
#include <sys/socket.h>
#include <netinet/in.h>		/* for sockaddr_in struct */
#include <netdb.h>		/* for gethostbyname()*/

#define MYPORT		3030	/* the port to connect to */

int func_write(int fd)
{
	char *p = NULL;

	if(write(fd, "abcdefghij", 10) < 0)
		return EXIT_FAILURE;
	*p = 'c'; // Intentional crash
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	int sockfd;				/* socket to create */
	//struct sockaddr_in sender_addr;		/* my address information */
	struct sockaddr_in listener_addr;	/* listener address information */
	struct hostent *he;

	int ret;

	if((he=gethostbyname(argv[1])) == NULL)
	{
		perror("gethostname");
		exit(1);
	}


	if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket() failed");
		exit(1);
	}


	listener_addr.sin_family = AF_INET; 	//host byte order
	listener_addr.sin_port = htons(MYPORT);
	listener_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(listener_addr.sin_zero), '\0', 8); 	//zero the rest of the struct

	/* Establish connection to the listener*/
	if(connect(sockfd, (struct sockaddr *)&listener_addr, sizeof(listener_addr)) < 0)
	{
		perror("connect() failed");
		exit(1);
	}

	ret = func_write(sockfd);
	write(sockfd, "abcdefghij", 10);	

	close(sockfd);
	return 0;
}

