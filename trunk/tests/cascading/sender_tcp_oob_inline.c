#include <stdio.h>
#include <unistd.h>		/* for exit() */
#include <stdlib.h>		/* for exit() */
#include <string.h>		/* for memset() */
#include <sys/socket.h>
#include <sys/types.h>		/* for setsockopt() */
#include <netinet/in.h>		/* for sockaddr_in struct */
#include <netdb.h>		/* for gethostbyname()*/
#include <stdbool.h>		/* for bool type */

#define MYPORT		3030	/* the port to connect to */

int main(int argc, char *argv[])
{
	int sockfd;				/* socket to create */
	struct sockaddr_in listener_addr;	/* listener address information */
	struct hostent *he;

	int err;
	int so_oobinline = 1;

	printf("Sending tcp OOB data!\n");
	
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

	if((err = setsockopt(sockfd, SOL_SOCKET, SO_OOBINLINE, &so_oobinline, sizeof(so_oobinline))) < 0)
	{
		perror("setsockopt failed");
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

	send(sockfd, "ab", 2, 0);
	send(sockfd, "1", 1, MSG_OOB);
	send(sockfd, "de", 2, 0);
	printf("End sending 3 characters,a MSG_OOB, and another character at the end\n");
	
	return 0;
}
