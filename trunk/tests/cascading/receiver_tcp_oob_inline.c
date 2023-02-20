/*
*	A stream socket receiver for normal and out-of-band data
*/

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>			/* for close() */
#include <sys/socket.h>
#include <arpa/inet.h>			/* for sockaddr_in */
#include <sys/types.h>			/* for setsockopt() */
#include <errno.h>			/* for errno */
#include <string.h>			/* for memset() */
#include <signal.h>			/* for signal() */
#include <fcntl.h>			/* for fcntl() */

#define MYPORT 3030			/* the listening port */
#define MAXPENDING 5
#define MAXRECVSTRING 255		/* Longets string to receive */

int sfd, cfd;			/* listen on sfd, new connection on cfd */

int main(int argc, char * argv[])
{
	struct sockaddr_in server_addr;	/* server address */
	struct sockaddr_in client_addr;	/* client address */
	unsigned int clnt_len;		/* length of client address data structure */
	char recv_string[MAXRECVSTRING+1];
	char oobdata;
	int recv_bytes = 0;
	int err;
	int so_oobinline = 1;


	/* get a new socket */
	if((sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
		perror("socket");
		exit(1);
	}

	if((err = setsockopt(sfd, SOL_SOCKET, SO_OOBINLINE, &so_oobinline, sizeof(so_oobinline))) < 0)
	{
		perror("setsockopt failed");
	}

	memset(&server_addr, 0, sizeof(server_addr));	// zero the rest of the struct
	server_addr.sin_family	= PF_INET;
	server_addr.sin_port	= htons(MYPORT);	//
	server_addr.sin_addr.s_addr	= INADDR_ANY;	// automatically fill with my IP

	/* bind */
	if(bind(sfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
	{
		perror("bind");
		exit(1);
	}

	/* listen */
	if(listen(sfd, MAXPENDING) == -1)
	{
		perror("listen");
		exit(1);
	}

	clnt_len = sizeof(client_addr);

	while(1)
	{
		/* waiting for clients to connect */
		if((cfd = accept(sfd, (struct sockaddr *)&client_addr, &clnt_len)) < 0)
		{
			perror("accept");
			exit(1);
		}
		printf("Accepted connection\n");	
		printf("%d\n", getpid());

		/* Receiving i packets from the client */	
		for(;;)
		{
			if((sockatmark(cfd))==1)
			{
				printf("at oob_mark\n");
				if(recv(cfd, &oobdata, 1, 0) > 0)
					printf("oobdata: %c\n", oobdata);
			}
			/* clear the recv_string buffer */
			memset(recv_string, 0, MAXRECVSTRING);
			
			/* Receive data from client */
			if((recv_bytes = recv(cfd, recv_string, 10, 0)) < 0)
			{
				perror("recv()");
				exit(1);
			}
			else if(recv_bytes==0)
			{
				close(cfd);
				printf("Connection closed!\n");
				break;
			}
			recv_string[recv_bytes] = '\0';
		
			/* Print the received string */
			printf("Received: %s \n", recv_string);
		
		} // end-for
		/* terminate the connection with the client */
		close(cfd);
	
	}//end-while

	/* release the binded port */
	close(sfd);

	return EXIT_SUCCESS;
}
