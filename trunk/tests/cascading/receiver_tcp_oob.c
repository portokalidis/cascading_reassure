/*
*	A stream socket receiver for normal and out-of-band data
*/

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>			/* for close() */
#include <sys/socket.h>
#include <arpa/inet.h>			/* for sockaddr_in */
#include <errno.h>			/* for errno */
#include <string.h>			/* for memset() */
#include <signal.h>			/* for signal() */
#include <fcntl.h>			/* for fcntl() */

#define MYPORT 3030			/* the listening port */
#define MAXPENDING 5
#define MAXRECVSTRING 255		/* Longets string to receive */

int sfd, cfd;			/* listen on sfd, new connection on cfd */
void sig_urg(int);

int main(int argc, char * argv[])
{
	struct sockaddr_in server_addr;	/* server address */
	struct sockaddr_in client_addr;	/* client address */
	unsigned int clnt_len;			/* length of client address data structure */
	char recv_string[MAXRECVSTRING+1];
	struct sigaction act;
	int recv_bytes = 0;
	int i = 0;

	/* get a new socket */
	if((sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
		perror("socket");
		exit(1);
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
		sleep(2);
		/* set up a SIGURG signal handler */
		signal(SIGURG, sig_urg);
#if 0
		memset(&act, '\0', sizeof(act));	
		act.sa_handler = sig_urg;
		act.sa_flags = 0;
		if((sigemptyset(&act.sa_mask) == -1) ||
			(sigaction(SIGURG, &act, NULL) == -1))
		{
			perror("Failed to set new SIGURG handler");
			exit(1);
		}
#endif
	
		if(fcntl(cfd, F_SETOWN, getpid()) != 0)
		{
			perror("fcntl F_SETOWN");
			exit(1);
		}
		

		/* Receiving i packets from the client */	
		for(i=0; i<10; i++)
		{
			/* clear the recv_string buffer */
			memset(recv_string, 0, MAXRECVSTRING);
			
			/* Receive data from client */
			//if((recv_bytes = recv(cfd, recv_string, 10, 0)) < 0)
			if((recv_bytes = read(cfd, recv_string, 11)) < 0)
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

void sig_urg(int signo)
{
	int n=0;
	char buff[10];

	memset(&buff, 0, 10);

	printf("SIGURG received\n");
	printf("%d\n", getpid());
	printf("n=%d (before recv)\n", n);
	if((n= recv(cfd, buff, sizeof(buff)-1, MSG_OOB))==EWOULDBLOCK)
	{
		printf("EWOULDBLOCK\n");
	}
//	buff[n]='\0';
	printf("read %d OOB byte: %s\n", n, buff);
}
