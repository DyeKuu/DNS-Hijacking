/*
 * dns_client.c
 *
 *  Created on: Apr 12, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdbool.h>
#include<time.h>

#include "dns.h"

/*
 * usage: dns_client [dns_server_address] [host_name]
 */
int main(int argc, char *argv[])
{
//	char *dns_server = "8.8.8.8"; //google's server
	char *dns_server = "129.104.32.41"; //X's dns server
//	char *dns_server = "127.0.0.1";

	int sockfd;

	uint8_t buf[BUF_SIZE], host_name[HOST_NAME_SIZE];
	res_record answers[10], auth[10], addit[10];
	query queries[10];

	if(argc != 3)
	{	// if no url provided, we simply look google's address
		strncpy((char*)host_name, "www.google.com", HOST_NAME_SIZE);
	}
	else
	{	// for url
		strncpy((char*)host_name, argv[2], HOST_NAME_SIZE);
		dns_server = argv[1];
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr server;
	struct sockaddr_in *server_v4 = (struct sockaddr_in *)(&server);
	server_v4->sin_family = AF_INET;
	server_v4->sin_port = htons(53);
	server_v4->sin_addr.s_addr = inet_addr(dns_server);

	//build and send out the query
	send_dns_query(sockfd, dns_server, (char*)host_name);

	//	memset(buf, 0, BUF_SIZE);
	printf("Receiving DNS answer...\n");
	socklen_t l = sizeof(struct sockaddr);
	if(recvfrom(sockfd, (char*)buf, BUF_SIZE, 0, &server, &l)< 0 )
	{
		perror("DNS receiving failed");
		exit(1);
	}
	printf("DNS message from %s received\n", host_name);

	//parse the query
	parse_dns_query(buf, queries, answers, auth, addit);

}

