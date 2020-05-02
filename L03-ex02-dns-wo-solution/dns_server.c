/*
 * dns_server.c
 *
 *  Created on: Apr 26, 2016
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

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr server;

	int port = 53; //the default port of DNS service


	//to keep the information received.
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
	query queries[ANS_SIZE];


	if(argc == 2)
	{
		port = atoi(argv[1]); //if we need to define the DNS to a specific port
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	int enable = 1;

	if(sockfd <0 )
	{
		perror("socket creation error");
		exit_with_error("Socket creation failed");
	}

	//in some operating systems, you probably need to set the REUSEADDR
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
	    perror("setsockopt(SO_REUSEADDR) failed");
	}

	//for v4 address
	struct sockaddr_in *server_v4 = (struct sockaddr_in*)(&server);
	server_v4->sin_family = AF_INET;
	server_v4->sin_addr.s_addr = htonl(INADDR_ANY);
	server_v4->sin_port = htons(port);

	//bind the socket
	if(bind(sockfd, &server, sizeof(*server_v4))<0){
		perror("Binding error");
		exit_with_error("Socket binding failed");
	}

	printf("The dns_server is now listening on port %d ... \n", port);
	//print out
	uint8_t buf[BUF_SIZE], send_buf[BUF_SIZE]; //receiving buffer and sending buffer
	struct sockaddr remote;
	int n;
	socklen_t addr_len = sizeof(remote);
	struct sockaddr_in *remote_v4 = (struct sockaddr_in*)(&remote);

	while(1)
	{
		//an infinite loop that keeps receiving DNS queries and send back a reply
		//complete your code here
		size_t len = recvfrom(sockfd,buf,BUF_SIZE*sizeof(char),0,(struct sockaddr *) &server,&addr_len);
		
		memcpy(send_buf,buf,BUF_SIZE);
		
		query queries[10];
		res_record answers[10], auth[10], addit[10];
		dns_header *dns = NULL;
		dns = (dns_header*)send_buf;
		parse_dns_query(send_buf, queries, answers, auth, addit);
		dns -> qr = 1;
		dns -> an_count = htons(1);
		uint8_t *p;
		p = &send_buf[sizeof(dns_header)]; //jump over the dns header


		printf("==========================\n");
		printf("=====Queries section======\n");

		for(int i=0; i<ntohs(dns->qd_count); i++)
		{

			uint8_t qname[HOST_NAME_SIZE];
			int position = 0;
			get_domain_name(p, send_buf, qname, &position);
			queries[i].qname = malloc(HOST_NAME_SIZE);
			memset(queries[i].qname, 0, HOST_NAME_SIZE);
			strncpy((char*)(queries[i].qname), (char*)qname, strlen((char*)qname));
			p+= position;

			queries[i].ques = (question*)p;
			p+= sizeof(question);
		}
		
		
		for(int i=0; i<ntohs(dns->qd_count); i++)
		{
			r_element* fixPart;
			res_record* resRec;
			int pos = 0;
			build_name_section((uint8_t*)p,queries[i].qname,&pos);
			p += pos;
			fixPart = (r_element*)p;
			fixPart -> type = htons(TYPE_A);
			fixPart ->_class = htons(CLASS_IN);
			fixPart ->ttl = htonl(255);
			fixPart ->rdlength = htons(4);
			p += sizeof(r_element);
			char* dest_addr = "140.82.118.3";
			inet_pton(AF_INET,dest_addr,p);
			p += 4;
		}
		
		


		
		sendto(sockfd,send_buf,p-send_buf,0,(struct sockaddr *) &server,addr_len);

	}
}
