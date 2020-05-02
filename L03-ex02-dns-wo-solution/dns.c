/*
 * dns.c
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




void send_dns_query(int sockfd, char *dns_server, char *host_name)
{
	//BEGIN_SOLUTION
	uint8_t buf[BUF_SIZE], *qname;
	struct sockaddr server;
	struct sockaddr_in *server_v4 = (struct sockaddr_in *)(&server);

	dns_header *dns = NULL;
	question *qdata = NULL;

	printf("The host name being resolved is: %s\n", host_name);

	server_v4->sin_family = AF_INET;
	server_v4->sin_port = htons(53);
	server_v4->sin_addr.s_addr = inet_addr(dns_server);

	//begin building the header

	dns = (dns_header*)&buf;
	build_dns_header(dns, 0, 0, 1, 0, 0, 0);

	//now the query part
	qname = (uint8_t*)&buf[sizeof(dns_header)]; //the query position
//	get_dns_name(qname, (uint8_t*)host_name);
//
//	qdata = (question*)&buf[sizeof(dns_header) + strlen((char*)qname) +1];
//	qdata->qtype = htons(TYPE_A);
//	qdata->qclass = htons(CLASS_IN);

	int offset = 0;
	build_name_section(qname, host_name, &offset);

	qdata = (question*)(qname + offset);

	qdata->qtype = htons(TYPE_A);
	qdata->qclass = htons(CLASS_IN);

	if(sendto(sockfd, (char*)buf,
			sizeof(dns_header) + sizeof(question) + strlen((char*)qname)+1,
			0, &server, sizeof(server)) < 0)
	{
		perror("DNS query sending failed. ");
	} else
	{
		printf("DNS query for %s sent out to %s \n\n", host_name, dns_server);
	}
	//END_SOLUTION
}

int parse_dns_query(uint8_t *buf, query *queries,
		res_record *answers, res_record *auth, res_record *addit)
{
	//BEGIN_SOLUTION
	dns_header *dns = NULL;
	dns = (dns_header*)buf;
	printf("The message header:\n");
	printf("\t Transaction ID: %d;\n", ntohs(dns->id));
	printf("\t Query(0)/Response(1): %d\n", dns->qr);
	printf("\t %d questions; \n", ntohs(dns->qd_count));
	printf("\t %d answers; \n", ntohs(dns->an_count));
	printf("\t %d authoritative servers; \n", ntohs(dns->ns_count));
	printf("\t %d additional records. \n\n", ntohs(dns->ar_count));

	uint8_t *p;
//	p = &buf[sizeof(dns_header) + strlen((char*)qname) +1 + sizeof(question)]; //jump to the answer part
	p = &buf[sizeof(dns_header)]; //jump over the dns header


	printf("==========================\n");
	printf("=====Queries section======\n");

	for(int i=0; i<ntohs(dns->qd_count); i++)
	{
		printf("Query No. %d\n", i+1);

		uint8_t qname[HOST_NAME_SIZE];
		int position = 0;
		get_domain_name(p, buf, qname, &position);
		queries[i].qname = malloc(HOST_NAME_SIZE);
		memset(queries[i].qname, 0, HOST_NAME_SIZE);
		strncpy((char*)(queries[i].qname), (char*)qname, strlen((char*)qname));
		printf("name: %s \n", queries[i].qname);
		p+= position;

		queries[i].ques = (question*)p;
		printf("query type: %d, class: %d\n",
				ntohs(queries[i].ques->qtype), ntohs(queries[i].ques->qclass));
		p+= sizeof(question);
	}

	if(ntohs(dns->an_count) > 0)
	{
		printf("=====Answers section======\n");
	}
	// answers
	for(int i=0; i<ntohs(dns->an_count); i++)
	{
		printf("Answers %d\n", i+1);
		//get the name field
		uint8_t name[HOST_NAME_SIZE];
		int position = 0;
		get_domain_name(p, buf, name, &position);
		answers[i].name = calloc(1, HOST_NAME_SIZE);
		strncpy((char*)(answers[i].name), (char*)name, strlen((char*)name));
		printf("name: %s \n", answers[i].name);

		p += position ; //jump to the next section
		answers[i].element = (r_element*)(p);
		printf("type: %d, class: %d, ttl: %d, rdlength: %d\n",
				ntohs(answers[i].element->type), ntohs(answers[i].element->_class),
				ntohl(answers[i].element->ttl), ntohs(answers[i].element->rdlength));

		int length = ntohs(answers[i].element->rdlength);
		p += sizeof(r_element); //2B type, 2B class, 4B ttl, 2B rdlength
			//pay attention that we can't simply use sizeof(r_element) here, because of padding
			//or we need to specify __attribute((packed)) when declaring the r_element
		if(ntohs(answers[i].element->type) == TYPE_A) //ipv4 address
		{
			answers[i].rdata = (uint8_t *)malloc(length);
			memset(answers[i].rdata, 0, length);
			memcpy(answers[i].rdata, p, length);

			char ip4[INET_ADDRSTRLEN];  // space to hold the IPv4 string
			inet_ntop(AF_INET, answers[i].rdata, ip4, INET_ADDRSTRLEN);
			printf("The IPv4 address is: %s\n", ip4);

		}
		p+=length;

		printf("====\n");
	}

	//authorities
	for(int i=0; i<ntohs(dns->ns_count); i++)
	{

	}

	//additional
	for(int i=0; i<ntohs(dns->ar_count); i++)
	{

	}

	return ntohs(dns->id);
	//END_SOLUTION
}


void get_domain_name(uint8_t *p, uint8_t *buff, uint8_t *name, int *position)
{
	//this function is improved by Pierre-Jean. Thx
    // true if the buffer uses compression (see below)
    bool compressed = false;

    int i = 0;

    // real length of the buffer, that is if we use compression,
    // the length will be smaller
    //     eg. 01 62 c0 5f will have buffer_len 4
    //         but the actual host_name is longer, because
    //         we use compression and concatenate what is
    //         at position 5f immediatly after 01 62
    int buffer_len = -1;

    while(*p!=0)
    {
        // the rest of the chain points to somewhere else
        if ((*p & 0xc0) == 0xc0) {
            //	The pointer takes the form of a two octet sequence:
            //
            //	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //	    | 1  1|                OFFSET                   |
            //	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //	The first two bits are ones. The OFFSET field specifies an offset from
            //	the start of the message (i.e., the first octet of the ID field in the
            //	domain header).

            uint16_t offset = ntohs(*((uint16_t*)p)) & 0x3fff;
            p = buff+offset;
            compressed = true;

            // +2 comes from c0 xx, where xx is the address
            // the pointer points to
            buffer_len = i+2;
        }
        uint8_t num = *((uint8_t*)p);
        strncpy((char*)(name+i), (char*)(p+1), num);
        p+= (num+1);
        i+= num;
        strncpy((char*)(name+i), ".", 1);
        i++;
    }
    *(name+i)='\0';

    // +1 because we take into account the nul length end character,
    // which is not present when using a pointer (ie. when we use
    // compression). Indeed, the pointer points to a chain already
    // ending by the \0 char
    if (compressed == false) buffer_len = i+1;

    // position can change both when there is compression
    // and when there is not. Thus, use not_compressed_len to see
    // if we moved forward in the chain
    if(buffer_len > 0) *position = buffer_len;
}

void get_dns_name(uint8_t *dns, uint8_t *host)
{
	char host_cp[HOST_NAME_SIZE];
	strncpy(host_cp, (char*)host, HOST_NAME_SIZE);

//	printf("host name: %s\n", host_cp);

	char *tk;
	tk = strtok(host_cp, ".");
	int i = 0;
	while(tk!=NULL)
	{
		//		sprintf(length, "%lu", strlen(tk));
		*(dns+i) = (uint8_t)(strlen(tk)); //set the number of chars in the label

		i++;
		strncpy((char*)(dns+i), tk, strlen(tk)); //the label

		i+= strlen(tk);
		tk = strtok(NULL,".");
	}
	*(dns+i) = '\0';
}

/**
 * exit with an error message
 */

void exit_with_error(char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}


void build_dns_header(dns_header *dns, int id, int query, int qd_count,
		int an_count, int ns_count, int ar_count)
{
//BEGIN_SOLUTION
	srand(time(NULL));

	if(id == 0)
		dns->id = (uint16_t)htons(rand()); //set a random id
	else
		dns->id = (uint16_t)htons(id);

	dns->qr = query;	//query
	dns->opcode = 0;	//standard query
	dns->aa = 0;	//no aa
	dns->tc = 0;	//not truncated
	dns->rd = 1;	//recursion desired

	dns->ra = 0;	//recursion not available
	dns->z = 0;	//must be 0
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0; //no error condition

	dns->qd_count = htons(qd_count); //  question
	dns->an_count = htons(an_count); //answer
	dns->ns_count = htons(ns_count); //authenticate
	dns->ar_count = htons(ar_count); //additional
//END_SOLUTION
}

void build_name_section(uint8_t *qname, char *host_name, int *position)
{
//BEGIN_SOLUTION
	get_dns_name(qname, (uint8_t*)host_name);
	*position = strlen((char*)qname) + 1; //calculate the offset
//END_SOLUTION
}


