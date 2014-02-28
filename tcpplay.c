#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <pcap.h>

#define ERROR_OK		0
#define ERROR_PARAMS		1
#define ERROR_IO		2

char pcap_errbuf[PCAP_ERRBUF_SIZE];

#define PCAP_INVOKE(x,pcapt,assert) if ((x) == (assert)) {\
	if (pcap_errbuf[0]!='\0') fprintf(stderr, "%s\n", pcap_errbuf);\
	if (pcapt) pcap_perror(pcapt, "PCAP ERROR");\
	exit(ERROR_IO);\
}

#define SOCK_INVOKE(x,assert) if ((x) == (assert)) {\
	perror("SOCK ERROR");\
	exit(ERROR_IO);\
}

void sleep_delta_timeval (struct timeval * from, struct timeval * to) {
	int delta_sec 	= to->tv_sec > from->tv_sec 
		? to->tv_sec  - from->tv_sec
		: 0; 
	int delta_usec 	= to->tv_usec >= from->tv_usec 
		? to->tv_usec - from->tv_usec 
		: (1000000-from->tv_usec) + to->tv_usec;
	sleep(delta_sec);
	usleep(delta_usec);
}

void usage () {
	fprintf(stderr, "Usage: \n");
	exit(ERROR_PARAMS);
}

/********** PCAP INJECT Send method implementation *********/
void* pcap_inject_init(char * device) {
	pcap_t* result;
	PCAP_INVOKE(result = pcap_open_live(device, 96, 0, 0, pcap_errbuf), NULL, NULL);
	return result;
}

void pcap_inject_send(void* handle, char* data, size_t size) {
	PCAP_INVOKE(pcap_inject((pcap_t*)handle, data, size), (pcap_t*)handle, 0);
}

/********* SOCKRAW Send method implementation ********/
void* sockraw_init(char * device) {
	int optval = 1;
	int* p_sd = (int*)malloc(sizeof(int));

	struct ifreq netif;
	memset(&netif, 0, sizeof(netif));
	strncpy(netif.ifr_ifrn.ifrn_name, device, IFNAMSIZ);	
	SOCK_INVOKE(*p_sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW), -1);
  	SOCK_INVOKE(setsockopt(*p_sd, IPPROTO_IP, IP_HDRINCL,
                  		(char*)&optval, sizeof(optval)), -1);
	SOCK_INVOKE(setsockopt(*p_sd, SOL_SOCKET, SO_BINDTODEVICE, &netif, sizeof(netif)), -1);
	return (void*)p_sd;	
}

void sockraw_send(void* handle, char * data, size_t size) {
	int ip_offset		= sizeof(struct ether_header);
	int ip_addr_offset	= 16; 

	struct sockaddr_in addr;
	addr.sin_family		= AF_INET;
	addr.sin_port		= htons(0);
	addr.sin_addr.s_addr 	= *(int*)&data[ip_offset+ip_addr_offset];

	SOCK_INVOKE(sendto(*(int*)handle, data+ip_offset, size-ip_offset, 0, (const struct sockaddr*)&addr, sizeof(addr)), -1);
}

int main(int argc, char *argv[])
{
	pcap_errbuf[0]='\0';

	struct pcap_pkthdr* pkt_header;
    	const u_char*       pkt_data;

	struct timeval*     prev_ts 	= NULL;

	pcap_t*		    pcap_in	= NULL;
	void*               send_out	= NULL;
	int	            sockraw_out	= 0;

	char*		    in_file	= NULL;
	char*	            out_device	= "";

	void* (*p_sendmethod_init)(char*)			= NULL;
	void  (*p_sendmethod_send)(void*, char*, size_t)	= NULL;

	p_sendmethod_init = &sockraw_init;
	p_sendmethod_send = &sockraw_send;

	char op;

	while ((op = getopt(argc, argv, "m:i:hH?")) != -1) {
		switch (op) {
			case 'i':
				out_device = optarg;
				break;
			case 'm':
				if (strcmp(optarg, "pcap_inject") == 0) {
					p_sendmethod_init = &pcap_inject_init;
					p_sendmethod_send = &pcap_inject_send;
				} else if (strcmp(optarg, "rawsock") == 0) {
					p_sendmethod_init = &sockraw_init;
					p_sendmethod_send = &sockraw_send;
				} else {
					fprintf(stderr, "Unknown send method \"%s\"\n", optarg);
					usage();
				}
				break;
			default:
				usage();
				break;
		}
	}

	if (optind >= argc)
		usage();

	in_file = argv[optind];
	
	PCAP_INVOKE(pcap_in = pcap_open_offline(in_file, pcap_errbuf), NULL, NULL);
	send_out = (*p_sendmethod_init) (out_device);
	
	int read_status = 1;
	while (read_status >= 0) {
		PCAP_INVOKE(read_status = pcap_next_ex(pcap_in, &pkt_header, &pkt_data), NULL, -1);

		if (prev_ts == NULL) {
			prev_ts = (struct timeval*)malloc(sizeof(struct timeval));
			memcpy(prev_ts, &pkt_header->ts, sizeof(struct timeval));
		}
		sleep_delta_timeval(prev_ts, &pkt_header->ts);
		memcpy(prev_ts, &pkt_header->ts, sizeof(struct timeval));
		printf("%d %d\n", pkt_header->ts.tv_sec, pkt_header->ts.tv_usec);

		(*p_sendmethod_send)(send_out, (char*)pkt_data, pkt_header->len);
	}

	exit(ERROR_OK);
}
