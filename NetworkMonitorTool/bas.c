#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include "headers.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

int main(int argc, char *argv[])
{
		pcap_t *handle;				/* Session handle */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

		int opt;
		char *filename;
		char *string;
		char *filter_exp;//"port 80";	/* The filter expression */
		char *dev;			/* The device to sniff on */
		int filter_exp_len = 0;
		/**
		* Parse command-line options
		*/
		while((opt = getopt(argc, argv, "i:r:s:")) != -1 )
		{
			switch(opt)
			{
				case 'i':
					dev = (char *) malloc(sizeof(char) * (strlen(optarg) + 1));
					strcpy(dev,optarg);
					printf(" i: %s\n", dev);
					break;
				case 'r':
					filename = (char *) malloc(sizeof(char)*(strlen(optarg) + 1));
					strcpy(filename,optarg);
					printf("r: %s\n", filename );
					break;
				case 's':
					string = (char *) malloc(sizeof(char)*(strlen(optarg) + 1));
					strcpy(string, optarg);
					printf("string :%s\n", string);
					break;
				default:
					printf("Error. Invalid usage\n");
					exit(1);
			}
		}

		for (int index = optind; index < argc; index++){
			filter_exp_len += strlen(argv[index]) + 1;	
		}

		filter_exp = (char *) malloc(sizeof(char)*(filter_exp_len + 1));
		filter_exp[0] = '\0';

		for (int index = optind; index < argc; index++)
		{
			strcat(filter_exp,argv[index]);
			strcat(filter_exp, " ");
		}
		
		printf("expression :%s\n", filter_exp);

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		/* Print its length */
		// printf("Jacked a packet with length of [%d]\t%li\n", header.len, header.ts.tv_sec);
		// printf("%s\n", packet);
		/* Loop over the packets*/
		pcap_loop(handle, -1,got_packet,NULL);

		/* And close the session */
		pcap_close(handle);
		return(0);
}


	void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
	{
		printf("Jacked a packet with length of [%d]\t%li\n", header->len, header->ts.tv_sec);
		printf("%s\n", packet);
	}
