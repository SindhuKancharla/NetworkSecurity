#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include "commons.h"

// Pattern saves the expression filter
char *pattern;

// Timestamp from the packet header 
char *current_time;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

void ip_handler(const u_char *packet, int hlen);
void arp_handler(const u_char *packet,int hlen);

void icmp_handler(const u_char *packet, const struct sniff_ip *ip, int hlen);
void udp_handler(const u_char *packet,const struct sniff_ip *ip, int hlen);
void tcp_handler(const u_char *packet,const struct sniff_ip *ip, int hlen);
void unknown_handler(const u_char *packet,const struct sniff_ip *ip, int hlen);


/***************************************************************
*
*	arp_handler() : Handles the ARP Packets from Ethernet
*
*	Prints Timestamp, Checks whether ARP Request or ARP Reply
*	and prints the corresponding output.
*
***************************************************************/

void arp_handler(const u_char *packet,int hlen)
{
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

	u_short type;
	int i;
	struct sniff_arp *arpheader;


	ethernet = (struct sniff_ethernet*)(packet);
	
	printf("%s  ",current_time);

	// Printing the source MAC Address
	printf("%s > ", ether_ntoa((const struct ether_addr *)ethernet->ether_shost)); 

	// Printing the Destination MAC Address
	printf("%s ", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost)); 
	

	type = ntohs(ethernet->ether_type);	
	printf("  ethertype ARP (%#x), length %d: ",type, hlen);

	// Point to the ARP header 
	arpheader = (struct sniff_arp *)(packet+ SIZE_ETHERNET); 

	if(ntohs(arpheader->oper) == ARP_REPLY)
	{
		// Printing ARP REPLY
		printf("Reply ");
		for(i=0; i<4; i++)
	    {    
	    	printf("%d", arpheader->tpa[i]); 
	    	if(i<3)
	    		printf(".");
		}

	    printf(" is-at ");
		for(i=0; i<6;i++){
	     
	        printf("%02x", arpheader->tha[i]); 
	    	if(i<5)
	    		printf(":");
	    }
	}
	else
	{

		// Printing ARP REQUEST
		printf("Request who-has ");
		for(i=0; i<4; i++)
	    {    
	    	printf("%d", arpheader->tpa[i]); 
	    	if(i<3)
	    		printf(".");
		}

	    printf(" tell ");
	    for(i=0; i<4; i++)
	    {    
	    	printf("%d", arpheader->spa[i]); 
	    	if(i<3)
	    		printf(".");
		}
	}

	// Length of ARP packet after subtracting ethernet header size
	printf(", length %d\n", hlen - SIZE_ETHERNET);
}


/***********************************************************************
*
*	icmp_handler() : Handles the ICMP Packets
*
*	Prints Timestamp, Source and Destination MAC addresses, 
*	Source and Destination IP Addresses, Type, Length
* 	of the packet, Protocol and Payload only if the pattern matches.
*
***********************************************************************/

void icmp_handler(const u_char *packet, const struct sniff_ip *ip, int hlen){

	int size_icmp;
	int size_payload;

	const u_char *payload;
	const struct sniff_ethernet *ethernet;  
	struct sniff_icmp *icmp;

	char *sub;
	int header_size;

	int size_ip = IP_HL(ip)*4;


	icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
	size_icmp = sizeof(icmp);

	header_size = SIZE_ETHERNET + size_ip + size_icmp;

	payload = (u_char*)(packet + header_size);
	size_payload = ntohs(ip->ip_len) - (size_ip);

	// Check if an expression is given and payload exists
	if(pattern!=NULL && size_payload > 0)
	{
		sub = strstr((char*)payload,pattern);

		// If payload doesn't contain the expression, then return
		if(sub == NULL)
		{
			return;
		}
	}
	else if(pattern!=NULL && size_payload==0)
	{
		return;
	}


	ethernet = (struct sniff_ethernet*)(packet);
	
	printf("\n%s ",current_time);

	// Printing source and dest MAC addresses
	printf("%s -> ", ether_ntoa((const struct ether_addr *)ethernet->ether_shost));
	printf("%s", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost));

	printf(" type %#x ",ntohs(ethernet->ether_type));

	printf(" len %d\n", hlen);
		
	// Printing source and dest IP addresses
	printf("%s ", inet_ntoa(ip->ip_src));
	printf("%s ",inet_ntoa(ip->ip_dst));

	printf("%s " , "ICMP");

	printf(" payload-length = %d\n", size_payload);

	// Various ICMP messages - refer commons.h macros
	switch(icmp->type)
	{
		case ICMP_ECHOREPLY:
			printf("Echo Reply ");
			break;
		case ICMP_DEST_UNREACH:
			printf("Destination Unreachable - ");
			switch(icmp->code)
			{
				case ICMP_NET_UNREACH:
					printf("Network Unreachable	");
					break;
				case ICMP_HOST_UNREACH:
					printf("Host Unreachable ");
					break;
				case ICMP_PROT_UNREACH:
					printf("Protocol Unreachable ");
					break;
				case ICMP_PORT_UNREACH:
					printf("Port Unreachable ");
					break;
				case ICMP_FRAG_NEEDED:
					printf("Fragmentation Needed/DF set ");
					break;
				case ICMP_SR_FAILED:
					printf("Source Route failed	");
					break;
				case ICMP_NET_UNKNOWN:
					printf("Network Unknown ");
					break;
				case ICMP_HOST_UNKNOWN:
					printf("Host Unknown ");
					break;
				case ICMP_HOST_ISOLATED:
					printf("Host Isolated ");
					break;
				case ICMP_NET_ANO:
					printf("Network Prohibited ");
					break;
				case ICMP_HOST_ANO:
					printf("Host Prohibited ");
					break;
				case ICMP_PKT_FILTERED:
					printf("Packet Filtered ");
					break;
				case ICMP_PREC_VIOLATION:
					printf("Precedence Violation ");
					break;
				case ICMP_PREC_CUTOFF:
					printf("Precedence cut off ");
					break;
				default:
					printf("Others ");
			}
			break;
		case ICMP_SOURCE_QUENCH:
			printf("Source Quench ");
			break;
		case ICMP_ECHO:
			printf("Echo Request ");
			break;
		case ICMP_TIME_EXCEEDED:
			printf("Time Exceeded ");
			break;
		case ICMP_REDIRECT:
			printf("Redirect - ");
			switch (icmp->code)
			{
				case ICMP_REDIR_NET:
					printf("Network ");
					break;
				case ICMP_REDIR_HOST:
					printf("Host ");
					break;
				case ICMP_REDIR_NETTOS:
					printf("Network for TOS ");
					break;
				case ICMP_REDIR_HOSTTOS:
					printf("Host for TOS ");
					break;
				default:
					printf("Others ");
					break;
			}
			break;
		default:
			printf("Others ");
	}

	printf("\n");

	// Print payload from ICMP packets
	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}
}


/*************************************************************************
*
*	udp_handler() : Handles the UDP Packets
*
*	Prints Timestamp, Source and Destination MAC addresses, 
*	Source and Destination IP Addresses and Ports, Type, Length
* 	of the packet, Protocol and Payload only if the pattern matches.
*
*************************************************************************/

void udp_handler(const u_char *packet,const struct sniff_ip *ip, int hlen){

	struct sniff_udp *udp ;

	int size_udp;
	int size_payload;

	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const u_char *payload;                    /* Packet payload */
	
	int header_size;
	char *sub;

	int size_ip = IP_HL(ip)*4;

	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = sizeof(udp);

	header_size = SIZE_ETHERNET + size_ip + size_udp;
	payload = (u_char*)(packet + header_size);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

	if(pattern!=NULL && size_payload > 0)
	{
		sub = strstr((char*)payload,pattern);

		if(sub == NULL)
		{
			return;
		}
	}
	else if(pattern!=NULL && size_payload==0)
	{
		return;
	}


	ethernet = (struct sniff_ethernet*)(packet);
	
	printf("\n%s ",current_time);

	printf("%s -> ", ether_ntoa((const struct ether_addr *)ethernet->ether_shost));
	printf("%s", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost));

	printf(" type %#x ",ntohs(ethernet->ether_type));

	printf(" len %d\n", hlen);
		

	printf("%s:%d -> ", inet_ntoa(ip->ip_src),ntohs(udp->uh_sport));
	printf("%s:%d ",inet_ntoa(ip->ip_dst),ntohs(udp->uh_dport));

	printf("%s " , "UDP");

	printf(" payload-length = %d\n", size_payload);

	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}
}


/***************************************************************
*
*	tcp_handler() : Handles the TCP Packets
*
*	Prints Timestamp, Source and Destination MAC addresses, 
*	Source and Destination IP Addresses and Ports, Type, Length
* 	of the packet, Protocol and Payload only if the pattern matches.
*
***************************************************************/

void tcp_handler(const u_char *packet,const struct sniff_ip *ip, int hlen)
{

	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

	int size_tcp;
	int size_payload;
	int header_size;
	char *sub;
	int size_ip = IP_HL(ip)*4;

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	header_size = SIZE_ETHERNET + size_ip + size_tcp;
	payload = (u_char *)(packet + header_size);
	
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if(pattern!=NULL && size_payload > 0)
	{
		sub = strstr((char*)payload,pattern);

		if(sub == NULL)
		{
			return;
		}
	}
	else if(pattern!=NULL && size_payload==0)
	{
		return;
	}

	if (size_tcp < 20) {
		printf(" Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	ethernet = (struct sniff_ethernet*)(packet);
	
	printf("\n%s ",current_time);

	printf("%s -> ", ether_ntoa((const struct ether_addr *)ethernet->ether_shost));
	printf("%s", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost));

	printf(" type %#x ",ntohs(ethernet->ether_type));

	printf(" len %d\n", hlen);
		
	printf("%s:%d -> ", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
	printf("%s:%d ",inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));


	printf("%s " , "TCP");
	printf(" payload-length = %d\n", size_payload);

	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}
}


/***************************************************************
*
*	unknown_handler() : Handles all other Packets
*
*	Prints Timestamp, Source and Destination MAC addresses, 
*	Source and Destination IP Addresses, Type, Length
* 	of the packet and Protocol as "OTHER".
*
***************************************************************/

void unknown_handler(const u_char *packet,const struct sniff_ip *ip, int hlen)
{

	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

	printf("\n%s ",current_time);
	ethernet = (struct sniff_ethernet*)(packet);
	
	printf("%s -> ", ether_ntoa((const struct ether_addr *)ethernet->ether_shost));
	printf("%s", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost));
	
	printf(" type %#x ",ntohs(ethernet->ether_type));

	printf(" len %d\n", hlen);
		
	printf("%s -> ", inet_ntoa(ip->ip_src));
	printf("%s ",inet_ntoa(ip->ip_dst));

	printf("%s\n" , "OTHER");
}


/***************************************************************
*
*	ip_handler() : Handles the IP Packets
*
*	Calls the different handlers using a switch based on the 
*	protocol. 
*
***************************************************************/

void ip_handler(const u_char *packet, int hlen){

	const struct sniff_ip *ip;              /* The IP header */

	int size_ip;
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	// Calling respective handlers for different protocols
	switch(ip->ip_p) {

		case IPPROTO_TCP:
			tcp_handler(packet,ip,hlen);
			break;
		case IPPROTO_UDP:
			udp_handler(packet,ip,hlen);
			break;
		case IPPROTO_ICMP:
			icmp_handler(packet,ip,hlen);
			break;
		default:
			unknown_handler(packet,ip,hlen);
	}
	
}

/***************************************************************
*
*	print_hex_ascii_line() : Prints the payload in a proper 
*							 format.
*
***************************************************************/

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/***************************************************************
*
*	print_payload() : reads characters from the payload and
*					  prints them in ascii format.
*
***************************************************************/

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/***************************************************************
*
*	got_packet() : This is the callback function which is called
* 				   when a new packet is captured.
*
***************************************************************/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{	
	const struct sniff_ethernet *ethernet; 
	time_t timestamp;

	char buf[20];
	char time_buf[255];
	struct tm tm;
	int hlen = 0;
	u_short type;

	hlen = header->len;
	timestamp = header->ts.tv_sec;

	snprintf(buf,20,"%lu",timestamp);
	strptime(buf, "%s", &tm);
	strftime(time_buf,sizeof(time_buf),"%Y-%m-%d %H:%M:%S", &tm);

	current_time = (char*)malloc(sizeof(time_buf)+sizeof(buf)+1);
	
	strcat(current_time,time_buf);
	strcat(current_time,".");
	

	snprintf(buf,20,"%d",header->ts.tv_usec);
	strcat(current_time,buf);

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	type = ntohs(ethernet->ether_type);
	
	// Calling respective handlers for IP/ ARP.
	if(type== ETHERTYPE_IP)
	{
		ip_handler(packet,hlen);
	}
	else if(type == ETHERTYPE_ARP)
	{
		arp_handler(packet,hlen);
	}

	return;
}

int main(int argc, char *argv[])
{

	// stores the interface
	char *dev;

	// writes errors to this buffer
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	// stores the device handler
	pcap_t *handle;

	// To loop infinitely.. Change this to see required number of packets.
	int num_packets = -1;
	
	int opt;
	int filter_exp_len = 0;

	char *interface;
	char *filename;
	char *bpf_filter_exp = "";
	int pattern_size;

	while((opt = getopt(argc,argv,"i:r:s:h")) != -1)
	{
		switch(opt)
		{
			case 'i':
				interface = optarg;
				break;
			case 'r':
				filename = optarg;
				break;
			case 's':
				pattern_size = strlen(optarg);
				pattern = (char*)malloc(sizeof(pattern_size));
				memset(pattern,0,pattern_size);
				strcat(pattern,optarg);
				break;
			case 'h':
				printf("Use the following command line inputs:\n");	
				printf("-i  Listen on network device <interface> (e.g., en0).\n");
				printf("-r  Read packets from <file>.\n");
				printf("-s  Keep only packets that contain <string> in their payload.\n");
				exit(0);
			default:
				printf("Use -h option to see which arguments are allowed\n");
				exit(0);
		}

	}

	for (int index = optind; index < argc; index++){
		filter_exp_len += strlen(argv[index]) + 1;	
	}

	bpf_filter_exp = (char *) malloc(sizeof(char)*(filter_exp_len + 1));
	bpf_filter_exp[0] = '\0';

	for (int index = optind; index < argc; index++)
	{
		strcat(bpf_filter_exp,argv[index]);
		strcat(bpf_filter_exp, " ");
	}

	// if no interface is given, use the default device
	if(interface == NULL)
	{
		dev = pcap_lookupdev(errbuf);
	}
	else{
		dev = interface;
	}

	if(dev==NULL)
	{
		fprintf(stderr," Couldn't find default device: %s\n",errbuf);
		return(2);
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// if no file is given, capture live packets in promiscous mode
	if(filename == NULL)
	{
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	}
	else{
		handle = pcap_open_offline(filename, errbuf);
	}

	if(handle == NULL)
	{
		fprintf(stderr,"Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// Exit if device doesn't provide Ethernet headers.
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr,"Device %s doesn't provide Ethernet headers - not supported \n",dev);
		return(2);
	}

	if(pcap_compile(handle, &fp, bpf_filter_exp, 0, net) == -1)
	{
		fprintf(stderr,"Couldn't parse filter %s: %s\n", bpf_filter_exp, pcap_geterr(handle));
		return(2);		
	}
		
	if(pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", bpf_filter_exp, pcap_geterr(handle));
		return(2);
	}

	// Loop num_packets times until EOF is reached or User Interrupt is given.
	pcap_loop(handle, num_packets, got_packet, NULL);
	
	// Freeing the resources at the end.
	pcap_freecode(&fp);
	pcap_close(handle);

	if(pattern!= NULL)
		free(pattern);

	if(current_time !=NULL)
		free(current_time);

	if(bpf_filter_exp!= NULL )
		free(bpf_filter_exp);

	return(0);

}
