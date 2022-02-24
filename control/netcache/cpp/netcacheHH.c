/*
	Packet sniffer using libpcap library

	$ gcc netcacheHH.c -lpcap -o netcacheHH

	$ sudo ./netcacheHH

	$ ipcs -q
*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> // for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	// Provides declarations for icmp header
#include<netinet/udp.h>	// Provides declarations for udp header
#include<netinet/tcp.h>	// Provides declarations for tcp header
#include<netinet/ip.h>	// Provides declarations for ip header

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <string.h>

struct message{
	long msg_type;
	uint32_t srcIP;
};

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int, const int*);
void print_tcp_packet(const u_char *  , int, const int*);

struct sockaddr_in source,dest;

void printMsgInfo(int msqid){
        struct msqid_ds m_stat;
        printf("========== messege queue info =============\n");
        if(msgctl(msqid,IPC_STAT,&m_stat)==-1){
                printf("msgctl failed");
                exit(0);
        }
        printf(" message queue info \n");
        printf(" msg_lspid : %d\n",m_stat.msg_lspid);
        printf(" msg_qnum : %ld\n",m_stat.msg_qnum);
        printf(" msg_stime : %ld\n",m_stat.msg_stime);

        printf("========== messege queue info end =============\n");
}

int main()
{
	/* get msgid */
	key_t key=12345;
	int msqid;
	if((msqid=msgget(key,IPC_CREAT|0666))==-1){
			printf("msgget failed\n");
			exit(0);
	}
    printMsgInfo(msqid);

	/* libpcap */
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100];
	// char *devname;
	char devs[100][100];
	int count = 1 , n;
	
	/* DPDK RX eth's iface */
	char* devname = "enp4s0f1";
	
	// Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	// Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , (u_char*)(&msqid));
	
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int* msqid = (int*)args;
	int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 6:  
		// TCP Protocol
			print_tcp_packet(buffer , size, msqid);
			break;
		
		default: //Some Other Protocol like ARP etc.
			break;
	}
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	// fprintf(logfile , "\n");
	// fprintf(logfile , "Ethernet Header\n");
	// fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	// fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	// fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size, const int* msqid)
{
	print_ethernet_header(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	// printf("SrcIP: %u\n", ntohl(iph->saddr));

	struct message msg;
	msg.msg_type = 1;
	msg.srcIP = ntohl(iph->saddr);
	if(msgsnd(*msqid,&msg,sizeof(uint32_t),0)==-1){
		printf("msgsnd failed\n");
		exit(0);
	}
}

void print_tcp_packet(const u_char * Buffer, int Size, const int * msqid)
{
	print_ip_header(Buffer,Size,msqid);
}