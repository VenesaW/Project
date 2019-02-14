/*
    AFDX Switch using libpcap library
*/

//---------------------------------------------------------------------------------------
//                LIBRARIES
//---------------------------------------------------------------------------------------
#include<pcap.h>//For libpcap library
#include<stdio.h>//For input and output
#include<stdlib.h>//For exit()
#include<string.h>//For memset -> used to fill a block of memory with a particular value
#include<sys/socket.h>//For Socket programming
#include<sys/time.h>//For timestamp
#include"sha2.h"//For SHA256**

#include<errno.h>//Defines macros for reporting and retrieving error conditions
#include<libconfig.h>//Processes the XML configuration file for the Linux client and the Linux server

#include<arpa/inet.h>//For inet_ntoa() -> returns the address of a system
#include<net/ethernet.h>//For IEEE 802.3 Ethernet constants
#include<netinet/if_ether.h>//For global definitions for the Ethernet IEEE 802.3 interface
#include<netinet/ip_icmp.h>//For icmp header declarations
#include<netinet/udp.h>//For udp header declarations
#include<netinet/tcp.h>//For tcp header delcarations
#include<netinet/ip.h>//For ip header declarations
#include<netinet/in.h>//For constants and structures needed for internet domain addresses
//---------------------------------------------------------------------------------------
//                GLOBAL DECLARATIONS
//---------------------------------------------------------------------------------------
//For the channels
char errorBuffer[PCAP_ERRBUF_SIZE];//Error buffer for sniffing channel. Errors encountered during sniffing are stored here
//BPi interfaces
u_char *Interface201 = "eth0.201";//Pointer to port 4
u_char *Interface202 = "eth0.202";//Pointer to port 1
u_char *Interface203 = "eth0.203";//Pointer to port 0
u_char *Interface204 = "eth0.204";//Pointer to port 2
//Channels on each interface
pcap_t* Channel201;//Channel for packet capture on port 4
pcap_t* Channel202;//Channel for packet capture on port 1
pcap_t* Channel203;//Channel for packet capture on port 0
pcap_t* Channel204;//Channel for packet capture on port 2
//Channel properties
bpf_u_int32 netMask;//Subnet mask
bpf_u_int32 ipAddr;//IP address
struct bpf_program compiledCode;//Stores compiled program
//---------------------------------------------------------------------------------------
//                STATIC DECLARATIONS
//---------------------------------------------------------------------------------------
#define SIZE_ETHERNET 14 //Ethernet headers are always exactly 14 bytes
#define ETHER_ALEN 6 //Ethernet addresses are 6 bytes
#define SIZE_IP 20 //IP headers are always 20 bytes
#define IP_VER_HLEN 0x45 //IP version and header length
#define IP_DATA_LEN (MTU - SIZE_IP)//IP data length (Maximum Transmission Unit - IP header length)
#define SIZE_UDP 8 //UDP header length are 8 bytes

#define SNAP_LEN 1518 //Default maximum bytes per packet to capture
#define INTERFACE_MODE 1 //Put interface in promiscuous mode (1) or non-promiscuous mode (0)
#define READ_TIMEOUT 1000 //The packet buffer timeout in milliseconds ->0 means no timeout (slows down the code execution)
#define PACKET_COUNT 0 //How many packets to capture->0 means unlimited
#define PACKET_CREATE 10 //How many packets to send
#define PACKET_DATA 486 //Example AFDX message with 486 bytes of data
#define PACKET_PAYLOAD 444 //Example AFDX message with 486 bytes of data - 444 bytes form the payload
#define PACKET_SIZE 518 //Example AFDX message with 486 bytes of data and a 20 byte message digest

#define KEY_LEN 129 //Key length of secret key is 128
#define KEY_OWNER_LEN 10 //Name of End System that owns the key in the key file
#define HASH_LEN 32 //Size of hash is 32 bytes

#define OFFSET 0//Start of payload after header and of hash after payload
//---------------------------------------------------------------------------------------
//                STRUCTS
//---------------------------------------------------------------------------------------
//Ethernet header parameters
struct ethernetHeader {
        u_char  ether_dhost[ETHER_ALEN];//Destination host address
        u_char  ether_shost[ETHER_ALEN];//Source host address */
        u_short ether_type;//IP or ARP or ...etc...
};
//IP header parameters
struct ipHeader {
        unsigned char ip_version: 4;//Internet Protocol version (4-bits)
        unsigned char ip_header_length: 4;//Internet Protocol header length (4 bits)
        unsigned char ip_service_type;//Internet Protocol type of service
        unsigned short ip_total_length;//Internet Protocol total length of IP datagram
        unsigned short ip_id;//Internet Protocol unique packet indeitifcation
        unsigned short ip_frag_offset: 5;//Internet Protocol fragment offset field
        unsigned short ip_more_fragment: 1;//Internet Protocol flags - more fragments
        unsigned short ip_dont_fragment: 1;//Internet Protocol flags - dont fragment
        unsigned short ip_reserved_zero: 1;//Internet Protocol flags - reserved
        unsigned char ip_frag_offset1; //Internet Protocol fragment offset
        unsigned char ip_ttl;//Internet Protocl time to live
        unsigned char ip_protocol;//Internet Protocol upper level protocol - TCP/UDP
        unsigned short ip_checksum;//Internet Protocol header checksum
        unsigned int ip_srcaddr;//Internet Protocol source address
        unsigned int ip_dstaddr;//Internet Protocol source addres
};
//UDP header parameters
struct udpHeader {
        unsigned short source_port;//Source port number
        unsigned short dest_port;//Destination port number
        unsigned short udp_length;//UDP packet length
        unsigned short udp_checksum;//UDP checksum (optional)
        unsigned char digest;//Message digest
};
//---------------------------------------------------------------------------------------
//                FUNCTIONS
//---------------------------------------------------------------------------------------
//Receives incoming packets and prints the timestamp and length of the packet
void packetHandler(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethernetHeader *ethdr=NULL;//Initialize struct
    struct ipheader *v4hdr=NULL;//Initialize struct
    struct udpheader *uhdr=NULL;//Initialize struct

    //Print packet length and time...//need to fix, time and date formatting is incorrect
    printf("\n---------------------------------------------------------------------\n");
    printf("Grabbed packet of length %d\n",header->len);
    printf("Received at ............ %s\n",ctime((const time_t*)&header->ts.tv_sec));
//    printf("\n---------------------------------------------------------------------\n");

        //Open outgoing channels...//maybe only one for now
        Channel201 = pcap_open_live(Interface201, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 4
        //Channel202 = pcap_open_live(Interface202, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 0
        //Channel203 = pcap_open_live(Interface203, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 1
        //Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 2

        //Send packet to recipient...Eventually will use "Switch/Case" to send packet on specific outgoing port(s)/VLs
        //Packets generated are 518 bytes
        if((pcap_sendpacket(Channel201, packet, PACKET_SIZE)) != 0){
            exit(EXIT_FAILURE);//Exit program
        }//endIF
        printf("\n\n>>>>....packet forwarded\n\n");
    printf("\n---------------------------------------------------------------------\n");
}//endPACKET_HANDLER
//---------------------------------------------------------------------------------------
//                MAIN
//---------------------------------------------------------------------------------------
void main()
{
//Port 4 (Eth0.201)
    Channel201 = pcap_open_live(Interface201, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 4
    pcap_setdirection(Channel201,PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel201, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel201, &compiledCode);//Apply filter to incoming traffic
//Port 0 (Eth0.202)
    Channel202 = pcap_open_live(Interface202, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 0
    pcap_setdirection(Channel202,PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel202, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel202, &compiledCode);//Apply filter to incoming traffic
//Port 1 (Eth0.203)
    Channel203 = pcap_open_live(Interface203, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 1
    pcap_setdirection(Channel203,PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel203, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel203, &compiledCode);//Apply filter to incoming traffic
//Port 2 (Eth0.204)
    Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 2
    pcap_setdirection(Channel204,PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel204, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel204, &compiledCode);//Apply filter to incoming traffic

    //All channels opened or not
    if((Channel201 == NULL) || (Channel202 == NULL) ||(Channel203 == NULL) ||(Channel204 == NULL)){
        printf("pcap_open_live() failed due to [%s]\n", errorBuffer);//At least one channel could not be opened
        exit(EXIT_FAILURE);//Exit program
    }//endIF

//Start sniffing incoming packets on all ports...//maybe just 1 for now //need to thread/fork this sp the sniff simultaneosly
//    pcap_loop(Channel201, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 4
//    pcap_loop(Channel202, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 0
//    pcap_loop(Channel203, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 1
    pcap_loop(Channel204, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 2

//Close channels
    pcap_close(Channel201);//Close channel on port 4
    pcap_close(Channel202);//Close channel on port 0
    pcap_close(Channel203);//Close channel on port 1
    pcap_close(Channel204);//Close channel on port 2
}//endMAIN