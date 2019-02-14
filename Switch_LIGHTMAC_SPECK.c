/*
    AFDX Switch using libpcap library
*/
//---------------------------------------------------------------------------------------
//                LIBRARIES
//---------------------------------------------------------------------------------------
#include<pcap.h>//For libpcap library
#include<stdint.h>//Allow programmers to write more portable code by providing a set of typedefs that specify exact-width integer types, together with the defined minimum and maximum allowable values for each type
#include<stdio.h>//Defines three variable types, several macros, and various functions for performing input and output
#include<stdlib.h>//Defines four variable types, several macros, and various functions for performing general functions
#include<string.h>//Defines one variable type, one macro, and various functions for manipulating arrays of characters
#include<sys/socket.h>//For Socket programming
#include<sys/time.h>//For timestamp

#include"speck.h"//For speck defnitions
#include"lightmac.h"//For lightmac definitions

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
#define PACKET_SIZE 494 //Example AFDX message with 486 bytes of data and a 20 byte message digest

#define LIGHTMAC 32 //Key retrieved from file (128-bit, 32 characters)
#define KEY_OWNER_LEN 10 //Name of End System that owns the key in the key file
#define HASH_LEN 8 //Size of hash is 32 bytes, 16 characters

#define OFFSET 0//Start of payload after header and of hash after payload
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
//LightMAC hashes
unsigned char lightMAChash[HASH_LEN];
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
    unsigned char ip_version : 4;//Internet Protocol version (4-bits)
    unsigned char ip_header_length : 4;//Internet Protocol header length (4 bits)
    unsigned char ip_service_type;//Internet Protocol type of service
    unsigned short ip_total_length;//Internet Protocol total length of IP datagram
    unsigned short ip_id;//Internet Protocol unique packet indeitifcation
    unsigned short ip_frag_offset : 5;//Internet Protocol fragment offset field
    unsigned short ip_more_fragment : 1;//Internet Protocol flags - more fragments
    unsigned short ip_dont_fragment : 1;//Internet Protocol flags - dont fragment
    unsigned short ip_reserved_zero : 1;//Internet Protocol flags - reserved
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
//                LIGHTMAC FUNCTIONS
//Author: Odzhan
//Name:   lightmac.c
//Source: https://github.com/odzhan/tinycrypt/tree/master/mac/lightmac
//---------------------------------------------------------------------------------------
typedef union _bc_blk_t {
    unsigned int ctr;
    unsigned int w[BLOCK_LENGTH / sizeof(unsigned int)];
    unsigned char  b[BLOCK_LENGTH];
} bc_blk;

#ifdef USE_ASM
#define LMX_TAG(w,x,y,z) lightmac_tagx(w,x,y,z)
#else
#define LMX_TAG(w,x,y,z) lightmac_tag(w,x,y,z)
#endif

//SPECK block cipher
void speck64_encryptx(const void *key, void *in)
{
    unsigned int i;
    unsigned int t;
    unsigned int k0;
    unsigned int k1;
    unsigned int k2;
    unsigned int k3;
    unsigned int x0;
    unsigned int x1;

    bc_blk   *x = (bc_blk*)in;
    bc_blk   *k = (bc_blk*)key;

    //copy 128-bit key to local registers
    k0 = k->w[0]; k1 = k->w[1];
    k2 = k->w[2]; k3 = k->w[3];

    x0 = x->w[0]; x1 = x->w[1];//copy M to local space

    for (i = 0; i < 27; i++)
    {
        //encrypt block
        x0 = (ROTR32(x0, 8) + x1) ^ k0;
        x1 = ROTL32(x1, 3) ^ x0;

        //create next subkey
        k1 = (ROTR32(k1, 8) + k0) ^ i;
        k0 = ROTL32(k0, 3) ^ k1;

        XCHG(k3, k2)(t);
        XCHG(k3, k1)(t);
    }//endFOR

    x->w[0] = x0; x->w[1] = x1;//save result
}//end SPECK_64_ENCRYPTX

#define ENCRYPT(x, y) speck64_encryptx(x, y)

void lightmac_tag(const void *msg, unsigned int msglen, void *tag, void* mkey)
{
    unsigned char  *data = (unsigned char*)msg;
    unsigned char  *key = (unsigned char*)mkey;
    unsigned int idx;
    unsigned int ctr;
    unsigned int i;
    bc_blk   m;
    bc_blk   *t = (bc_blk*)tag;

    t->w[0] = 0; t->w[1] = 0;//zero initialize T
    ctr = 0; idx = 0;//set counter + index to zero

    //while we have msg data
    while (msglen) {
        m.b[COUNTER_LENGTH + idx++] = *data++;//add byte to M

        // M filled?
        if (idx == (BLOCK_LENGTH - COUNTER_LENGTH))
        {
            // add S counter in big endian format
            ctr++;
            m.ctr = SWAP32(ctr);

            ENCRYPT(key, &m);// encrypt M with E using K1

            // update T
            t->w[0] ^= m.w[0];
            t->w[1] ^= m.w[1];

            idx = 0;// reset index
        }//endIF

        msglen--;// decrease length
    }//endWHILE

    m.b[COUNTER_LENGTH + idx++] = 0x80;//add the end bit

    //update T with anything remaining
    for (i = 0; i < idx; i++)
    {
        t->b[i] ^= m.b[COUNTER_LENGTH + i];
    }//endFOR

    key += BC_KEY_LENGTH;//advance key to K2

    ENCRYPT(key, t);//encrypt T with E using K2

    memcpy(lightMAChash, tag, 8);
    /*printf("\nHASH:\n");
    for (int p = 0; p < 8; p++)
    {
        printf("%02x", lightMAChash[i]);//Print in hexadecimal format
    }//endFOR*/

}//endLIGHT_MAC_TAG

int lightmac_verify(const void *msg, unsigned int msglen, void* tag, void* key)
{
    unsigned char tempTag[TAG_LENGTH];

    LMX_TAG(msg, msglen, tempTag, key);

    return memcmp(tag, tempTag, TAG_LENGTH) == 0;
}//endLIGHT_MAC_VERIFY
//---------------------------------------------------------------------------------------
//                FUNCTIONS
//---------------------------------------------------------------------------------------
//Receives incoming packets and prints the timestamp and length of the packet
void packetHandler(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethernetHeader *ethdr = NULL;//Initialize struct
    struct ipheader *v4hdr = NULL;//Initialize struct
    struct udpheader *uhdr = NULL;//Initialize struct

    FILE *keys;//Pointer to file with hashing keys
    char ownerES1[10] = "ES1";//Key owner name
    char ownerES2[10] = "ES2";//Key owner name
    char ownerES3[10] = "ES3";//Key owner name
    char ownerES4[10] = "ES4";//Key owner name

    unsigned char *payload;//Pointer to packet payload
    unsigned char *oldDigest;//Pointer to packet message digest
    unsigned char *newDigest;//Pointer to recalculated message digest
    unsigned char hash[HASH_LEN];//memory area for chaskey output hash; should be at most 128-bits (32 characters; 16 bytes)
    unsigned char key_owner[KEY_OWNER_LEN];//Holds key owner name retrieved from file with hashing keys
    unsigned char secret_Key[LIGHTMAC];//128-bit secret-key (key); 32 characters (16 bytes)

    unsigned char plaintext[PACKET_PAYLOAD];//Packet payload
    unsigned char hashValue[HASH_LEN];//Packet hash value
    unsigned char hashCalculated[HASH_LEN];//Hash calculated by the switch

    int getPayload;//Used in FOR loop to retrieve packet payload
    int getDigest;//Used in FOR loop to retrieve packet digest
    int getKey;//Used in FOR loop to retrieve secret key
    int verification;

    ethdr = (struct ethernetHeader*)(packet);//Ethernet header offset
    v4hdr = (struct ipheader*)(packet + SIZE_ETHERNET);//IP header offset
    uhdr = (struct udpheader*)(packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
    payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset
    oldDigest = (u_char *)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP + PACKET_PAYLOAD);//Hash offset

    //Print packet length and time...//need to fix, time and date formatting is incorrect
    printf("\n---------------------------------------------------------------------\n");
    printf("Grabbed packet of length %d\n", header->len);
    printf("Received at ............ %s\n", ctime((const time_t*)&header->ts.tv_sec));
    //    printf("\n---------------------------------------------------------------------\n");


        //Get hashing key
    keys = fopen("LIGHTMAC_keys.txt", "r");//Open file with keys
    if (keys == NULL) {
        printf("Unable to open file\n");//Could not read file with keys
        exit(EXIT_FAILURE);//exit program
    }//endIF
    while (fgets(key_owner, KEY_OWNER_LEN, keys) != NULL) {
        if (strstr(key_owner, ownerES1)) {
            fgets(secret_Key, LIGHTMAC, keys);//Get secret key for this ES
            fclose(keys);//Close file - key has been retrieved
            break;
        }//endIF
        printf("\nNo key found\n");//No key found for ES
        exit(EXIT_FAILURE);//exit program
    }//endWHILE

    //printf("\nPAYLOAD: \n");
    for (getPayload = OFFSET; getPayload < PACKET_PAYLOAD; getPayload++) {
        // Start printing on the next after every 16 octets
        /*if ((getPayload % 16) == 0){
            printf("\n");//print on next line
        }//endIF*/
        //printf("%02x ", payload[getPayload]);//Print in hexadecimal format
        plaintext[getPayload] = payload[getPayload];//Fill payload array for hash calculation
        //printf("%c", plaintext[getPayload]);
    }//endFOR

    /*printf("\n\nKEY: \n");
    for(getKey = OFFSET; getKey < 128; getKey++){
        // Start printing on the next after every 16 octets
        if ((getKey % 16) == 0){
            printf("\n");//Print on next line
        }//endIF
        printf("%c", secret_Key[getKey]);//Print in hexadecimal format
    }//endFOR*/

    printf("\n\nold DIGEST: \n");
    for (getDigest = OFFSET; getDigest < HASH_LEN; getDigest++) {
        // Start printing on the next after every 16 octets
        if ((getDigest % 16) == 0) {
            printf("\n");//Print on next line
        }//endIF
        //printf("%02x", oldDigest[getDigest]);//Print in hexadecimal format
        hashValue[getDigest] = oldDigest[getDigest];//Fill hash from incoming message
        printf("%02x", hashValue[getDigest]);
    }//endFOR

    //MAC generation
    //Calculate hash and compare to appended hash
    verification = lightmac_verify(plaintext, PACKET_PAYLOAD, hash, secret_Key);
    memcpy(hashCalculated, lightMAChash, HASH_LEN);//Copy hash to message digest array

    printf("\n\nnew DIGEST: \n");
    for (getDigest = OFFSET; getDigest < HASH_LEN; getDigest++) {
        //Start printing on the next after every 16 octets
        if ((getDigest % 16) == 0) {
            printf("\n");//Print on next line
        }//endIF
        printf("%02x", hashCalculated[getDigest]);//Print in hexadecimal format
    }//endFOR

    //Compare hashes
    if (memcmp(hashValue, hashCalculated, sizeof(hashValue)) == 0)
    {
        //Open outgoing channels...//maybe only one for now
        Channel201 = pcap_open_live(Interface201, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 4
        //Channel202 = pcap_open_live(Interface202, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 0
        //Channel203 = pcap_open_live(Interface203, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 1
        //Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open outgoing channel on port 2

        //Send packet to recipient...Eventually will use "Switch/Case" to send packet on specific outgoing port(s)/VLs
        //Packets generated are 518 bytes
        if ((pcap_sendpacket(Channel201, packet, PACKET_SIZE)) != 0) {
            exit(EXIT_FAILURE);//Exit program
        }//endIF
        printf("\n\n>>>>hashes matched....packet forwarded\n\n");
        printf("\n---------------------------------------------------------------------\n");
    }//endIF
}//endPACKET_HANDLER
//---------------------------------------------------------------------------------------
//                MAIN
//---------------------------------------------------------------------------------------
void main()
{
    //Port 4 (Eth0.201)
    Channel201 = pcap_open_live(Interface201, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 4
    pcap_setdirection(Channel201, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel201, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel201, &compiledCode);//Apply filter to incoming traffic
//Port 0 (Eth0.202)
    Channel202 = pcap_open_live(Interface202, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 0
    pcap_setdirection(Channel202, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel202, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel202, &compiledCode);//Apply filter to incoming traffic
//Port 1 (Eth0.203)
    Channel203 = pcap_open_live(Interface203, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 1
    pcap_setdirection(Channel203, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel203, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel203, &compiledCode);//Apply filter to incoming traffic
//Port 2 (Eth0.204)
    Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 2
    pcap_setdirection(Channel204, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel204, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel204, &compiledCode);//Apply filter to incoming traffic

    //All channels opened or not
    if ((Channel201 == NULL) || (Channel202 == NULL) || (Channel203 == NULL) || (Channel204 == NULL)) {
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