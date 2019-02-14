/*
    AFDX sending ES using libpcap library
*/

//---------------------------------------------------------------------------------------
//                WARNINGS
//---------------------------------------------------------------------------------------
#define _WINSOCK_DEPRECATED_NO_WARNINGS //Ignore Winsock deprecated warnings
#define _CRT_SECURE_NO_WARNINGS //Ignore some compiler warnings
//---------------------------------------------------------------------------------------
//                LIBRARIES 
//---------------------------------------------------------------------------------------
#include<pcap.h>//For libpcap library
#include<stdint.h>//Allow programmers to write more portable code by providing a set of typedefs that specify exact-width integer types, together with the defined minimum and maximum allowable values for each type
#include<stdio.h>//Defines three variable types, several macros, and various functions for performing input and output
#include<stdlib.h>//Defines four variable types, several macros, and various functions for performing general functions
#include<string.h>//Defines one variable type, one macro, and various functions for manipulating arrays of characters
#include<sys/socket.h>//For Socket programming
#include<sys/time.h>//For various time-based functions

#include "speck.h"//For speck defnitions
#include "lightmac.h"//For lightmac definitions

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
#define SIZE_UDP 8 //UDP header length are 8 bytes
#define IP_VER_HLEN 0x45 //IP version and header length
#define IP_DATA_LEN (MTU - SIZE_IP)//IP data length (Maximum Transmission Unit - IP header length)

#define SNAP_LEN 1518 //default maximum bytes per packet to capture
#define INTERFACE_MODE 1 //Put interface in promiscuous mode (1) or non-promiscuous mode (0)
#define READ_TIMEOUT 1000 //The packet buffer timeout in milliseconds ->0 means no timeout (slows down the code execution)
#define PACKET_COUNT 0 //How many packets to capture->0 means unlimited
#define PACKET_CREATE 1 //How many packets to send
#define PACKET_DATA 486 //Example AFDX message with 486 bytes of data
#define PACKET_PAYLOAD 444 //Example AFDX message with 486 bytes of data - 444 bytes form the payload
#define PACKET_SIZE 494 //Example AFDX message with 486 bytes of data and a 32 byte message digest

#define LIGHTMAC 32 //Key retrieved from file (128-bit, 32 characters)
#define KEY_OWNER_LEN 10 //Name of End System that owns the key in the key file
#define HASH_LEN 8 //Size of hash is 32 bytes, 16 characters

#define OFFSET 0//Start of payload after header and of hash after payload
//---------------------------------------------------------------------------------------
//                GLOBAL DECLARATIONS
//---------------------------------------------------------------------------------------
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
    unsigned char message_digest;//Hash value of AFDX payload
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
//                MAIN
//***For now, the end system only sends packets
//***Packet handler may or may not be defined later on
//---------------------------------------------------------------------------------------
void main()
{
    bpf_u_int32 netMask;//Subnet mask
    bpf_u_int32 ipAddr;//IP address
    pcap_if_t *all_Interfaces;//All available interfaces
    pcap_t* Channel204;//Channel for packet capture on port 0
    u_char *Interface204 = "eth0.204";//Pointer to port 0

    struct bpf_program compiledCode;//Stores compiled program

    char errorBuffer[PCAP_ERRBUF_SIZE];//Error buffer for sniffing channel. Errors encountered during sniffing are stored here
    const char *hex_digits = "0123456789ABCDEF";//Used to generate payload

    int afdx_payload = 0;//Used in FOR loop where the afdx payload is built
    int BAG = 4;//Minimum time gap between successive messages
    int getHash = 0;//Used in for loop to append hash to afdx packet
    int getPlaintext = 0;//Used in for loop to retrieve payload for hash calculation
    int transmit = 0;//Used in FOR loop where the packet is being sent

    int verification;

    FILE *keys;//Pointer to file with hashing keys
    char ownerES1[10] = "ES1";//Key owner name
    char ownerES2[10] = "ES2";//Key owner name
    char ownerES3[10] = "ES3";//Key owner name
    char ownerES4[10] = "ES4";//Key owner name

    unsigned char *digest;//Hash output
    unsigned char hash[HASH_LEN];//memory area for chaskey output hash; should be at most 128-bits (32 characters; 16 bytes)
    unsigned char key_owner[KEY_OWNER_LEN];//Holds key owner name retrieved from file with hashing keys
    unsigned char messageDigest[HASH_LEN] = { 0 };
    unsigned char packet[PACKET_SIZE];//AFDX packet
    unsigned char plaintext[PACKET_PAYLOAD];//Plaintext message for hashing
    unsigned char secret_Key[LIGHTMAC];//Holds hashing key retrieved from file with hashing keys

    // Prepare a list of all the devices
    if (pcap_findalldevs(&all_Interfaces, errorBuffer) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errorBuffer);
        exit(EXIT_FAILURE);
    }//endIF

//Port 2 (Eth0.204)
    Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 0
    pcap_setdirection(Channel204, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel204, &compiledCode, "len >= 486", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel204, &compiledCode);//Apply filter to incoming traffic

    //All channels opened or not
    if (Channel204 == NULL) {
        printf("pcap_open_live() failed due to [%s]\n", errorBuffer);//Channel could not be opened
        exit(EXIT_FAILURE);//Exit program
    }//endIF

    //Build AFDX packet
        //dst_MAC
    packet[0] = (0xaa);
    packet[1] = (0x01);
    packet[2] = (0x02);
    packet[3] = (0x03);
    packet[4] = (0x04);
    packet[5] = (0x05);//PC
    //src_MAC
    packet[6] = (0xbb);
    packet[7] = (0x01);
    packet[8] = (0x02);
    packet[9] = (0x03);
    packet[10] = (0x04);
    packet[11] = (0x05);//ES BPi
    //ether_type
    packet[12] = (0x08);
    packet[13] = (0x00);
    //IPv4
    packet[14] = (0x45);
    packet[15] = (0x00);
    //total_length
    packet[16] = (0x01);
    packet[17] = (0xd8);
    //identification
    packet[18] = (0x1d);
    packet[19] = (0x94);
    //flags
    packet[20] = (0x00);
    //fragment
    packet[21] = (0x00);
    //ttl
    packet[22] = (0x01);
    //protocol
    packet[23] = (0x11);
    //ip_checksum
    packet[24] = (0x91);
    packet[25] = (0x6e);
    //src_ip
    packet[26] = (0xc0);
    packet[27] = (0xa8);
    packet[28] = (0xb2);
    packet[29] = (0x40);//ES Bpi port 3
    //dst_ip
    packet[30] = (0xc0);
    packet[31] = (0xa8);
    packet[32] = (0xb2);
    packet[33] = (0x5c);//PC (.92)
    //src_port
    packet[34] = (0x07);
    packet[35] = (0xd0);
    //dst_port
    packet[36] = (0x04);
    packet[37] = (0x15);
    //udp_length
    packet[38] = (0x01);
    packet[39] = (0xc4);
    //udp_checksum
    packet[40] = (0x00);
    packet[41] = (0x00);

    do {
        //for (transmit = 0; transmit < 1; transmit++) {
            //Payload maximum 1417 bytes(offset 0x42)
        getPlaintext = 0;
        for (afdx_payload = 42; afdx_payload < PACKET_DATA; afdx_payload++) {
            packet[afdx_payload] = hex_digits[(rand() % 256)];//Generate new payload for each packet
            plaintext[getPlaintext] = packet[afdx_payload];
            getPlaintext++;
        }//endFOR
        //printf("\nPacket built\n");

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

        //MAC generation
        verification = lightmac_verify(plaintext, PACKET_PAYLOAD, hash, secret_Key);
        memcpy(messageDigest, lightMAChash, HASH_LEN);//Copy hash to message digest array

        //Append MAC to end of packet
        for (getHash = 0; getHash < HASH_LEN; getHash++) {
            packet[afdx_payload] = messageDigest[getHash];//Append digest
            afdx_payload++;
        }//endFOR

        //Send Packet
        pcap_sendpacket(Channel204, packet, PACKET_SIZE);//Packet is 486 bytes (based on example AFDX pcap) + 32 bytes of hash
        printf("\n\npacket sent\n");

        sleep(BAG);
        //}//endFOR
    } while (1);//endWHILE

    pcap_close(Channel204);//close channel on which packets are sent
}//endMAIN