/*
    AFDX sending ES using libpcap library
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
#include<sys/time.h>//For various time-based functions

#include<assert.h>//Provides a macro called assert which can be used to verify assumptions made by the program and print a diagnostic message if this assumption is false
#include<errno.h>//Defines macros for reporting and retrieving error conditions
#include<libconfig.h>//Processes the XML configuration file for the Linux client and the Linux server

#include "speck.h"//For speck defnitions
#include "lightmac.h"//For lightmac definitions

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
#define PACKET_SIZE 502 //Example AFDX message with 486 bytes of data and a 32 byte message digest

#define CHASKEY 32 //Secret key retrieved from key database (128-bit, 32 characters)
#define KEY_LEN 4 //Key length of secret key is 128-bits (32 characters grouped into "4" groups of 8 characters)
#define KEY_OWNER_LEN 10 //Name of End System that owns the key in the key database
#define HASH_LEN 16 //Size of hash is 16 bytes (32 characters)e

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
//                CHASKEY FUNCTIONS
//Author: Nicky Mouha
//Name:   Chaskey-12 reference C implementation
//Source: https://mouha.be/wp-content/uploads/chaskey12.c
//---------------------------------------------------------------------------------------
//Round function
#define ROTL(x,b) (unsigned int)( ((x) >> (32 - (b))) | ( (x) << (b)) )

//For the rounds of the permutation
#define ROUND \
  do { \
        v[0] += v[1]; v[1]=ROTL(v[1], 5); v[1] ^= v[0]; v[0]=ROTL(v[0],16); \
        v[2] += v[3]; v[3]=ROTL(v[3], 8); v[3] ^= v[2]; \
        v[0] += v[3]; v[3]=ROTL(v[3],13); v[3] ^= v[0]; \
        v[2] += v[1]; v[1]=ROTL(v[1], 7); v[1] ^= v[2]; v[2]=ROTL(v[2],16); \
  } while(0)

//128-bit permutation that iterates over the message
    //Built using 3 operations (ARX): (1)addition modulo 232; (2) bit rotations and (3)XOR
    //Consists of eith (8) applications of a round function
        //Recommendation: use the 16-round variant Chaskey-LTS (long term security) as a fallback in case of cryptanalytical breakthroughs
#define PERMUTE \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND;

//Used in generation of subkey2
const volatile unsigned int bitString[2] = { 0x00, 0x87 };//bit string (0^126)(10), which is 2 in decimal notation

//Chaskey ALGORITHM 1: TIMESTWO
//The subkey1 and subkey2 are generated from the the scret-key (key)
    //subkey1 = xK
    //subkey2 = (x^2)(subkey1); x corresponds to bit string (0^126)(10), which is 2 in decimal notation
//Subkeys are returned as "out"
#define TIMESTWO(out,in) \
  do { \
        out[0] = (in[0] << 1) ^ bitString[in[3] >> 31]; \
        out[1] = (in[1] << 1) | (in[0] >> 31); \
        out[2] = (in[2] << 1) | (in[1] >> 31); \
        out[3] = (in[3] << 1) | (in[2] >> 31); \
  } while(0)

//For every secret-key (key), two subkeys (subkey1 and subkey2) are generated
void subkeys(unsigned int subkey1[4], unsigned int subkey2[4], const unsigned int key[4])
{
    /*printf("\n\nKey: \n");
    for (int i = 0; i < 4; i++) {
        //Start printing on the next after every 16 octets
        if ((i % 16) == 0) {
            printf("\n");//Print on next line
        }//endIF
        printf("%08X", key[i]);//Print in hexadecimal format
    }//endFOR*/

    TIMESTWO(subkey1, key);//call ALGORITHM 1 to generate subkey1
    TIMESTWO(subkey2, subkey1);//call ALGORITHM 1 to generate subkey2
}//endSUBKEYS

//Calculation of MAC
//Parameters: pointer to hash, hash length,  message, message length, key, subkey 1, subkey 2
unsigned char* chaskey(unsigned char *hash, const unsigned char *message, const unsigned int key[4], const unsigned int subkey1[4], const unsigned int subkey2[4])
{
    const unsigned int msgLen = PACKET_PAYLOAD;

    const unsigned int *M = (unsigned int*)message;//
    const unsigned int *end = M + (((msgLen - 1) >> 4) << 2);//pointer to last message block

    const unsigned int *last;//pointer to
    unsigned char lb[16];//
    const unsigned int *lastblock;//pointer to
    unsigned int v[4];//

    int i;//
    int hashLoop;//used in loop where hash is printed
    unsigned char *p;//

    assert(HASH_LEN <= 16);//verify hash length is less than or equal to 16

    v[0] = key[0];//pass key character into 
    v[1] = key[1];//
    v[2] = key[2];//
    v[3] = key[3];//

    //description
    if (msgLen != 0)
    {
        for (; M != end; M += 4)
        {
            //If compiling in debug mode
#ifdef DEBUG
            printf("(%3d) v[0] %08X\n", msgLen, v[0]);//
            printf("(%3d) v[1] %08X\n", msgLen, v[1]);//
            printf("(%3d) v[2] %08X\n", msgLen, v[2]);//
            printf("(%3d) v[3] %08X\n", msgLen, v[3]);//
            printf("(%3d) compress %08X %08X %08X %08X\n", msgLen, message[0], message[1], message[2], message[3]);//
#endif
            //assign value using Bitwise exclusive OR
            v[0] ^= M[0];
            v[1] ^= M[1];
            v[2] ^= M[2];
            v[3] ^= M[3];

            PERMUTE;//call to permutation algorithm
        }//endFOR
    }//endIF

    //description
    if ((msgLen != 0) && ((msgLen & 0xF) == 0))
    {
        last = subkey1;//
        lastblock = M;//
    }
    else {
        last = subkey2;
        p = (unsigned char*)M;
        i = 0;

        for (; p != message + msgLen; p++, i++)
        {
            lb[i] = *p;
        }//endFOR

        lb[i++] = 0x01;//padding bit

        for (; i != 16; i++)
        {
            lb[i] = 0;
        }//endFOR
        lastblock = (unsigned int*)lb;
    }//endIF

  //If compiling in debug mode
#ifdef DEBUG
    printf("(%3d) v[0] %08X\n", msgLen, v[0]);
    printf("(%3d) v[1] %08X\n", msgLen, v[1]);
    printf("(%3d) v[2] %08X\n", msgLen, v[2]);
    printf("(%3d) v[3] %08X\n", msgLen, v[3]);
    printf("(%3d) last block %08X %08X %08X %08X\n", msgLen, lastblock[0], lastblock[1], lastblock[2], lastblock[3]);//
#endif

    v[0] ^= lastblock[0];//
    v[1] ^= lastblock[1];//
    v[2] ^= lastblock[2];//
    v[3] ^= lastblock[3];//

    v[0] ^= last[0];//
    v[1] ^= last[1];//
    v[2] ^= last[2];//
    v[3] ^= last[3];//

    PERMUTE;//call to 128-bit permutation algorithm

  //If compiling in debug mode
#ifdef DEBUG
    printf("(%3d) v[0] %08X\n", msgLen, v[0]);//
    printf("(%3d) v[1] %08X\n", msgLen, v[1]);//
    printf("(%3d) v[2] %08X\n", msgLen, v[2]);//
    printf("(%3d) v[3] %08X\n", msgLen, v[3]);//
#endif

    //assignment by Bitwise exclusive OR
    v[0] ^= last[0];
    v[1] ^= last[1];
    v[2] ^= last[2];
    v[3] ^= last[3];

    memcpy(hash, v, HASH_LEN);//copies |hash length| characters from memory area v to memory area hash  

    /*printf("\n\nDIGEST: \n");
    for (hashLoop = 0; hashLoop < HASH_LEN; hashLoop++) {
        //Start printing on the next after every 16 octets
        if ((hashLoop % 16) == 0) {
            printf("\n");//Print on next line
        }//endIF
        printf("%x", hash[hashLoop]);//Print in hexadecimal format
    }//endFOR*/

    return(hash);//return calculated hash
}//endCHASKEY
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
    unsigned char secret_Key[CHASKEY];//128-bit secret-key (key); 32 characters (16 bytes)
    unsigned int mainKey[KEY_LEN];//secret-key
    unsigned int subkey1[KEY_LEN];//subkey1
    unsigned int subkey2[KEY_LEN];//subkey2

    unsigned char subString[8];//holds key during trasnformation from char to int


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
        keys = fopen("CHAS_keys.txt", "r");//Open file with keys
        if (keys == NULL) {
            printf("Unable to open file\n");//Could not read file with keys
            exit(EXIT_FAILURE);//exit program
        }//endIF

        while (fgets(key_owner, KEY_OWNER_LEN, keys) != NULL) {
            if (strstr(key_owner, ownerES1)) {
                fgets(secret_Key, KEY_LEN, keys);//Get secret key for this ES
                fclose(keys);//Close file - key has been retrieved
                break;
            }//endIF
            printf("\nNo key found\n");//No key found for ES
            exit(EXIT_FAILURE);//exit program
        }//endWHILE

    memcpy(subString, secret_Key, 8);
    mainKey[0] = strtoul(subString, NULL, HASH_LEN);
    memcpy(subString, secret_Key + 8, 8);
    mainKey[1] = strtoul(subString, NULL, HASH_LEN);
    memcpy(subString, secret_Key + 16, 8);
    mainKey[2] = strtoul(subString, NULL, HASH_LEN);
    memcpy(subString, secret_Key + 24, 8);
    mainKey[3] = strtoul(subString, NULL, HASH_LEN);

    subkeys(subkey1, subkey2, mainKey);//call to key schedule function

//If compiling in debug mode
#if DEBUG
    printf("K0 %08X %08X %08X %08X\n", mainKey[0], mainKey[1], mainKey[2], mainKey[3]);
    printf("K1 %08X %08X %08X %08X\n", subkey1[0], subkey1[1], subkey1[2], subkey1[3]);
    printf("K2 %08X %08X %08X %08X\n", subkey2[0], subkey2[1], subkey2[2], subkey2[3]);
#endif

//If compiling in debug mode
#if DEBUG
        printf("K0 %08X %08X %08X %08X\n", key[0], key[1], key[2], key[3]);
        printf("K1 %08X %08X %08X %08X\n", subkey1[0], subkey1[1], subkey1[2], subkey1[3]);
        printf("K2 %08X %08X %08X %08X\n", subkey2[0], subkey2[1], subkey2[2], subkey2[3]);
#endif

        //MAC generation
        digest = chaskey(hash, plaintext, secret_Key, subkey1, subkey2);//pointer to returned chasekey mac calculation
        memcpy(messageDigest, digest, HASH_LEN);//Copy hash to message digest array

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