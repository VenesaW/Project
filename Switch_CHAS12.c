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

#include<assert.h>//Provides a macro called assert which can be used to verify assumptions made by the program and print a diagnostic message if this assumption is false
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
#define PACKET_SIZE 502 //Example AFDX message with 486 bytes of data and a 32 byte message digest

#define CHASKEY 32 //Secret key retrieved from key database (128-bit, 32 characters)
#define KEY_LEN 4 //Key length of secret key is 128-bits (32 characters grouped into "4" groups of 8 characters)
#define KEY_OWNER_LEN 10 //Name of End System that owns the key in the key database
#define HASH_LEN 16 //Size of hash is 16 bytes (32 characters)

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
    unsigned char digest;//Message digest
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
    unsigned char secret_Key[CHASKEY];//128-bit secret-key (key); 32 characters (16 bytes)
    unsigned int mainKey[KEY_LEN];//secret-key
    unsigned int subkey1[KEY_LEN];//subkey1
    unsigned int subkey2[KEY_LEN];//subkey2

    unsigned char subString[8];//holds key during trasnformation from char to int

    unsigned char plaintext[PACKET_PAYLOAD];//Packet payload
    unsigned char hashValue[HASH_LEN];//Packet hash value
    unsigned char hashCalculated[HASH_LEN];//Hash calculated by the switch

    int getPayload;//Used in FOR loop to retrieve packet payload
    int getDigest;//Used in FOR loop to retrieve packet digest
    int getKey;//Used in FOR loop to retrieve secret key

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
    keys = fopen("CHAS_keys.txt", "r");//Open file with keys
    if (keys == NULL) {
        printf("Unable to open file\n");//Could not read file with keys
        exit(EXIT_FAILURE);//exit program
    }//endIF
    while (fgets(key_owner, KEY_OWNER_LEN, keys) != NULL) {
        if (strstr(key_owner, ownerES1)) {
            fgets(secret_Key, CHASKEY, keys);//Get secret key for this ES
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
    newDigest = chaskey(hash, plaintext, mainKey, subkey1, subkey2);//pointer to returned chasekey mac calculation
    memcpy(hashCalculated, newDigest, HASH_LEN);//Copy hash to message digest array

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