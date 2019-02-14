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
//                SHA DECLARATIONS
//---------------------------------------------------------------------------------------
#define UNPACK32(x, str)                      \
{                                             \
*((str) + 3) = (unsigned char) ((x)      );       \
*((str) + 2) = (unsigned char) ((x) >>  8);       \
*((str) + 1) = (unsigned char) ((x) >> 16);       \
*((str) + 0) = (unsigned char) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
*(x) =   ((unsigned int) *((str) + 3)      )    \
| ((unsigned int) *((str) + 2) <<  8)    \
| ((unsigned int) *((str) + 1) << 16)    \
| ((unsigned int) *((str) + 0) << 24);   \
}

#define SHA256_SCR(i)                         \
{                                             \
w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
+ SHA256_F3(w[i - 15]) + w[i - 16]; \
}
//---------------------------------------------------------------------------------------
//                SHA256 GLOBAL DECLARATIONS
//---------------------------------------------------------------------------------------
unsigned int sha256_h0[8] =
{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };//

unsigned int sha256_k[64] =
{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };//
///* SHA-256 functions */
//---------------------------------------------------------------------------------------
//                HMAC-SHA256 FUNCTIONS
//Author: HOHO Labs
//Name:   HMAC-SHA256-in-C
//Source: github.com/HOHOLabs/HMAC-SHA256-in-C
//---------------------------------------------------------------------------------------
//SHA-256 functions
void sha256_transf(sha256_ctx *ctx, const unsigned char *message,
    unsigned int block_nb)
{
    unsigned int w[64];
    unsigned int wv[8];
    unsigned int t1, t2;
    const unsigned char *sub_block;
    int i;

    int j;

    for (i = 0; i < (int)block_nb; i++) {
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}//endsha256_transf

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}//endsha256

void sha256_init(sha256_ctx *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}//endsha256_init

void sha256_update(sha256_ctx *ctx, const unsigned char *message,
    unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
        rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}//endsha256_update

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
        < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}//sha256_final

unsigned char * HMAC_SHA256(unsigned char * msg, unsigned char * key)
{
    int i, j, k, l, m, n, p;
    int s;
    unsigned char q;
    unsigned int blocksize = 64;
    unsigned char * Key0 = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_ipad = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_ipad_concat_text = (unsigned char *)calloc((blocksize + strlen(msg)), sizeof(unsigned char));
    unsigned char * Key0_ipad_concat_text_digest = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_opad = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_opad_concat_prev = (unsigned char *)calloc(blocksize + 32, sizeof(unsigned char));

    unsigned char * HMAC_SHA256 = (unsigned char *)malloc(32 * sizeof(unsigned char));

    /*printf("\n\nPAYLOAD: \n");
    for(s=0; s < 444; s++){
        // Start printing on the next after every 16 octets
        if ((s % 16) == 0){
            printf("\n");//print on next line
        }//endIF
        printf("%02x ", msg[s]);//Print in hexadecimal format
    }//endFOR

    printf("\n\nKEY: \n");
    for(s=0; s < 128; s++){
        // Start printing on the next after every 16 octets
        if ((s % 16) == 0){
            printf("\n");//print on next line
        }//endIF
        printf("%02x ", key[s]);//Print in hexadecimal format
    }//endFOR*/

    if (strlen(key) < blocksize) {
        for (i = 0; i < blocksize; i++) {
            if (i < strlen(key)) Key0[i] = key[i];
            else Key0[i] = 0x00;
        }
    }
    else if (strlen(key) > blocksize) {
        sha256(key, strlen(key), Key0);
        for (q = strlen(key); q < blocksize; q++) {
            Key0[q] = 0x00;
        }
    }

    for (j = 0; j < blocksize; j++) {
        Key0_ipad[j] = Key0[j] ^ 0x36;
    }
    for (k = 0; k < blocksize; k++) {
        Key0_ipad_concat_text[k] = Key0_ipad[k];
    }
    for (l = blocksize; l < blocksize + strlen(msg); l++) {
        Key0_ipad_concat_text[l] = msg[l - blocksize];
    }

    sha256(Key0_ipad_concat_text, blocksize + (unsigned int)strlen(msg), Key0_ipad_concat_text_digest);

    for (m = 0; m < blocksize; m++) {
        Key0_opad[m] = Key0[m] ^ 0x5C;
    }

    for (n = 0; n < blocksize; n++) {
        Key0_opad_concat_prev[n] = Key0_opad[n];
    }
    for (p = blocksize; p < blocksize + 32; p++) {
        Key0_opad_concat_prev[p] = Key0_ipad_concat_text_digest[p - blocksize];
    }

    sha256(Key0_opad_concat_prev, blocksize + 32, HMAC_SHA256);
    return HMAC_SHA256;
}//end HMAC_SHA256
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

    FILE *keys;//Pointer to file with hashing keys
    char ownerES1[10] = "ES1";//Key owner name
    char ownerES2[10] = "ES2";//Key owner name
    char ownerES3[10] = "ES3";//Key owner name
    char ownerES4[10] = "ES4";//Key owner name

    unsigned char *payload;//Pointer to packet payload
    unsigned char *oldDigest;//Pointer to packet message digest
    unsigned char *newDigest;//Pointer to recalculated message digest
//    unsigned char messageDigest[32] = { 0 };
    unsigned char key_owner[KEY_OWNER_LEN];//Holds key owner name retrieved from file with hashing keys
    unsigned char secret_Key[KEY_LEN];//Holds hashing key retrieved from file with hashing keys


    unsigned char plaintext[PACKET_PAYLOAD];//Packet payload
    unsigned char hashValue[HASH_LEN];//Packet hash value
    unsigned char hashCalculated[HASH_LEN];//Hash calculated by the switch

    int getPayload;//Used in FOR loop to retrieve packet payload
    int getDigest;//Used in FOR loop to retrieve packet digest
    int getKey;//Used in FOR loop to retrieve secret key

    ethdr = (struct ethernetHeader*)(packet);//Ethernet header offset
    v4hdr = (struct ipheader*)(packet + SIZE_ETHERNET);//IP header offset
    uhdr  = (struct udpheader*)(packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
    payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset
    oldDigest = (u_char *)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP + PACKET_PAYLOAD);//Hash offset

    //Print packet length and time...//need to fix, time and date formatting is incorrect
    printf("\n---------------------------------------------------------------------\n");
    printf("Grabbed packet of length %d\n",header->len);
    printf("Received at ............ %s\n",ctime((const time_t*)&header->ts.tv_sec));
//    printf("\n---------------------------------------------------------------------\n");


    //Get hashing key
    keys = fopen("ES_keys.txt", "r");//Open file with keys
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

    //printf("\nPAYLOAD: \n");
    for(getPayload = OFFSET; getPayload < PACKET_PAYLOAD; getPayload++){
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
    for(getDigest = OFFSET; getDigest < HASH_LEN; getDigest++){
        // Start printing on the next after every 16 octets
        if ((getDigest % 16) == 0){
            printf("\n");//Print on next line
        }//endIF
        //printf("%02x", oldDigest[getDigest]);//Print in hexadecimal format
        hashValue[getDigest] = oldDigest[getDigest];//Fill hash from incoming message
        printf("%02x", hashValue[getDigest]);
    }//endFOR

    //Calculate hash and compare to appended hash
    newDigest = HMAC_SHA256(plaintext, secret_Key);
    memcpy(hashCalculated, newDigest, 32);//Copy hash to message digest array

    printf("\n\nnew DIGEST: \n");
    for(getDigest = OFFSET; getDigest < HASH_LEN; getDigest++){
        //Start printing on the next after every 16 octets
        if ((getDigest % 16) == 0){
            printf("\n");//Print on next line
        }//endIF
        printf("%02x", hashCalculated[getDigest]);//Print in hexadecimal format
    }//endFOR

    //Compare hashes
    if(memcmp(hashValue, hashCalculated, sizeof(hashValue)) == 0)
    {
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