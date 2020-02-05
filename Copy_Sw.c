/*
	Switch using libpcap library
*/
//---------------------------------------------------------------------------------------
//                LIBRARIES
//---------------------------------------------------------------------------------------
#include "aes.h"//For AES
#include<assert.h>//Provides a macro called assert which can be used to verify assumptions made by the program and print a diagnostic message if this assumption is false
#include<errno.h>//Defines macros for reporting and retrieving error conditions
#include<libconfig.h>//Processes the XML configuration file for the Linux client and the Linux server
#include<math.h>//For mathematical fuctions
#include<pcap.h>//For libpcap library
#include<stdint.h>//Allow programmers to write more portable code by providing a set of typedefs that specify exact-width integer types, together with the defined minimum and maximum allowable values for each type
#include<stdio.h>//Defines three variable types, several macros, and various functions for performing input and output
#include<stdlib.h>//Defines four variable types, several macros, and various functions for performing general functions
#include<string.h>//Defines one variable type, one macro, and various functions for manipulating arrays of characters
#include<sys/socket.h>//For Socket programming
#include<sys/time.h>//For timestamp

#include<arpa/inet.h>//For inet_ntoa() -> returns the address of a system
#include<net/ethernet.h>//For IEEE 802.3 Ethernet constants
#include<netinet/if_ether.h>//For global definitions for the Ethernet IEEE 802.3 interface
#include<netinet/ip_icmp.h>//For icmp header declarations
#include<netinet/udp.h>//For udp header declarations
#include<netinet/tcp.h>//For tcp header delcarations
#include<netinet/ip.h>//For ip header declarations
#include<netinet/in.h>//For constants and structures needed for internet domain addresses
//---------------------------------------------------------------------------------------
//                FUNCTIONS FORWARD DECLARATIONS
//---------------------------------------------------------------------------------------
void handleMsg(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet);
//---------------------------------------------------------------------------------------
//                STATIC DECLARATIONS
//---------------------------------------------------------------------------------------
//Ethernet structure properties
#define ETHER_ALEN 6 //Ethernet addresses are 6 bytes
#define INTERFACE_MODE 1 //Put interface in promiscuous mode (1) or non-promiscuous mode (0)
#define PACKET_DATA 486 //Example AFDX message with 486 bytes of data
#define PACKET_PAYLOAD 444 //Example AFDX message with 486 bytes of data - 444 bytes form the payload
#define PACKET_SIZE 502 //Example AFDX message with 486 bytes of data and a 32 byte message digest
#define PCAP_NETMASK_UNKNOWN 0xffffffff//default netmask
#define READ_TIMEOUT 1000 //The packet buffer timeout in milliseconds ->0 means no timeout (slows down the code execution)
#define TAG_LEN 1 //1 Byte
#define SIZE_ETHERNET 14 //Ethernet headers are always exactly 14 bytes
#define SIZE_IP 20 //IP headers are always 20 bytes
#define SIZE_UDP 8 //UDP header length are 8 bytes
#define SNAP_LEN 1518 //default maximum bytes per packet to capture
#define FLAG_LEN 1 //1 Byte

//Listen for the next [x] packets
#define NEXT_INCOMING 1 

//Packet lengths (total)
#define KEY_EST_MSG1_LEN 59 //Length of KEY EST MSG 1 packet
#define KEY_EST_MSG2_LEN 115 //Length of KEY EST MSG 2 packet
#define KEY_EST_MSG3_LEN 97 //Length of KEY EST MSG 3 packet
#define KEY_EST_MSG4_LEN 59 //Length of KEY EST MSG 4 packet
#define KEY_EST_MSG5_LEN 59 //Length of KEY EST MSG 5 packet
#define KEY_EST_MSG6_LEN 59 //Length of KEY EST MSG 6 packet
#define KEY_EST_MSG7_LEN 59 //Length of KEY EST MSG 7 packet
#define KEY_EST_MSG8_LEN 44 //Length of KEY EST MSG 8 packet
#define KEY_EST_MSG9_LEN 44 //Length of KEY EST MSG 9 packet
#define KEY_EST_MSG10_LEN 75 //Length of KEY EST MSG 10 packet
#define NONCE_LEN 16 //16 Byte random number (Nonce) for key establishment
#define RANDOM_NUM_LEN 16 //16 Byte random number (Nonce) for key establishment
#define KEYING_MAT_LEN 16 //16 Byte keying material for key establishment

//Payload lengths
#define ANSWER_LEN 2 //Length of success/failure answer for key establishment
#define CHALLENGE_LEN 16 //Length of challenge for key establishment
#define IDENTIFIER_LEN 8 //Length of identifier for key establishment
#define MSG1_PAYLOAD_LEN 16 //Length of concatenated payload for message 1
#define MSG2_PAYLOAD_LEN 70 //Length of concatenated payload for message 2
#define MSG3_PAYLOAD_LEN 54 //Length of concatenated payload for message 3
#define MSG4_PAYLOAD_LEN 16 //Length of concatenated payload for message 4
#define MSG5_PAYLOAD_LEN 16 //Length of concatenated payload for message 5
#define MSG6_PAYLOAD_LEN 16 //Length of concatenated payload for message 6
#define MSG7_PAYLOAD_LEN 16 //Length of concatenated payload for message 7
#define MSG8_PAYLOAD_LEN 1 //Length of concatenated payload for message 8
#define MSG9_PAYLOAD_LEN 1 //Length of concatenated payload for message 9
#define MSG10_PAYLOAD_LEN 32 //Length of concatenated payload for message 10
#define OFFSET 0 //Offset of payload in packet

//Keying and hashing material lengths
#define AES_BLOCK 64 //Size of AES block
#define CHAS_SUBKEY 4 //Key length of CHASKEY subkey
#define CHAS_SUBSTRING 2 //Key length of CHASKEY subkey used in key transformation
#define HASH_LEN 8 //Size of hash is 8 bytes (16 characters)
#define KEY_LEN 16 //Key length of 128 bit secret key (32 characters)

//Thresholds
#define KEY_UPDATE_MAX 10 //Ensure next session key is available at this point
#define KEY_CHANGE_OVER_MAX 30 //Ensure key change-over occurs at this point
#define KDF_FAILURE_MAX 5 //Stop communication and generate new key key
#define MAC_MISMATCH_MAX 10 //Stop communication and change-over or generate key

//Channel/Packet parameters
u_char *Interface201 = "eth0.201";//Pointer to port 4
u_char *Interface202 = "eth0.202";//Pointer to port 1
u_char *Interface203 = "eth0.203";//Pointer to port 0
u_char *Interface204 = "eth0.204";//Pointer to port 2
///****************************************
///Static Declarations for AES
///AES https://github.com/kokke/tiny-AES-c
///****************************************
#define CBC 1
#define CTR 1
#define ECB 1

#define Nb 4 // The number of columns comprising a state in AES. This is a constant in AES. Value=4

#if defined(AES256) && (AES256 == 1)
#define Nk 8
#define Nr 14
#elif defined(AES192) && (AES192 == 1)
#define Nk 6
#define Nr 12
#else
#define Nk 4 // The number of 32 bit words in a key.
#define Nr 10 // The number of rounds in AES Cipher.
#endif

#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif

typedef uint8_t state_t[4][4];//state - array holding the intermediate results during decryption

static const uint8_t sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

//---------------------------------------------------------------------------------------
//                STRUCTS
//---------------------------------------------------------------------------------------
//Ethernet header parameters for all messages
struct ethernetHeader {
	u_char  ether_dhost[ETHER_ALEN];//Destination host address
	u_char  ether_shost[ETHER_ALEN];//Source host address */
	u_short ether_type;//IP or ARP or ...etc...
};
//IP header parameters for all messages
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
//UDP header parameters for all messages
struct udpheader {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char udp_payload;//UDP payload
};
//---------------------------------------------------------------------------------------
//                GLOBAL DECLARATIONS
//---------------------------------------------------------------------------------------
//For keying material
///Master Key paramaters
char* SwMaster_Key = "AA112233445566778899AABBCCDDEEFF";//pointer to master key (encryption and decryption) as a character stream

///Session Key paramaters
unsigned int SwSession_Key[KEY_LEN] = { 0x833D3433, 0x009F389F, 0x2398E64F, 0x417ACF39 };//master key as hex
unsigned char sessionKey[33] = "833D3433009F389F2398E64F417ACF39";//master key as hex
unsigned int chaskeySubkey1[KEY_LEN];//subkey1
unsigned int chaskeySubkey2[KEY_LEN];//subkey2
unsigned int chaskeyMsgLen;
unsigned int hashLen = 8;
unsigned char TSNMICinput[] = "";//TSNMIC concatenated payload
unsigned char msgFlag[] = "";//Array to hold message flag

///hash codes and encrypted packets
unsigned char hash[HASH_LEN];//memory area for chaskey output hash; should be at most 128-bits (32 characters; 16 bytes)
unsigned char iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

//For channel
bpf_u_int32 netMask;//Subnet mask
bpf_u_int32 ipAddr;//IP address
char *Interface;//Pointer to Ethernet port on Windows device
char errorBuffer[PCAP_ERRBUF_SIZE];//Error buffer for sniffing channel. Errors encountered during sniffing are stored here
int list_interfaces = 0;//Used in FOR loop where the interfaces are being listed
int max_interfaces = 2;//Set as 0 or 7 for *my* Windows PC
int num_interfaces;//Interface 0 or 7 for *my* Windows PC
pcap_if_t *all_Interfaces;//All available interfaces
pcap_if_t *select_Interface;//Gets specific interface from list (Windows)
pcap_t* outChannel;//Channel for packet capture
pcap_t* Channel201;//Channel for packet capture on port 4
pcap_t* Channel202;//Channel for packet capture on port 1
pcap_t* Channel203;//Channel for packet capture on port 0
pcap_t* Channel204;//Channel for packet capture on port 2
struct bpf_program compiledCode;//Stores compiled program for filtering the incoming traffic

//For packets
///key establishment packets flags
unsigned char msg1_flag[FLAG_LEN];//Array to hold flag from message 1 packet
unsigned char msg2_flag[FLAG_LEN];//Array to hold flag from message 2 packet
unsigned char msg3_flag[FLAG_LEN];//Array to hold flag from message 3 packet
unsigned char msg4_flag[FLAG_LEN];//Array to hold flag from message 4 packet
unsigned char msg5_flag[FLAG_LEN];//Array to hold flag from message 5 packet
unsigned char msg6_flag[FLAG_LEN];//Array to hold flag from message 6 packet
unsigned char msg7_flag[FLAG_LEN];//Array to hold flag from message 7 packet
unsigned char msg8_flag[FLAG_LEN];//Array to hold flag from message 8 packet
unsigned char msg9_flag[FLAG_LEN];//Array to hold flag from message 9 packet
unsigned char msg10_flag[FLAG_LEN];//Array to hold flag from message 10 packet
///key establishment packets
unsigned char msg1_packet[KEY_EST_MSG1_LEN];//Array to hold key establishment message 1 packet
unsigned char msg2_packet[KEY_EST_MSG2_LEN];//Array to hold key establishment message 2 packet
unsigned char msg3_packet[KEY_EST_MSG3_LEN];//Array to hold key establishment message 3 packet
unsigned char msg4_packet[KEY_EST_MSG4_LEN];//Array to hold key establishment message 4 packet
unsigned char msg5_packet[KEY_EST_MSG5_LEN];//Array to hold key establishment message 5 packet
unsigned char msg6_packet[KEY_EST_MSG6_LEN];//Array to hold key establishment message 6 packet
unsigned char msg7_packet[KEY_EST_MSG7_LEN];//Array to hold key establishment message 7 packet
unsigned char msg8_packet[KEY_EST_MSG8_LEN];//Array to hold key establishment message 8 packet
unsigned char msg9_packet[KEY_EST_MSG9_LEN];//Array to hold key establishment message 9 packet
unsigned char msg10_packet[KEY_EST_MSG10_LEN];//Array to hold key establishment message 10 packet
///key establishment packets payloads
unsigned char msg1_payload[MSG1_PAYLOAD_LEN];//Array to hold payload from message 1 packet
unsigned char msg2_payload[MSG2_PAYLOAD_LEN];//Array to hold payload from message 2 packet
unsigned char msg3_payload[MSG3_PAYLOAD_LEN];//Array to hold payload from message 3 packet
unsigned char msg4_payload[MSG4_PAYLOAD_LEN];//Array to hold payload from message 4 packet
unsigned char msg5_payload[MSG5_PAYLOAD_LEN];//Array to hold payload from message 5 packet
unsigned char msg6_payload[MSG6_PAYLOAD_LEN];//Array to hold payload from message 6 packet
unsigned char msg7_payload[MSG7_PAYLOAD_LEN];//Array to hold payload from message 7 packet
unsigned char msg8_payload[MSG8_PAYLOAD_LEN];//Array to hold payload from message 8 packet
unsigned char msg9_payload[MSG9_PAYLOAD_LEN];//Array to hold payload from message 9 packet
unsigned char msg10_payload[MSG10_PAYLOAD_LEN];//Array to hold payload from message 10 packet
///key establishment packet parameters (outgoing)
unsigned char Sw_RandomNum[RANDOM_NUM_LEN] = "804724F27A8CB534";//16 Byte Random number for Key Establishment message 1
unsigned char Sw_ESID[IDENTIFIER_LEN] = "FEDCBAED";//Identifier for Key Establishment message 3
unsigned char Sw_SWID[IDENTIFIER_LEN] = "DCBFEAED";//Identifier for comparison in Key Establishment message 2
unsigned char Sw_keyMat[KEYING_MAT_LEN] = "2774063BADC66035";//Keying material for Key Establishment message 3
unsigned char Sw_Nonce[NONCE_LEN] = "6035F92A5BDD673";//Nonce for Key Establishment message 3
unsigned char Sw_challenge[] = "FFEEDDAAFFEEDDAA";//Challenge response for Key Establishment message 5
unsigned char Sw_challengeHash[HASH_LEN];//Challenge response for Key Establishment message 5
unsigned char successfulMSG[ANSWER_LEN] = "59";//Successful response for Key Establishment message 6
unsigned char failureMSG[ANSWER_LEN] = "4e";//Successful response for Key Establishment message 6
///key establishment packets parameters (incoming)
unsigned char ES_RandomNum[RANDOM_NUM_LEN];//Random number from Key Establishment message 2
unsigned char ES_swID[IDENTIFIER_LEN];//Identifier from Key Establishment message 2
unsigned char ES_keyMat[KEYING_MAT_LEN];//Keying material from Key Establishment message 2
unsigned char ES_Nonce[NONCE_LEN];//Nonce from Key Establishment message 2
unsigned char ES_challengeResponse[CHALLENGE_LEN];//Challenge from Key Establishment message 4
///key establishment packet checkpoints
unsigned char *ES_payload;//Pointer to packet payload for incoming Key Establishment messages
unsigned char incoming_flag[] = "";//Array to hold the flag from incoming Key Establishment messages
unsigned char incoming_payload[] = " ";//Array to hold incoming Key Establishment messages
unsigned char integrity_payload[RANDOM_NUM_LEN];//Array to hold the integrity value from incoming Key Establishment messages

///key derivation function
double d;//ceiling value //d = Lb/Lh
double Lb = 128;//bit length of the output of the KDF//size of 128 bit key to be extracted from output
double Lh = 64;//bit length of the output of the hash//Chaskey outputs a 64 bit hash

int Lc = 32;//bit-length of the binary encoding of the counter c//encoded as a 32-bit, big-endian bit string
int c;//counter

char b[32]= " ";//128 bit key (32 characters) to be extracted from output
char p[8] = "HMI00001";//Label
char s[32];//concatenation of keying materials (FA||FB)
char salt[20] = "AA112233445566778899";
char u[20] = "AA112233445566778899";//auxilary value
char h[] = "";
char z[] = " ";//bit string output of Chaskey from which to take key

///Regular key usage
unsigned char hashCalculated[HASH_LEN];//Hash calculated by the switch
unsigned char hashValue[HASH_LEN];//Packet hash value
unsigned char packet[PACKET_SIZE];//Array to hold regular AFDX message with hash
unsigned char plaintext[PACKET_PAYLOAD];//Plaintext message for hashing

unsigned char *hashedPacket;//Pointer to packet segment for hashing
unsigned char *oldDigest;//Pointer to packet message digest
unsigned char *newDigest;//Pointer to recalculated message digest

///Counters
int keyCheck = 0;
int key_usage_threshold = 0;
int key_change_over_threshold = 0;
int kdf_failure = 0;
int mac_mismatch = 0;

///For loops
int appendData;//Used in for loop for parsing packet parameters
int getData;//Used in FOR loop to get packet 
int checkData = 0;

//---------------------------------------------------------------------------------------
//                AES FUNCTIONS
//Author: kokke
//Name:   Small portable AES128/192/256 in C
//Source: https://github.com/kokke/tiny-AES-c
//---------------------------------------------------------------------------------------
 /*
 static uint8_t getSBoxValue(uint8_t num)
 {
   return sbox[num];
 }
*/

#define getSBoxValue(num) (sbox[(num)])

/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/

#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
	unsigned i, j, k;
	uint8_t tempa[4]; // Used for the column/row operations

	// The first round key is the key itself.
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}//end_FOR

	// All other round keys are found from the previous round keys.
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
			k = (i - 1) * 4;
			tempa[0] = RoundKey[k + 0];
			tempa[1] = RoundKey[k + 1];
			tempa[2] = RoundKey[k + 2];
			tempa[3] = RoundKey[k + 3];

		}//end

		if (i % Nk == 0)
		{
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				const uint8_t u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}//end

			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}//end

			tempa[0] = tempa[0] ^ Rcon[i / Nk];
		}//end_IF

#if defined(AES256) && (AES256 == 1)
		if (i % Nk == 4)
		{
			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}//end
		}//end_IF
#endif
		j = i * 4; k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}//end_FOR    
}//end_KEY_EXPANSION

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
	KeyExpansion(ctx->RoundKey, key);
}//end_AES_INIT_CTX

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
	KeyExpansion(ctx->RoundKey, key);
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}//end_AES_INIT_CTX_IV

void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}//end_AES_CTX_SET_IV
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}//end_FOR
	}//end_FOR
}//end_ADD_ROUND_KEY

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}//end_FOR
	}//end_FOR
}//end_SUB_BYTES

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
	uint8_t temp;

	// Rotate first row 1 columns to left  
	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	// Rotate second row 2 columns to left  
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to left
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}//end_SHIFT_ROWS

static uint8_t xtime(uint8_t x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}//end_X_TIME

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
	uint8_t i;
	uint8_t Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}//end_FOR
}//end_MIX_COLUMNS

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
	return (((y & 1) * x) ^
		((y >> 1 & 1) * xtime(x)) ^
		((y >> 2 & 1) * xtime(xtime(x))) ^
		((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
		((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}//end_MULTIPLY
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)
	{
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}//end_FOR
}//end_INV_MIX_COLUMNS

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}//end_FOR
	}//end_FOR
}//end_INV_SUB_BYTES

static void InvShiftRows(state_t* state)
{
	uint8_t temp;

	// Rotate first row 1 columns to right  
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;

	// Rotate second row 2 columns to right 
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to right
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}//end_INV_SHIFT_ROWS

#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round = 1; round < Nr; ++round)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}//end_FOR

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(Nr, state, RoundKey);
}//end_CIPHER

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(Nr, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round = (Nr - 1); round > 0; --round)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		InvMixColumns(state);
	}//end_FOR

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(0, state, RoundKey);
}//end_INV_CIPHER

#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)

void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
	// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher((state_t*)buf, ctx->RoundKey);
}//end_AES_ECB_ENCRYPT

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
	// The next function call decrypts the PlainText with the Key using AES algorithm.
	InvCipher((state_t*)buf, ctx->RoundKey);
}//end_ECB_DECRYPT

#endif // #if defined(ECB) && (ECB == 1)
#if defined(CBC) && (CBC == 1)

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
	uint8_t i;
	for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
	{
		buf[i] ^= Iv[i];
	}//end_FOR
}//end_XOR_WITH_IV

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, uint32_t length)
{
	uintptr_t i;
	uint8_t *Iv = ctx->Iv;
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		XorWithIv(buf, Iv);
		Cipher((state_t*)buf, ctx->RoundKey);
		Iv = buf;
		buf += AES_BLOCKLEN;
		//printf("Step %d - %d", i/16, i);
	}//end_FOR
	/* store Iv in ctx for next call */
	memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}//end_AES_CBC_ENCRYPT_BUFFER

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
	uintptr_t i;
	uint8_t storeNextIv[AES_BLOCKLEN];
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		memcpy(storeNextIv, buf, AES_BLOCKLEN);
		InvCipher((state_t*)buf, ctx->RoundKey);
		XorWithIv(buf, ctx->Iv);
		memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
	}//end_FOR
}//end_AES_CBC_DECRYPT_BUFFER

#endif // #if defined(CBC) && (CBC == 1)

#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
	uint8_t buffer[AES_BLOCKLEN];

	unsigned i;
	int bi;
	for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
	{
		if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
		{

			memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
			Cipher((state_t*)buffer, ctx->RoundKey);

			/* Increment Iv and handle overflow */
			for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
			{
				/* inc will overflow */
				if (ctx->Iv[bi] == 255)
				{
					ctx->Iv[bi] = 0;
					continue;
				}//end_IF
				ctx->Iv[bi] += 1;
				break;
			}//end_FOR
			bi = 0;
		}//end_IF

		buf[i] = (buf[i] ^ buffer[bi]);
	}//end_FOR
}//end_AES_CTR_XCRYPT_BUFFER

#endif // #if defined(CTR) && (CTR == 1)

static void phex(uint8_t* str);
static int test_encrypt_cbc(void);
static int test_decrypt_cbc(void);
static int test_encrypt_ctr(void);
static int test_decrypt_ctr(void);
static int test_encrypt_ecb(void);
static int test_decrypt_ecb(void);
static void test_encrypt_ecb_verbose(void);

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
const volatile unsigned int C[2] = { 0x00, 0x87 };//bit string (0^126)(10), which is 2 in decimal notation

												  //Chaskey ALGORITHM 1: TIMESTWO
//The subkey1 and subkey2 are generated from the the scret-key (key)
	//subkey1 = xK
	//subkey2 = (x^2)(subkey1); x corresponds to bit string (0^126)(10), which is 2 in decimal notation
//Subkeys are returned as "out"
#define TIMESTWO(out,in) \
  do { \
    out[0] = (in[0] << 1) ^ C[in[3] >> 31]; \
    out[1] = (in[1] << 1) | (in[0] >> 31); \
    out[2] = (in[2] << 1) | (in[1] >> 31); \
    out[3] = (in[3] << 1) | (in[2] >> 31); \
  } while(0)

//For every secret-key (key), two subkeys (subkey1 and subkey2) are generated
void subkeys(unsigned int subkey1[4], unsigned int subkey2[4], const unsigned int key[4])
{
	TIMESTWO(subkey1, key);
	TIMESTWO(subkey2, subkey1);
}//end_SUBKEYS

//Calculation of MAC
//Parameters: pointer to hash, hash length,  message, message length, key, subkey 1, subkey 2
unsigned char* chaskey(unsigned char *hash, const unsigned char *msg, const unsigned int key[4], const unsigned int subkey1[4], const unsigned int subkey2[4])
{
	//const unsigned int msgLen = 5;
	const unsigned int *M = (unsigned int*)msg;
	const unsigned int *end = M + (((chaskeyMsgLen - 1) >> 4) << 2); /* pointer to last message block */

	const unsigned int *last;
	unsigned char lb[16];
	const unsigned int *lastblock;
	unsigned int v[4];

	int i;
	unsigned char *p;

	assert(hashLen <= 16);//verify hash length is less than or equal to 16

	v[0] = key[0];//pass key character into 
	v[1] = key[1];
	v[2] = key[2];
	v[3] = key[3];

	if (chaskeyMsgLen != 0)
	{
		for (; M != end; M += 4)
		{
			//If compiling in debug mode
#ifdef DEBUG
			printf("(%3d) v[0] %08x\n", chaskeyMsgLen, v[0]);
			printf("(%3d) v[1] %08x\n", chaskeyMsgLen, v[1]);
			printf("(%3d) v[2] %08x\n", chaskeyMsgLen, v[2]);
			printf("(%3d) v[3] %08x\n", chaskeyMsgLen, v[3]);
			printf("(%3d) compress %08x %08x %08x %08x\n", chaskeyMsgLen, m[0], m[1], m[2], m[3]);
#endif
			//assign value using Bitwise exclusive OR
			v[0] ^= M[0];
			v[1] ^= M[1];
			v[2] ^= M[2];
			v[3] ^= M[3];

			PERMUTE;//call to permutation algorithm
		}//end_FOR
	}//end_IF

	if ((chaskeyMsgLen != 0) && ((chaskeyMsgLen & 0xF) == 0))
	{
		last = subkey1;
		lastblock = M;
	}//end_IF
	else
	{
		last = subkey2;
		p = (unsigned char*)M;
		i = 0;

		for (; p != msg + chaskeyMsgLen; p++, i++)
		{
			lb[i] = *p;
		}//end_FOR

		lb[i++] = 0x01;//padding bit

		for (; i != 16; i++)
		{
			lb[i] = 0;
		}//end_FOR

		lastblock = (unsigned int*)lb;
	}//end_ELSE

	//If compiling in debug mode
#ifdef DEBUG
	printf("(%3d) v[0] %08x\n", chaskeyMsgLen, v[0]);
	printf("(%3d) v[1] %08x\n", chaskeyMsgLen, v[1]);
	printf("(%3d) v[2] %08x\n", chaskeyMsgLen, v[2]);
	printf("(%3d) v[3] %08x\n", chaskeyMsgLen, v[3]);
	printf("(%3d) last block %08x %08x %08x %08x\n", chaskeyMsgLen, lastblock[0], lastblock[1], lastblock[2], lastblock[3]);
#endif
	v[0] ^= lastblock[0];
	v[1] ^= lastblock[1];
	v[2] ^= lastblock[2];
	v[3] ^= lastblock[3];

	v[0] ^= last[0];
	v[1] ^= last[1];
	v[2] ^= last[2];
	v[3] ^= last[3];

	PERMUTE;//call to 128-bit permutation algorithm

	//If compiling in debug mode
#ifdef DEBUG
	printf("(%3d) v[0] %08x\n", chaskeyMsgLen, v[0]);
	printf("(%3d) v[1] %08x\n", chaskeyMsgLen, v[1]);
	printf("(%3d) v[2] %08x\n", chaskeyMsgLen, v[2]);
	printf("(%3d) v[3] %08x\n", chaskeyMsgLen, v[3]);
#endif

	//assignment by Bitwise exclusive OR
	v[0] ^= last[0];
	v[1] ^= last[1];
	v[2] ^= last[2];
	v[3] ^= last[3];

	memcpy(hash, v, hashLen);//copies |hash length| characters from memory area v to memory area hash  
}//end_CHASKEY-12
//---------------------------------------------------------------------------------------
//                GET LIST OF INTERFACES FOR SENDING PACKET
///For Windows System
//---------------------------------------------------------------------------------------
//1) Check if interfaces are available
//2) Open selected interface
	//a) Call function to select interface
void openInterfaces()
{
//Port 4 (Eth0.201)
    Channel201 = pcap_open_live(Interface201, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 4
    pcap_setdirection(Channel201, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel201, &compiledCode, "dst port 1045", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel201, &compiledCode);//Apply filter to incoming traffic
//Port 0 (Eth0.202)
    Channel202 = pcap_open_live(Interface202, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 0
    pcap_setdirection(Channel202, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel202, &compiledCode, "dst port 1045", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel202, &compiledCode);//Apply filter to incoming traffic
//Port 1 (Eth0.203)
    Channel203 = pcap_open_live(Interface203, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 1
    pcap_setdirection(Channel203, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel203, &compiledCode, "dst port 1045", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel203, &compiledCode);//Apply filter to incoming traffic
//Port 2 (Eth0.204)
    Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 2
    pcap_setdirection(Channel204, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel204, &compiledCode, "dst port 1045", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel204, &compiledCode);//Apply filter to incoming traffic

    //All channels opened or not
    if ((Channel201 == NULL) || (Channel202 == NULL) || (Channel203 == NULL) || (Channel204 == NULL)) {
        printf("pcap_open_live() failed due to [%s]\n", errorBuffer);//At least one channel could not be opened
        exit(EXIT_FAILURE);//Exit program
    }//endIF
}//endOPEN_INTERFACES
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                FIRST KE MESSAGE FROM SWITCH TO ES
					//1)Switch sends E[masterkey](R[Sw]||I[ES]||F[sw]||Nonce[SW])||R[ES]
//---------------------------------------------------------------------------------------
void KE_secondMessage()
{    
    //Build packet for message 2 and encrypt the payload
        //dst_MAC (ES4, VL1)
    msg2_packet[0] = (0x45);//E
    msg2_packet[1] = (0x53);//S
    msg2_packet[2] = (0x34);//4
    msg2_packet[3] = (0x56);//V
    msg2_packet[4] = (0x4c);//L
    msg2_packet[5] = (0x31);//1
        //src_MAC (Switch)
    msg2_packet[6] = (0x45);//E
    msg2_packet[7] = (0x53);//S
    msg2_packet[8] = (0x31);//1
    msg2_packet[9] = (0x56);//V
    msg2_packet[10] = (0x4c);//L
    msg2_packet[11] = (0x31);//1
        //ether_type
    msg2_packet[12] = (0x08);
    msg2_packet[13] = (0x00);
    //IPv4
    msg2_packet[14] = (0x45);
    msg2_packet[15] = (0x00);
    //total_length
    msg2_packet[16] = (0x00);
    msg2_packet[17] = (0x1a);//26 bytes
    //identification
    msg2_packet[18] = (0x1d);
    msg2_packet[19] = (0x94);//random
    //flags
    msg2_packet[20] = (0x00);
    //fragment
    msg2_packet[21] = (0x00);
    //ttl
    msg2_packet[22] = (0x01);
    //protocol
    msg2_packet[23] = (0x11);
    //ip_checksum
    msg2_packet[24] = (0x91);
    msg2_packet[25] = (0x6e);//random
    //src_ip
    msg2_packet[26] = (0xc0);
    msg2_packet[27] = (0xa8);
    msg2_packet[28] = (0xb2);
    msg2_packet[29] = (0x5c);//random
        //dst_ip
    msg2_packet[30] = (0xc0);
    msg2_packet[31] = (0xa8);
    msg2_packet[32] = (0xb2);
    msg2_packet[33] = (0x5a);//random
        //src_port
    msg2_packet[34] = (0x04);
    msg2_packet[35] = (0x15);//random
		//dst_port
    msg2_packet[36] = (0x04);
    msg2_packet[37] = (0x16);//random
		//udp_length
    msg2_packet[38] = (0x00);
    msg2_packet[39] = (0x12);//18 bytes
		//udp_checksum
    msg2_packet[40] = (0xaa);
    msg2_packet[41] = (0xff);//random
	
	//Append flag
	msg2_packet[42] = (0x02);//Key est msg 2 flag

	//Append other parmeters for key establishment message 2
	///(1) R(Sw) --> Switch Random Number (16 bytes)
	appendData = 43;
	for (getData = 0; getData < RANDOM_NUM_LEN; getData++)
	{
		msg2_packet[appendData] = Sw_RandomNum[getData];
		appendData++;
	}//endFOR
	///(2) I(ES) --> ES Identifier (8 bytes)
	appendData = 59;
	for (getData = 0; getData < IDENTIFIER_LEN; getData++)
	{
		msg2_packet[appendData] = Sw_ESID[getData];
		appendData++;
	}//endFOR
	///(3) F(Sw) --> Switch Keying Material (16 bytes)
	appendData = 67;
	for (getData = 0; getData < KEYING_MAT_LEN; getData++)
	{
		msg2_packet[appendData] = Sw_keyMat[getData];
		appendData++;
	}//endFOR
	///(4) Nonce(Sw) --> Switch Nonce (16 bytes)
	appendData = 83;
	for (getData = 0; getData < NONCE_LEN; getData++)
	{
		msg2_packet[appendData] = Sw_Nonce[getData];
		appendData++;
	}//endFOR
	///(5) Nonce(Sw) --> Switch Nonce (16 bytes)
	appendData = 99;
	for (getData = 0; getData < NONCE_LEN; getData++)
	{
		msg2_packet[appendData] = ES_RandomNum[getData];
		appendData++;
	}//endFOR
			
	//send packet
	pcap_sendpacket(Channel204, msg2_packet, KEY_EST_MSG2_LEN);//KDF message 1 packet
	//listen for response
	//pcap_loop(Channel204, NEXT_INCOMING, handleMsg, NULL);
}//end_KE_SECOND_MESSAGE
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                HANDLING KEY DERIVATION MESSAGE 2 FROM Switch
					//1)Read message from switch
					//2)ES sends E[masterkey](R[ES]||R[sw]||F[sw]||Text[2])
					//3)Initiate key derivation function
//---------------------------------------------------------------------------------------
void handleMsg(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet)
{
	struct ethernetHeader *ethdr = NULL;//Initialize struct
	struct ipheader *v4hdr = NULL;//Initialize struct
	struct udpheader *udpMsg2 = NULL;//Initialize struct

	ethdr = (struct ethernetHeader*)(in_packet);//Ethernet header offset
	v4hdr = (struct ipheader*)(in_packet + SIZE_ETHERNET);//IP header offset
	udpMsg2 = (struct udpheader*)(in_packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
	ES_payload = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset
	
	printf("\n---------------------------------------------------------------------\n");
    printf("Grabbed packet of length %d\n", header->len);
	printf("\n---------------------------------------------------------------------\n");
	printf("\n");
	
	//Retrieve  flag and call appropriate function 
	for (getData = OFFSET; getData < FLAG_LEN; getData++)
	{
		msgFlag[getData] =  ES_payload[getData];//Fill payload array for decryption
	}//endFOR
	
	switch (msgFlag[0])
		{
        case 0x01:
			printf("\nKey Establishment Message Type 1 recognized\n");
			//Retrieve message 1 random number
			printf("\nRandom Number:\n");
			appendData = 0;
			for (getData = 1; getData < MSG1_PAYLOAD_LEN + 1; getData++)
			{
				ES_RandomNum[appendData] = ES_payload[getData];//Fill payload array for decryption
				printf("%c", ES_RandomNum[appendData]);
				appendData++;
			}//endFOR
			printf("\n");
			pcap_breakloop(Channel204);
			KE_secondMessage();//Create and send message 2
			pcap_next(Channel204, NEXT_INCOMING, handleMsg, NULL);
		break;
		
		case 0x02:
		break;
		
		case 0x03:
			printf("\nKey Establishment Message Type 3 recognized\n");
		break;
		
		case 0x04:
		break;
		
		case 0x05:
		break;
		
		case 0x06:
		break;
		
		case 0x07:
		break;
		
		case 0x08:
		break;
		
		case 0x09:
		break;
		
		case 0x10:
		break;
		
		case 0x11:
		break;
		
		case 0x12:
		break;
		
		default: printf("\nUnrecognized message\n");
		break;
		}//endSWITCH
}//end_HANDLE_MSG
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                MAIN
//---------------------------------------------------------------------------------------
void main()
{
	///call functions to start communication
	openInterfaces();//Open channels for sending and receiving
	
    //Start sniffing incoming packets on all ports...//maybe just 1 for now //need to thread/fork this sp the sniff simultaneosly
	//pcap_loop(Channel201, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 4
	//pcap_loop(Channel202, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 0
	//pcap_loop(Channel203, PACKET_COUNT, packetHandler, NULL);//Start packet capture on port 1
        pcap_loop(Channel204, NEXT_INCOMING, handleMsg, NULL);//Start packet capture on port 2

}//end_MAIN