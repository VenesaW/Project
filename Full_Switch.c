/*
	Switch using libpcap library
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
#include "aes.h"//For AES

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
//                STATIC DECLARATIONS
//---------------------------------------------------------------------------------------
//Ethernet structure properties
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
#define PACKET_CREATE 10 //How many packets to send
#define PACKET_DATA 486 //Example AFDX message with 486 bytes of data
#define PACKET_PAYLOAD 444 //Example AFDX message with 486 bytes of data - 444 bytes form the payload
#define PACKET_SIZE 518 //Example AFDX message with 486 bytes of data and a 32 byte message digest
#define PCAP_NETMASK_UNKNOWN 0xffffffff//default netmask

//Listen for the next [x] packets
#define NEXT_INCOMING 1 

//Packet lengths (total)
#define ACC_DENY_LEN 48 //Length of ACCEPT/DENY packet
#define CHALLENGE_REQUEST_LEN 106 //Length of CHALLENGE REQUEST packet
#define CHALLENGE_RESPONSE_LEN 74 //Length of CHALLENGE RESPONSE packet
#define INI_PACKET_LEN 47 //Size of initial packet
#define KEY_EST_MSG1_LEN 46 //Length of KEY EST MSG 1 packet
#define KEY_EST_MSG2_LEN 74 //Length of KEY EST MSG 2 packet
#define KEY_EST_MSG3_LEN 66 //Length of KEY EST MSG 3 packet

//Payload lengths
#define ACCEPT_DENY_LEN 6 //Length of accept following successful initialization
#define CHALLENGE_LEN 32 //Length of challenge for system establishment
#define DATA_FIELD_LEN 8 //Length of random number for key establishment
#define IDENTIFIER_LEN 8 //Length of random number for key establishment
#define KEY_ID_LEN 5 //Length of identifers for current key, next key and master key
#define KEYING_MAT_LEN 8 //Length of keying material for key establishment
#define RANDOM_NUM_LEN 4 //Length of random number for key establishment
#define MSG2_CONCAT_LEN 32 //Length of concatenated message 2
#define MSG3_CONCAT_LEN 24 //Length of concatenated message 3

#define OFFSET 0 //Offset of payload in packet

//Keying and hashing material lengths
#define AES_BLOCK 64 //Size of AES block
#define HASH_LEN 8 //Size of hash is 32 bytes
#define KEY_LEN 16 //Key length of secret key (128 bits)
#define CHAS_SUBKEY 4 //Key length of CHASKEY subkey
#define CHAS_SUBSTRING 2 //Key length of CHASKEY subkey
#define SUB_STR_LEN 2 //For holding character pairs for key transformation

///AES https://github.com/kokke/tiny-AES-c
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
  
//Channel/Packet parameters
unsigned char ES201_identifier[KEY_ID_LEN] = "ES201";
unsigned char ES202_identifier[KEY_ID_LEN] = "ES202";
unsigned char ES203_identifier[KEY_ID_LEN] = "ES203";
unsigned char ES204_identifier[KEY_ID_LEN] = "ES204";
u_char *Interface201 = "eth0.201";//Pointer to port 4
u_char *Interface202 = "eth0.202";//Pointer to port 1
u_char *Interface203 = "eth0.203";//Pointer to port 0
u_char *Interface204 = "eth0.204";//Pointer to port 2

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
//UDP header parameters for initialization
struct udpheaderInitialization {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char identifier;//Hash value of AFDX payload
};
//UDP header parameters for regular usage
struct udpheader {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char message_digest;//Hash value of AFDX payload
};
//UDP header parameters for challenge request
struct udpheaderChallenge {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char message_challenge;//Encrypted hash challenge from switch
};
//UDP header parameters for challenge response
struct udpheaderResponse {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char message_response;//Accept/Deny based on ES challenge response
};
//UDP header parameters for ISO/IEC 11770-2 Mechanism 6 message 1
struct udpheaderMsg1 {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char msg_1;//Message 1 of key establishment from ES
};
//UDP header parameters for ISO/IEC 11770-2 Mechanism 6 message 2
struct udpheaderMsg2 {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char msg_2;//Message 2 of key establishment from switch
};
//UDP header parameters for ISO/IEC 11770-2 Mechanism 6 message 3
struct udpheaderMsg3 {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char msg_3;//Message 3 of key establishment from ES
};
//UDP header parameters for ISO/IEC 11770-6 OKDF 4
struct udpheaderOKDF {
	unsigned short source_port;//Source port number
	unsigned short dest_port;//Destination port number
	unsigned short udp_length;//UDP packet length
	unsigned short udp_checksum;//UDP checksum (optional)
	unsigned char okdf_output;//OKDF output
};
//---------------------------------------------------------------------------------------
//                GLOBAL DECLARATIONS
//---------------------------------------------------------------------------------------
//For keying material
char* ES201_Key = "AA112233445566778899AABBCCDDEEFF";//pointer to master key (encryption and decryption) as a character stream
char* ES202_Key = "AA112233445566778899AABBCCDDEEFF";//pointer to master key (encryption and decryption) as a character stream
char* ES203_Key = "AA112233445566778899AABBCCDDEEFF";//pointer to master key (encryption and decryption) as a character stream
char* ES204_Key = "AA112233445566778899AABBCCDDEEFF";//pointer to master key (encryption and decryption) as a character stream
unsigned char ES201_masterKey[KEY_LEN];//master key as hex
unsigned char ES202_masterKey[KEY_LEN];//master key as hex
unsigned char ES203_masterKey[KEY_LEN];//master key as hex
unsigned char ES204_masterKey[KEY_LEN];//master key as hex
unsigned char subString[SUB_STR_LEN];//holds key during trasnformation from cracter string to hex format

unsigned char iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

char* keyStream;//pointer to the session key, generated as a character stream

unsigned char hash[HASH_LEN];//memory area for chaskey output hash; should be at most 128-bits (32 characters; 16 bytes)
unsigned char sessionKey_curr[CHAS_SUBKEY];//current session key (hashing)
unsigned char sessionKey_next[CHAS_SUBKEY];//key session key (hashing)
unsigned char subString[CHAS_SUBSTRING];//holds keyStream during trasnformation from character string to hex format

unsigned int chaskeySubkey1[KEY_LEN];//subkey1
unsigned int chaskeySubkey2[KEY_LEN];//subkey2
unsigned int chaskeyMsgLen;
unsigned int hashLen = 8;

//For channel
bpf_u_int32 netMask;//Subnet mask
bpf_u_int32 ipAddr;//IP address
char errorBuffer[PCAP_ERRBUF_SIZE];//Error buffer for sniffing channel. Errors encountered during sniffing are stored here
pcap_t* Channel201;//Channel for packet capture on port 4
pcap_t* Channel202;//Channel for packet capture on port 1
pcap_t* Channel203;//Channel for packet capture on port 0
pcap_t* Channel204;//Channel for packet capture on port 2
struct bpf_program compiledCode;//Stores compiled program for filtering the incoming traffic

//For packets
const char *hex_digits = "0123456789ABCDEF";//For generating payloads
unsigned char plaintext[PACKET_PAYLOAD];//Plaintext message for hashing (regular usage)
///initialization packet
unsigned char the_identifier[KEY_ID_LEN];//Identifier from ES to switch 
unsigned char *identifierPayload;//Pointer to packet payload with identifier from ES
unsigned char ini_packet[INI_PACKET_LEN];//Initialization packet from ES to switch
///challenge packet (request and response)
unsigned char *challengeRequestPayload;//Pointer to packet payload with challenge request from Switch
unsigned char *challengeResponsePayload;//Pointer to packet payload with challenge response from Switch
unsigned char *challengeRequestDigest;//Pointer to calculated message digest for challenge request
unsigned char *challengeResponseDigest;//Pointer to calculated message digest for challenge response
unsigned char crq_packet[CHALLENGE_REQUEST_LEN];//Challenge request packet
unsigned char crp_packet[CHALLENGE_RESPONSE_LEN];//Challenge response packet
unsigned char the_challenge[CHALLENGE_LEN];//Challenge request in payload
unsigned char the_request[CHALLENGE_LEN];//Challenge request
unsigned char the_response[CHALLENGE_LEN];//Challenge response
///accept/deny packet
unsigned char *accept_reject;//Pointer to packet payload with response from Switch
unsigned char accept_packet[ACC_DENY_LEN];//Array to hold accept or deny reponse packet
unsigned char acceptConnection[ACCEPT_DENY_LEN];
unsigned char AcceptDeny[ACC_DENY_LEN];//Array to hold accept packet payload
///key establishment packets
unsigned char *keyEST_mg1;//Pointer to packet payload with key establishment message 1
unsigned char *keyEST_mg2;//Pointer to packet payload with key establishment message 2
unsigned char *keyEST_mg3;//Pointer to packet payload with key establishment message 3
unsigned char msg2_concat[MSG2_CONCAT_LEN];//Array to hold concatenated message 2
unsigned char msg3_concat[MSG3_CONCAT_LEN];//Array to hold concatenated message 3
unsigned char msg1_packet[KEY_EST_MSG1_LEN];//Array to hold key establishment message 1 packet
unsigned char msg2_packet[KEY_EST_MSG2_LEN];//Array to hold key establishment message 2 packet
unsigned char msg3_packet[KEY_EST_MSG3_LEN];//Array to hold key establishment message 3 packet
unsigned char msg_packet1[RANDOM_NUM_LEN];//Array to hold message 1 packet payload
unsigned char msg_packet2[MSG2_CONCAT_LEN];//Array to hold message 2 packet payload
unsigned char msg_packet3[MSG3_CONCAT_LEN];//Array to hold message 3 packet payload
///key establishment parameters
unsigned char random_numberES[RANDOM_NUM_LEN];
unsigned char random_numberSw[RANDOM_NUM_LEN];
unsigned char identifer_ES[IDENTIFIER_LEN];
unsigned char key_est_keyingMaterial[KEYING_MAT_LEN];
unsigned char key_est_data[DATA_FIELD_LEN];

//For loops
int appendChallenge;//Used in FOR loop to append challenge at switch
int appendCiphertext;//Used in FOR loop to extract and append cipher text
int appendMaster;//Used in FOR loop to extract and append key
int appendParameter;//Used in FOR loop to append key establishment parameters
int appendRandomNumber;//Used in FOR loop to append random number
int appendResponse;//Used in FOR loop to append response

int compareID;//Used in FOR loop to compare Key ID
int compareChallenge;//Used in FOR loop to compare challenge request and response

int getAcceptDeny;//Used in FOR loop to extract accept/deny response
int getChallenge;//Used in FOR loop to extract challenge from packet
int getCiphertext;//Used in FOR loop to extract cipher text
int getID;//Used in FOR loop to extract Key ID
int getKey;//Used in FOR loop to extract and append key
int getParameter;//Used in FOR loop to get key establishment parameters
int getPayload;//Used in FOR loop to get packet payload
int getRandomNumber;//Used in FOR loop to extract random number in message 1
int getRequest;//Used in FOR loop to extract request
int getResponse;//Used in FOR loop to extract and append response

//Misc.
int initialization_failure;//Error count
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
void chaskey(unsigned char *hash, const unsigned char *msg, const unsigned int key[4], const unsigned int subkey1[4], const unsigned int subkey2[4])
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
//				GENERATE CHALLENGE
//---------------------------------------------------------------------------------------
void generateChallenge (){
			
	for (getChallenge = 0; getChallenge < CHALLENGE_LEN; getChallenge++)
	{
		the_challenge[getChallenge] = hex_digits[(rand() % 256)];//Generate challenge
		the_request[getChallenge] = the_challenge[getChallenge];
	}//endFOR
}//end_GENERATEE_CHALLENGE
//---------------------------------------------------------------------------------------
//				GENERATE CHALLENGE REQUEST PACKET
//---------------------------------------------------------------------------------------
void challengeRequestPacket (){
	//Build challenge response packet
		//dstMAC
	crq_packet[0] = (0xaa);
	crq_packet[1] = (0x01);
	crq_packet[2] = (0x02);
	crq_packet[3] = (0x03);
	crq_packet[4] = (0x04);
	crq_packet[5] = (0x05);//Pi switch
		//src_MAC
	crq_packet[6] = (0xbb);
	crq_packet[7] = (0x01);
	crq_packet[8] = (0x02);
	crq_packet[9] = (0x03);
	crq_packet[10] = (0x04);
	crq_packet[11] = (0x05);//PC
		//ether_type
	crq_packet[12] = (0x08);
	crq_packet[13] = (0x00);
	//IPv4
	crq_packet[14] = (0x45);
	crq_packet[15] = (0x00);
	//total_length
	crq_packet[16] = (0x00);
	crq_packet[17] = (0x1a);
	//identification
	crq_packet[18] = (0x1d);
	crq_packet[19] = (0x94);
	//flags
	crq_packet[20] = (0x00);
	//fragment
	crq_packet[21] = (0x00);
	//ttl
	crq_packet[22] = (0x01);
	//protocol
	crq_packet[23] = (0x11);
	//ip_checksum
	crq_packet[24] = (0x91);
	crq_packet[25] = (0x6e);
	//src_ip
	crq_packet[26] = (0xc0);
	crq_packet[27] = (0xa8);
	crq_packet[28] = (0xb2);
	crq_packet[29] = (0x5a);//Pi/9/0
		//dst_ip
	crq_packet[30] = (0xc0);
	crq_packet[31] = (0xa8);
	crq_packet[32] = (0xb2);
	crq_packet[33] = (0x5c);//PC//92
		//src_port
	crq_packet[34] = (0x07);
	crq_packet[35] = (0xd0);
	//dst_port
	crq_packet[36] = (0x04);
	crq_packet[37] = (0x15);
	//udp_length
	crq_packet[38] = (0x01);
	crq_packet[39] = (0x07);
	//udp_checksum
	crq_packet[40] = (0x00);
	crq_packet[41] = (0x00);
	
	getChallenge = 0;//initialize for FOR loop
	//append response to packet
	for (appendChallenge = 42; appendChallenge < CHALLENGE_REQUEST_LEN; appendChallenge++)
	{
		crq_packet[appendChallenge] = the_request[getChallenge];
		getChallenge++;
	}//endFOR
}//end_CHALLENGE_REQUEST_PACKET
//---------------------------------------------------------------------------------------
//				CHALLENGE REQUEST TO ES
				//1) Get initialization packet
				//2) Extract identifier from packet
				//3) Find matching key
				//4) Create challenge
				//5) Hash challenge
				//6) Encrypt challenge
				//7) Generate packet
				//8) Append encrypted challenge
				//9) Send packet
//---------------------------------------------------------------------------------------
void initializationHandler(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet)
{
	struct ethernetHeader *ethdr = NULL;//Initialize struct
	struct ipheader *v4hdr = NULL;//Initialize struct
	struct udpheaderInitialization *udpIni = NULL;//Initialize struct
	struct AES_ctx ctx;//Initialize AES struct

	ethdr = (struct ethernetHeader*)(in_packet);//Ethernet header offset
	v4hdr = (struct ipheader*)(in_packet + SIZE_ETHERNET);//IP header offset
	udpIni = (struct udpheaderInitialization*)(in_packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
	identifierPayload = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Challenge offset

	chaskeyMsgLen = 32;
	
	//Retrieve challenge request
	for (getID = OFFSET; getID < IDENTIFIER_LEN; getID++)
	{
		the_identifier[getID] = identifierPayload[getID];//Fill payload array for decryption
	}//endFOR
	
	//match ID --> successful: create and send challenge
	if (0 == memcmp((char*)ES201_identifier, (char*)the_identifier, KEY_ID_LEN))
	{
		printf("201 SUCCESS!\n");
		generateChallenge();//Generate challenge
		subkeys(chaskeySubkey1, chaskeySubkey2, (unsigned int*)ES201_masterKey);
		chaskey(hash, the_challenge, (unsigned int*)ES201_masterKey, chaskeySubkey1, chaskeySubkey2);//pointer to returned chasekey mac calculation
		//Encrypt challenge
		AES_init_ctx_iv(&ctx, ES201_masterKey, iv);
		AES_CBC_encrypt_buffer(&ctx, the_request, AES_BLOCK);
		challengeRequestPacket();//Generate packet
		pcap_sendpacket(Channel201, crq_packet, INI_PACKET_LEN);//Challenge request packet
	} else if(0 == memcmp((char*)ES202_identifier, (char*)the_identifier, KEY_ID_LEN)){
		printf("202 SUCCESS!\n");
		generateChallenge();//Generate challenge
		subkeys(chaskeySubkey1, chaskeySubkey2, (unsigned int*)ES202_masterKey);
		chaskey(hash, the_challenge, (unsigned int*)ES202_masterKey, chaskeySubkey1, chaskeySubkey2);//pointer to returned chasekey mac calculation
		//Encrypt challenge
		AES_init_ctx_iv(&ctx, ES202_masterKey, iv);
		AES_CBC_encrypt_buffer(&ctx, the_request, AES_BLOCK);
		challengeRequestPacket();//Generate packet
		pcap_sendpacket(Channel202, crq_packet, INI_PACKET_LEN);//Challenge request packet
	} else if(0 == memcmp((char*)ES203_identifier, (char*)the_identifier, KEY_ID_LEN)){
		printf("203 SUCCESS!\n");
		generateChallenge();//Generate challenge
		subkeys(chaskeySubkey1, chaskeySubkey2, (unsigned int*)ES203_masterKey);
		chaskey(hash, the_challenge, (unsigned int*)ES203_masterKey, chaskeySubkey1, chaskeySubkey2);//pointer to returned chasekey mac calculation
		//Encrypt challenge
		AES_init_ctx_iv(&ctx, ES203_masterKey, iv);
		AES_CBC_encrypt_buffer(&ctx, the_request, AES_BLOCK);
		challengeRequestPacket();//Generate packet
		pcap_sendpacket(Channel203, crq_packet, INI_PACKET_LEN);//Challenge request packet
	} else if(0 == memcmp((char*)ES204_identifier, (char*)the_identifier, KEY_ID_LEN)){
		printf("204 SUCCESS!\n");
		generateChallenge();//Generate challenge
		subkeys(chaskeySubkey1, chaskeySubkey2, (unsigned int*)ES204_masterKey);
		chaskey(hash, the_challenge, (unsigned int*)ES204_masterKey, chaskeySubkey1, chaskeySubkey2);//pointer to returned chasekey mac calculation
		//Encrypt challenge
		AES_init_ctx_iv(&ctx, ES204_masterKey, iv);
		AES_CBC_encrypt_buffer(&ctx, the_request, AES_BLOCK);
		challengeRequestPacket();//Generate packet
		pcap_sendpacket(Channel204, crq_packet, INI_PACKET_LEN);//Challenge request packet
	} else {
		//otherwise --> close channel
		printf("ERORR!\n");
		initialization_failure++;
		pcap_close(Channel204);//Close channel on port 2
	}//end_IF_ELSE
		
}//end_INITIALIZATION_HANDLER
//---------------------------------------------------------------------------------------
//                OPEN CHANNEL FOR LISTENING
					//1) Check if interfaces are available
					//2) Open selected interface
						//a) Call function to select interface
//---------------------------------------------------------------------------------------
void openInterfaces()
{
    //Port 4 (Eth0.201)
    Channel201 = pcap_open_live(Interface201, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 4
    pcap_setdirection(Channel201, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel201, &compiledCode, "len >= 47", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel201, &compiledCode);//Apply filter to incoming traffic
//Port 0 (Eth0.202)
    Channel202 = pcap_open_live(Interface202, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 0
    pcap_setdirection(Channel202, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel202, &compiledCode, "len >= 47", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel202, &compiledCode);//Apply filter to incoming traffic
//Port 1 (Eth0.203)
    Channel203 = pcap_open_live(Interface203, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 1
    pcap_setdirection(Channel203, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel203, &compiledCode, "len >= 47", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
    pcap_setfilter(Channel203, &compiledCode);//Apply filter to incoming traffic
//Port 2 (Eth0.204)
    Channel204 = pcap_open_live(Interface204, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//Open incoming channel on port 2
    pcap_setdirection(Channel204, PCAP_D_IN);//Sniff incoming traffic
    pcap_compile(Channel204, &compiledCode, "len >= 47", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
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
    pcap_loop(Channel204, NEXT_INCOMING, initializationHandler, NULL);//Start packet capture on port 2

	//Channel is open --> call function to listen for Initialization packet

}//endOPEN_INTERFACES
//---------------------------------------------------------------------------------------
//					FORMAT MASTER KEYS FROM CHARACTER STREAM TO HEX
//---------------------------------------------------------------------------------------
void formatMasterKeys()
{
	//ES201 master key
	memcpy(subString, ES201_Key, 2);
	ES201_masterKey[0] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 2, 2);
	ES201_masterKey[1] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 4, 2);
	ES201_masterKey[2] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 6, 2);
	ES201_masterKey[3] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 8, 2);
	ES201_masterKey[4] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 10, 2);
	ES201_masterKey[5] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 12, 2);
	ES201_masterKey[6] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 14, 2);
	ES201_masterKey[7] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 16, 2);
	ES201_masterKey[8] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 18, 2);
	ES201_masterKey[9] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 20, 2);
	ES201_masterKey[10] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 22, 2);
	ES201_masterKey[11] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 24, 2);
	ES201_masterKey[12] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 26, 2);
	ES201_masterKey[13] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 28, 2);
	ES201_masterKey[14] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES201_Key + 30, 2);
	ES201_masterKey[15] = strtoul(subString, NULL, HASH_LEN);
	
	//ES202 master key
	memcpy(subString, ES202_Key, 2);
	ES202_masterKey[0] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 2, 2);
	ES202_masterKey[1] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 4, 2);
	ES202_masterKey[2] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 6, 2);
	ES202_masterKey[3] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 8, 2);
	ES202_masterKey[4] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 10, 2);
	ES202_masterKey[5] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 12, 2);
	ES202_masterKey[6] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 14, 2);
	ES202_masterKey[7] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 16, 2);
	ES202_masterKey[8] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 18, 2);
	ES202_masterKey[9] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 20, 2);
	ES202_masterKey[10] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 22, 2);
	ES202_masterKey[11] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 24, 2);
	ES202_masterKey[12] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 26, 2);
	ES202_masterKey[13] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 28, 2);
	ES202_masterKey[14] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES202_Key + 30, 2);
	ES202_masterKey[15] = strtoul(subString, NULL, HASH_LEN);
	
	//ES203 master key
	memcpy(subString, ES203_Key, 2);
	ES203_masterKey[0] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 2, 2);
	ES203_masterKey[1] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 4, 2);
	ES203_masterKey[2] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 6, 2);
	ES203_masterKey[3] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 8, 2);
	ES203_masterKey[4] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 10, 2);
	ES203_masterKey[5] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 12, 2);
	ES203_masterKey[6] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 14, 2);
	ES203_masterKey[7] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 16, 2);
	ES203_masterKey[8] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 18, 2);
	ES203_masterKey[9] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 20, 2);
	ES203_masterKey[10] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 22, 2);
	ES203_masterKey[11] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 24, 2);
	ES203_masterKey[12] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 26, 2);
	ES203_masterKey[13] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 28, 2);
	ES203_masterKey[14] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES203_Key + 30, 2);
	ES203_masterKey[15] = strtoul(subString, NULL, HASH_LEN);

	//ES204 master key
	memcpy(subString, ES204_Key, 2);
	ES204_masterKey[0] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 2, 2);
	ES204_masterKey[1] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 4, 2);
	ES204_masterKey[2] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 6, 2);
	ES204_masterKey[3] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 8, 2);
	ES204_masterKey[4] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 10, 2);
	ES204_masterKey[5] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 12, 2);
	ES204_masterKey[6] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 14, 2);
	ES204_masterKey[7] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 16, 2);
	ES204_masterKey[8] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 18, 2);
	ES204_masterKey[9] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 20, 2);
	ES204_masterKey[10] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 22, 2);
	ES204_masterKey[11] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 24, 2);
	ES204_masterKey[12] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 26, 2);
	ES204_masterKey[13] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 28, 2);
	ES204_masterKey[14] = strtoul(subString, NULL, HASH_LEN);
	memcpy(subString, ES204_Key + 30, 2);
	ES204_masterKey[15] = strtoul(subString, NULL, HASH_LEN);
}//end_FORMAT_MASTER_KEYS
 //---------------------------------------------------------------------------------------
//                MAIN
//---------------------------------------------------------------------------------------
void main()
{
	formatMasterKeys();//Character stream to hex
	openInterfaces();//Open channels for listening
	//formatSessionKeys();//Character stream to hex
	
	//Close channels
    pcap_close(Channel201);//Close channel on port 4
    pcap_close(Channel202);//Close channel on port 0
    pcap_close(Channel203);//Close channel on port 1
    pcap_close(Channel204);//Close channel on port 2
}