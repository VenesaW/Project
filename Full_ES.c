/*
	ES using libpcap library
*/
//---------------------------------------------------------------------------------------
//                WARNINGS
//---------------------------------------------------------------------------------------
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
//---------------------------------------------------------------------------------------
//                LIBRARIES
//---------------------------------------------------------------------------------------
#include "aes.h"//For AES
#include<assert.h>//Provides a macro called assert which can be used to verify assumptions made by the program and print a diagnostic message if this assumption is false
#include<errno.h>//Defines macros for reporting and retrieving error conditions
#include<math.h>//For mathematical fuctions
#include<pcap.h>//For libpcap library
#include<stdint.h>//Allow programmers to write more portable code by providing a set of typedefs that specify exact-width integer types, together with the defined minimum and maximum allowable values for each type
#include<stdio.h>//Defines three variable types, several macros, and various functions for performing input and output
#include<stdlib.h>//Defines four variable types, several macros, and various functions for performing general functions
#include<string.h>//Defines one variable type, one macro, and various functions for manipulating arrays of characters
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
#define SIZE_ETHERNET 14 //Ethernet headers are always exactly 14 bytes
#define SIZE_IP 20 //IP headers are always 20 bytes
#define SIZE_UDP 8 //UDP header length are 8 bytes
#define SNAP_LEN 1518 //default maximum bytes per packet to capture
#define TAG_LEN 1 //1 Byte

//Listen for the next [x] packets
#define NEXT_INCOMING 1 

//Packet lengths (total)
#define KEY_EST_MSG1_LEN 59 //Length of KEY EST MSG 1 packet
#define KEY_EST_MSG3_LEN 91 //Length of KEY EST MSG 3 packet
#define KEY_EST_MSG5_LEN 75 //Length of KEY EST MSG 5 packet
#define KEY_EST_MSG67_LEN 59 //Length of KEY EST MSG 5 packet
#define NONCE_LEN 16 //16 Byte random number (Nonce) for key establishment
#define RANDOM_NUM_LEN 16 //16 Byte random number (Nonce) for key establishment
#define KEYING_MAT_LEN 16 //16 Byte keying material for key establishment

//Payload lengths
#define ANSWER_LEN 2 //Length of success/failure answer for key establishment
#define CHALLENGE_LEN 16 //Length of challenge for key establishment
#define IDENTIFIER_LEN 8 //Length of identifier for key establishment
#define MSG2_ENC_LEN 64 //Length of encrypted payload for message 2
#define MSG2_CONCAT_LEN 54 //Length of concatenated payload for message 2
#define MSG3_ENC_LEN 48 //Length of encrypted payload for message 3
#define MSG3_CONCAT_LEN 38 //Length of concatenated payload for message 3
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
char* ESMaster_Key = "AA112233445566778899AABBCCDDEEFF";//pointer to master key (encryption and decryption) as a character stream
///Session Key paramaters
unsigned int ESSession_Key[KEY_LEN] = { 0x833D3433, 0x009F389F, 0x2398E64F, 0x417ACF39 };//master key as hex
unsigned int next_ESSession_Key;
unsigned char sessionKey[33] = "833D3433009F389F2398E64F417ACF39";//master key as hex
unsigned int chaskeySubkey1[KEY_LEN];//subkey1
unsigned int chaskeySubkey2[KEY_LEN];//subkey2
unsigned int chaskeyMsgLen;
unsigned int hashLen = 8;

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
struct bpf_program compiledCode;//Stores compiled program for filtering the incoming traffic

//For packets
///key establishment packets
unsigned char msg1_packet[KEY_EST_MSG1_LEN];//Array to hold key establishment message 1 packet
unsigned char msg3_packet[KEY_EST_MSG3_LEN];//Array to hold key establishment message 3 packet
unsigned char msg3_concat[MSG3_CONCAT_LEN];//Array to hold concatenated key establishment message 3
unsigned char msg5_packet[KEY_EST_MSG5_LEN];//Array to hold key establishment message 5 packet
unsigned char msg5_encrypt[] = " ";//Array to hold concatenated key establishment message 5
unsigned char msg1_TAG[TAG_LEN] = "1";//TAG for Key Establishment message 1
unsigned char msg2_TAG[TAG_LEN] = "2";//TAG for Key Establishment message 2 
unsigned char msg3_TAG[TAG_LEN] = "3";//TAG for Key Establishment message 3
unsigned char msg4_TAG[TAG_LEN] = "4";//TAG for Key Establishment message 4
unsigned char msg5_TAG[TAG_LEN] = "5";//TAG for Key Establishment message 5
unsigned char msg6_TAG[TAG_LEN] = "6";//TAG for Key Establishment message 6
///key establishment packet parameters (outgoing)
unsigned char ES_RandomNum[RANDOM_NUM_LEN] = "C6065B5FBC61B1B1";//16 Byte Random number for Key Establishment message 1
unsigned char ES_ESID[IDENTIFIER_LEN] = "FEDCBAED";//Identifier for Key Establishment message 3
unsigned char ES_SWID[IDENTIFIER_LEN] = "DCBFEAED";//Identifier for comparison in Key Establishment message 2
unsigned char ES_keyMat[KEYING_MAT_LEN] = "29961282D2848EAE";//Keying material for Key Establishment message 3
unsigned char ES_Nonce[NONCE_LEN] = "B9908C25A5CFDFDA";//Nonce for Key Establishment message 3
unsigned char ES_challengeResponse[HASH_LEN];//Challenge response for Key Establishment message 5
unsigned char successfulMSG[ANSWER_LEN] = "59";//Successful response for Key Establishment message 6
///key establishment packets parameters (incoming)
unsigned char switch_RandomNum[RANDOM_NUM_LEN];//Random number from Key Establishment message 2
unsigned char switch_ESID[IDENTIFIER_LEN];//Identifier from Key Establishment message 2
unsigned char switch_keyMat[KEYING_MAT_LEN];//Keying material from Key Establishment message 2
unsigned char switch_Nonce[NONCE_LEN];//Nonce from Key Establishment message 2
unsigned char switch_Challenge[CHALLENGE_LEN];//Challenge from Key Establishment message 4
unsigned char switch_Answer[KEY_EST_MSG67_LEN];//Answer from Key Establishment message 6/7
///key establishment packet checkpoints
unsigned char *switch_payload;//Pointer to packet payload for incoming Key Establishment messages
unsigned char encrypted_payload[] = " ";//Array to hold encrypted Key Establishment messages
unsigned char incoming_payload[] = " ";//Array to hold incoming Key Establishment messages
unsigned char integrity_payload[RANDOM_NUM_LEN];//Array to hold the integrity value from incoming Key Establishment messages
unsigned char KE_Answer[ANSWER_LEN];//Answer from Key Establishment message 6/7

///key derivation function
double d;//ceiling value //d = Lb/Lh
double Lb = 128;//bit length of the output of the KDF//size of 128 bit key to be extracted from output
double Lh = 64;//bit length of the output of the hash//Chaskey outputs a 64 bit hash

int Lc = 32;//bit-length of the binary encoding of the counter c//encoded as a 32-bit, big-endian bit string
int c;//counter

char b[32] = " ";//128 bit key (32 characters) to be extracted from output
char p[8] = "HMI00001";//Label
char s[32];//concatenation of keying materials (FA||FB)
char salt[20] = "AA112233445566778899";//*****************************************************************************
char u[20] = "AA112233445566778899";//auxilary value
char h[] = " ";
char z[] = " ";//bit string output of Chaskey from which to take key

///Regular key usage
unsigned char hashCalculated[HASH_LEN];//Hash calculated by the switch
unsigned char hashValue[HASH_LEN];//Packet hash value
unsigned char packet[PACKET_SIZE];//Array to hold regular AFDX message with hash
unsigned char plaintext[PACKET_PAYLOAD];//Plaintext message for hashing

unsigned char *hashedPacket;//Pointer to packet segment for hashing
unsigned char *oldDigest;//Pointer to packet message digest
unsigned char *newDigest;//Pointer to recalculated message digest

//unsigned int BAG = 2000;//The BAG value for the ES

const char *hex_digits = "0123456789ABCDEF";//Used to generate payload

///Counters
int keyCheck = 0;
int key_usage_threshold = 0;
int key_change_over_threshold = 0;
int kdf_failure = 0;
int mac_mismatch = 0;
int toggleBit;

///For loops
int appendData;//Used in for loop for parsing packet parameters
int getData;//Used in FOR loop to get packet payload

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
//                GRAB INTERFACE FOR SENDING PACKET
///For Windows System
//---------------------------------------------------------------------------------------
char *getInterface(pcap_if_t *alldevs)
{
	for (select_Interface = alldevs, num_interfaces = 0; num_interfaces < 3; select_Interface = select_Interface->next, num_interfaces++);
	return select_Interface->name;//Return interface 2
}//endGET_INTERFACE

//---------------------------------------------------------------------------------------
//                GET LIST OF INTERFACES FOR SENDING PACKET
///For Windows System
//---------------------------------------------------------------------------------------
//1) Check if interfaces are available
//2) Open selected interface
	//a) Call function to select interface
void openInterfaces()
{
	if (pcap_findalldevs(&all_Interfaces, errorBuffer) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errorBuffer);
		exit(EXIT_FAILURE);
	}//endIF

	/*
	pcap_if_t *iterate_Interfaces;//Interates through list of available interfaces
	//Print the list of devices
	printf("\nlisting interfaces\n");
	for (iterate_Interfaces = all_Interfaces; iterate_Interfaces; iterate_Interfaces = iterate_Interfaces->next)
	{
		printf("%d. %s", ++list_interfaces, iterate_Interfaces->name);
		if (iterate_Interfaces->description)
			printf(" (%s)\n", iterate_Interfaces->description);
		else
			printf(" (Sorry, No description available for this device)\n");
	}//endFOR
	*/

	Interface = getInterface(all_Interfaces);//Get Ethernet interface 2 or 3 for Windows PC
	//printf("selected: (%s)\n", select_Interface->description);
	outChannel = pcap_open_live(Interface, SNAP_LEN, INTERFACE_MODE, READ_TIMEOUT, errorBuffer);//OpenChannel on sender interface
	pcap_setdirection(outChannel, PCAP_D_IN);//Sniff incoming traffic
	pcap_compile(outChannel, &compiledCode, "dst port 1046", 1, PCAP_NETMASK_UNKNOWN);//Compile the filter expression
	pcap_setfilter(outChannel, &compiledCode);//Apply filter to incoming traffic

	if (outChannel == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errorBuffer);//Channel could not be opened
		exit(EXIT_FAILURE);//Exit program
	}//endIF
	//Channel is open --> return to main to call function to send Initialization packet
}//endOPEN_INTERFACES
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                HANDLING REGULAR HASHED MESSAGES
					//1)Extract hash
					//2)Calculate hash
					//3)Compare hashes
//---------------------------------------------------------------------------------------
void handle_incoming(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet)
{
	struct ethernetHeader *ethdr = NULL;//Initialize struct
	struct ipheader *v4hdr = NULL;//Initialize struct
	struct udpheader *udpMsg = NULL;//Initialize struct

	ethdr = (struct ethernetHeader*)(in_packet);//Ethernet header offset
	v4hdr = (struct ipheader*)(in_packet + SIZE_ETHERNET);//IP header offset
	udpMsg = (struct udpheader*)(in_packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
	switch_payload = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset
	hashedPacket = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset
	oldDigest = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP + PACKET_PAYLOAD);//Hash offset

	subkeys(chaskeySubkey1, chaskeySubkey2, ESSession_Key);//call to key schedule function

	//printf("\nPAYLOAD: \n");
	for (getData = OFFSET; getData < PACKET_PAYLOAD; getData++) {
		// Start printing on the next after every 16 octets
		/*if ((getData % 16) == 0){
			printf("\n");//print on next line
		}//endIF*/
		//printf("%02x ", hashedPacket[getData]);//Print in hexadecimal format
		plaintext[getData] = hashedPacket[getData];//Fill payload array for hash calculation
		//printf("%c", plaintext[getData]);
	}//endFOR

	printf("\n\nold DIGEST: \n");
	for (getData = OFFSET; getData < HASH_LEN; getData++) {
		//printf("%02x", oldDigest[getData]);//Print in hexadecimal format
		hashValue[getData] = oldDigest[getData];//Fill hash from incoming message
		printf("%02x", hashValue[getData]);
	}//endFOR

	//MAC generation
	//Calculate hash and compare to appended hash
	chaskey(hash, plaintext, ESSession_Key, chaskeySubkey1, chaskeySubkey2);//pointer to returned chasekey mac calculation
	memcpy(hashCalculated, hash, HASH_LEN);//Copy hash to message digest array

	printf("\n\nnew DIGEST: \n");
	for (getData = OFFSET; getData < HASH_LEN; getData++) {
		//Start printing on the next after every 16 octets
		if ((getData % 16) == 0) {
			printf("\n");//Print on next line
		}//endIF
		printf("%02x", hashCalculated[getData]);//Print in hexadecimal format
	}//endFOR

	//Compare hashes
	if (memcmp(hashValue, hashCalculated, sizeof(hashValue)) == 0)
	{
		printf("\n\n>>>>hashes matched....packet forwarded to upper layers\n\n");
		printf("\n---------------------------------------------------------------------\n");
	}//endIF
	//increment error counter
	//countinue listening until error threshold*************************************************************
}//end_HANDLE_INCOMING
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                GENERATING REGULAR HASHED MESSAGES
					//1)Generate message
					//2)Calculate and append hash
					//3)Send message
					//4)Increment key usage count
//---------------------------------------------------------------------------------------
void regularUsage()
{
	//Generate packet
	//Build AFDX message
		//dstMAC (ES1, VL1)
	packet[0] = (0x45);//E
	packet[1] = (0x53);//S
	packet[2] = (0x31);//1
	packet[3] = (0x56);//V
	packet[4] = (0x4c);//L
	packet[5] = (0x31);//1
		//src_MAC (ES4, VL1)
	packet[6] = (0x45);//E
	packet[7] = (0x53);//S
	packet[8] = (0x34);//4
	packet[9] = (0x56);//V
	packet[10] = (0x4c);//L
	packet[11] = (0x31);//1
		//ether_type
	packet[12] = (0x08);
	packet[13] = (0x00);
	//IPv4
	packet[14] = (0x45);
	packet[15] = (0x00);
	//total_length
	packet[16] = (0x00);
	packet[17] = (0x1a);
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
	packet[29] = (0x5a);//Pi//90
		//dst_ip
	packet[30] = (0xc0);
	packet[31] = (0xa8);
	packet[32] = (0xb2);
	packet[33] = (0x5c);//PC//92
		//src_port
	packet[34] = (0x04);
	packet[35] = (0x16);
	//dst_port
	packet[36] = (0x04);
	packet[37] = (0x15);
	//udp_length
	packet[38] = (0x01);
	packet[39] = (0x07);

	do {
		//Payload maximum 1417 bytes(offset 0x42)
		getData = 0;
		for (appendData = 42; appendData < PACKET_DATA; appendData++)
		{
			packet[appendData] = hex_digits[(rand() % 256)];//***Generate new payload for each packet
			plaintext[getData] = packet[appendData];
			getData++;
		}//endFOR
		//printf("\nPacket built\n");

		subkeys(chaskeySubkey1, chaskeySubkey2, ESSession_Key);//call to key schedule function

		//MAC generation
		chaskey(hash, plaintext, ESSession_Key, chaskeySubkey1, chaskeySubkey2);//pointer to returned chasekey mac calculation

		printf("\n\nDIGEST: %d\n", sizeof(hash));

		//Append and print MAC to end of packet
		for (int getData = 0; getData < HASH_LEN; getData++)
		{
			packet[appendData] = hash[getData];//Append digest
			appendData++;

			if ((getData % 16) == 0) {
				printf("\n");
			}//endIF
			printf("%02x", hash[getData]);

		}//endFOR

		//Send Packet
		pcap_sendpacket(outChannel, packet, PACKET_SIZE);//Packet is 486 bytes (based on example AFDX pcap) + 32 bytes of hash
		printf("\n\npacket sent\n");

		key_usage_threshold++;
		key_change_over_threshold++;
		switch (keyCheck)
		{
		case 0:
			if (key_usage_threshold >= KEY_UPDATE_MAX)
			{
				if (next_ESSession_Key == NULL)
				{
					//generate new key*******************************************************************
				}

				printf("\nnext key available\n");
				keyCheck = 1;//set to 1 now that the key update threshold has been met
			}//endIF
			break;

		case 1:
			if (key_change_over_threshold >= KEY_CHANGE_OVER_MAX)
			{
				//update toggle bit
				if (toggleBit == 0)
				{
					toggleBit = 1;
				}
				else
				{
					toggleBit = 0;
				}

				//update key pointer

				printf("\nevent: key change over\n");
				keyCheck = 0;//set to 0 now that the key change-over threshold has been met
			}//endIF
			break;
		}//endSWITCH

			///Listen for incoming then loop back
		pcap_loop(outChannel, NEXT_INCOMING, handle_incoming, NULL);//Start packet capture on port 2

	//}//endFOR
	} while (1);//endWHILE

	pcap_close(outChannel);//close channel on which packets are sent
}////end_REGULAR_USAGE
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                HANDLING KEY DERIVATION MESSAGE 4 FROM Switch
					//1)Extract challenge
					//2)Create hash
//---------------------------------------------------------------------------------------
void handleKE_successfailureMsg(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet)
{
	struct ethernetHeader *ethdr = NULL;//Initialize struct
	struct ipheader *v4hdr = NULL;//Initialize struct
	struct udpheader *udpMsgReg = NULL;//Initialize struct

	ethdr = (struct ethernetHeader*)(in_packet);//Ethernet header offset
	v4hdr = (struct ipheader*)(in_packet + SIZE_ETHERNET);//IP header offset
	udpMsgReg = (struct udpheader*)(in_packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
	switch_payload = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset

	//Retrieve message 6/7 payload challenge
	for (getData = OFFSET; getData < KEY_EST_MSG67_LEN; getData++)
	{
		switch_Answer[getData] = switch_payload[getData];
	}//endFOR

	//Retrieve message 6/7 payload
	appendData = 0;
	for (getData = 0; getData < ANSWER_LEN; getData++)
	{
		KE_Answer[getData] = switch_Answer[getData];
		appendData++;
	}//endFOR
	//Retrieve message 6/7 payload integrity value
	for (getData = 0; getData < CHALLENGE_LEN; getData++)
	{
		integrity_payload[getData] = switch_Answer[appendData];
		appendData++;
	}//endFOR


	//Compare I(ES) and I(ES)'
	if ((0 == memcmp((char*)integrity_payload, (char*)successfulMSG, ANSWER_LEN)))
	{
		//save key

		///Start using key
		regularUsage();
	}
	else {
		//otherwise --> close channel
		printf("ERORR!\n");
		//kdf_failure++;//Increment error count
		pcap_close(outChannel);//Close channel OR //start over??*********************************************************************************************************************************
	}//end_IF_ELSE
}//end_HANDLE_KE_SUCCESS_FAILURE_MESSAGE
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                FIFTH KDF MESSAGE TO Switch
				//1) The ES sends the hash of the challenge
//---------------------------------------------------------------------------------------
void KE_fifthMessage()
{
	//Generate packet
	//Build KDF message 5
		//dstMAC (ES1, VL1)
	msg5_packet[0] = (0x45);//E
	msg5_packet[1] = (0x53);//S
	msg5_packet[2] = (0x31);//1
	msg5_packet[3] = (0x56);//V
	msg5_packet[4] = (0x4c);//L
	msg5_packet[5] = (0x31);//1
	//src_MAC (ES4, VL1)
	msg5_packet[6] = (0x45);//E
	msg5_packet[7] = (0x53);//S
	msg5_packet[8] = (0x34);//4
	msg5_packet[9] = (0x56);//V
	msg5_packet[10] = (0x4c);//L
	msg5_packet[11] = (0x31);//1
		//ether_type
	msg5_packet[12] = (0x08);
	msg5_packet[13] = (0x00);
	//IPv4
	msg5_packet[14] = (0x45);
	msg5_packet[15] = (0x00);
	//total_length
	msg5_packet[16] = (0x00);
	msg5_packet[17] = (0x1a);
	//identification
	msg5_packet[18] = (0x1d);
	msg5_packet[19] = (0x94);
	//flags
	msg5_packet[20] = (0x00);
	//fragment
	msg5_packet[21] = (0x00);
	//ttl
	msg5_packet[22] = (0x01);
	//protocol
	msg5_packet[23] = (0x11);
	//ip_checksum
	msg5_packet[24] = (0x91);
	msg5_packet[25] = (0x6e);
	//src_ip
	msg5_packet[26] = (0xc0);
	msg5_packet[27] = (0xa8);
	msg5_packet[28] = (0xb2);
	msg5_packet[29] = (0x5a);//Pi//90
		//dst_ip
	msg5_packet[30] = (0xc0);
	msg5_packet[31] = (0xa8);
	msg5_packet[32] = (0xb2);
	msg5_packet[33] = (0x5c);//PC//92
		//src_port
	msg5_packet[34] = (0x04);
	msg5_packet[35] = (0x16);
	//dst_port
	msg5_packet[36] = (0x04);
	msg5_packet[37] = (0x15);
	//udp_length
	msg5_packet[38] = (0x01);
	msg5_packet[39] = (0x07);
	//udp_checksum
	msg5_packet[40] = (0x00);
	msg5_packet[41] = (0x00);

	appendData = 42;
	for (getData = 0; getData < HASH_LEN; getData++)
	{
		msg5_packet[appendData] = msg5_encrypt[getData];
		appendData++;
	}//endFOR

	//send packet
	pcap_sendpacket(outChannel, msg5_packet, KEY_EST_MSG5_LEN);//KDF message 5 packet

	//listen for KE message 6/7 from ES
	pcap_loop(outChannel, NEXT_INCOMING, handleKE_successfailureMsg, NULL);//Start packet capture on port 2
}//end_KE_FIFTH_MESSAGE
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                HANDLING KEY DERIVATION MESSAGE 4 FROM Switch
					//1)Extract challenge
					//2)Create hash
//---------------------------------------------------------------------------------------
/*void handleKE_Msg4(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet)
{
	struct ethernetHeader *ethdr = NULL;//Initialize struct
	struct ipheader *v4hdr = NULL;//Initialize struct
	struct udpheader *udpMsg2 = NULL;//Initialize struct
	struct AES_ctx ctx;//Initialize struct

	ethdr = (struct ethernetHeader*)(in_packet);//Ethernet header offset
	v4hdr = (struct ipheader*)(in_packet + SIZE_ETHERNET);//IP header offset
	udpMsg2 = (struct udpheader*)(in_packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
	switch_payload = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset

	//Retrieve message 4 payload challenge
	for (getData = OFFSET; getData < CHALLENGE_LEN; getData++)
	{
		switch_Challenge[getData] = switch_payload[getData];//Fill payload array for hashing
	}//endFOR

	//decrypt message
	//Call decryption program
	AES_init_ctx_iv(&ctx, ESMaster_Key, iv);
	AES_CBC_decrypt_buffer(&ctx, switch_Challenge, AES_BLOCK);

	chaskeyMsgLen = 16;
	//Generate challenge response
	chaskey(hash, switch_payload, ESSession_Key, chaskeySubkey1, chaskeySubkey2);
	memcpy(msg5_encrypt, hash, HASH_LEN);

	//Encrypt concatenation
	AES_init_ctx_iv(&ctx, ESMaster_Key, iv);
	///Call encryption function
	AES_CBC_encrypt_buffer(&ctx, msg5_encrypt, AES_BLOCK);
	//Append challenge response key establishment

	KE_fifthMessage();

}//end_HANDLE_KE_MSG_4*/
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                THIRD KDF MESSAGE TO Switch
				//1) The ES sends the switch the random numbers R(switch) and R(ES), and the keying material F(switch)
				//2) The data fields are encrypted using the master key
//---------------------------------------------------------------------------------------
void KE_thirdMessage()
{
	struct AES_ctx ctx;//Initialize struct

	//Generate packet
	//Build KDF message 3
		//dstMAC (ES1, VL1)
	msg3_packet[0] = (0x45);//E
	msg3_packet[1] = (0x53);//S
	msg3_packet[2] = (0x31);//1
	msg3_packet[3] = (0x56);//V
	msg3_packet[4] = (0x4c);//L
	msg3_packet[5] = (0x31);//1
	//src_MAC (ES4, VL1)
	msg3_packet[6] = (0x45);//E
	msg3_packet[7] = (0x53);//S
	msg3_packet[8] = (0x34);//4
	msg3_packet[9] = (0x56);//V
	msg3_packet[10] = (0x4c);//L
	msg3_packet[11] = (0x31);//1
		//ether_type
	msg3_packet[12] = (0x08);
	msg3_packet[13] = (0x00);
	//IPv4
	msg3_packet[14] = (0x45);
	msg3_packet[15] = (0x00);
	//total_length
	msg3_packet[16] = (0x00);
	msg3_packet[17] = (0x1a);
	//identification
	msg3_packet[18] = (0x1d);
	msg3_packet[19] = (0x94);
	//flags
	msg3_packet[20] = (0x00);
	//fragment
	msg3_packet[21] = (0x00);
	//ttl
	msg3_packet[22] = (0x01);
	//protocol
	msg3_packet[23] = (0x11);
	//ip_checksum
	msg3_packet[24] = (0x91);
	msg3_packet[25] = (0x6e);
	//src_ip
	msg3_packet[26] = (0xc0);
	msg3_packet[27] = (0xa8);
	msg3_packet[28] = (0xb2);
	msg3_packet[29] = (0x5a);//Pi//90
		//dst_ip
	msg3_packet[30] = (0xc0);
	msg3_packet[31] = (0xa8);
	msg3_packet[32] = (0xb2);
	msg3_packet[33] = (0x5c);//PC//92
		//src_port
	msg3_packet[34] = (0x04);
	msg3_packet[35] = (0x16);
	//dst_port
	msg3_packet[36] = (0x04);
	msg3_packet[37] = (0x15);
	//udp_length
	msg3_packet[38] = (0x01);
	msg3_packet[39] = (0x07);
	//udp_checksum
	msg3_packet[40] = (0x00);
	msg3_packet[41] = (0x00);

	//Re-insert and concatenate parameters for key establishment
	///(1) I(Sw) --> Switch Identifier
	appendData = 0;
	for (getData = 0; getData < IDENTIFIER_LEN; getData++)
	{
		msg3_concat[appendData] = ES_SWID[getData];
		appendData++;
	}//endFOR
	///(2) F(ES) --> ES Keying Material
	appendData = 8;
	for (getData = 0; getData < KEYING_MAT_LEN; getData++)
	{
		msg3_concat[appendData] = ES_keyMat[getData];
		appendData++;
	}//endFOR
	///(3) Nonce(ES) --> ES Nonce
	appendData = 24;
	for (getData = 0; getData < NONCE_LEN; getData++)
	{
		msg3_concat[appendData] = ES_Nonce[getData];
		appendData++;
	}//endFOR

	//Encrypt concatenation
	AES_init_ctx_iv(&ctx, ESMaster_Key, iv);
	///Call encryption function
	AES_CBC_encrypt_buffer(&ctx, msg3_concat, AES_BLOCK);

	///Append encrypted payload on to packet
	appendData = 42;
	//Append encrypted payload to packet
	for (getData = 0; getData < MSG3_ENC_LEN; getData++)
	{
		msg3_packet[appendData] = msg3_concat[getData];
		appendData++;
	}//end_FOR

	///Append integrity value on to packet
	appendData = 90;
	//Append encrypted payload to packet
	for (getData = 0; getData < RANDOM_NUM_LEN; getData++)
	{
		msg3_packet[appendData] = switch_RandomNum[getData];
		appendData++;
	}//end_FOR

	//send packet
	pcap_sendpacket(outChannel, msg3_packet, KEY_EST_MSG3_LEN);//KDF message 3 packet

	//listen for KE message 4 from ES
	//pcap_loop(outChannel, NEXT_INCOMING, handleKE_Msg4, NULL);//Start packet capture on port 2
}//end_KE_THIRD_MESSAGE
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                SESSION KEY _ KDF
//---------------------------------------------------------------------------------------
void sessionKeys()
{
	/*
		Set d = ceil(Lb / Lh)
		If d >= (2Lc), then halt and output invalid
		Set z = empty string
		For c = 1 to d :
			Set z = z || h(s || c || p || t || [u])
			Set b = the leftmost L_b bits of z
	*/
	//concatenate the keying materials to create s
	appendData = 0;
	for (getData = 0; getData < KEYING_MAT_LEN; getData++)
	{
		s[appendData] = switch_keyMat[getData];
		appendData++;
	}
	for (getData = 0; getData < KEYING_MAT_LEN; getData++)
	{
		s[appendData] = ES_keyMat[getData];
		appendData++;
	}


	d = ceil(Lb / Lh);
	//printf("\nd is: %f\n", d);

	if (d >= (2 * Lc))
	{
		printf("\nINVALID\n");
		exit(EXIT_FAILURE);
	} //endIF

	for (c = 1; c <= d; c++)
	{
		//concatenate input strings: s; p; salt; u;
		appendData = 0;
		///(1)s
		for (getData = 0; getData < 32; getData++)
		{
			h[appendData] = s[getData];
			appendData++;
		}//endFOR
		///(2)c
		h[appendData] = c;
		appendData++;

		///(3)p
		for (getData = 0; getData < 8; getData++)
		{
			h[appendData] = p[getData];
			appendData++;
		}//endFOR

		///(4)t
		for (getData = 0; getData < 20; getData++)
		{
			h[appendData] = salt[getData];
			appendData++;
		}//endFOR

		///(5)u
		for (getData = 0; getData < 20; getData++)
		{
			h[appendData] = u[getData];
			appendData++;
		}//endFOR

		chaskeyMsgLen = sizeof(h);

		//call Chaskey
		chaskey(hash, h, ESSession_Key, chaskeySubkey1, chaskeySubkey2);//pointer to returned chaskey mac calculation

		//create z
		for (appendData = 0; appendData < HASH_LEN; appendData++)
		{
			z[appendData] = hash[appendData];
		}//endFOR
	}//endFOR

	for (appendData = 0; appendData < 32; appendData++)
	{
		b[appendData] = z[appendData];
	}//endFOR	
}//endSESSION_KEYS
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                HANDLING KEY DERIVATION MESSAGE 2 FROM Switch
					//1)Read message from switch
					//2)ES sends E[masterkey](R[ES]||R[sw]||F[sw]||Text[2])
					//3)Initiate key derivation function
//---------------------------------------------------------------------------------------
void handleKE_Msg2(u_char *Uselesspointr, const struct pcap_pkthdr *header, const u_char *in_packet)
{
	struct ethernetHeader *ethdr = NULL;//Initialize struct
	struct ipheader *v4hdr = NULL;//Initialize struct
	struct udpheader *udpMsg2 = NULL;//Initialize struct
	struct AES_ctx ctx;//Initialize struct

	ethdr = (struct ethernetHeader*)(in_packet);//Ethernet header offset
	v4hdr = (struct ipheader*)(in_packet + SIZE_ETHERNET);//IP header offset
	udpMsg2 = (struct udpheader*)(in_packet + SIZE_ETHERNET + SIZE_IP);//UDP header offset
	switch_payload = (u_char *)(in_packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);//Payload offset

	printf("\n---------------------------------------------------------------------\n");
	printf("Grabbed packet of length %d\n", header->len);
	printf("\n---------------------------------------------------------------------\n");
	printf("\n");

	//Retrieve message 2 payload encrypted segment
	for (getData = OFFSET + 2; getData < MSG2_ENC_LEN + 2; getData++)
	{
		encrypted_payload[getData] = switch_payload[getData];//Fill payload array for decryption
	}//endFOR

	//Retrieve message 2 integrity value
	for (getData = 0; getData < RANDOM_NUM_LEN + 1; getData++)
	{
		integrity_payload[getData] = switch_payload[getData + 65];//Fill payload array for decryption
	}//endFOR

	//Compare R(ES) == R(ES)
	if ((0 == memcmp((char*)integrity_payload, (char*)ES_RandomNum, RANDOM_NUM_LEN)))
	{
		//decrypt message
		//Call decryption program
		AES_init_ctx_iv(&ctx, ESMaster_Key, iv);
		AES_CBC_decrypt_buffer(&ctx, encrypted_payload, AES_BLOCK);

		for (getData = 0; getData < 64; getData++)
		{
			printf("%02x", encrypted_payload[getData]);
		}
	}
	else {
		//otherwise --> close channel
		printf("\nRandom numbers mismatch error\n");
		kdf_failure++;//Increment error count
		pcap_close(outChannel);//Close channel OR //start over??*********************************************************************************************************************************
	}//end_IF_ELSE

	//Parse payload for:
	///(1) R(switch) --> switch random number as integrity value
	printf("\nRandom:\n");
	appendData = 0;
	for (getData = 0; getData < RANDOM_NUM_LEN; getData++)
	{
		switch_RandomNum[getData] = encrypted_payload[appendData];
		appendData++;
		printf("%02x", switch_RandomNum[getData]);
	}
	printf("\n");
	///(2) I(ES) --> ES identifier
	for (getData = 0; getData < IDENTIFIER_LEN; getData++)
	{
		switch_ESID[getData] = encrypted_payload[appendData];
		appendData++;
		printf("%02x", switch_ESID[getData]);
	}
	///(3) F(switch) --> Keying material
	for (getData = 0; getData < KEYING_MAT_LEN; getData++)
	{
		switch_keyMat[getData] = encrypted_payload[appendData];
		appendData++;
	}
	///(4) N(switch) --> Nonce
	for (getData = 0; getData < NONCE_LEN; getData++)
	{
		switch_Nonce[getData] = encrypted_payload[appendData];
		appendData++;
	}

	//Compare I(ES) and I(ES)'
	if ((0 == memcmp((char*)switch_ESID, (char*)ES_ESID, IDENTIFIER_LEN)))
	{
		printf("match\n");
		//generate session keys
		//sessionKeys();
		//create and send message 3
		//KE_thirdMessage();
	}
	else {
		//otherwise --> close channel
		printf("\nIdentifier mismatch error!\n");
		//kdf_failure++;//Increment error count
		pcap_close(outChannel);//Close channel OR //start over??*********************************************************************************************************************************
	}//end_IF_ELSE
	
}//end_HANDLE_KE_MSG_2
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                FIRST KE MESSAGE TO Switch
				//1) The ES sends the Switch a random number R(ES) in message 1
//---------------------------------------------------------------------------------------
void KE_firstMessage()
{
	//Generate packet
	//Build KDF message 1 packet
		//dstMAC (ES4, VL1)
	msg1_packet[0] = (0x45);//E
	msg1_packet[1] = (0x53);//S
	msg1_packet[2] = (0x31);//1
	msg1_packet[3] = (0x56);//V
	msg1_packet[4] = (0x4c);//L
	msg1_packet[5] = (0x31);//1
	//src_MAC (ES4, VL1)
	msg1_packet[6] = (0x45);//E
	msg1_packet[7] = (0x53);//S
	msg1_packet[8] = (0x34);//4
	msg1_packet[9] = (0x56);//V
	msg1_packet[10] = (0x4c);//L
	msg1_packet[11] = (0x31);//1
		//ether_type
	msg1_packet[12] = (0x08);
	msg1_packet[13] = (0x00);//IPv4
	//IPv4
	msg1_packet[14] = (0x45);
	msg1_packet[15] = (0x00);
	//total_length
	msg1_packet[16] = (0x00);
	msg1_packet[17] = (0x1a);//26 bytes
	//identification
	msg1_packet[18] = (0x1d);
	msg1_packet[19] = (0x94);//random
	//flags
	msg1_packet[20] = (0x00);
	//fragment
	msg1_packet[21] = (0x00);
	//ttl
	msg1_packet[22] = (0x01);
	//protocol
	msg1_packet[23] = (0x11);
	//ip_checksum
	msg1_packet[24] = (0x91);
	msg1_packet[25] = (0x6e);//random
	//src_ip
	msg1_packet[26] = (0xc0);
	msg1_packet[27] = (0xa8);
	msg1_packet[28] = (0xb2);
	msg1_packet[29] = (0x5a);//random
		//dst_ip
	msg1_packet[30] = (0xc0);
	msg1_packet[31] = (0xa8);
	msg1_packet[32] = (0xb2);
	msg1_packet[33] = (0x5c);//random
		//src_port
	msg1_packet[34] = (0x04);
	msg1_packet[35] = (0x16);//random
	//dst_port
	msg1_packet[36] = (0x04);
	msg1_packet[37] = (0x15);//random
	//udp_length
	msg1_packet[38] = (0x00);
	msg1_packet[39] = (0x12);//18 bytes
	//udp_checksum
	msg1_packet[40] = (0xaa);
	msg1_packet[41] = (0xff);//random

	//Append TAG
	msg1_packet[42] = msg1_TAG[0];

	///Random number (NONCE) must be 16 bytes
	getData = 0;//initialize for FOR loop
	//generate and append random number to packet
	for (appendData = 43; appendData < KEY_EST_MSG1_LEN; appendData++)
	{
		msg1_packet[appendData] = ES_RandomNum[getData];
		getData++;
	}//endFOR

	//send packet
	pcap_sendpacket(outChannel, msg1_packet, KEY_EST_MSG1_LEN);//KDF message 1 packet

	//listen for KE message 2 from ES
	pcap_loop(outChannel, NEXT_INCOMING, handleKE_Msg2, NULL);//Start packet capture on port 2
}//end_KE_FIRST_MESSAGE
//////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------------------
//                MAIN
//---------------------------------------------------------------------------------------
void main()
{
	///call functions to start communication
	openInterfaces();//Open channels for sending and receiving
	KE_firstMessage();
}//end_MAIN