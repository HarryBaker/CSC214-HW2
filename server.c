/* Harry Baker & John Brady
CSC214, Stone
HW2 - Client-Server protocol
February 24, 2015
server.c - contains server-side protocols
TODO: use gettimeofday as timestamp?
cast time_t to unsigned char?
*/

#include <sys/time.h>

 	 unsigned char pk[24]; //server public key
     unsigned char sk[24]; //server secret key
     unsigned char n1[24]; //first nonce
     unsigned char n2[24]; //second nonce
     unsigned char n3[24]; //third nonce
     unsigned char clientpublic[24]; //client public key

int step2(unsigned char prekey[24], unsigned char serverkey[24], unsigned char io[200]) {
	//copy server private key to sk
	memcpy(sk, serverkey, 24);

     //decrypt message stored in io into plaintext variable
	unsigned char plaintext[200];
	crypto_box_open(plaintext,io,48,n1,prekey,sk);

     //separate nonce from client public key
	memcpy(n1, plaintext, 24);
	memcpy(clientpublic, plaintext[24], 24);

	//generate new nonce N2
	crypto_box_keypair(n2, n2);

	//generate timestamp
	struct timeval timestamp;
	gettimeofday(&timeval, NULL)
	unsigned char timestamp[64] = (unsigned char) timeval.tv_sec; //How should we store/cast timestamp

	//concatenate timestamp and nonces N1 and N2
	unsigned char concat[112];
	memcpy(concat, n1, 24);
	memcpy(concat[24],n2,24);
	memcpy(concat[48],timestamp, 48);

	//create message
	crypto_box(io,concat,112,n2,clientpublic,sk);

	//create signature
		//hash message
		unsigned char hash[34];
		hash = crypt(io, "$1$00000000$");
		//encrypt hash with private key and store in io
		crypto_box(io[112],hash,34,n2,clientpublic,sk);

return 0;
} //step2


M1 contains N1 and EC - server now has first nonce and client's public key
S -> C: {M1, {h(M1)}DS}EC

takes the message it just got, decrypt it, take the nonce N1. Encrypt N1, a new nonce N2, and timestamp T. Concatenate that with its hash. Encrypt with client's public key and send.

