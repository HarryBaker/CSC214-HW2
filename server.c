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
     unsigned char question[24]; //question from client
     unsigned char answer[24]; //answer to client from server

int step2(unsigned char prekey[24], unsigned char serverkey[24], unsigned char io[200]) {
	//copy server private key to sk
	memcpy(sk, serverkey, 24);

     //decrypt message stored in io into plaintext variable
	unsigned char plaintext[200];
	crypto_box_open(plaintext,io,48,(unsigned char) '000000000000000000000000',prekey,sk);

     //separate nonce from client public key
	memcpy(n1, plaintext, 24);
	memcpy(clientpublic, plaintext[24], 24);

	//generate new nonce N2
	crypto_box_keypair(n2, n2);

	//generate timestamp
	struct timeval timestamp;
	gettimeofday(&timeval, NULL);
	unsigned char timestamp[64] = (unsigned char) timeval.tv_sec; //How should we store/cast timestamp

	//concatenate timestamp and nonces N1 and N2
	unsigned char concat[112];
	memcpy(concat, n1, 24);
	memcpy(concat[24],n2,24);
	memcpy(concat[48],timestamp, 48);

	unsigned char message[148];
	memcpy(message, concat, 112);



	//create signature
		//hash message
		unsigned char hash[34];
		hash = crypt(concat, "$1$00000000$");
		//encrypt hash with private key and store in message
		crypto_box(message[112],hash,34,n2,clientpublic,sk);

			//create message
	crypto_box(io,message,148,n2,clientpublic,sk);

return 0;
} //step2

int step4(unsigned char io[200]) {

     //check if signature is valid
     unsigned char decrypthash[34];
     crypto_box_open(decrypthash, io[72],34,n2,clientpublic,sk);
     unsigned char experimenthash[34] = crypt(io, "$1$00000000$");
     //if invalid, exit
     if (diff(experimenthash, decrypthash)){
     	return 1;
     } //if

     //decrypt the message
     unsigned char plaintext[200];
     crypto_box_open(plaintext, io,72,n2,clientpublic,sk);
     //check that nonce n2 matches
     unsigned char receivedn2[24];
     memcpy(receivedn2, io, 24);
     //if nonces don't match, exit
     if (diff(n2, receivedn2)){
     	return 1;
     } //if

     //copy nonce n3 out of message
     memcpy(n3, io[24], 24);

     //copy question out of message
     memcpy(question, io[48], 24);
     //answer question
     (int) answer = (int) question * (int) question;
     //concatenate n3 and the answer A
     unsigned char concat[48];
     memcpy(concat, n3, 24);
     memcpy(concat[24], answer, 24);
     unsigned char message[82];
     memcpy(message, concat, 48)

  	//generate hash of encrypted message
     unsigned char hash[34];
     hash = crypt(concat, "$1$00000000$");
	//encrypt hash with private key and store in io
	crypto_box(message[48],hash,34,n2,serverpublic,sk);


     //encrypt message
     crypto_box(io, message, 82, n3, clientpublic, sk);

     return 0; 

} //step4



