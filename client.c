/* Harry Baker & John Brady
CSC214, Stone
HW2 - Client-Server protocol
February 24, 2015
client.c - contains client-side protocols
TODO: Why is nonce needed in the crypto_box call? Do we still need to concat and include it in the message if it's called in crypto_box or for step 1, does it just need to be a pre-shared value?
how does crypt know where the end of the message is?
*/

	 unsigned char pk[24]; //client public key
     unsigned char sk[24]; //client secret key
     unsigned char n1[24]; //first nonce
     unsigned char n2[24]; //second nonce
     unsigned char n3[24]; //third nonce
     unsigned char serverpublic[24]; //server's public key


int step1(unsigned char prekey[24], unsigned char serverkey[24], unsigned char io[200]) {

     memcpy(serverpublic, serverkey, 24);
     crypto_box_keypair(pk,sk); //generate keypair
     crypto_box_keypair(n1,n1); //generate nonce 1

     //concatenate nonce 1 and client public key
     unsigned char concat[48];
     memcpy(concat, n1, 24);
     memcpy(concat[24], pk, 24);

     //encrypt with preset key as sender secret key
     crypto_box(io, concat, 48, n1, serverkey, prekey);
return 0;
} //step1

int step3(unsigned char io[200]) {

     //check if signature is valid
     unsigned char decrypthash[34];
     crypto_box_open(decrypthash, io[112],34,n2,serverpublic,sk)
     unsigned char experimenthash[34] = crypt(io, "$1$00000000$")
     //if invalid, exit
     if (diff(experimenthash, decrypthash)){
     	return 1;
     } //if

     //decrypt the message
     unsigned char plaintext[200];
     crypto_box_open(plaintext, io,112,n2,serverpublic,sk)
     //check that nonce n1 matches
     unsigned char receivedn1[24];
     memcpy(receivedn1, io, 24)
     //if nonces don't match, exit
     if (diff(n1 receivedn1)){
     	return 1;
     } //if

     //copy nonce n2 out of message
     memcpy(n2, io[24], 24);

     //copy timestamp out of message
	unsigned char receivedtimestamp[64];
     memcpy(receivedtimestamp, io[48], 64)
     //get new timestamp
    struct timeval timestamp;
	gettimeofday(&timeval, NULL)
	unsigned char timestamp[64] = (unsigned char) timeval.tv_sec;
     //if timestamps are >90 apart, exit
     if (90<(receivedtimestamp-timestamp){
     	return 1;
     } //if

     //Generate n3
     crypto_box_keypair(n3,n3); //generate nonce 3
     //concatenate n2 and n3 and the text
     memcpy
     //encrypt and send
 
} //step3

//Step 1:
C -> S: {N1, EC}ES
//Generate Nonce
//Generate Encrypted Keypair


//Create Message 
     const unsigned char m[200]; 
     unsigned long long mlen = 200.0;
     unsigned char c[200];
     crypto_box(c,m,mlen,n,pk,sk);
//Send to server



C -> S: {M2, {h(M2)}DC}ES
S -> C: {M3, {h(M3)}DS}EC