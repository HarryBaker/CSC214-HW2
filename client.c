/* Harry Baker & John Brady
CSC214, Stone
HW2 - Client-Server protocol
February 24, 2015
client.c - contains client-side protocols
*/



//Step 1:
C -> S: {N1, EC}ES
//Generate Nonce
//Generate Encrypted Keypair
	 unsigned char pk[24];
     unsigned char sk[24];
     unsigned char n[24];
     
     crypto_box_keypair(pk,sk); //generate keypair
     crypto_box_keypair(n,n); //generate nonce
//Create Message 
     const unsigned char m[200]; 
     unsigned long long mlen = 200.0;
     unsigned char c[200];
     crypto_box(c,m,mlen,n,pk,sk);
//Send to server


S -> C: {M1, {h(M1)}DS}EC
C -> S: {M2, {h(M2)}DC}ES
S -> C: {M3, {h(M3)}DS}EC