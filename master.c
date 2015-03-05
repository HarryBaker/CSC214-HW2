#include "client.c"
#include "server.c"


int main(int argc, char const *argv[])
{
	unsigned char startPk[24];
	unsigned char startSk[24];
	crypto_box_keypair(startPk, startSk); //generate keypair for first step (to avoid using cryptostream)
	unsigned char serverPk[24];
	unsigned char serverSk[24];
	crypto_box_keypair(serverPk, serverSk); //generate keypair for first step (to avoid using cryptostream)

	int text = 100;

	unsigned char io[200]; //passes input and output between client/server


	step1(startPk, serverPk, io); //this starts the chain from the client, starting Step 1 and storing M0 in io
	//Now the server can read io and see the message it was sent from the client. Then update io with the new message.
	step2(startSk, serverSk, io); //server
	//Now the client has the message M1 and can prep and send M2 with the actual question.
	step3(io, (unsigned char) text); //client
	//Now the server has the question Q, checks to make sure the message is from the client, answers the question, and sends it back
	step4(io); //server
	//Now all communication is done. The client gets the answer and we are done.
	step5(io); //client




	return 0;
}

