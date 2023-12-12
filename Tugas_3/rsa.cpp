#include "../main_header.h"

int main()
{
	long long int p = 11, q = 17;
	RSA rsa(p, q); 
    long long int public_key = 1;
	srand(time(0));
	// public_key <= p*q-2
	for (int i = 0; i < 5; i++) 
        public_key = public_key * rand() % (p*q-1);
	cout << public_key << "\n";
	cout << rsa.encrypt(public_key) << "\n";
	cout << rsa.decrypt(rsa.encrypt(public_key)) << "\n";

	cout << rsa.getPublicKey().first << "\n";
	cout << rsa.getPublicKey().second << "\n";

	CHAT msg;
	msg.randomizeKey();
	cout << msg.getKey();
	return 0;
}