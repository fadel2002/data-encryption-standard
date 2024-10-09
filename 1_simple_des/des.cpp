#include "../main_header.h"

void hexInput(string key);
void asciiInput(string key);

int main(){
    bool is_valid;
	string key;

	cout << "Enter a key of exactly 16 character written in hexadecimal : ";
	do {
		is_valid = true;
		cin >> key;

		if (key.size() != 16)
			is_valid = false;
		else{
			for (int i = 0; i < key.size(); i++)
				if (!((key[i] <= 'f' && key[i] >= 'a') ||
					(key[i] <= 'F' && key[i] >= 'A') ||
					(key[i] >= '0' && key[i] <= '9')))
				{
					is_valid = false;
					break;
				}
		}
		if (!is_valid)
			cout << "invalid input, try again : ";
	} while (!is_valid);

    printf("\n1 Input hexadecimal\n2 Input any string\n\n>> ");
    int option; cin >> option;
    while (option < 1 || option > 2){
        printf("No option, re-enter choice\n\n>> ");
        cin >> option;
    }

    if (option == 1)
        hexInput(key);
    else 
        asciiInput(key);
    
	return 0;
}

void asciiInput(string key)
{
	DES_Encryption DES; 
	string plain_txt, hexa_text;
	int iteration;
	
	cout << "\nEnter plain text : ";

	getchar();
	getline(cin, plain_txt); 

	// Untuk input ascii maka semua string text diubah dulu menjadi hexa
	hexa_text = DES.ASCIItoHEX(plain_txt);

	// Menentukan banyaknya iterasi yang dilakukan untuk menghitung semua panjang 
	// string per 64 bit / 16 karakter
	iteration = DES.countIteration(hexa_text);

	// Menambahkan padding jika string tidak per 64 bit
	hexa_text = DES.addPadding(iteration, hexa_text);
	cout << "\nHexadec   : " << hexa_text << "\n";

	// Encrypt hexa secara berurutan dengan panjang per 16 karakter atau 64 bit
	string result_encrypted = DES.recurrentEncryption(iteration, hexa_text, key);
	cout << "Encrypted : " << result_encrypted << "\n";

	// Decrypt hexa secara berurutan dengan panjang per 16 karakter atau 64 bit
	string result_decrypted = DES.recurrentDecryption(iteration, result_encrypted, key);
	
	cout << "Decrypted : " << result_decrypted << "\n";
	cout << "ASCII     : " << DES.hexToASCII(result_decrypted) << "\n";
}

void hexInput(string key)
{
	DES_Encryption DES; 
	string hexa_text;
	int iteration;
	
	cout << "\nEnter hexa text : ";

	cin >> hexa_text;

	// Menentukan banyaknya iterasi yang dilakukan untuk menghitung semua panjang 
	// string per 64 bit / 16 karakter
	iteration = (int)ceil((float)hexa_text.size()/16.0);

	// Tambahkan padding jika jumlah hexa bukan merupakan kelipatan 16
	// Contoh panjang hexa 14 sedangkan DES menerima 64 bit sehingga diperlukan 16 hexa
	// maka ditambahkan dengan padding yaitu 00 sehingga hexa sekarang ialah 16
	string padding = "";
	for(int i=iteration*16-hexa_text.size(); i>0; i--){
		padding = padding + "0";
	}
	hexa_text = hexa_text + padding;

	cout << "\nHexadec   : " << hexa_text << "\n";

	// Encrypt hexa secara berurutan dengan panjang per 16 karakter atau 64 bit
	string temp = "";
	string result_encrypted = "";
	for(int i=0; i<iteration; i++){
		for (int j=i*16; j<(i+1)*16; j++){
			temp = temp + hexa_text[j];
		}
		result_encrypted = result_encrypted + DES.encrypt(temp, key, false);
		temp = "";
	}

	cout << "Encrypted : " << result_encrypted << "\n";

	// Decrypt hexa secara berurutan dengan panjang per 16 karakter atau 64 bit
	string result_decrypted = "";
	for(int i=0; i<iteration; i++){
		for (int j=i*16; j<(i+1)*16; j++){
			temp = temp + result_encrypted[j];
		}
		result_decrypted = result_decrypted + DES.encrypt(temp, key, true);
		temp = "";
	}
	
	cout << "Decrypted : " << result_decrypted << "\n";
}