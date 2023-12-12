#ifndef CHAT_LIB_H   
#define CHAT_LIB_H

/* 
	Function List On CHAT Class:

    randomizeKey();
    void setKey(string k);
    string getKey();
    void setMessage(string msg);
    string getMessage();
    string messageEncryption(string message);
    string messageDecryption(string message);
*/

class CHAT{
    DES_Encryption DES;
    string message = "";
    string key = "0123456789ABCDEF";
public:
    void randomizeKey(){
        int max_char = 16;
        char hexa[max_char] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        long long int val = 1;
        key = "";
        srand(time(0)); 
        while(true){
            val = 1;
            for (int i = 0; i < 5; i++) 
                val = val * rand() % max_char;
            if (val != 1 && val != 0 && val != 2) break;
        }
        for (int i = 0; i<max_char; i++){
            val = (val * (i+1)) + 1;
            key = key + hexa[val % max_char];
        }
    }
    void setKey(string k){
        key = k;
    }
    string getKey(){
        return key;
    }
    void setMessage(string msg){
        message = msg;
    }
    string getMessage(){
        return message;
    }
    void messageEncryption(){
        message = DES.ASCIItoHEX(message);
        int des_iteration = DES.countIteration(message);
        message = DES.addPadding(des_iteration, message);
        message = DES.recurrentEncryption(des_iteration, message, key);
    }
    void messageDecryption(){
        int des_iteration = DES.countIteration(message);
        message = DES.recurrentDecryption(des_iteration, message, key);
        message = DES.hexToASCII(message);
    }
};

#endif