#ifndef CHAT_LIB_H   
#define CHAT_LIB_H

/* 
	Function List On CHAT Class:

    string messageEncryption(string message);
    string messageDecryption(string message);
*/

class CHAT{
    DES_Encryption DES;
    string message = "";
    string key = "0123456789ABCDEF";
public:
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