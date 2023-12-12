#include "../main_header.h"

/* Run code
    cd "...\" ; if ($?) { g++ chat_client.cpp -o chat_client -lws2_32 } ; if ($?) { .\chat_client }
*/

DWORD WINAPI listenThread(LPVOID lpParam) {
    SOCKET clientSocket = *static_cast<SOCKET*>(lpParam);
	DES_Encryption DES; 
    CHAT message;
    string received_message;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;

    while (true) {
        // Menerima panjang pesan dari server
        bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message length.\n";
            break;
        }
        // Membuat buffer sesuai panjang pesan dari server
        char* buffer = new char[messageLength+1];
        // Menerima pesan dari server
        bytesReceived = recv(clientSocket, buffer, messageLength, 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message.\n";
            delete[] buffer;
            break;
        }
        // Batasi string dengan null agar hanya ditampilkan string yang sesuai
        buffer[bytesReceived] = '\0';
        message.setMessage(buffer);
        // DES Decryption
        message.messageDecryption();
        cout << "\n\nReceived message from server: " << buffer << "\n";
        cout << "Actual message from server: " << message.getMessage() << "\n\n";
        // Hapus buffer setelah digunakan agar memori tidak tertumpuk
        delete[] buffer;
        cout << "Enter a message: ";
    }
    return 0; 
}

DWORD WINAPI sendThread(LPVOID lpParam) {
    SOCKET clientSocket = *static_cast<SOCKET*>(lpParam);
	DES_Encryption DES; 
    CHAT message;
    string userMessage;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;

    while (true) {
        // Prompt pesan kepada user server
        cout << "Enter a message: "; getline(cin, userMessage); cout << "\n";
        message.setMessage(userMessage);
        // DES Encryption
        message.messageEncryption();
        // Kirim panjang pesan yang akan diterima oleh client
        messageLength = message.getMessage().length();
        send(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        // Kirim pesan ke client
        send(clientSocket, message.getMessage().c_str(), messageLength, 0);
    }
    return 0; 
}

int main() {
    CONNECTION con;
    // Jika return -1 maka error
    if (con.startClientSocket(12345, "127.0.0.1") == -1) return 0;
    if (con.startClient() == -1) return 0;
    SOCKET clientSocket = con.getClientSocket();
    
    HANDLE thread1, thread2;
    thread1 = CreateThread(NULL, 0, listenThread, &clientSocket, 0, NULL);
    thread2 = CreateThread(NULL, 0, sendThread, &clientSocket, 0, NULL);

    if (thread1 == NULL || thread2 == NULL) {
        cerr << "Error creating threads" << endl;
        return 1;
    }

    WaitForSingleObject(thread1, INFINITE);
    WaitForSingleObject(thread2, INFINITE);

    CloseHandle(thread1);
    CloseHandle(thread2);
    
    con.closeSocket(clientSocket);
    con.cleanUp();
    return 0;
}