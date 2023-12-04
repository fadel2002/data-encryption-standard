#include "../main_header.h"

DWORD WINAPI listenThread(LPVOID lpParam) {
    SOCKET clientSocket = *static_cast<SOCKET*>(lpParam);
	DES_Encryption DES; 
    CHAT chat;
    string received_message;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;

    while (true) {
        // Menerima panjang pesan dari client
        bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message length.\n";
            break;
        }
        // Membuat buffer sesuai panjang pesan dari client
        char* buffer = new char[messageLength+1];
        // Menerima pesan dari client
        bytesReceived = recv(clientSocket, buffer, messageLength, 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message.\n";
            delete[] buffer;
            break;
        }
        // Batasi string dengan null agar hanya ditampilkan string yang sesuai
        buffer[bytesReceived] = '\0';
        chat.setMessage(buffer);
        // DES Decryption
        chat.messageDecryption();
        cout << "\n\nReceived message from client: " << buffer << "\n";
        cout << "Actual message from client: " << chat.getMessage() << "\n\n";
        // Hapus buffer setelah digunakan agar memori tidak tertumpuk
        delete[] buffer;
        cout << "Enter a message: ";
    }

    return 0; 
}

DWORD WINAPI sendThread(LPVOID lpParam) {
    SOCKET clientSocket = *static_cast<SOCKET*>(lpParam);
	DES_Encryption DES; 
    CHAT chat;
    string userMessage;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;

    while (true) {
        // Prompt pesan kepada user server
        cout << "Enter a message: "; getline(cin, userMessage); cout << "\n";
        chat.setMessage(userMessage);
        // DES Encryption
        chat.messageEncryption();
        // Kirim panjang pesan yang akan diterima oleh client
        messageLength = chat.getMessage().length();
        send(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        // Kirim pesan ke client
        send(clientSocket, chat.getMessage().c_str(), messageLength, 0);
    }
    return 0; 
}

int main() {
    CONNECTION con;
    // Jika return -1 maka error
    if (con.startServerSocket(12345, INADDR_ANY) == -1) return 0;
    if (con.startServer() == -1) return 0;
    SOCKET serverSocket = con.getServerSocket();
    SOCKET clientSocket = con.getClientSocket();

    HANDLE thread1, thread2;
    thread1 = CreateThread(NULL, 0, listenThread, &clientSocket, 0, NULL);
    thread2 = CreateThread(NULL, 0, sendThread, &clientSocket, 0, NULL);

    // Check if threads are created successfully
    if (thread1 == NULL || thread2 == NULL) {
        cerr << "Error creating threads" << endl;
        return 1;
    }

    WaitForSingleObject(thread1, INFINITE);
    WaitForSingleObject(thread2, INFINITE);

    CloseHandle(thread1);
    CloseHandle(thread2);

    con.closeSocket(clientSocket);
    con.closeSocket(serverSocket);
    con.cleanUp();
    return 0;
}
