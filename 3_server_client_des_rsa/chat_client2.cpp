#include "../main_header.h"

/* Run code
    cd "...\" ; if ($?) { g++ chat_client1.cpp -o chat_client1 -lws2_32 } ; if ($?) { .\chat_client1 }
*/

CONNECTION con;
HANDLE listen_thread, send_thread;
const long long int P = 7, Q = 23;
string client_id = "bertold";

struct Data{
    SOCKET sock;
    string key;
};

Data createNewData (){
    Data temp;
    temp.sock = 0;
    temp.key = "0123456789ABCDEF";
    return temp;
}

DWORD WINAPI listenThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
    SOCKET clientSocket = data.sock;
	DES_Encryption DES; 
    CHAT message;
    message.setKey(data.key);
    string received_message;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;

    while (true) {
        // Menerima panjang pesan dari server
        bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        if (bytesReceived <= 0) {
            cerr << "\n\nError receiving message length.\nClosing thread.\n";
            CloseHandle(send_thread);
            break;
        }
        // Membuat buffer sesuai panjang pesan dari server
        char* buffer = new char[messageLength+1];
        // Menerima pesan dari server
        bytesReceived = recv(clientSocket, buffer, messageLength, 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message.\n";
            delete[] buffer;
            CloseHandle(send_thread);
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
    Data data = *static_cast<Data*>(lpParam);
    SOCKET clientSocket = data.sock;
	DES_Encryption DES; 
    CHAT message;
    message.setKey(data.key);
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

int recv_key(SOCKET client_socket, string msg){
    int n_client = 0, bytesReceived;
    bytesReceived = recv(client_socket, reinterpret_cast<char*>(&n_client), sizeof(n_client), 0);
    if (bytesReceived <= 0) {
        cerr << msg << "\n";
        con.closeSocket(client_socket);
        return -1;
    }
    return n_client;
}

int main() {
    // Jika return -1 maka error
    if (con.startClientSocket(12345, "127.0.0.1") == -1) return 0;
    if (con.startClient() == -1) return 0;
    SOCKET client_socket = con.getClientSocket();
    
    RSA rsa(P, Q);
    int bytesReceived = 0, 
        n_client = 0, 
        n_server = 0, 
        n_client_from_server=0, 
        n_client_encrypt = 0, 
        n_server_encrypt = 0, 
        n_client_from_server_encrypt=0, 
        idLength=0,
        des_key_len = 16;
    int self_ekey = rsa.getPublicKey().first;
    int self_nkey = rsa.getPublicKey().second;
    pair<int, int> server_pk;
    string des_key = "";
    
    // Pertukaran public key
    cout << "PUBLIC KEY DISTRIBUTION\nclient public key\n"; 
    cout << self_ekey << "\n";
    cout << self_nkey << "\n";
    send(client_socket, reinterpret_cast<char*>(&self_ekey), sizeof(self_ekey), 0);
    send(client_socket, reinterpret_cast<char*>(&self_nkey), sizeof(self_nkey), 0);
    cout << "server public key\n\n"; 
    if ((server_pk.first = recv_key(client_socket, "Error receiving client public key.")) == -1) return 0;
    if ((server_pk.second = recv_key(client_socket, "Error receiving client public key.")) == -1) return 0;
    cout << server_pk.first << "\n";
    cout << server_pk.second << "\n\n";

    // Pertukaran N
    cout << "N CLIENT KEY EXCHANGE" << "\n";
    // Skema 1
    n_client = rsa.generateKeyDistribution(server_pk.first, server_pk.second);
    n_client_encrypt = rsa.encrypt(n_client, server_pk.first, server_pk.second);
    send(client_socket, reinterpret_cast<char*>(&n_client_encrypt), sizeof(n_client_encrypt), 0);
    cout << "n C in C: " << n_client << "\n";
    cout << "n C using S pk encrypt: " << n_client_encrypt << "\n";
    // Skema 2
    bytesReceived = recv(client_socket, reinterpret_cast<char*>(&n_client_from_server_encrypt), sizeof(n_client_from_server_encrypt), 0);
    if (bytesReceived <= 0) {
        cerr << "Error receiving client n_key.\n";
        con.closeSocket(client_socket);
        return 0;
    }
    n_client_from_server = rsa.decrypt(n_client_from_server_encrypt);
    cout << "n C from S using C pk encrypt: " << n_client_from_server_encrypt << "\n";
    cout << "n C from S: " << n_client_from_server << "\n\n";
    if (n_client_from_server != n_client){
        cerr << "Conection failed due to wrong n_key client from server\n";
        con.closeSocket(client_socket);
        return 0;
    }
    
    cout << "N SERVER KEY EXCHANGE" << "\n";
    // Skema 3
    bytesReceived = recv(client_socket, reinterpret_cast<char*>(&n_server_encrypt), sizeof(n_server_encrypt), 0);
    if (bytesReceived <= 0) {
        cerr << "Error receiving server n_key.\n";
        return 0;
    }
    n_server = rsa.decrypt(n_server_encrypt);
    cout << "n S from S using C pk encrypt: " << n_server_encrypt << "\n";
    cout << "n S from S: " << n_server << "\n";
    // Skema 4
    n_server_encrypt = rsa.encrypt(n_server, server_pk.first, server_pk.second);
    send(client_socket, reinterpret_cast<char*>(&n_server_encrypt), sizeof(n_server_encrypt), 0);
    cout << "n S using S pk encrypt: " << n_server_encrypt << "\n\n";
    
    // Mengirim id client ke server
    cout << "CLIENT ID SEND" << "\n";
    cout << client_id << "\n\n";
    int messageLength = client_id.length();
    send(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
    send(client_socket, client_id.c_str(), messageLength, 0);
    
    // Penerimaan des key
    cout << "DES KEY RECEIVE" << "\n";
    char* buffer = new char[des_key_len+1];
    bytesReceived = recv(client_socket, buffer, des_key_len, 0);
    if (bytesReceived <= 0) {
        cerr << "Error receiving des key from server.\n";
        delete[] buffer;
        return 0;
    }        
    buffer[bytesReceived] = '\0';
    des_key = buffer;
    cout << des_key << "\n\n";
    delete[] buffer;

    // Memulai percakapan
    Data data = createNewData();
    data.sock = client_socket;
    data.key = des_key;
    send_thread = CreateThread(NULL, 0, sendThread, &data, 0, NULL);
    listen_thread = CreateThread(NULL, 0, listenThread, &data, 0, NULL);
    
    if (listen_thread == NULL || send_thread == NULL) {
        cerr << "Error creating threads" << endl;
    }

    WaitForSingleObject(listen_thread, INFINITE);
    WaitForSingleObject(send_thread, INFINITE);

    CloseHandle(listen_thread);
    CloseHandle(send_thread);
    
    con.closeSocket(client_socket);
    con.cleanUp();
    return 0;
}