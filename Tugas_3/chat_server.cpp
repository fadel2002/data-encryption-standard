#include "../main_header.h"

/* Run code
    cd "...\" ; if ($?) { g++ chat_server.cpp -o chat_server -lws2_32 } ; if ($?) { .\chat_server }
*/

struct isConnected {
    SOCKET value = 0;
};

struct desKey {
    string value = "";
};

CONNECTION con;
map<string, isConnected> client_sockets;
map<string, desKey> client_des_keys;
vector<string> client_ids;
const long long int P = 13, Q = 17;

struct Data{
    SOCKET sock;
    HANDLE thread;
    string message;
};

Data createNewData (){
    Data temp;
    temp.sock = 0;
    temp.thread = NULL;
    temp.message = "";
    return temp;
}

DWORD WINAPI sendThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
	DES_Encryption DES; 
    CHAT message;
    string userMessage;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;

    // Split key, nama, dan message
    size_t spacePos = data.message.find(' '); 
    string name = data.message.substr(0, spacePos);
    string msg = data.message.substr(spacePos + 1);
    if (client_sockets[name].value == 0){
        cerr << "No user named " << name << "\n\n";
        return 0; 
    }
    SOCKET client_socket = client_sockets[name].value;
    message.setKey(client_des_keys[name].value);
    message.setMessage(msg);
    // DES Encryption
    message.messageEncryption();
    // Kirim panjang pesan yang akan diterima oleh client
    messageLength = message.getMessage().length();
    send(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
    // Kirim pesan ke client
    send(client_socket, message.getMessage().c_str(), messageLength, 0);
    return 0; 
}

void eraseClient(string val){
    client_ids.erase(remove(client_ids.begin(), client_ids.end(), val), client_ids.end());
    client_sockets[val].value = 0;
    client_des_keys[val].value = "";
    cout << "\n" << val << " has been disconected\nRemaining user:\n";
    for (auto client_id : client_ids)
        cout << client_id << "|";
    cout << "\n";
}

DWORD WINAPI listenThread(LPVOID lpParam) {
    Data data = *static_cast<Data*>(lpParam);
    SOCKET client_socket = data.sock;
	DES_Encryption DES; 
    CHAT message;
    string received_message;
    int messageLength=0;
    int des_iteration=0;
    int bytesReceived=0;
    int des_key_len = 16;
    string des_key = "";

    // Pengiriman key des
    cout << "DES KEY SEND" << "\n";
    message.randomizeKey();
    des_key = message.getKey();
    client_des_keys[data.message].value = des_key; 
    cout << des_key << "\n\n";
    send(client_socket, des_key.c_str(), des_key_len, 0);

    while (true) {
        // Print user yang terhubung
        cout << "Connected user:\n";
        for (auto client_id : client_ids)
            cout << client_id << "|";
        cout << "\n\n";
        // Menerima panjang pesan dari client
        bytesReceived = recv(client_socket, reinterpret_cast<char*>(&messageLength), sizeof(messageLength), 0);
        if (bytesReceived <= 0) {
            cerr << "\n\nError receiving message length.\nClosing thread.\n";
            eraseClient(data.message);
            break;
        }
        // Membuat buffer sesuai panjang pesan dari client
        char* buffer = new char[messageLength+1];
        // Menerima pesan dari client
        bytesReceived = recv(client_socket, buffer, messageLength, 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message.\n";
            eraseClient(data.message);
            delete[] buffer;
            break;
        }
        // Batasi string dengan null agar hanya ditampilkan string yang sesuai
        buffer[bytesReceived] = '\0';
        message.setMessage(buffer);
        // DES Decryption
        message.messageDecryption();
        cout << "Received message from client: " << buffer << "\n";
        cout << "Actual message from client: " << message.getMessage() << "\n\n";
        // Hapus buffer setelah digunakan agar memori tidak tertumpuk
        delete[] buffer;

        data = createNewData();
        data.message = message.getMessage();
        HANDLE send_thread = CreateThread(NULL, 0, sendThread, &data, 0, NULL);
        if (send_thread == NULL) {
            cerr << "Error creating threads" << endl;
            continue;
        }
        WaitForSingleObject(send_thread, INFINITE);
        CloseHandle(send_thread);
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
    if (con.startServerSocket(12345, INADDR_ANY) == -1) return 0;
    if (con.startServerMultipleClient() == -1) return 0;
    SOCKET server_socket = con.getServerSocket();

    HANDLE listen_thread;
    vector<HANDLE> threads;

    int bytesReceived = 0;
    int n_client = 0, 
        n_server = 0, 
        n_server_from_client=0,
        n_client_encrypt = 0, 
        n_server_encrypt = 0, 
        n_server_from_client_encrypt =0;
    int idLength = 0;
    pair<int, int> client_pk;

    while(true){
        con.acceptClient();
        SOCKET client_socket = con.getClientSocket();
        RSA rsa(P, Q);
        int self_ekey = rsa.getPublicKey().first;
        int self_nkey = rsa.getPublicKey().second;

        // Pertukaran public key
        if ((client_pk.first = recv_key(client_socket, "Error receiving client public key.")) == -1) continue;
        if ((client_pk.second = recv_key(client_socket, "Error receiving client public key.")) == -1) continue;
        cout << "PUBLIC KEY DISTRIBUTION\nclient public key\n"; 
        cout << client_pk.first << "\n";
        cout << client_pk.second << "\n";
        cout << "server public key\n"; 
        cout << self_ekey << "\n";
        cout << self_nkey << "\n\n";
        send(client_socket, reinterpret_cast<char*>(&self_ekey), sizeof(self_ekey), 0);
        send(client_socket, reinterpret_cast<char*>(&self_nkey), sizeof(self_nkey), 0);

        // Pertukaran N
        cout << "N CLIENT KEY EXCHANGE" << "\n";
        // Skema 1
        bytesReceived = recv(client_socket, reinterpret_cast<char*>(&n_client_encrypt), sizeof(n_client_encrypt), 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving client n_key.\n";
            continue;
        }
        n_client = rsa.decrypt(n_client_encrypt);
        cout << "n C from C using S pk encrypt: " << n_client_encrypt << "\n";
        cout << "n C from C: " << n_client << "\n";
        // Skema 2
        n_client_encrypt = rsa.encrypt(n_client, client_pk.first, client_pk.second);
        send(client_socket, reinterpret_cast<char*>(&n_client_encrypt), sizeof(n_client_encrypt), 0);
        cout << "n C using C pk encrypt: " << n_client_encrypt << "\n\n";
    
        cout << "N SERVER KEY EXCHANGE" << "\n";
        // Skema 3
        n_server=rsa.generateKeyDistribution(client_pk.first, client_pk.second);
        n_server_encrypt = rsa.encrypt(n_server, client_pk.first, client_pk.second);
        send(client_socket, reinterpret_cast<char*>(&n_server_encrypt), sizeof(n_server_encrypt), 0);
        cout << "n S in S: " << n_server << "\n";
        cout << "n S using C pk encrypt: " << n_server_encrypt << "\n";
        // Skema 4
        bytesReceived = recv(client_socket, reinterpret_cast<char*>(&n_server_from_client_encrypt), sizeof(n_server_from_client_encrypt), 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving client n_key.\n";
            con.closeSocket(client_socket);
            continue;
        }
        n_server_from_client = rsa.decrypt(n_server_from_client_encrypt);
        cout << "n C from S using C pk encrypt: " << n_server_from_client_encrypt << "\n";
        cout << "n C from S: " << n_server_from_client << "\n\n";
        if (n_server_from_client != n_server){
            cerr << "Conection failed due to wrong n_key server from client\n";
            con.closeSocket(client_socket);
            continue;
        }

        // Mengambil id client
        cout << "CLIENT ID RECEIVE" << "\n";
        bytesReceived = recv(client_socket, reinterpret_cast<char*>(&idLength), sizeof(idLength), 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving id length.\n";
            continue;
        }
        char* buffer = new char[idLength+1];
        bytesReceived = recv(client_socket, buffer, idLength, 0);
        if (bytesReceived <= 0) {
            cerr << "Error receiving message.\n";
            delete[] buffer;
            continue;
        }        
        buffer[bytesReceived] = '\0';
        string client_id = buffer;
        cout << client_id << "\n\n";
        delete[] buffer;

        // Register client ke database server
        client_ids.push_back(client_id);
        client_sockets[client_id].value = client_socket;

        // Koneksi sudah fully establish
        Data data = createNewData();
        data.sock = client_socket;
        data.message = client_id;
        listen_thread = CreateThread(NULL, 0, listenThread, &data, 0, NULL);

        // Check jika thread berhasil terbuat atau tidak
        if (listen_thread == NULL) {
            cerr << "Error creating threads" << endl;
            closesocket(client_socket);
            continue;
        }

        threads.push_back(listen_thread);
    }

    WaitForMultipleObjects(static_cast<DWORD>(threads.size()), threads.data(), TRUE, INFINITE);
    for (auto& thread : threads) {
        CloseHandle(thread);
    }
    for (auto& client_socket : client_sockets){
        con.closeSocket(client_socket.second.value);
    }
    con.closeSocket(server_socket);
    con.cleanUp();
    return 0;
}
