
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <map>
#include <cstdlib>

const int PORT = 8080;

class Encoder {
public:

    Encoder() {

        mutual_generated = false;

        private_key = rand() % 100 + 1;
        G = rand() % 100 + 1;
        P = rand() % 100 + 1;

        total_len = 0;
        mutual_key = 1;

    }

    void encode(char* buffer) {
        for (int i = 0; i < strlen(buffer); i++) {
            buffer[i] = char(buffer[i] + mutual_key);
        }
    }

    void decode(char* buffer) {
        for (int i = 0; i < strlen(buffer); i++) {
            buffer[i] = char(buffer[i] - mutual_key);
        }
        total_len += strlen(buffer);
    }

    int generate_secret_key() {
        return power(G, private_key);
    }

    void generate_mutual_key(int secret_key) {
        mutual_key = power(secret_key, private_key);
        mutual_generated = true;
    }

    bool is_mutual_generated() { return mutual_generated; }

    int get_G() { return G; }

    int get_P() { return P; }

    int get_total_len() { return total_len; }

private:

    int G;
    int P;
    int private_key;

    int mutual_key;
    bool mutual_generated;

    int total_len;

    int power(int a, int b) {
        int pow = 1;
        for (int i = 0; i < b; i++) {
            pow = (a * pow) % P;
        }
        return pow;
    }

};

class ClientHandler {
public:

    ClientHandler() {}

    Encoder* add_client(std::pair<unsigned short, unsigned long> addr) {
        Encoder* encoder = new Encoder();
        clients[addr] = encoder;
        return encoder;
    }

    bool client_exists(std::pair<unsigned short, unsigned long> addr) {
        for (auto client : clients) {
            if (client.first.first == addr.first) {
                if (client.first.second == addr.second) {
                    return true;
                }
            }
        }
        return false;
    }

    Encoder* get_encoder(std::pair<unsigned short, unsigned long> addr) {
        return clients[addr];
    }


private:
    std::map<std::pair<unsigned short, unsigned long>, Encoder*> clients;
};

int main() {

    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        std::cout << "Socket creation failed!" << std::endl;
        return 1;
    }
    std::cout << "Socket created." << std::endl;

    sockaddr_in server_addresss;
    server_addresss.sin_family = AF_INET;
    server_addresss.sin_port = htons(PORT);
    server_addresss.sin_addr.s_addr = inet_addr("10.0.0.3");

    int bind_response = bind(udp_socket, (struct sockaddr*)&server_addresss,
        sizeof(server_addresss));
    if (bind_response < 0) {
        std::cout << "Bind failed!" << std::endl;
        return 1;
    }
    std::cout << "Socket binded." << std::endl;

    ClientHandler handler;
    char buffer[1024] = {0};
    while (true) {

        struct sockaddr_in client_address;
        socklen_t len = sizeof(client_address);
        std::stringstream stream;

        int n = recvfrom(udp_socket, buffer, 1024, MSG_WAITALL,
            (struct sockaddr*)&client_address, &len);
        buffer[n] = '\0';

        if (handler.client_exists({client_address.sin_port, client_address.sin_addr.s_addr})) {

            Encoder* encoder = handler.get_encoder({client_address.sin_port, client_address.sin_addr.s_addr});

            if (!encoder->is_mutual_generated()) {
                int secret_key;
                stream << buffer;
                stream >> secret_key;
                encoder->generate_mutual_key(secret_key);
            }
            else {
                encoder->decode(buffer);
                std::cout <<  "message: "<< buffer << std::endl;
                stream << encoder->get_total_len() << std::endl;
                char* response = (char*)stream.str().c_str();
                encoder->encode(response);
                sendto(udp_socket, response, strlen(response), MSG_CONFIRM,
                    (struct sockaddr*)&client_address, len);
            }

        }
        else {
            Encoder* encoder = handler.add_client({client_address.sin_port, client_address.sin_addr.s_addr});
            stream << encoder->get_G() << " " << encoder->get_P() << " "
                << encoder->generate_secret_key() << std::endl;
            const char* response = stream.str().c_str();
            sendto(udp_socket, response, strlen(response), MSG_CONFIRM,
                (struct sockaddr*)&client_address, len);
        }
        
    }

    close(udp_socket);

    return 0;

}