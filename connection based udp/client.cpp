
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>

#define PORT 8080

class Encoder {
public:

    Encoder(int G, int P) : G(G), P(P) {
        private_key = rand() % 10;
        mutual_key = 1;
    }

    void encode(char* buffer) {
        for (int i = 0; i < strlen(buffer); i++) {
            buffer[i] = char(buffer[i] + mutual_key);
        }
    }

    int generate_secret_key() {
        return power(G, private_key);
    }

    void generate_mutual_key(int secret_key) {
        mutual_key = power(secret_key, private_key);
    }

private:

    int G;
    int P;
    int private_key;
    int mutual_key;

    int power(int a, int b) {
        int pow = 1;
        for (int i = 0; i < b; i++) {
            pow = (a * pow) % P;
        }
        return pow;
    }

};

int main() {

    int server_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket < 0) {
        std::cout << "Socket creation failed!" << std::endl;
        return 1;
    }
    else {
        std::cout << "Socket created." << std::endl;
    }

    struct sockaddr_in server_addresss;
    server_addresss.sin_family = AF_INET;
    server_addresss.sin_port = htons(PORT);
    server_addresss.sin_addr.s_addr = inet_addr("127.0.0.1");

    char buffer[1024] = {0};
    socklen_t len = sizeof(server_addresss);

    sendto(server_socket, buffer, strlen(buffer), MSG_CONFIRM,
        (struct sockaddr*)&server_addresss, len);

    int n = recvfrom(server_socket, buffer, 1024, MSG_WAITALL,
        (struct sockaddr*)&server_addresss, &len);
    buffer[n] = '\0';

    int G, P, secret_key;
    std::stringstream stream;
    stream << buffer;
    stream >> G >> P >> secret_key;
    Encoder encoder(G, P);
    encoder.generate_mutual_key(secret_key);

    stream.clear();
    stream << encoder.generate_secret_key();
    const char* response = stream.str().c_str();

    sendto(server_socket, response, strlen(response), MSG_CONFIRM,
        (struct sockaddr*)&server_addresss, len);

    while (true) {
        std::cin >> buffer;
        encoder.encode(buffer);
        sendto(server_socket, buffer, strlen(buffer), MSG_CONFIRM,
            (struct sockaddr*)&server_addresss, len);
    }

    close(server_socket);

    return true;

}