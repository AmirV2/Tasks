
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080

int main() {

    int client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket < 0) {
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

    connect(client_socket, (struct sockaddr*)&server_addresss,
        sizeof(server_addresss));
    std::cout << "Connected to server." << std::endl;

    char message[1024] = {0};
    char buffer[1024] = {0};
    while (true) {
        std::cout << "Message: ";
        std::cin >> message;
        std::cout << "Sending..." << std::endl;
        send(client_socket, message, strlen(message), 0);
        std::cout << "Reading..." << std::endl;
        read(client_socket, buffer, sizeof(buffer));
        std::cout << buffer << std::endl;
    }

    close(client_socket);

    return true;

}