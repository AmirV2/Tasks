
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080

int main() {

    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        std::cout << "Socket creation failed!" << std::endl;
        return 1;
    }
    else {
        std::cout << "Socket created." << std::endl;
    }

    struct sockaddr_in server_addresss, client_address;
    server_addresss.sin_family = AF_INET;
    server_addresss.sin_port = htons(PORT);
    server_addresss.sin_addr.s_addr = inet_addr("127.0.0.1");

    bind(udp_socket, (struct sockaddr*)&server_addresss,
        sizeof(server_addresss));
    std::cout << "Socket binded." << std::endl;

    std::cout << "Listening..." << std::endl;
    listen(udp_socket, 1);

    socklen_t client_address_len = sizeof(client_address);
    int client_socket = accept(udp_socket, (struct sockaddr*)&client_address,
        &client_address_len);
    std::cout << "Client accepted." << std::endl;

    char buffer[1024] = {0};
    while (true) {
        std::cout << "Reading..." << std::endl;
        read(client_socket, buffer, sizeof(buffer));
        std::cout << "Sending..." << std::endl;
        send(client_socket, buffer, strlen(buffer), 0);
    }

    close(client_socket);
    close(udp_socket);

    return 0;

}