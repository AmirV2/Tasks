
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>

#define PORT 8080

int main() {

    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        std::cout << "Socket creation failed!" << std::endl;
        return 1;
    }
    std::cout << "Socket created." << std::endl;

    struct sockaddr_in server_addresss, client_address;
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

    char buffer[1024] = {0};
    while (true) {

        socklen_t len = sizeof(client_address);

        std::cout << "Reading..." << std::endl;
        int n = recvfrom(udp_socket, buffer, 1024, MSG_WAITALL,
            (struct sockaddr*)&client_address, &len);
        buffer[n] = '\0';

        std::cout << "Sending..." << std::endl;
        sendto(udp_socket, buffer, strlen(buffer), MSG_CONFIRM,
            (struct sockaddr*)&client_address, len);

    }

    close(udp_socket);

    return 0;

}