
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080

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
    server_addresss.sin_addr.s_addr = inet_addr("10.0.0.5");

    char message[1024] = "hello!";
    char buffer[1024] = {0};
    while (true) {

        socklen_t len = sizeof(server_addresss);

        sendto(server_socket, message, strlen(message), MSG_CONFIRM,
            (struct sockaddr*)&server_addresss, len);

        int n = recvfrom(server_socket, buffer, 1024, MSG_WAITALL,
            (struct sockaddr*)&server_addresss, &len);
        buffer[n] = '\0';
        std::cout << buffer << std::endl;

    }

    close(server_socket);

    return true;

}