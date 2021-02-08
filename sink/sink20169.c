#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>


int main() {
    int sockfd;
    struct sockaddr servaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(20169);

    bind(sockfd, (SA*) &servaddr, sizeof(servaddr));

    uint8_t buf[1024];

    while (1) {
        int n = recv(sockfd, buf, sizeof(buf), 0);
        printf("received %d octets\n");
    }

}