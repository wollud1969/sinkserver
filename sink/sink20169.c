#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>


int main() {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddrlen = sizeof(cliaddr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(20169);

    bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    uint8_t buf[1024];

    while (1) {
        int n = recvfrom(sockfd, buf, sizeof(buf), 0,
                         (struct sockaddr *) &cliaddr, &cliaddrlen);
        printf("received %d octets from %04x\n", 
               n, cliaddr.sin_addr.s_addr);
    }

}
