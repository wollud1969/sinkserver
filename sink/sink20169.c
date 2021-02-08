#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include <sinkStruct.h>


typedef struct {
    char deviceId[sizeof(((t_configBlock*)0)->deviceId)];
    char sharedSecret[sizeof(((t_configBlock*)0)->sharedSecret)];
} t_device;

const t_device devices[] = {
    { .deviceId = "MainsCnt01", .sharedSecret = "sharedSecretGanzGeheim" },
    { .deviceId = "", .sharedSecret = "" }
};



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

    t_minuteBuffer buf;

    while (1) {
        int n = recvfrom(sockfd, buf.b, sizeof(buf.b), MSG_TRUNC,
                         (struct sockaddr *) &cliaddr, &cliaddrlen);
        printf("received %d octets from %04x\n", 
               n, cliaddr.sin_addr.s_addr);

        if (n != sizeof(buf.b)) {
            printf("Illegal packet size: %d\n", n);
            continue;
        }

        uint8_t i = 0;
        while (1) {
            if (strlen(devices[i].deviceId) == 0) {
                break;
            }

            if (strncmp(devices[i].deviceId, buf.s.deviceId, sizeof(((t_configBlock*)0)->deviceId)) == 0) {
                printf("Device found: %s\n", devices[i].deviceId);

                uint8_t receivedHash[SHA256_BLOCK_SIZE];
                memcpy(receivedHash, buf.s.hash, SHA256_BLOCK_SIZE);
                memcpy(buf.s.hash, devices[i].sharedSecret, SHA256_BLOCK_SIZE);

                SHA256_CTX ctx;
                uint8_t calculatedHash[SHA256_BLOCK_SIZE];
                sha256_init(&ctx);
                sha256_update(&ctx, buf.b, sizeof(buf.b));
                sha256_final(&ctx, calculatedHash);

                if (memcmp(receivedHash, calculatedHash, SHA256_BLOCK_SIZE) != 0) {
                    printf("Invalid hash\n");
                }

                printf("DeviceId: %s\n", buf.s.deviceId);
                printf("Location: %s\n", buf.s.location);
                for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
                    printf("Time: %lu, Frequency: %u\n", buf.s.events[j].timestamp, buf.s.events[j].frequency);
                }
                printf("\n");


                break;
            } else {
                printf("Unknown device\n");
            }

            i++;
        }

    }

}
