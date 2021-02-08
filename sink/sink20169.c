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

                printf("recv. hash, 1. half is %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       receivedHash[0],
                       receivedHash[1],
                       receivedHash[2],
                       receivedHash[3],
                       receivedHash[4],
                       receivedHash[5],
                       receivedHash[6],
                       receivedHash[7],
                       receivedHash[8],
                       receivedHash[9],
                       receivedHash[10],
                       receivedHash[11],
                       receivedHash[12],
                       receivedHash[13],
                       receivedHash[14],
                       receivedHash[15]
                       );
                printf("recv. hash, 2. half is %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       receivedHash[16],
                       receivedHash[17],
                       receivedHash[18],
                       receivedHash[19],
                       receivedHash[20],
                       receivedHash[21],
                       receivedHash[22],
                       receivedHash[23],
                       receivedHash[24],
                       receivedHash[25],
                       receivedHash[26],
                       receivedHash[27],
                       receivedHash[28],
                       receivedHash[29],
                       receivedHash[30],
                       receivedHash[31]
                       );

                SHA256_CTX ctx;
                uint8_t calculatedHash[SHA256_BLOCK_SIZE];
                sha256_init(&ctx);
                sha256_update(&ctx, buf.b, sizeof(buf.b));
                sha256_final(&ctx, calculatedHash);

                printf("calc. hash, 1. half is %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       calculatedHash[0],
                       calculatedHash[1],
                       calculatedHash[2],
                       calculatedHash[3],
                       calculatedHash[4],
                       calculatedHash[5],
                       calculatedHash[6],
                       calculatedHash[7],
                       calculatedHash[8],
                       calculatedHash[9],
                       calculatedHash[10],
                       calculatedHash[11],
                       calculatedHash[12],
                       calculatedHash[13],
                       calculatedHash[14],
                       calculatedHash[15]
                       );
                printf("calc. hash, 2. half is %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       calculatedHash[16],
                       calculatedHash[17],
                       calculatedHash[18],
                       calculatedHash[19],
                       calculatedHash[20],
                       calculatedHash[21],
                       calculatedHash[22],
                       calculatedHash[23],
                       calculatedHash[24],
                       calculatedHash[25],
                       calculatedHash[26],
                       calculatedHash[27],
                       calculatedHash[28],
                       calculatedHash[29],
                       calculatedHash[30],
                       calculatedHash[31]
                       );


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
