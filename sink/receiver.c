#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sinkStruct.h>
#include <logging.h>
#include <libconfig.h>


int receiver(config_t *cfg) {
    config_setting_t *devicesConfig = config_lookup(cfg, "devices");
    if (devicesConfig == NULL) {
        logmsg(LOG_ERR, "receiver: no devices configuration found");
        return -1;
    }

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
        logmsg(LOG_INFO, "received %d octets from %04x", n, cliaddr.sin_addr.s_addr);

        if (n != sizeof(buf.b)) {
            logmsg(LOG_INFO, "Illegal packet size: %d", n);
            continue;
        }
        
        config_setting_t *deviceConfig = config_setting_get_member(devicesConfig, buf.s.deviceId);
        if (deviceConfig == NULL) {
            logmsg(LOG_INFO, "Unknown device: %s", buf.s.deviceId);
            continue;
        } 
        
        const char *sharedSecret;
        if (! config_setting_lookup_string(deviceConfig, "sharedSecret", &sharedSecret)) {
            logmsg(LOG_ERR, "No sharedsecret configured for device %s", buf.s.deviceId);
            continue;
        }
        logmsg(LOG_INFO, "SharedSecret is %s", sharedSecret);

        if (strlen(sharedSecret) > SHA256_BLOCK_SIZE) {
            logmsg(LOG_ERR, "Configured sharedsecret for device %s is too long", buf.s.deviceId);
            continue;
        }

        uint8_t receivedHash[SHA256_BLOCK_SIZE];
        memcpy(receivedHash, buf.s.hash, SHA256_BLOCK_SIZE);
        memcpy(buf.s.hash, sharedSecret, SHA256_BLOCK_SIZE);

        SHA256_CTX ctx;
        uint8_t calculatedHash[SHA256_BLOCK_SIZE];
        sha256_init(&ctx);
        sha256_update(&ctx, buf.b, sizeof(buf.b));
        sha256_final(&ctx, calculatedHash);

        if (memcmp(receivedHash, calculatedHash, SHA256_BLOCK_SIZE) != 0) {
            logmsg(LOG_INFO, "Invalid hash in msg for device %s", buf.s.deviceId);
            continue;
        }

        logmsg(LOG_INFO, "DeviceId: %s", buf.s.deviceId);
        logmsg(LOG_INFO, "Location: %s", buf.s.location);
        for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
            logmsg(LOG_INFO, "Time: %lu, Frequency: %u", buf.s.events[j].timestamp, buf.s.events[j].frequency);
        }
    }

    return 0;
}
