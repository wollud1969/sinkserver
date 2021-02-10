#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>

#include <libconfig.h>

#include <sinkStruct.h>
#include <logging.h>
#include <sha256.h>


config_t cfg;
config_setting_t *devicesConfig;

int receiveSockFd;


void readConfig() {
    config_init(&cfg);
    if (! config_read_file(&cfg, "./sink20169.cfg")) {
        logmsg(LOG_ERR, "failed to read config file: %s:%d - %s\n",
            config_error_file(&cfg), config_error_line(&cfg),
            config_error_text(&cfg));
        config_destroy(&cfg);
        exit(-1);
    }

    devicesConfig = config_lookup(cfg, "devices");
    if (devicesConfig == NULL) {
        logmsg(LOG_ERR, "receiver: no devices configuration found");
        exit(-2);
    }
}

void initReceiver() {
    struct sockaddr_in servaddr;

    receiveSockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiveSockFd == -1) {
        logmsg(LOG_ERR, "failed to create receive socket: %d", errno);
        exit(-3);
    }

    int receivePort = 20169;
    config_setting_lookup_int(&cfg, "receivePort", &receivePort);
    if (receivePort < 1 || receivePort > 65535) {
        logmsg(LOG_ERR, "illegal receive port configured");
        exit(-4);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(receivePort);

    if (-1 == bind(receiveSockFd, (const struct sockaddr *) &servaddr, sizeof(servaddr))) {
        logmsg(LOG_ERR, "unable to bind receive: %d", errno);
        exit(-5);
    }
}

int receiveAndVerifyMinuteBuffer(t_minuteBuffer *buf) {
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddrlen = sizeof(cliaddr);

    int n = recvfrom(receiveSockFd, buf->b, sizeof(buf->b), MSG_TRUNC,
                        (struct sockaddr *) &cliaddr, &cliaddrlen);
    logmsg(LOG_INFO, "received %d octets from %04x", n, cliaddr.sin_addr.s_addr);

    if (n != sizeof(buf->b)) {
        logmsg(LOG_INFO, "Illegal packet size: %d", n);
        return -1;
    }
    
    config_setting_t *deviceConfig = config_setting_get_member(devicesConfig, buf->s.deviceId);
    if (deviceConfig == NULL) {
        logmsg(LOG_INFO, "Unknown device: %s", buf->s.deviceId);
        return -2;
    } 
    
    const char *sharedSecret;
    if (! config_setting_lookup_string(deviceConfig, "sharedSecret", &sharedSecret)) {
        logmsg(LOG_ERR, "No sharedsecret configured for device %s", buf->s.deviceId);
        return -3;
    }
    logmsg(LOG_INFO, "SharedSecret is %s", sharedSecret);

    if (strlen(sharedSecret) >= SHA256_BLOCK_SIZE) {
        logmsg(LOG_ERR, "Configured sharedsecret for device %s is too long", buf->s.deviceId);
        return -4;
    }

    uint8_t receivedHash[SHA256_BLOCK_SIZE];
    memcpy(receivedHash, buf->s.hash, SHA256_BLOCK_SIZE);
    memcpy(buf->s.hash, sharedSecret, SHA256_BLOCK_SIZE);

    SHA256_CTX ctx;
    uint8_t calculatedHash[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, buf->b, sizeof(buf->b));
    sha256_final(&ctx, calculatedHash);

    if (memcmp(receivedHash, calculatedHash, SHA256_BLOCK_SIZE) != 0) {
        logmsg(LOG_INFO, "Invalid hash in msg for device %s", buf->s.deviceId);
        return -5;
    }

    return 0;
}

int forwardMinuteBuffer(t_minuteBuffer &buf) {
    logmsg(LOG_INFO, "DeviceId: %s", buf->s.deviceId);
    logmsg(LOG_INFO, "Location: %s", buf->s.location);
    for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
        logmsg(LOG_INFO, "Time: %lu, Frequency: %u", buf->s.events[j].timestamp, buf->s.events[j].frequency);
    }

    return 0;
}
int main() {
    readConfig();
    
    initReceiver();

    while (1) {
        t_minuteBuffer buf;
        
        if (receiveAndVerifyMinuteBuffer(&buf) < 0) {
            logmsg(LOG_ERR, "error in receiveAndVerify");
        } else {
            if (forwardMinuteBuffer(&buf) < 0) {
                logmsg(LOG_ERR, "error in send");
            }
        }
    }

    close(receiveSockFd);
    config_destroy(&cfg);
}
