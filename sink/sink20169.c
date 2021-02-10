#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>

#include <libconfig.h>
#include <curl/curl.h>

#include <sinkStruct.h>
#include <logging.h>
#include <sha256.h>


config_t cfg;

typedef struct {
    config_setting_t *devicesConfig;
    int receiveSockFd;
} t_receiverHandle;

t_receiverHandle receiverHandle;

typedef struct {
    config_setting_t *devicesConfig;
    const char *influxUser;
    const char *influxPass;
    const char *influxServer;
    uint16_t influxPort;
    const char *influxDatabase;
    const char *influxMeasurement;
    char influxUrl[1024];
} t_forwarderHandle;

t_forwarderHandle forwarderHandle = { 
    .influxUser = NULL, .influxPass = NULL, .influxServer = NULL, 
    .influxPort = 8086, .influxDatabase = NULL, .influxMeasurement = NULL
};


int readConfig(config_t *cfg) {
    config_init(cfg);
    if (! config_read_file(cfg, "./sink20169.cfg")) {
        logmsg(LOG_ERR, "failed to read config file: %s:%d - %s\n",
            config_error_file(cfg), config_error_line(cfg),
            config_error_text(cfg));
        config_destroy(cfg);
        return -1;
    }
    return 0;
}

int initReceiver(config_t *cfg, t_receiverHandle *handle) {
    handle->devicesConfig = config_lookup(cfg, "devices");
    if (handle->devicesConfig == NULL) {
        logmsg(LOG_ERR, "receiver: no devices configuration found");
        exit(-2);
    }

    struct sockaddr_in servaddr;

    handle->receiveSockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (handle->receiveSockFd == -1) {
        logmsg(LOG_ERR, "failed to create receive socket: %d", errno);
        return -1;
    }

    int receivePort = 20169;
    config_lookup_int(cfg, "receivePort", &receivePort);
    if (receivePort < 1 || receivePort > 65535) {
        logmsg(LOG_ERR, "illegal receive port configured");
        return -2;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(receivePort);

    if (-1 == bind(handle->receiveSockFd, (const struct sockaddr *) &servaddr, sizeof(servaddr))) {
        logmsg(LOG_ERR, "unable to bind receive: %d", errno);
        return -3;
    }
    return 0;
}

void deinitReceiver(t_receiverHandle *handle) {
    close(handle->receiveSockFd);
}

int receiveAndVerifyMinuteBuffer(t_receiverHandle *handle, t_minuteBuffer *buf) {
    struct sockaddr_in cliaddr;
    socklen_t cliaddrlen = sizeof(cliaddr);

    int n = recvfrom(handle->receiveSockFd, buf->b, sizeof(buf->b), MSG_TRUNC,
                     (struct sockaddr *) &cliaddr, &cliaddrlen);
    logmsg(LOG_INFO, "received %d octets from %d.%d.%d.%d", 
           n, 
           (cliaddr.sin_addr.s_addr & 0x0ff), 
           ((cliaddr.sin_addr.s_addr >> 8) & 0x0ff), 
           ((cliaddr.sin_addr.s_addr >> 16) & 0x0ff), 
           ((cliaddr.sin_addr.s_addr >> 24) & 0x0ff));

    if (n != sizeof(buf->b)) {
        logmsg(LOG_INFO, "Illegal packet size: %d", n);
        return -1;
    }
    
    config_setting_t *deviceConfig = config_setting_get_member(handle->devicesConfig, buf->s.deviceId);
    if (deviceConfig == NULL) {
        logmsg(LOG_INFO, "Unknown device: %s", buf->s.deviceId);
        return -2;
    } 
    
    const char *sharedSecret;
    if (! config_setting_lookup_string(deviceConfig, "sharedSecret", &sharedSecret)) {
        logmsg(LOG_ERR, "No sharedsecret configured for device %s", buf->s.deviceId);
        return -3;
    }
    // logmsg(LOG_INFO, "SharedSecret is %s", sharedSecret);

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

int initForwarder(config_t *cfg, t_forwarderHandle *handle) {
    handle->devicesConfig = config_lookup(cfg, "devices");
    if (handle->devicesConfig == NULL) {
        logmsg(LOG_ERR, "no devices configuration found");
        exit(-2);
    }

    config_lookup_string(cfg, "influxUser", &(handle->influxUser));
    config_lookup_string(cfg, "influxPass", &(handle->influxPass));
    config_lookup_string(cfg, "influxServer", &(handle->influxServer));
    config_lookup_string(cfg, "influxDatabase", &(handle->influxDatabase));
    config_lookup_string(cfg, "influxMeasurement", &(handle->influxMeasurement));

    int influxPort = 8086;
    config_lookup_int(cfg, "influxPort", &influxPort);
    if (influxPort < 1 || influxPort > 65535) {
        logmsg(LOG_ERR, "illegal influx port configured");
        return -2;
    }
    handle->influxPort = influxPort;

    if (! handle->influxServer) {
        logmsg(LOG_ERR, "no influxServer configured");
        return -1;
    }
    if (! handle->influxDatabase) {
        logmsg(LOG_ERR, "no influxDatabase configured");
        return -2;
    }
    if (! handle->influxMeasurement) {
        logmsg(LOG_ERR, "no influxMeasurement configured");
        return -3;
    }

    int res = snprintf(handle->influxUrl, sizeof(handle->influxUrl),
                       "http://%s:%d/write?db=%s&precision=s",
                       handle->influxServer, handle->influxPort, handle->influxDatabase);
    if (res > sizeof(handle->influxUrl)) {
        logmsg(LOG_ERR, "influxUrl has not enough space");
        return -4;
    }
    logmsg(LOG_INFO, "influxUrl is %s", handle->influxUrl);

    return 0;
}

void deinitForwarder(t_forwarderHandle *handle) {

}

int httpPostRequest(char *url, char *user, char *pass, char *payload) {
    CURL *curl = curl_easy_init();
    if (! curl) {
        logmsg(LOG_ERR, "error instantiating curl");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (user && pass) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
        curl_easy_setopt(curl, CURLOPT_USERNAME, user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logmsg(LOG_ERR, "post request failed: %s", curl_easy_strerror(res));
        return -2;
    }

    curl_easy_cleanup(curl);

    return 0;
}

int forwardMinuteBuffer(t_forwarderHandle *handle, t_minuteBuffer *buf) {
    logmsg(LOG_INFO, "DeviceId: %s", buf->s.deviceId);

    const char *location;
    if (! config_setting_lookup_string(deviceConfig, "location", &location)) {
        logmsg(LOG_ERR, "No location configured for device %s", buf->s.deviceId);
        return -3;
    }
    logmsg(LOG_INFO, "Location: %s", location);

    for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
        logmsg(LOG_INFO, "Time: %lu, Frequency: %u", buf->s.events[j].timestamp, buf->s.events[j].frequency);

        int frequency_before_point = buf->s.events[j].frequency / 1000;
        int frequency_behind_point = buf->s.events[j].frequency - (frequency_before_point * 1000);

        char payload[256];
        int res = snprintf(payload, sizeof(payload),
                           "%s,valid=1,location=%s,host=%s freq=%d.%03d %lu",
                           handle->influxMeasurement, location, buf->s.deviceId, 
                           frequency_before_point, frequency_behind_point, 
                           buf->s.events[j].timestamp);
        if (res > sizeof(payload)) {
            logmsg(LOG_ERR, "payload buffer to small");
            return -1;
        }
        logmsg(LOG_INFO, "Payload: %s", payload);
    }

    return 0;
}

int main() {
    if (0 != readConfig(&cfg)) {
        logmsg(LOG_ERR, "error when reading configuration");
        exit(-1);
    }
    
    if (0 != initReceiver(&cfg, &receiverHandle)) {
        logmsg(LOG_ERR, "error when initializing receiver");
        exit(-2);
    }

    if (0 != initForwarder(&cfg, &forwarderHandle)) {
        logmsg(LOG_ERR, "error when initializing forwarder");
        exit(-2);
    }


    while (1) {
        t_minuteBuffer buf;
        
        if (receiveAndVerifyMinuteBuffer(&receiverHandle, &buf) < 0) {
            logmsg(LOG_ERR, "error in receiveAndVerify");
            continue;
        }

        if (forwardMinuteBuffer(&forwarderHandle, &buf) < 0) {
            logmsg(LOG_ERR, "error in send");
        }
    }


    deinitForwarder(&forwarderHandle);
    deinitReceiver(&receiverHandle);
    config_destroy(&cfg);
}
