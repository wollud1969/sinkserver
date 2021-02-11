#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <getopt.h>

#include <libconfig.h>
#include <curl/curl.h>

#include <sinkStruct.h>
#include <logging.h>
#include <sha256.h>


const char DEFAULT_CONFIG_FILENAME[] = "./sink20169.cfg";

typedef struct {
    const char *deviceId;
    const char *location;
    const char *sharedSecret;
} t_device;

typedef struct {
    config_t cfg;
    uint16_t numOfDevices;
    t_device *devices;    
} t_configHandle;

typedef struct {
    t_configHandle *configHandle;
    int receiveSockFd;
} t_receiverHandle;

typedef struct {
    t_configHandle *configHandle;
    const char *influxUser;
    const char *influxPass;
    const char *influxServer;
    uint16_t influxPort;
    const char *influxDatabase;
    const char *influxMeasurement;
    char influxUrl[1024];
} t_forwarderHandle;

bool verbose = false;


int initConfig(const char *configFilename, t_configHandle *configHandle) {
    configHandle->numOfDevices = 0;
    configHandle->devices = NULL;

    config_init(&(configHandle->cfg));
    if (! config_read_file(&(configHandle->cfg), configFilename)) {
        logmsg(LOG_ERR, "failed to read config file: %s:%d - %s\n",
            config_error_file(&(configHandle->cfg)), config_error_line(&(configHandle->cfg)),
            config_error_text(&(configHandle->cfg)));
        config_destroy(&(configHandle->cfg));
        return -1;
    }

    config_setting_t *devicesConfig = config_lookup(&(configHandle->cfg), "devices");
    if (devicesConfig == NULL) {
        logmsg(LOG_ERR, "receiver: no devices configuration found");
        return -2;
    }
    configHandle->numOfDevices = config_setting_length(devicesConfig);
    configHandle->devices = (t_device*) malloc(configHandle->numOfDevices * sizeof(t_device));
    for (uint16_t i = 0; i < configHandle->numOfDevices; i++) {
        config_setting_t *deviceConfig = config_setting_get_elem(devicesConfig, i);
        if (! config_setting_lookup_string(deviceConfig, "deviceId", &(configHandle->devices[i].deviceId))) {
            logmsg(LOG_ERR, "no deviceId for device %d", i);
            return -3;
        }
        if (! config_setting_lookup_string(deviceConfig, "location", &(configHandle->devices[i].location))) {
            logmsg(LOG_ERR, "no location for device %d", i);
            return -4;
        }
        if (! config_setting_lookup_string(deviceConfig, "sharedSecret", &(configHandle->devices[i].sharedSecret))) {
            logmsg(LOG_ERR, "no sharedSecret for device %d", i);
            return -5;
        }
        if (strlen(configHandle->devices[i].sharedSecret) >= SHA256_BLOCK_SIZE) {
            logmsg(LOG_ERR, "Configured sharedsecret for device %d is too long", i);
            return -6;
        }
        logmsg(LOG_INFO, "Device loaded: %d %s %s %s", i, 
               configHandle->devices[i].deviceId, 
               configHandle->devices[i].location, 
               configHandle->devices[i].sharedSecret);
    }

    return 0;
}

void deinitConfig(t_configHandle *configHandle) {
    config_destroy(&(configHandle->cfg));
    if (configHandle->devices) {
        free(configHandle->devices);
        configHandle->devices = NULL;
    }
}

t_device *findDevice(t_configHandle *configHandle, char *deviceId) {
    for (uint16_t i = 0; i < configHandle->numOfDevices; i++) {
        if (! strcmp(configHandle->devices[i].deviceId, deviceId)) {
            return &(configHandle->devices[i]);
        }
    }
    return NULL;
}

int initReceiver(t_configHandle *configHandle, t_receiverHandle *handle) {
    handle->configHandle = configHandle;

    struct sockaddr_in servaddr;

    handle->receiveSockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (handle->receiveSockFd == -1) {
        logmsg(LOG_ERR, "failed to create receive socket: %d", errno);
        return -1;
    }

    int receivePort = 20169;
    config_lookup_int(&(configHandle->cfg), "receivePort", &receivePort);
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

    t_device *device = findDevice(handle->configHandle, buf->s.deviceId);    
    const char *sharedSecret = device->sharedSecret;

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


int initForwarder(t_configHandle *configHandle, t_forwarderHandle *handle) {
    handle->configHandle = configHandle;

    handle->influxUser = NULL;
    handle->influxPass = NULL;
    handle->influxServer = NULL;
    handle->influxDatabase = NULL;
    handle->influxMeasurement = NULL;

    config_lookup_string(&(configHandle->cfg), "influxUser", &(handle->influxUser));
    config_lookup_string(&(configHandle->cfg), "influxPass", &(handle->influxPass));
    config_lookup_string(&(configHandle->cfg), "influxServer", &(handle->influxServer));
    config_lookup_string(&(configHandle->cfg), "influxDatabase", &(handle->influxDatabase));
    config_lookup_string(&(configHandle->cfg), "influxMeasurement", &(handle->influxMeasurement));

    int influxPort = 8086;
    config_lookup_int(&(configHandle->cfg), "influxPort", &influxPort);
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

int httpPostRequest(char *url, const char *user, const char *pass, char *payload) {
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
    t_device *device = findDevice(handle->configHandle, buf->s.deviceId);
    const char *location = device->location;

    for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
        logmsg(LOG_DEBUG, "Time: %lu, Frequency: %u", buf->s.events[j].timestamp, buf->s.events[j].frequency);

        int frequency_before_point = buf->s.events[j].frequency / 1000;
        int frequency_behind_point = buf->s.events[j].frequency - (frequency_before_point * 1000);

        char payload[256];
        int res = snprintf(payload, sizeof(payload),
                           "%s,valid=1,location=%s,host=%s freq=%d.%03d"
#ifdef OpenBSD
                           " %llu"
#else
                           " %lu"
#endif                                                      
                           "",
                           handle->influxMeasurement, location, buf->s.deviceId, 
                           frequency_before_point, frequency_behind_point, 
                           buf->s.events[j].timestamp);
        if (res > sizeof(payload)) {
            logmsg(LOG_ERR, "payload buffer to small");
            return -1;
        }
        logmsg(LOG_DEBUG, "Payload: %s", payload);
        res = httpPostRequest(handle->influxUrl, handle->influxUser, handle->influxPass, payload);
        if (res == 0) {
            logmsg(LOG_DEBUG, "Successfully sent to InfluxDB");
        }
    }

    logmsg(LOG_INFO, "Successfully sent whole minute to InfluxDB");
    return 0;
}

void usage() {
    printf("sinkserver for mainsfrequency counter\n");
    printf("https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-stm32\n");
    printf("Version: " VERSION "\n");
    printf("\nUsage\n");
    printf("  -f FILENAME R..... Config file to be used\n");
    printf("  -v ............... Verbose, writes all logging on stdout too\n");
    printf("  -s FACILITY ...... Sets syslog facility, only LOCAL[0..7]\n");
    printf("                     USER and DAEMON are supported\n");
    printf("  -h ............... This help\n");
}

int main(int argc, char **argv) {
    t_configHandle configHandle;
    t_forwarderHandle forwarderHandle;
    t_receiverHandle receiverHandle;


    const char *configFilename = DEFAULT_CONFIG_FILENAME;

    int c;
    while ((c = getopt(argc, argv, "f:vs:h")) != -1) {
        switch (c) {
            case 'f':
                configFilename = strdup(optarg);
                break;
            case 'v':
                verbose = true;
                break;
            case 's':
                setfacility(optarg);
                break;
            case 'h':
                usage();
                exit(0);
                break;
        }
    }

    if (0 != initConfig(configFilename, &configHandle)) {
        logmsg(LOG_ERR, "error when reading configuration");
        exit(-1);
    }
    
    if (0 != initReceiver(&configHandle, &receiverHandle)) {
        logmsg(LOG_ERR, "error when initializing receiver");
        exit(-2);
    }

    if (0 != initForwarder(&configHandle, &forwarderHandle)) {
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
    deinitConfig(&configHandle);
}
