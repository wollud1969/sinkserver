/*
 * vim:sw=4:ts=4:et
 */


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
#include <pwd.h>
#include <libconfig.h>
#include <libpq-fe.h>
#include <sinkStruct.h>
#include <logging.h>
#include <sha256.h>


const char DEFAULT_CONFIG_FILENAME[] = "./sink20169.cfg";

typedef struct {
    const char *deviceId;
    const char *location;
    const char *sharedSecret;
    int inactive;
} t_device;

typedef struct {
    config_t cfg;
    uint16_t numOfDevices;
    t_device *devices;    
} t_configHandle;

#define NUM_OF_STMT_PARAMS 4

typedef struct {
    t_configHandle *configHandle;
    int receiveSockFd;
    int32_t lowerBound;
    int32_t upperBound;
    const char *postgresqlConnInfo;
    PGconn *conn;
} t_commonHandle;

bool verbose = false;



int openDatabaseConnection(t_commonHandle *handle) {
    int res = 0;
    
    if (! handle->conn) {
        logmsg(LOG_DEBUG, "Opening connection to database");
        handle->conn = PQconnectdb(handle->postgresqlConnInfo);
    } else if (PQstatus(handle->conn) != CONNECTION_OK) {
        logmsg(LOG_DEBUG, "Resetting connection to database");
        PQreset(handle->conn);
    }

    if (PQstatus(handle->conn) != CONNECTION_OK) {
        logmsg(LOG_ERR, "Connection to database failed: %s", PQerrorMessage(handle->conn));
        res = -1;
    }

    return res;
}

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
        if (! config_setting_lookup_bool(deviceConfig, "inactive", &(configHandle->devices[i].inactive))) {
            logmsg(LOG_INFO, "no inactive flag set for device %d, consider as active", i);
            configHandle->devices[i].inactive = 0;
        }
        logmsg(LOG_INFO, "Device loaded: %d %s %d %s %s", i, 
               configHandle->devices[i].deviceId, 
               configHandle->devices[i].inactive,
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

t_device *findDevice(t_commonHandle *handle, char *deviceId) {
    t_device *foundDevice = NULL;
    if (0 == openDatabaseConnection(handle)) {
        char stmt[256];
        int res1 = snprintf(stmt, sizeof(stmt),
                            "SELECT sharedsecret, active "
                            "  FROM device_t "
                            "  WHERE deviceid = '%s'",
                            deviceId);
        if (res1 > sizeof(stmt)) {
            logmsg(LOG_ERR, "stmt buffer to small");
        } else {
            logmsg(LOG_DEBUG, "Statement: %s", stmt);
            PGresult *res2 = PQexec(handle->conn, stmt);
            ExecStatusType execStatus = PQresultStatus(res2);
            if (execStatus != PGRES_TUPLES_OK) {
                logmsg(LOG_INFO, "findDevice query fails, database returns %s", PQresStatus(execStatus));
            } else {
                int ntuples = PQntuples(res2);
                if (ntuples == 1) {
                    logmsg(LOG_DEBUG, "device found");
                    char *sharedsecret = PQgetvalue(res2, 0, 0);
                    char *active = PGgetvalue(res2, 0, 1);
                    logmsg(LOG_DEBUG, "found sharedsecret is %s, active is %d", sharedsecret, active[0]);
                } else {
                    logmsg(LOG_ERR, "no device found");
                }
            }
            PQclear(res2);
        }
    } else {
        logmsg(LOG_ERR, "No database connection available, data lost");
    } 



    t_configHandle *configHandle = handle->configHandle;
    for (uint16_t i = 0; i < configHandle->numOfDevices; i++) {
        if (! strcmp(configHandle->devices[i].deviceId, deviceId)) {
            foundDevice = &(configHandle->devices[i]);
            break;
        }
    }
    return foundDevice;
}

int initReceiver(t_configHandle *configHandle, t_commonHandle *handle) {
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

void deinitReceiver(t_commonHandle *handle) {
    close(handle->receiveSockFd);
}

int receiveAndVerifyMinuteBuffer(t_commonHandle *handle, t_minuteBuffer *buf) {
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

    t_device *device = findDevice(handle, buf->s.deviceId);    
    if (device == NULL) {
        logmsg(LOG_ERR, "Device %s not found", buf->s.deviceId);
        return -4;
    }
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


int initForwarder(t_configHandle *configHandle, t_commonHandle *handle) {
    handle->configHandle = configHandle;

    handle->postgresqlConnInfo = NULL;
    config_lookup_string(&(configHandle->cfg), "postgresqlConnInfo", &(handle->postgresqlConnInfo));
    if (! handle->postgresqlConnInfo) {
        logmsg(LOG_ERR, "no postgresql connInfo configured");
        return -1;
    }

    handle->conn = NULL;

    handle->lowerBound = 45000;
    config_lookup_int(&(configHandle->cfg), "lowerBound", &(handle->lowerBound));
    handle->upperBound = 55000;
    config_lookup_int(&(configHandle->cfg), "upperBound", &(handle->upperBound));
    logmsg(LOG_INFO, "lowerBound: %u, upperBound: %u", handle->lowerBound, handle->upperBound);

    return 0;
}

void deinitForwarder(t_commonHandle *handle) {
    PQfinish(handle->conn);
}

int sendToDB(t_commonHandle *handle, const char *location, const char *deviceId, 
             uint32_t frequency, uint64_t timestamp) {
    int retcode = 0;
    if (0 == openDatabaseConnection(handle)) {
        int frequency_before_point = frequency / 1000;
        int frequency_behind_point = frequency - (frequency_before_point * 1000);
        char stmt[256];
        int res1 = snprintf(stmt, sizeof(stmt),
                            "INSERT INTO mainsfrequency (time, host, location, freq) "
                            "VALUES(to_timestamp("
#ifdef OpenBSD
                                                 "%llu"
#else
                                                 "%lu"
#endif                                                      
                                                       "), '%s', '%s', %d.%03d)",
                            timestamp, deviceId, location, 
                            frequency_before_point, frequency_behind_point);
        if (res1 > sizeof(stmt)) {
            logmsg(LOG_ERR, "stmt buffer to small");
            retcode = -1;
        } else {
            logmsg(LOG_DEBUG, "Statement: %s", stmt);
            PGresult *res2 = PQexec(handle->conn, stmt);
            if (PQresultStatus(res2) != PGRES_COMMAND_OK) {
                logmsg(LOG_ERR, "Failed to insert into database (%s), data lost", 
                       PQresultErrorMessage(res2));
                retcode = -2;
            }
            PQclear(res2);
        }
    } else {
        logmsg(LOG_ERR, "No database connection available, data lost");
        retcode = -1;
    } 

    return retcode;
}


int forwardMinuteBuffer(t_commonHandle *handle, t_minuteBuffer *buf) {
    t_device *device = findDevice(handle, buf->s.deviceId);
    if (device == NULL) {
        logmsg(LOG_ERR, "Device %s not found", buf->s.deviceId);
        return -4;
    }
    const char *location = device->location;

    logmsg(LOG_INFO, "D: %s, R: %u, P: %u, W: %u, V: %08x, L: %s", 
           buf->s.deviceId, buf->s.totalRunningHours, buf->s.totalPowercycles, buf->s.totalWatchdogResets,
           buf->s.version, location);
           
    int sendSuccess = 0;
    for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
        uint64_t timestamp = buf->s.timestamp + j;
        logmsg(LOG_DEBUG, "Time: %lu, Frequency: %u", timestamp, buf->s.frequency[j]);
            
        if (device->inactive == 0) {
            if ((buf->s.frequency[j] >= handle->lowerBound) && (buf->s.frequency[j] <= handle->upperBound)) {
                sendSuccess += sendToDB(handle, location, buf->s.deviceId, buf->s.frequency[j], timestamp);
            } else {
                logmsg(LOG_ERR, "%u out of bound, ignored", buf->s.frequency[j]);
            }
        } else {
            logmsg(LOG_DEBUG, "Inactive device, not sent to database");
        }
    }

    if (device->inactive == 0) {
        if (sendSuccess == 0) {
            logmsg(LOG_INFO, "Successfully sent whole minute to database");
        } else {
            logmsg(LOG_INFO, "Errors when sending to database, see above");
        }
    } else {
        logmsg(LOG_INFO, "Not sent to database, device is marked as inactive");
    }
    return 0;
}

void usage() {
    printf("sinkserver for mainsfrequency counter implementations\n");
    printf("https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-stm32,\n");
    printf("https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-esp32,\n");
    printf("https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-rpi,\n");
    printf("https://github.com/wollud1969/sinkConvert1\n");
    printf("Repo: https://home.hottis.de/gitlab/wolutator/sinkserver\n");
    printf("Version: " VERSION "\n");
    printf("\nUsage\n");
    printf("  -f FILENAME ...... Config file to be used\n");
    printf("  -v ............... Verbose, writes all logging on stdout too\n");
    printf("  -s FACILITY ...... Sets syslog facility, only LOCAL[0..7]\n");
    printf("                     USER and DAEMON are supported\n");
    printf("  -n USER .......... If started as root drop privileges and become\n");
    printf("                     USER\n");
    printf("  -b ............... fork into background\n");
    printf("  -h ............... This help\n");
}

int main(int argc, char **argv) {
    t_configHandle configHandle;
    t_commonHandle commonHandle;


    const char *configFilename = DEFAULT_CONFIG_FILENAME;
    const char *dropPrivilegesToUser = NULL;
    bool doFork = false;

    int c;
    while ((c = getopt(argc, argv, "f:vs:hn:b")) != -1) {
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
            case 'n':
                dropPrivilegesToUser = strdup(optarg);
                break;
            case 'b':
                doFork = true;
                break;
            case 'h':
                usage();
                exit(0);
                break;
        }
    }

    if ((getuid() == 0) && (dropPrivilegesToUser != NULL)) {
        logmsg(LOG_INFO, "dropping root privileges, become %s", dropPrivilegesToUser);
        struct passwd *userEntry = getpwnam(dropPrivilegesToUser);
        if (userEntry == NULL) {
            logmsg(LOG_ERR, "can not find entry for user %s", dropPrivilegesToUser);
            exit(1);
        }        

        if (setuid(userEntry->pw_uid) != 0) {
            logmsg(LOG_ERR, "unable to drop root privileges to %d", userEntry->pw_uid);
            exit(2);
        }
    }

    logmsg(LOG_INFO, "Version: " VERSION);

    if (0 != initConfig(configFilename, &configHandle)) {
        logmsg(LOG_ERR, "error when reading configuration");
        exit(3);
    }
    
    if (doFork) {
        int pid = fork();
        if (pid == -1) {
            logmsg(LOG_ERR, "error when forking into background: %d", errno);
            exit(4);
        }
        if (pid != 0) {
            logmsg(LOG_INFO, "successfully forking into background, child's pid is %d", pid);
            exit(0);
        }
    }

    if (0 != initReceiver(&configHandle, &commonHandle)) {
        logmsg(LOG_ERR, "error when initializing receiver");
        exit(5);
    }

    if (0 != initForwarder(&configHandle, &commonHandle)) {
        logmsg(LOG_ERR, "error when initializing forwarder");
        exit(6);
    }


    while (1) {
        t_minuteBuffer buf;
        
        if (receiveAndVerifyMinuteBuffer(&commonHandle, &buf) < 0) {
            logmsg(LOG_ERR, "error in receiveAndVerify");
            continue;
        }

        if (forwardMinuteBuffer(&commonHandle, &buf) < 0) {
            logmsg(LOG_ERR, "error in send");
        }
    }


    deinitForwarder(&commonHandle);
    deinitReceiver(&commonHandle);
    deinitConfig(&configHandle);
}
