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
    PGresult *deviceResult;
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
    PGconn *conn;
    t_device foundDevice;
} t_commonHandle;

bool verbose = false;
bool debug = false;


int openDatabaseConnection(t_commonHandle *handle) {
    int res = 0;
    
    if (! handle->conn) {
        logmsg(LOG_DEBUG, "Opening connection to database");
        handle->conn = PQconnectdb("");
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
    config_init(&(configHandle->cfg));
    if (! config_read_file(&(configHandle->cfg), configFilename)) {
        logmsg(LOG_ERR, "failed to read config file: %s:%d - %s\n",
            config_error_file(&(configHandle->cfg)), config_error_line(&(configHandle->cfg)),
            config_error_text(&(configHandle->cfg)));
        config_destroy(&(configHandle->cfg));
        return -1;
    }

    return 0;
}

void deinitConfig(t_configHandle *configHandle) {
    config_destroy(&(configHandle->cfg));
}

// When you got a result here, remember to free it using freeDevice
int findDevice(t_commonHandle *handle, char *deviceId) {
    int retCode = 0;

    // we already have found it
    if (handle->foundDevice.deviceResult) {
        return 0;
    }

    if (0 == openDatabaseConnection(handle)) {
        char stmt[256];
        int res1 = snprintf(stmt, sizeof(stmt),
                            "SELECT sharedsecret, active, location "
                            "  FROM device_t "
                            "  WHERE deviceid = '%s'",
                            deviceId);
        if (res1 > sizeof(stmt)) {
            logmsg(LOG_ERR, "stmt buffer to small");
            retCode = -1;
        } else {
            logmsg(LOG_DEBUG, "Statement: %s", stmt);
            PGresult *res2 = PQexec(handle->conn, stmt);
            ExecStatusType execStatus = PQresultStatus(res2);
            if (execStatus != PGRES_TUPLES_OK) {
                logmsg(LOG_ERR, "findDevice query fails, database returns %s", PQresStatus(execStatus));
                retCode = -2;
            } else {
                int ntuples = PQntuples(res2);
                if (ntuples == 1) {
                    handle->foundDevice.deviceResult = res2;
                    handle->foundDevice.sharedSecret = PQgetvalue(res2, 0, 0);
                    handle->foundDevice.inactive = (strcmp(PQgetvalue(res2, 0, 1), "f") == 0);
                    handle->foundDevice.location = PQgetvalue(res2, 0, 2);
                    logmsg(LOG_DEBUG, "found sharedsecret is %s, inactive is %d, location is %s", 
                           handle->foundDevice.sharedSecret, handle->foundDevice.inactive,
                           handle->foundDevice.location);
                } else {
                    logmsg(LOG_ERR, "no device found");
                    PQclear(res2);
                    retCode = -3;
                }
            }
        }
    } else {
        logmsg(LOG_ERR, "No database connection available, data lost");
        retCode = -4;
    } 
    
    return retCode;
}

void freeDevice(t_commonHandle *handle) {
    if (handle->foundDevice.deviceResult) {
        PQclear(handle->foundDevice.deviceResult);
        handle->foundDevice.deviceResult = NULL;
        handle->foundDevice.deviceId = NULL;
        handle->foundDevice.sharedSecret = NULL;
        handle->foundDevice.location = NULL;
        logmsg(LOG_DEBUG, "device has been free");
    }
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

    if (0 != findDevice(handle, buf->s.deviceId)) {
        logmsg(LOG_ERR, "Device %s not found", buf->s.deviceId);
        return -4;
    }
    const char *sharedSecret = handle->foundDevice.sharedSecret;

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
             uint32_t frequency, uint8_t valid, uint64_t timestamp) {
    int retcode = 0;
    if (0 == openDatabaseConnection(handle)) {
        int frequency_before_point = frequency / 1000;
        int frequency_behind_point = frequency - (frequency_before_point * 1000);
        char stmt[256];
        int res1 = snprintf(stmt, sizeof(stmt),
                            "INSERT INTO mainsfrequency (time, host, location, valid, freq) "
                            "VALUES(to_timestamp("
#ifdef OpenBSD
                                                 "%llu"
#else
                                                 "%lu"
#endif                                                      
                                                       "), '%s', '%s', %d, %d.%03d)",
                            timestamp, deviceId, location, valid,
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
    if (0 != findDevice(handle, buf->s.deviceId)) {
        logmsg(LOG_ERR, "Device %s not found", buf->s.deviceId);
        return -4;
    }
    t_device *device = &(handle->foundDevice);
    const char *location = device->location;

    logmsg(LOG_INFO, "D: %s, R: %u, P: %u, W: %u, V: %08x, L: %s", 
           buf->s.deviceId, buf->s.totalRunningHours, buf->s.totalPowercycles, buf->s.totalWatchdogResets,
           buf->s.version, location);
           
    int sendSuccess = 0;
    for (uint8_t j = 0; j < SECONDS_PER_MINUTE; j++) {
        uint64_t timestamp = buf->s.timestamp + j;
        logmsg(LOG_DEBUG, "Time: %lu, Frequency: %u", timestamp, buf->s.frequency[j]);
            
        if (device->inactive == 0) {
            uint8_t valid = ((buf->s.frequency[j] >= handle->lowerBound) && (buf->s.frequency[j] <= handle->upperBound)) ? 1 : 0;
            if (valid == 0) {
                logmsg(LOG_INFO, "Out of range: Time: %lu, Frequency: %u", timestamp, buf->s.frequency[j]);
            }
            sendSuccess += sendToDB(handle, location, buf->s.deviceId, buf->s.frequency[j], valid, timestamp);
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
    printf("  -d ............... Also log debug output\n");
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
    commonHandle.foundDevice.deviceResult = NULL;


    const char *configFilename = DEFAULT_CONFIG_FILENAME;
    const char *dropPrivilegesToUser = NULL;
    bool doFork = false;

    int c;
    while ((c = getopt(argc, argv, "f:vds:hn:b")) != -1) {
        switch (c) {
            case 'f':
                configFilename = strdup(optarg);
                break;
            case 'v':
                verbose = true;
                break;
            case 'd':
                debug = true;
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

        // this is relevant AFTER one or both of the following calls,
        // is has an effect first in the second cycle through the loop
        freeDevice(&commonHandle);

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
