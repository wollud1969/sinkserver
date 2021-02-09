#include <stdio.h>
#include <stdlib.h>

#include <sinkStruct.h>
#include <logging.h>
#include <libconfig.h>


typedef struct {
    char deviceId[sizeof(((t_configBlock*)0)->deviceId)];
    char sharedSecret[sizeof(((t_configBlock*)0)->sharedSecret)];
} t_device;

const t_device devices[] = {
    { .deviceId = "MainsCnt01", .sharedSecret = "sharedSecretGanzGeheim" },
    { .deviceId = "", .sharedSecret = "" }
};

config_t cfg;


int readConfig() {
  config_init(&cfg);
  if (! config_read_file(&cfg, "/etc/sink20169.cfg")) {
    logmsg(LOG_ERR, "failed to read config file: %s:%d - %s\n",
        config_error_file(&cfg), config_error_line(&cfg),
        config_error_text(&cfg));
    config_destroy(&cfg);
    exit(-1);
  }
}

int main() {
    readConfig();
    
    int res = receiver(cfg);
    if (res < 0) {
        logmsg(LOG_ERR, "receiver failed to start, error: ", res);
    }

    config_destroy(&cfg);
}
