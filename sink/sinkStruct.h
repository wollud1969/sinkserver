#ifndef _SINKSTRUCT_H_
#define _SINKSTRUCT_H_

#include <stdint.h>
#include <sha256.h>

#define SECONDS_PER_MINUTE 60
typedef struct __attribute__((__packed__)) {
    char deviceId[16];
    uint8_t hash[SHA256_BLOCK_SIZE];
    uint32_t totalRunningHours;
    uint32_t totalPowercycles;
    uint32_t totalWatchdogResets;
    uint32_t version;
    uint64_t timestamp;
    uint32_t frequency[SECONDS_PER_MINUTE];
} t_minuteStruct;

typedef union {
    t_minuteStruct s;
    uint8_t b[sizeof(t_minuteStruct)];
} t_minuteBuffer;

#endif // _SINKSTRUCT_H_
