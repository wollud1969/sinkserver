## sinkserver

The `sinkserver` receives measurement values from mains frequency counters in small UDP packets as described below.

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

The `deviceId` is set from the measurement device for identification purposes, the `hash` is calculated from the data in the above structure and a device specific shared secret. It is used by the sinkserver for authentication of the device. To calculate the hash, the device copies the shared secret, which has exactly 32 octets, into the `hash` array in the above structure, fills the rest of the structure with the values to be transmitted and calculated the SHA256 hash of the whole structure. The hash is copied afterwards into the `hash` array, the whole structure is then sent as an UDP packet.

The timestamp should be the UNIX time (seconds since epoch (midnight 1970-01-01 UTC)), `totalRunningHours` should be the uptime of the device, for the STM32 variant of the device it is the total uptime since deploy, for the ESP32 and RPi variants it is the current uptime. `totalPowercycles` and `totalWatchdogResets` are only filled by the STM32 variant with real data, the other variants set 0 here.

`version` is for my variants the short SHA value of the Git repo the software is built from, however, a different meaning could be used.

`frequency` finally are the averaged frequency values of the seconds of one minute in mHz.

The sink server filters frequency values which are less than 45000mHz and greater than 55000mHz. Frequency gradient filtering is currently not applied.

Device Id and corresponding shared secret are provisioned into the devices, the sinkserver has them in a configuration together with the location where the device is deployed.

The sinkserver is deployed under the name `sink.hottis.de` and receives at UDP port 20169.

Measurement is visualized at https://grafana.mainscnt.eu. 

The projects of the three current variants are at [RPi](https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-rpi), [STM32](https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-stm32) and [ESP32](https://home.hottis.de/gitlab/wolutator/mains-frequency-counter-esp32).



