CREATE SEQUENCE device_s START WITH 1 INCREMENT BY 1;

CREATE TABLE device_t (
    id integer PRIMARY KEY DEFAULT NEXTVAL('device_s'),
    deviceid varchar(16) UNIQUE NOT NULL,
    sharedsecret varchar(31) NOT NULL CHECK(char_length(sharedSecret) = 31),
    location varchar(128) NOT NULL,
    active boolean NOT NULL DEFAULT false
);
