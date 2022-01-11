CREATE SEQUENCE device_s START WITH 1 INCREMENT BY 1;

CREATE TABLE device_t (
    id integer PRIMARY KEY DEFAULT NEXTVAL('device_s'),
    deviceid varchar(16) UNIQUE NOT NULL,
    sharedsecret varchar(31) NOT NULL CHECK(char_length(sharedSecret) = 31),
    location varchar(128) NOT NULL,
    active boolean NOT NULL DEFAULT false
);

CREATE SEQUENCE alarm_event_s START WITH 1 INCREMENT BY 1;

CREATE TABLE alarm_event_t (
    id integer PRIMARY KEY DEFAULT NEXTVAL('alarm_event_s'),
    time timestamp without time zone NOT NULL DEFAULT now(),
    status varchar(32) NOT NULL,
    info varchar(256) NOT NULL,
    name varchar(32) NOT NULL
);

CREATE TABLE mainsfrequency (
    time timestamp without time zone NOT NULL,
    host text,
    location text,
    freq double precision,
    valid smallint NOT NULL DEFAULT 1
);

SELECT create_hypertable('mainsfrequency', 'time');
