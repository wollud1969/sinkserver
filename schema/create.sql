create sequence device_s;

CREATE TABLE device_t (
    id integer DEFAULT nextval('device_s') NOT NULL,
    deviceid character varying(64) NOT NULL,
    sharedsecret character varying(31) NOT NULL,
    location character varying(128) NOT NULL,
    active boolean DEFAULT false NOT NULL,
    contact character varying(128),
    flaky boolean DEFAULT false NOT NULL,
    CONSTRAINT device_t_sharedsecret_check CHECK ((char_length((sharedsecret)::text) = 31))
);

ALTER TABLE ONLY device_t
    ADD CONSTRAINT device_t_deviceid_key UNIQUE (deviceid);

ALTER TABLE ONLY device_t
    ADD CONSTRAINT device_t_pkey PRIMARY KEY (id);

CREATE TABLE mainsfrequency (
    "time" timestamp without time zone NOT NULL,
    host text,
    location text,
    freq double precision,
    valid smallint DEFAULT 1 NOT NULL
);

select create_hypertable('mainsfrequency', 'time');


