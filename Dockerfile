FROM alpine:3.18.3 AS builder

ARG VERSION="dockerized"

COPY sink/ /tmp/sink

RUN \
  apk update && \
  apk add alpine-sdk && \
  apk add libconfig-dev && \
  apk add postgresql-dev && \
  cd /tmp/sink && \
  make VERSION=${VERSION}


FROM alpine:3.18.3

ENV PGHOST=""
ENV PGDATABASE="mainscnt"
ENV PGUSER="sink"
ENV PGPASSWORD=""
ENV PGSSLMODE="require"
ENV LOWER_BOUND="44000"
ENV UPPER_BOUND="56000"

COPY --from=builder /tmp/sink/build/sink20169 /usr/local/bin/

RUN \
  apk add --no-cache libpq && \
  apk add --no-cache libconfig 

EXPOSE 20169/udp
USER nobody

CMD [ "/usr/local/bin/sink20169", "-v", "-d" ]

  



