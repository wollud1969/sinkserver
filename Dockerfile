FROM alpine:3.13 AS builder

ARG VERSION ${CI_COMMIT_SHORT_SHA}

COPY sink/ /tmp/sink

RUN \
  apk update && \
  apk add alpine-sdk && \
  apk add libconfig-dev && \
  apk add postgresql-dev && \
  cd /tmp/sink && \
  make VERSION=${VERSION}


FROM alpine:3.13

COPY --from=builder /tmp/sink/build/sink20169 /usr/local/bin/

RUN \
  apk add --no-cache libpq && \
  apk add --no-cache libconfig && \
  mkdir /etc/sink

EXPOSE 20169/udp

VOLUME /etc/sink

CMD [ "/usr/local/bin/sink20169", "-f", "/etc/sink/sink20169.cfg", "-n", "nobody", "-v" ]

  



