FROM golang:1.7-alpine

RUN mkdir -p /run/docker/plugins

RUN set -ex \
    && apk add --no-cache --virtual .build-deps gcc libc-dev


COPY . /go/src/github.com/ekristen/docker-volume-vault-pki
WORKDIR /go/src/github.com/ekristen/docker-volume-vault-pki

RUN \
    go install --ldflags '-extldflags "-static"' \
    && apk del .build-deps

CMD ["/go/bin/docker-volume-vault-pki"]
