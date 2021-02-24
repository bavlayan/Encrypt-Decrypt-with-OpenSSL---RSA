FROM alpine:latest
LABEL maintainer = "Everybody :)"

COPY . /usr/src/openssl_app
WORKDIR /usr/src/openssl_app

RUN apk update && \
    apk upgrade && \
    apk --update add \
        g++ \
        make \
        openssl-dev \
        bash \
    rm -rf /var/cache/apk/* && \
    make

ENTRYPOINT ["./rsa_encrypt_decrypt"]