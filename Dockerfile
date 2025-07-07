FROM gravitl/go-builder:1.23.0 AS builder
# add glib support daemon manager
WORKDIR /app

COPY . . 

RUN go mod tidy
RUN GOOS=linux CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags="-s -w" -o netclient-app .

FROM alpine:3.22.0

WORKDIR /root/

RUN apk add --no-cache --update \
        bash \
        libmnl \
        gcompat \
        openresolv \
        iproute2 \
        wireguard-tools \
        openrc \
        iptables \
        ip6tables \
        iptables-nft \
        nftables \
    && mkdir -p /run/openrc \
    && touch /run/openrc/softlevel
    
COPY --from=builder /app/netclient-app ./netclient
COPY --from=builder /app/scripts/netclient.sh .
RUN chmod 0755 netclient && chmod 0755 netclient.sh

ENTRYPOINT ["/bin/bash", "./netclient.sh"]
