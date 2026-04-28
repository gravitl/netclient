FROM gravitl/go-builder:1.25.3 AS builder
WORKDIR /app

COPY . . 

RUN go mod tidy
RUN GOOS=linux CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags="-s -w" -o netclient-app .

# Use version 3.22.3 until this issue is resolved.
# https://github.com/NetworkConfiguration/openresolv/issues/45
FROM alpine:3.22.3

WORKDIR /root/

RUN apk add --no-cache --update \
        bash \
        iproute2 \
        wireguard-tools \
        openresolv \
        iptables \
        ip6tables \
        nftables

COPY --from=builder /app/netclient-app ./netclient
COPY --from=builder /app/scripts/netclient.sh .
RUN chmod 0755 netclient && chmod 0755 netclient.sh && ln -s /root/netclient /usr/bin/netclient

ENTRYPOINT ["/bin/bash", "./netclient.sh"]
