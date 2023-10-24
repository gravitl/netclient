FROM gravitl/go-builder as builder
# add glib support daemon manager
WORKDIR /app

COPY . . 

RUN go mod tidy
RUN GOOS=linux CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags="-s -w" -o netclient-app .

FROM alpine:3.18.4

WORKDIR /root/

RUN apk add --no-cache --update bash libmnl gcompat openresolv iproute2 openrc \
    && mkdir -p /run/openrc \
    && touch /run/openrc/softlevel
RUN apk add iptables ip6tables \
    && mv -v /sbin/ip6tables /sbin/ip6tables-disabled \
    && cp -v /sbin/ip6tables-nft /sbin/ip6tables
COPY --from=builder /app/netclient-app ./netclient
COPY --from=builder /app/scripts/netclient.sh .
RUN chmod 0755 netclient && chmod 0755 netclient.sh

# accepts an arg for gui server to be enabled - by default, it's disabled.
# if you need the gui server, build the image with this variable set to "true"
# i.e.: `docker build ... --build-arg gui_server_enabled="true"` to enable it
ARG gui_server_enabled="false"
# pass the arg to an env var that the script checks to enable guiserver
ENV GUI_SERVER_ENABLED=$gui_server_enabled

ENTRYPOINT ["/bin/bash", "./netclient.sh"]
