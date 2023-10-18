FROM gravitl/go-builder as builder
# add glib support daemon manager
WORKDIR /app

COPY . . 

RUN go mod tidy
RUN GOOS=linux CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags="-s -w" -o netclient-app .

FROM alpine:3.18.3

WORKDIR /root/

RUN apk add --no-cache --update bash libmnl gcompat openresolv iproute2
RUN apk add iptables ip6tables \
    && mv -v /sbin/ip6tables /sbin/ip6tables-disabled \
    && cp -v /sbin/ip6tables-nft /sbin/ip6tables
COPY --from=builder /app/netclient-app ./netclient
COPY --from=builder /app/scripts/netclient.sh .
RUN chmod 0755 netclient && chmod 0755 netclient.sh

# accepts an arg for gui server to be disabled, which is true by default.
# if you need the guiserver, build the image with this variable set to ""
# i.e.: `docker build ... --build-arg gui_server_disable=""` to enable it
ARG gui_server_disable="true"
# pass the arg to an env var that the script checks to disable guiserver
ENV GUI_SERVER_DISABLE=$gui_server_disable

ENTRYPOINT ["/bin/bash", "./netclient.sh"]
