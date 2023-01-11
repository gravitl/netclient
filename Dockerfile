FROM gravitl/go-builder as builder
# add glib support daemon manager
WORKDIR /app
ARG version

RUN apk add git libpcap-dev
COPY . . 

ENV GO111MODULE=auto
RUN go mod tidy
RUN GOOS=linux CGO_ENABLED=1 /usr/local/go/bin/go build -ldflags="-X 'main.version=${version}'" -tags headless -o netclient-app .

FROM alpine:3.16.2

WORKDIR /root/

RUN apk add --no-cache --update bash libmnl gcompat iptables openresolv iproute2
COPY --from=builder /app/netclient-app ./netclient
COPY --from=builder /app/scripts/netclient.sh .
RUN chmod 0755 netclient && chmod 0755 netclient.sh


ENTRYPOINT ["/bin/bash", "./netclient.sh"]
