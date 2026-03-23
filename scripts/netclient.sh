#!/bin/bash

cleanup() {
    ip rule delete pref 3000 2>/dev/null || true
    ip rule delete pref 2500 2>/dev/null || true
    ip rule delete pref 2000 2>/dev/null || true
    if [ "${IFACE_NAME}" == "" ]; then
        IFACE_NAME="netmaker"
    fi
    echo "deleting interface $IFACE_NAME"
    ip link del "$IFACE_NAME" 2>/dev/null || true
}

trap 'cleanup' SIGTERM SIGINT

VERBOSITY_CMD=""
if [ "$VERBOSITY" != "" ]; then
    VERBOSITY_CMD="-v ${VERBOSITY}"
fi

TOKEN_CMD=""
if [ "$TOKEN" != "" ]; then
    TOKEN_CMD="-t $TOKEN"
fi

PORT_CMD=""
if [ "${PORT}" != "" ]; then
    PORT_CMD="-p ${PORT}"
fi

ENDPOINT_CMD=""
if [ "${ENDPOINT}" != "" ]; then
    ENDPOINT_CMD="-e ${ENDPOINT}"
fi

ENDPOINT6_CMD=""
if [ "${ENDPOINT6}" != "" ]; then
    ENDPOINT6_CMD="-E ${ENDPOINT6}"
fi

HOSTNAME_CMD=""
if [ "${HOST_NAME}" != "" ]; then
    HOSTNAME_CMD="-o ${HOST_NAME}"
fi

IFACE_CMD=""
if [ "${IFACE_NAME}" != "" ]; then
    IFACE_CMD="-I ${IFACE_NAME}"
fi

FIREWALL_CMD=""
if [ "${FIREWALL}" != "" ]; then
    FIREWALL_CMD="-f ${FIREWALL}"
fi

# Join network
echo "[netclient] joining network"
JOIN_CMD="/root/netclient join $TOKEN_CMD $PORT_CMD $ENDPOINT_CMD $MTU_CMD $HOSTNAME_CMD $STATIC_CMD $STATIC_PORT_CMD $IFACE_CMD $ENDPOINT6_CMD $FIREWALL_CMD"
$JOIN_CMD
if [ $? -ne 0 ]; then
    echo "Failed to join, quitting."
    exit 1
fi

# Run daemon directly as the foreground process
echo "[netclient] starting netclient daemon"
exec /root/netclient daemon $VERBOSITY_CMD
