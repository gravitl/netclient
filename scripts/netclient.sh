#!/bin/bash

sh -c rc-status
#Define cleanup
cleanup() {
    ip rule delete pref 3000
    ip rule delete pref 2500
    ip rule delete pref 2000
    echo "deleting interface" $net
    if [ "${IFACE_NAME}" == "" ];then
        IFACE_NAME="netmaker"
    fi
    ip link del $IFACE_NAME
}



# install netclient
echo "[netclient] starting netclient daemon"
/root/netclient install
wait $!

# join network based on env vars
echo "[netclient] joining network"

TOKEN_CMD=""
if [ "$TOKEN" != "" ]; then
    TOKEN_CMD="-t $TOKEN"
fi

PORT_CMD=""
if [ "${PORT}" != "" ]; then
    PORT_CMD="-p ${PORT}"
fi

ENDPOINT_CMD=""
if [ "${ENDPOINT}" != "" ];then
    ENDPOINT_CMD="-e ${ENDPOINT}"
fi

ENDPOINT6_CMD=""
if [ "${ENDPOINT6}" != "" ];then
    ENDPOINT6_CMD="-E ${ENDPOINT6}"
fi

MTU_CMD=""
if [ "${MTU}" != "" ];then
    MTU_CMD="-m ${MTU}"
fi

HOSTNAME_CMD=""
if [ "${HOST_NAME}" != "" ];then
    HOSTNAME_CMD="-o ${HOST_NAME}"
fi

STATIC_CMD=""
if [ "${IS_STATIC}" != "" ];then
    STATIC_CMD="-i ${IS_STATIC}"
fi
IFACE_CMD=""
if [ "${IFACE_NAME}" != "" ];then
    IFACE_CMD="-I ${IFACE_NAME}"
fi

netclient join $TOKEN_CMD $PORT_CMD $ENDPOINT_CMD $MTU_CMD $HOSTNAME_CMD $STATIC_CMD $IFACE_CMD $ENDPOINT6_CMD
if [ $? -ne 0 ]; then { echo "Failed to join, quitting." ; exit 1; } fi

tail -f /var/log/netclient.log &

#Trap SigTerm
trap 'cleanup' SIGTERM

wait $!
