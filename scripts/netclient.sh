#!/bin/bash

sh -c rc-status
#Define cleanup
cleanup() {
    nets=($(wg show interfaces))
    for net in ${nets[@]}; do
        echo "deleting interface" $net
        ip link del $net
    done
}

#Trap SigTerm
trap 'cleanup' SIGTERM

# install netclient
echo "[netclient] starting netclient daemon"
/root/netclient install
wait $!

# check if needs to use the gui server
if [ "${GUI_SERVER_ENABLED}" == "true" ]; then
    echo "[netclient] enabling gui server"
    netclient guiServer enable
else
    echo "[netclient] disabling gui server"
    netclient guiServer disable
fi

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
if [ "${ENPOINT}" != "" ];then
    ENDPOINT_CMD="-e ${ENPOINT}"
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

netclient join $TOKEN_CMD $PORT_CMD $ENDPOINT_CMD $MTU_CMD $HOSTNAME_CMD $STATIC_CMD
if [ $? -ne 0 ]; then { echo "failed to join, quitting." ; exit 1; } fi

sleep infinity
