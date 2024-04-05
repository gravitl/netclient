#!/bin/bash

TOKEN="eyJzZXJ2ZXIiOiJhcGkuc2VsZi1zY2FsZS5jbHVzdGVyY2F0LmNvbSIsInZhbHVlIjoiM1hXNFpUSEJDNEY2QUY3QVZHVkZIRlE2SU9DVUZISU8ifQ=="
PORT=51821
for i in {1..30}
do
   echo "spining Up container ${i}"
   sudo docker run -d  --privileged -p ${PORT}:${PORT}/udp -e TOKEN=${TOKEN} -e HOST_NAME=netclient${i} -v /etc/netclient${i}:/etc/netclient --name netclient${i} abhi9686/netclient:NET-1082
   PORT=$((PORT+1))
   sleep 2
done