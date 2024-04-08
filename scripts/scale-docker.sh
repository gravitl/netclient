#!/bin/bash

TOKEN="eyJzZXJ2ZXIiOiJhcGkuc2VsZi1zY2FsZS5jbHVzdGVyY2F0LmNvbSIsInZhbHVlIjoiQ0kzT1BFWVBXR0dNTzNETlVYTjM3M1BUSzc0NVZQS04ifQ=="
PORT=51820
ENDPOINT=""

run(){
   for i in {1..30}
   do
      echo "spining Up container ${i}"
      port=$((PORT+${i}))
      sudo docker run -d  --privileged -p ${port}:${port}/udp -p ${port}:${port}/tcp -e TOKEN=${TOKEN} -e PORT=${port} -e ENDPOINT=${ENDPOINT}  -e HOST_NAME=netclient${i} -v /etc/netclient${i}:/etc/netclient --name netclient${i} abhi9686/netclient:NET-1082
      sleep 2
   done
}
cleanUp(){
   # remove all containers
   docker container rm $(docker container ls -aq) -f
   # delete config directories
   rm -rf /etc/netclient*
}
restart(){

}

main(){

   while getopts :sdr flag; do
	case "${flag}" in
   s)
      run
   ;;
   d)
      cleanUp
   ;;
   r)
      restart
   ;;
   esac
done
}

main "${@}"