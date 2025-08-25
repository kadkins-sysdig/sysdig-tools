#1/bin/bash

export HTTPS_PROXY="<YOUR PROXY>"
export HTTP_PROXY="<YOUR PROXY>"
export NO_PROXY="localhost,127.0.0.1,::1,.svc,.svc.cluster.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

export CLUSTER_NAME="<YOUR CLUSTER NAME>"
export API_URL_AUTHORITY="<YOUR API URL AUTHORITY>"
export API_URL="<YOUR API URL>"
export BEARER_TOKEN="<YOUR API TOKEN>"
export COMMAND="<YOUR COMMAND TO CALL ON NO RESULTS>"

#Default 5 minute polling interval
#export INTERVAL="300"
