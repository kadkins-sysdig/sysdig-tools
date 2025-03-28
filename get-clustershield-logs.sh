#!/bin/bash

# Check if the namespace argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <namespace>"
    exit 1
fi

# Set the namespace from the command line argument
namespace="$1"

# Check if oc is available, otherwise fall back to kubectl
if command -v oc &>/dev/null; then
    KUBECTL_CMD="oc"
else
    KUBECTL_CMD="kubectl"
fi

# Get the list of clustershield pods
podNameList=$($KUBECTL_CMD get pods -n "$namespace" -l app.kubernetes.io/name=clustershield --no-headers -o custom-columns=":metadata.name")

# Get the cluster name from the clustershield config map
clusterName=$($KUBECTL_CMD get configmap -n "$namespace" sysdig-clustershield -o json | jq '.data."cluster-shield.yaml"' | grep -oP 'name:\s*\K[\w\-]+' | head -n 1)

# Iterate over each pod in the pod list
for podName in $podNameList
do
    # Get the logs and save them to a file named <clusterName>-<podName>.log
    kubectl logs -n "$namespace" "$podName" > "$clusterName-$podName.log"

    # gzip the log file
    gzip "$clusterName-$podName.log"

    echo "Log collected for $podName and output to: $clusterName-$podName.log.gz"
done
