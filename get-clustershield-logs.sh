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

# Generate a timestamp
timestamp=$(date +%Y%m%d-%H%M%S)

# Iterate over each pod in the pod list
for podName in $podNameList
do
    # Build the output filename with cluster, pod, and timestamp
    outFile="${clusterName}-${podName}-${timestamp}.log"

    # Get the logs and save them to a timestamped file
    $KUBECTL_CMD logs -n "$namespace" "$podName" > "$outFile"

    # gzip the log file
    gzip "$outFile"

    echo "Log collected for $podName and output to: ${outFile}.gz"
done
