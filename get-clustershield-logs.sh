#!/bin/bash

# Check if the namespace argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <namespace>"
    exit 1
fi

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
clusterName=$($KUBECTL_CMD get configmap -n "$namespace" sysdig-clustershield -o json \
    | jq '.data."cluster-shield.yaml"' \
    | grep -oP 'name:\s*\K[\w\-]+' | head -n 1)

# Generate a timestamp
timestamp=$(date +%Y%m%d-%H%M%S)

# Directory to hold temporary logs
workdir="logs-${clusterName}-${timestamp}"
mkdir -p "$workdir"

# Array to keep track of per-pod tar files
tarFiles=()

# Iterate over each pod in the pod list
for podName in $podNameList
do
    logFile="${podName}.log"
    tarFile="${clusterName}-${podName}-${timestamp}.tar"

    # Collect logs
    $KUBECTL_CMD logs -n "$namespace" "$podName" > "$workdir/$logFile"

    # Create a tarball containing the log
    tar -cf "$workdir/$tarFile" -C "$workdir" "$logFile"

    # Clean up the raw log file
    rm -f "$workdir/$logFile"

    # Track the tar file
    tarFiles+=("$workdir/$tarFile")

    echo "Log collected and archived for $podName: $workdir/$tarFile"
done

# Combine only the tracked tar files into one gzipped archive
finalArchive="${clusterName}-all-logs-${timestamp}.tar.gz"
tar -czf "$finalArchive" -C "$workdir" $(basename -a "${tarFiles[@]}")

echo "All tar files combined into archive: $finalArchive"
