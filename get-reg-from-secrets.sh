#!/bin/bash

# Check if kubectl or oc command is available
if command -v oc &> /dev/null; then
    CLI_COMMAND="oc"
elif command -v kubectl &> /dev/null; then
    CLI_COMMAND="kubectl"
else
    echo "Error: Neither 'oc' nor 'kubectl' is installed."
    exit 1
fi

# Get all secrets of type 'kubernetes.io/dockerconfigjson' in all namespaces
all_secrets=$($CLI_COMMAND get secrets --all-namespaces --field-selector type=kubernetes.io/dockerconfigjson -o jsonpath="{range .items[*]}{.metadata.namespace}={.metadata.name}{'\n'}{end}")

# Loop through each secret and extract the registry
for secret in $all_secrets; do
    secret_namespace="${secret%%=*}"  # Extract namespace
    secret_name="${secret#*=}"        # Extract secret name

    # Fetch and decode the secret to get the registry name
    secret_registry=$($CLI_COMMAND get secret "$secret_name" -n "$secret_namespace" -o jsonpath="{.data.\.dockerconfigjson}" | base64 --decode | jq -r '.auths | keys[]')

    # Output the result
    echo "Namespace: $secret_namespace, Secret Name: $secret_name, Registry: $secret_registry"
done
