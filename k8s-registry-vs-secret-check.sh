#!/usr/bin/env bash
set -euo pipefail

# Choose oc or kubectl
if command -v oc >/dev/null 2>&1; then
    CLI_COMMAND="oc"
elif command -v kubectl >/dev/null 2>&1; then
    CLI_COMMAND="kubectl"
else
    echo "Error: Neither 'oc' nor 'kubectl' is installed."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: 'jq' is required."
    exit 1
fi

# Normalize an image reference to a registry hostname
# Rules:
# - image with explicit registry host: use first path element if it contains '.' or ':' or is 'localhost'
# - otherwise default to docker.io
normalize_registry() {
    local image="$1"
    local first_part

    # Remove any @sha256 digest suffix for easier parsing
    image="${image%@*}"

    first_part="${image%%/*}"

    if [[ "$image" != */* ]]; then
        # Example: nginx:latest
        echo "docker.io"
    elif [[ "$first_part" == *.* || "$first_part" == *:* || "$first_part" == "localhost" ]]; then
        # Example: quay.io/org/app:1.0 or my-registry:5000/team/app:2
        echo "$first_part"
    else
        # Example: library/nginx:latest or bitnami/nginx:latest
        echo "docker.io"
    fi
}

echo "Collecting registries from image pull secrets..." >&2

# Build a unique list of registries found in dockerconfigjson secrets
mapfile -t secret_registries < <(
    $CLI_COMMAND get secrets --all-namespaces \
        --field-selector type=kubernetes.io/dockerconfigjson \
        -o json |
    jq -r '
        .items[]
        | .data[".dockerconfigjson"]
        | select(. != null)
        | @base64d
        | fromjson
        | .auths
        | keys[]
    ' |
    sed 's#^https\?://##' |
    sed 's#/$##' |
    sort -u
)

echo "Collecting registries from images used by pods..." >&2

# Pull image references from containers, initContainers, and ephemeralContainers
mapfile -t images_in_use < <(
    $CLI_COMMAND get pods --all-namespaces -o json |
    jq -r '
        .items[]
        | [
            (.spec.containers[]?.image),
            (.spec.initContainers[]?.image),
            (.spec.ephemeralContainers[]?.image)
          ]
        | .[]
        | select(. != null and . != "")
    ' |
    sort -u
)

# Normalize image refs to registries
declare -A used_registry_map=()
for image in "${images_in_use[@]}"; do
    reg="$(normalize_registry "$image")"
    used_registry_map["$reg"]=1
done

mapfile -t used_registries < <(
    printf '%s\n' "${!used_registry_map[@]}" | sort -u
)

echo
echo "=== Registries found in image pull secrets ==="
printf '%s\n' "${secret_registries[@]:-}"

echo
echo "=== Registries used by pod images ==="
printf '%s\n' "${used_registries[@]:-}"

echo
echo "=== Registries used by pod images that do NOT have a matching dockerconfigjson secret ==="

# Compare used registries vs secret registries
declare -A secret_registry_map=()
for reg in "${secret_registries[@]}"; do
    secret_registry_map["$reg"]=1
done

missing_any=0
for reg in "${used_registries[@]}"; do
    if [[ -z "${secret_registry_map[$reg]:-}" ]]; then
        echo "$reg"
        missing_any=1
    fi
done

if [[ "$missing_any" -eq 0 ]]; then
    echo "None"
fi
