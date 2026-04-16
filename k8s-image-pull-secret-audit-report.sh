#!/usr/bin/env bash
set -euo pipefail

# Select CLI
if command -v oc >/dev/null 2>&1; then
  CLI=oc
elif command -v kubectl >/dev/null 2>&1; then
  CLI=kubectl
else
  echo "Error: neither 'oc' nor 'kubectl' found" >&2
  exit 1
fi

# Dependencies
for cmd in jq base64; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' is required" >&2
    exit 1
  fi
done

# Optional output file
OUTPUT_FILE="${1:-}"

normalize_registry() {
  local image="$1"
  local first_part

  # Strip digest
  image="${image%@*}"
  first_part="${image%%/*}"

  if [[ "$image" != */* ]]; then
    # nginx:latest
    echo "docker.io"
  elif [[ "$first_part" == *.* || "$first_part" == *:* || "$first_part" == "localhost" ]]; then
    # quay.io/org/app:1.0
    # my-registry:5000/team/app:2
    echo "$first_part"
  else
    # library/nginx:latest
    # bitnami/nginx:latest
    echo "docker.io"
  fi
}

normalize_auth_key() {
  local key="$1"

  # Remove scheme if present
  key="${key#https://}"
  key="${key#http://}"

  # Trim common Docker Hub path variants
  key="${key%/}"
  key="${key#/v1/}"

  echo "$key"
}

is_likely_public_registry() {
  local registry="$1"

  case "$registry" in
    docker.io|index.docker.io|registry.k8s.io|k8s.gcr.io|quay.io|ghcr.io|mcr.microsoft.com|public.ecr.aws)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

csv_escape() {
  local value="${1:-}"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

pods_json="$tmpdir/pods.json"
sa_json="$tmpdir/serviceaccounts.json"
secrets_json="$tmpdir/secrets.json"

$CLI get pods --all-namespaces -o json > "$pods_json"
$CLI get serviceaccounts --all-namespaces -o json > "$sa_json"
$CLI get secrets --all-namespaces -o json > "$secrets_json"

# Build ServiceAccount -> imagePullSecrets map
declare -A SA_PULLSECRETS
while IFS=$'\t' read -r ns sa secret_names; do
  SA_PULLSECRETS["$ns/$sa"]="$secret_names"
done < <(
  jq -r '
    .items[]
    | [
        .metadata.namespace,
        .metadata.name,
        ((.imagePullSecrets // []) | map(.name) | join(","))
      ]
    | @tsv
  ' "$sa_json"
)

# Build Secret -> auth registries map
declare -A SECRET_AUTHS
declare -A SECRET_TYPE

while IFS=$'\t' read -r ns name type dockerconfigjson; do
  SECRET_TYPE["$ns/$name"]="$type"

  if [[ "$type" == "kubernetes.io/dockerconfigjson" && -n "$dockerconfigjson" && "$dockerconfigjson" != "null" ]]; then
    auths="$(
      printf '%s' "$dockerconfigjson" \
        | base64 --decode 2>/dev/null \
        | jq -r '.auths | keys[]?' 2>/dev/null \
        | while read -r key; do normalize_auth_key "$key"; done \
        | paste -sd, -
    )"
    SECRET_AUTHS["$ns/$name"]="$auths"
  else
    SECRET_AUTHS["$ns/$name"]=""
  fi
done < <(
  jq -r '
    .items[]
    | [
        .metadata.namespace,
        .metadata.name,
        .type,
        (.data[".dockerconfigjson"] // "")
      ]
    | @tsv
  ' "$secrets_json"
)

emit_line() {
  local namespace="$1"
  local pod="$2"
  local serviceaccount="$3"
  local image="$4"
  local registry="$5"
  local auth_source="$6"
  local status="$7"
  local note="$8"

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$namespace")" \
    "$(csv_escape "$pod")" \
    "$(csv_escape "$serviceaccount")" \
    "$(csv_escape "$image")" \
    "$(csv_escape "$registry")" \
    "$(csv_escape "$auth_source")" \
    "$(csv_escape "$status")" \
    "$(csv_escape "$note")"
}

generate_report() {
  emit_line "namespace" "pod" "serviceaccount" "image" "registry" "auth_source" "status" "note"

  jq -c '
    .items[]
    | {
        namespace: .metadata.namespace,
        pod: .metadata.name,
        serviceaccount: (.spec.serviceAccountName // "default"),
        podPullSecrets: ((.spec.imagePullSecrets // []) | map(.name)),
        images: (
          [
            (.spec.initContainers[]?.image),
            (.spec.containers[]?.image),
            (.spec.ephemeralContainers[]?.image)
          ]
          | map(select(. != null and . != ""))
        )
      }
  ' "$pods_json" | while read -r pod_json; do
    ns="$(jq -r '.namespace' <<<"$pod_json")"
    pod_name="$(jq -r '.pod' <<<"$pod_json")"
    sa="$(jq -r '.serviceaccount' <<<"$pod_json")"

    mapfile -t pod_pullsecrets < <(jq -r '.podPullSecrets[]?' <<<"$pod_json")
    mapfile -t images < <(jq -r '.images[]?' <<<"$pod_json")

    IFS=',' read -r -a sa_pullsecrets <<< "${SA_PULLSECRETS[$ns/$sa]:-}"

    declare -A candidate_map=()
    for s in "${pod_pullsecrets[@]}"; do
      [[ -n "$s" ]] && candidate_map["$s"]="pod:$s"
    done
    for s in "${sa_pullsecrets[@]}"; do
      [[ -n "$s" && -z "${candidate_map[$s]:-}" ]] && candidate_map["$s"]="serviceaccount:$s"
    done

    for image in "${images[@]}"; do
      registry="$(normalize_registry "$image")"
      auth_source=""
      status=""
      note=""

      matched_source=""
      matched_secret=""
      candidate_list=()

      for secret_name in "${!candidate_map[@]}"; do
        candidate_list+=("${candidate_map[$secret_name]}")
        auths="${SECRET_AUTHS[$ns/$secret_name]:-}"

        IFS=',' read -r -a auth_keys <<< "$auths"
        for auth_key in "${auth_keys[@]}"; do
          [[ -z "$auth_key" ]] && continue

          if [[ "$registry" == "$auth_key" ]]; then
            matched_source="${candidate_map[$secret_name]}"
            matched_secret="$secret_name"
            break
          fi

          # Docker Hub variations
          if [[ "$registry" == "docker.io" && ( "$auth_key" == "index.docker.io" || "$auth_key" == "index.docker.io/v1" ) ]]; then
            matched_source="${candidate_map[$secret_name]}"
            matched_secret="$secret_name"
            break
          fi
        done

        [[ -n "$matched_secret" ]] && break
      done

      if [[ -n "$matched_secret" ]]; then
        auth_source="$matched_source"
        status="covered_by_secret"
        note="Referenced pull secret contains auth for registry"
      else
        if [[ ${#candidate_list[@]} -eq 0 ]]; then
          auth_source="none"
          if is_likely_public_registry "$registry"; then
            status="warning"
            note="No Pod or ServiceAccount imagePullSecrets; registry may be public or cluster may use node-level auth"
          else
            status="missing_secret_path"
            note="No Pod or ServiceAccount imagePullSecrets found for this Pod"
          fi
        else
          auth_source="$(IFS='; '; echo "${candidate_list[*]}")"
          if is_likely_public_registry "$registry"; then
            status="warning"
            note="Candidate pull secrets exist, but none match registry; image may still work if registry is public or node-level auth is in use"
          else
            status="no_matching_secret"
            note="Pod/ServiceAccount references pull secrets, but none contain auth for this registry"
          fi
        fi
      fi

      emit_line "$ns" "$pod_name" "$sa" "$image" "$registry" "$auth_source" "$status" "$note"
    done
  done
}

if [[ -n "$OUTPUT_FILE" ]]; then
  generate_report > "$OUTPUT_FILE"
  echo "Wrote report to $OUTPUT_FILE"
else
  generate_report
fi
