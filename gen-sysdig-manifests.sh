#!/bin/bash
#set -x #echo on

#===========================================================
# This script was written by Kendall Adkins for Verizon to
# generate manifest files using the sysdig-deploy helm
# chart.
#
# Please direct any questions to kendall.adkins@sysdig.com
#
# Risk! In the event that the helm template output changes 
# as a result of helm chart updates, this script could break.
#
# Date: November 2th, 2022
#
#===========================================================

function help {
  echo ""
  echo "Script: $(basename ${0})"
  echo ""
  echo "Description: This script will generate manifests using the sysdig-deploy helm chart."
  echo "             Helm must be installed and a helm values file is required."
  echo ""
  echo "Usage: $(basename ${0}) [ -f <helm values file>] [ -n <namespace>] [ -p <prefix>] [ -h]"
  echo ""
  echo "options:"
  echo "  -f, --helm-values-file: the helm values file (required)"
  echo "  -n, --namespace: the kubernetes namespace used in the manifests (default: sysdig-agent)"
  echo "  -p, --manifests-prefix: the prefix used in the manifest output file names (optional)"
  echo "  -h, --help: display this help message"
  echo ""
}

function is_valid_value {
  if [[ ${1} == -* ]] || [[ ${1} == --* ]] || [[ -z ${1} ]]; then
    return 1
  else
    return 0
  fi
}

function is_valid_file {
  if [ ! -f ${1} ]; then
    return 1
  else
    return 0
  fi
}

#
# validate and load the arguments
#
HELM_VALUES_FILE=""
NAMESPACE="sysdig-agent"
MANIFEST_PREFIX=""

if [[ ${#} -eq 0 ]]; then
  help
  exit 1
fi

while [[ ${#} > 0 ]]
do

  case ${1} in
    
    -f|--helm-values-file)
      if is_valid_value "${2}"; then
        if is_valid_file "${2}"; then
          HELM_VALUES_FILE=${2}
        else
          echo "ERROR: Helm values file does not exist"
          echo "Use -h | --help for $(basename ${0}) usage."
          exit 1
        fi
      else
        echo "ERROR: Invalid argument for helm values file"
        echo "Use -h | --help for $(basename ${0}) usage."
        exit 1
      fi
      shift
      ;;

    -n|--namespace)
      if is_valid_value "${2}"; then
        NAMESPACE=${2}
      else
        echo "ERROR: Invalid argument for namespace"
        echo "Use -h | --help for $(basename ${0}) usage."
        exit 1
      fi
      shift
      ;;

    -p|--manifests-prefix)
      if is_valid_value "${2}"; then
        MANIFEST_PREFIX=${2}
      else
        echo "ERROR: Invalid argument for manifest prefix"
        echo "Use -h | --help for $(basename ${0}) usage."
        exit 1
      fi
      shift
      ;;

    -h|--help)
      help
      exit 1
      ;;

    *) 
      echo "ERROR: Invalid option: ${1}, use -h | --help for $(basename ${0}) usage."
      exit 1
      ;;

  esac
  shift
done

#
# validate that helm is installed
#
echo "STATUS: Checking for Helm..."
if ! [ -x "$(command -v helm)" ]
then
  echo "Error: Helm not installed! See: https://helm.sh/docs/intro/install/"
  exit 1
fi

#
# Update the chart and use helm template to
# generate the manifests
#
TIMESTAMP=`date +"%Y-%m-%d_%H-%M-%S"`
TEMPLATE_FILE=helm-template-${TIMESAMP}.txt

echo "STATUS: Executing helm template to generate the Sysdig manifests"

helm repo add sysdig https://charts.sysdig.com --force-update > /dev/null
helm_exit_code=$?
if [ $helm_exit_code -ne 0 ]; then
  echo "ERROR: Unable to add Sysdig helm charts: https://charts.sysdig.com"
  exit 1
fi

helm template -f ${HELM_VALUES_FILE} sysdig-agent --namespace ${NAMESPACE} --skip-tests \
	sysdig/sysdig-deploy > ${TEMPLATE_FILE}
	#sysdig/sysdig-deploy --version 1.3.13 > ${TEMPLATE_FILE}
helm_exit_code=$?
if [ $helm_exit_code -ne 0 ]; then
  echo "ERROR: Helm template generation failed. This is likely due to an invalid values file."
  exit 1
fi

#
# Parse the helm output into individual files
#
echo "STATUS: Parsing helm template output file"
input=${TEMPLATE_FILE}
found_seperator="false"
found_manifest_name="false"

while IFS= read -r line
do
  if [ "$found_manifest_name" = "true" ] && [ "$line" != "---" ]; then 
    echo "$line" >> $manifest_name
  fi
  if [ "$found_seperator" = "true" ]; then 
    manifest_name="${line#*/}"
    manifest_name="${manifest_name#charts\/}"
    manifest_name="${manifest_name//templates\//}"
    manifest_name="${manifest_name//\//-}"
    found_seperator="false"
    found_manifest_name="true"
  fi
  if [ "$line" = "---" ]; then 
    found_seperator="true"
    found_manifest_name="false"
  fi
done < $input

rm ${TEMPLATE_FILE}

#
# Rename the raw helm template names using 
# a standard manifest naming convention
#
echo "STATUS: Renaming parsed manifest files"
prefix=${MANIFEST_PREFIX}
mv agent-clusterrole.yaml ${prefix}sa-cr.yaml 2> /dev/null
mv agent-clusterrolebinding.yaml ${prefix}sa-crb.yaml 2> /dev/null
mv agent-configmap.yaml ${prefix}sa-cm.yaml 2> /dev/null
mv agent-daemonset.yaml ${prefix}sa-ds.yaml 2> /dev/null
mv agent-psp.yaml ${prefix}sa-psp.yaml 2> /dev/null
mv agent-secrets.yaml ${prefix}sa-se.yaml 2> /dev/null
mv agent-serviceaccount.yaml ${prefix}sa-sa.yaml 2> /dev/null
mv nodeAnalyzer-clusterrole-node-analyzer.yaml ${prefix}sana-cr.yaml 2> /dev/null
mv nodeAnalyzer-clusterrolebinding-node-analyzer.yaml ${prefix}sana-crb.yaml 2> /dev/null
mv nodeAnalyzer-daemonset-node-analyzer.yaml ${prefix}sana-ds.yaml 2> /dev/null
mv nodeAnalyzer-psp.yaml ${prefix}sana-psp.yaml 2> /dev/null
mv nodeAnalyzer-runtimeScanner-runtime-scanner-configmap.yaml ${prefix}sana-rs-cm.yaml 2> /dev/null
mv nodeAnalyzer-secrets.yaml ${prefix}sana-se.yaml 2> /dev/null
mv nodeAnalyzer-serviceaccount-node-analyzer.yaml ${prefix}sana-sa.yaml 2> /dev/null
mv nodeAnalyzer-configmap-kspm-analyzer.yaml sana-kspm-cm.yaml 2> /dev/null
mv kspmCollector-clusterrole.yaml kspm-cr.yaml 2> /dev/null
mv kspmCollector-clusterrolebinding.yaml kspm-crb.yaml 2> /dev/null
mv kspmCollector-configmap.yaml kspm-cm.yaml 2> /dev/null
mv kspmCollector-deployment.yaml kspm-de.yaml 2> /dev/null
mv kspmCollector-secret.yaml kspm-se.yaml 2> /dev/null
mv kspmCollector-serviceaccount.yaml kspm-sa.yaml 2> /dev/null

#
# Done
#
echo "SUCCESS: Sysdig deployment manifests generation complete."
