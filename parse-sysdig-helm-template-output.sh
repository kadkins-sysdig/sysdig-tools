#!/bin/bash
#set -x #echo on

#===========================================================
# This script was written by Kendall Adkins to parse
# the template output from helm into individual manifest 
# files when using the sysdig-deploy helm chart.
#
# Please direct any questions to kendall.adkins@sysdig.com
#
# Risk! In the event that the helm template output changes 
# as a result of helm chart updates, this script could break.
#
# Date: June 27th, 2023
#
#===========================================================

function help {
  echo ""
  echo "Script: $(basename ${0})"
  echo ""
  echo "Description: This script will parse the template output from helm into individual"
  echo "             manifest files when using the sysdig-deploy helm chart."
  echo ""
  echo "Usage: $(basename ${0}) [ -f <helm template output file>] [ -p <prefix>] [ -h]"
  echo ""
  echo "options:"
  echo "  -f, --helm-template-file: the helm template file (required)"
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
MANIFEST_PREFIX=""

if [[ ${#} -eq 0 ]]; then
  help
  exit 1
fi

while [[ ${#} > 0 ]]
do

  case ${1} in
    
    -f|--helm-template-file)
      if is_valid_value "${2}"; then
        if is_valid_file "${2}"; then
          TEMPLATE_FILE=${2}
        else
          echo "ERROR: Helm template file does not exist"
          echo "Use -h | --help for $(basename ${0}) usage."
          exit 1
        fi
      else
        echo "ERROR: Invalid argument for helm template file"
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

if [[ "${TEMPLATE_FILE}" == "" ]]; then
  echo "ERROR: Helm template file argument is required."
  echo "Use -h | --help for $(basename ${0}) usage."
  exit 1
fi

#
# Parse the helm output into individual files
#
echo "STATUS: Parsing helm template output file: ${TEMPLATE_FILE}"
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

#
# Rename the raw helm template names using 
# a standard manifest naming convention
#
echo "STATUS: Renaming parsed manifest files"
prefix=${MANIFEST_PREFIX}
mv agent-role.yaml ${prefix}sa-r.yaml 2> /dev/null
mv agent-rolebinding.yaml ${prefix}sa-rb.yaml 2> /dev/null
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
mv nodeAnalyzer-configmap-host-scanner.yaml sana-hs-cm.yaml 2> /dev/null
mv kspmCollector-clusterrole.yaml sa-kspm-cr.yaml 2> /dev/null
mv kspmCollector-clusterrolebinding.yaml sa-kspm-crb.yaml 2> /dev/null
mv kspmCollector-configmap.yaml sa-kspm-cm.yaml 2> /dev/null
mv kspmCollector-deployment.yaml sa-kspm-de.yaml 2> /dev/null
mv kspmCollector-secret.yaml sa-kspm-se.yaml 2> /dev/null
mv kspmCollector-serviceaccount.yaml sa-kspm-sa.yaml 2> /dev/null
#
# Done
#
echo "SUCCESS: Parsing of Sysdig helm template output file complete."
