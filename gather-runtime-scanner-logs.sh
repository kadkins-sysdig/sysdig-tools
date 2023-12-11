#!/bin/bash
set -x #echo on

# Set to the namespace you are running Sysdig in
NAMESPACE=kube-system

SFX=`date +"%Y-%m-%d_%H-%M-%S"`
OUTPUT_DIR=sysdig-rs-scan-logs-${SFX}

mkdir ${OUTPUT_DIR}
cd ${OUTPUT_DIR}

SANA_PODS=`kubectl get pods -n ${NAMESPACE} -o json | jq -r '.items[].metadata | select(.ownerReferences[].name=="sysdig-agent-node-analyzer") | .name'`
for pod in $SANA_PODS
do
  mkdir sana-${pod}
  cd sana-${pod}
  kubectl -n ${NAMESPACE} logs -c sysdig-runtime-scanner ${pod} > ${pod}.log
  kubectl -n ${NAMESPACE} describe pod ${pod} > ${pod}_describe.txt
  cd ..
done

kubectl -n ${NAMESPACE} get ds sysdig-agent-node-analyzer -o yaml > sana-ds.yaml
kubectl -n ${NAMESPACE} get cm sysdig-agent-runtime-scanner -o yaml > sana-cm.yaml
kubectl get pods -n ${NAMESPACE} -o wide > sysdig-running-pods.txt
kubectl get ds -n ${NAMESPACE} -o wide > sysdig-running-ds.txt
kubectl get nodes -o json | jq -r '.items[].status.images[] | .sizeBytes' | sort -nr | head -1 > largest-image-size.txt
kubectl get services > clusterip.txt
kubectl describe nodes > nodes-describe.txt
kubectl get events -A --sort-by=.metadata.creationTimestamp > all-events.txt 

cd ..
tar -czvf ${OUTPUT_DIR}.tar.gz ./${OUTPUT_DIR}
rm -r ./${OUTPUT_DIR}

echo "COMPLETE: Please send ${OUTPUT_DIR}.tar.gz to Sysdig"
