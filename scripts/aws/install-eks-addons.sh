#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?Set AWS_REGION}"
: "${EKS_CLUSTER_NAME:?Set EKS_CLUSTER_NAME}"
: "${VPC_ID:?Set VPC_ID}"

helm repo add eks https://aws.github.io/eks-charts
helm repo add external-secrets https://charts.external-secrets.io
helm repo update eks external-secrets

kubectl create namespace external-secrets --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --version 1.14.0 \
  --set clusterName="${EKS_CLUSTER_NAME}" \
  --set region="${AWS_REGION}" \
  --set vpcId="${VPC_ID}" \
  --set replicaCount=2 \
  --set serviceAccount.create=true \
  --set serviceAccount.name=aws-load-balancer-controller \
  --wait --timeout 10m

helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --version 2.13.0 \
  --set replicaCount=2 \
  --set serviceAccount.create=true \
  --set serviceAccount.name=external-secrets \
  --wait --timeout 10m

kubectl rollout status deployment/aws-load-balancer-controller -n kube-system --timeout=5m
kubectl rollout status deployment/external-secrets -n external-secrets --timeout=5m
