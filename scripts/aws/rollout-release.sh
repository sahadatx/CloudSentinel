#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?Set AWS_REGION}"
: "${EKS_CLUSTER_NAME:?Set EKS_CLUSTER_NAME}"
: "${BACKEND_IMAGE:?Set BACKEND_IMAGE to a digest-pinned image}"
: "${FRONTEND_IMAGE:?Set FRONTEND_IMAGE to a digest-pinned image}"
: "${GITHUB_RUN_ID:?Set GITHUB_RUN_ID}"

aws eks update-kubeconfig \
  --region "${AWS_REGION}" \
  --name "${EKS_CLUSTER_NAME}" \
  --alias "cloudsentinel-${AWS_REGION}-${EKS_CLUSTER_NAME}"
kubectl config use-context "cloudsentinel-${AWS_REGION}-${EKS_CLUSTER_NAME}" >/dev/null

run_suffix="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}"
migration_job="cloudsentinel-migrate-${run_suffix}"
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${migration_job}
  namespace: cloudsentinel
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: backend
        app.kubernetes.io/component: migration
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      serviceAccountName: cloudsentinel-api
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: migration
          image: ${BACKEND_IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["python", "-m", "alembic", "upgrade", "head"]
          envFrom:
            - secretRef:
                name: cloudsentinel-runtime
          env:
            - name: CLOUDSENTINEL_APP_ENV
              value: production
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: "1"
              memory: 512Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
EOF

if ! kubectl wait --for=condition=complete "job/${migration_job}" \
  -n cloudsentinel --timeout=20m; then
  kubectl logs "job/${migration_job}" -n cloudsentinel || true
  exit 1
fi

rollout_started=0
rollback() {
  status=$?
  if [[ ${status} -ne 0 && ${rollout_started} -eq 1 ]]; then
    for deployment in backend worker outbox-relay frontend; do
      kubectl rollout undo "deployment/${deployment}" -n cloudsentinel || true
    done
  fi
  exit "${status}"
}
trap rollback EXIT

rollout_started=1
kubectl set image deployment/backend backend="${BACKEND_IMAGE}" -n cloudsentinel
kubectl set image deployment/worker worker="${BACKEND_IMAGE}" -n cloudsentinel
kubectl set image deployment/outbox-relay outbox-relay="${BACKEND_IMAGE}" -n cloudsentinel
kubectl set image deployment/frontend frontend="${FRONTEND_IMAGE}" -n cloudsentinel

for deployment in backend worker outbox-relay frontend; do
  kubectl rollout status "deployment/${deployment}" -n cloudsentinel --timeout=10m
done

trap - EXIT
