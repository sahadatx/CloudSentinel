#!/usr/bin/env bash
set -euo pipefail

: "${DRILL_ENVIRONMENT:?Set DRILL_ENVIRONMENT=staging}"
: "${DRILL_ACKNOWLEDGEMENT:?Set DRILL_ACKNOWLEDGEMENT=rollback-staging-release}"
: "${DRILL_CONTEXT:?Set DRILL_CONTEXT to the exact kubectl staging context}"
: "${DRILL_EVIDENCE_DIR:?Set DRILL_EVIDENCE_DIR for the drill record}"

[[ "${DRILL_ENVIRONMENT}" == "staging" ]] || { echo "Refusing: release rollback drills are restricted to staging." >&2; exit 2; }
[[ "${DRILL_ACKNOWLEDGEMENT}" == "rollback-staging-release" ]] || { echo "Refusing: explicit staging rollback acknowledgement is required." >&2; exit 2; }
current_context="$(kubectl config current-context)"
[[ "${current_context}" == "${DRILL_CONTEXT}" ]] || { echo "Refusing: kubectl context does not match DRILL_CONTEXT." >&2; exit 2; }

namespace="cloudsentinel"
deployments=(backend worker outbox-relay frontend)
for deployment in "${deployments[@]}"; do
  kubectl get "deployment/${deployment}" -n "${namespace}" >/dev/null
done

mkdir -p "${DRILL_EVIDENCE_DIR}"
evidence_file="${DRILL_EVIDENCE_DIR}/rollback-$(date -u +%Y%m%dT%H%M%SZ).json"
state_file="${evidence_file%.json}.tsv"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date +%s)"
status="failed"
declare -A before_image before_revision

write_evidence() {
  local exit_status=$?
  trap - EXIT
  [[ "${exit_status}" -eq 0 ]] && status="passed" || status="failed"
  : > "${state_file}"
  for deployment in "${deployments[@]}"; do
    after_image="$(kubectl get "deployment/${deployment}" -n "${namespace}" -o jsonpath='{.spec.template.spec.containers[*].image}' 2>/dev/null || true)"
    after_revision="$(kubectl get "deployment/${deployment}" -n "${namespace}" -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}' 2>/dev/null || true)"
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "${deployment}" \
      "${before_image[${deployment}]:-}" \
      "${before_revision[${deployment}]:-}" \
      "${after_image}" \
      "${after_revision}" >> "${state_file}"
  done
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  elapsed_seconds="$(( $(date +%s) - started_epoch ))"
  DRILL_STATUS="${status}" \
    DRILL_STARTED_AT="${started_at}" \
    DRILL_ENDED_AT="${ended_at}" \
    DRILL_ELAPSED_SECONDS="${elapsed_seconds}" \
    DRILL_CONTEXT="${DRILL_CONTEXT}" \
    DRILL_STATE_FILE="${state_file}" \
    python3 - "${evidence_file}" <<'PY'
import json
import os
import sys

deployments = {}
with open(os.environ["DRILL_STATE_FILE"], encoding="utf-8") as stream:
    for line in stream:
        name, before_image, before_revision, after_image, after_revision = line.rstrip("\n").split("\t", 4)
        deployments[name] = {
            "before_image": before_image or None,
            "before_revision": before_revision or None,
            "after_image": after_image or None,
            "after_revision": after_revision or None,
        }

record = {
    "drill": "staging-application-release-rollback",
    "status": os.environ["DRILL_STATUS"],
    "context": os.environ["DRILL_CONTEXT"],
    "namespace": "cloudsentinel",
    "deployments": deployments,
    "started_at": os.environ["DRILL_STARTED_AT"],
    "ended_at": os.environ["DRILL_ENDED_AT"],
    "elapsed_seconds": int(os.environ["DRILL_ELAPSED_SECONDS"]),
    "rto_target_seconds": 14_400,
    "rto_target_met": os.environ["DRILL_STATUS"] == "passed" and int(os.environ["DRILL_ELAPSED_SECONDS"]) <= 14_400,
    "database_migrations_reversed": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as evidence:
    json.dump(record, evidence, indent=2, sort_keys=True)
    evidence.write("\n")
PY
  rm -f "${state_file}"
  echo "Staging rollback drill evidence: ${evidence_file}"
  return "${exit_status}"
}
trap write_evidence EXIT

for deployment in "${deployments[@]}"; do
  before_image["${deployment}"]="$(kubectl get "deployment/${deployment}" -n "${namespace}" -o jsonpath='{.spec.template.spec.containers[*].image}')"
  before_revision["${deployment}"]="$(kubectl get "deployment/${deployment}" -n "${namespace}" -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"
done

for deployment in "${deployments[@]}"; do
  kubectl rollout undo "deployment/${deployment}" -n "${namespace}"
done
for deployment in "${deployments[@]}"; do
  kubectl rollout status "deployment/${deployment}" -n "${namespace}" --timeout=10m
done
status="passed"
