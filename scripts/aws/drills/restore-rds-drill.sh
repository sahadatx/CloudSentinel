#!/usr/bin/env bash
set -euo pipefail

: "${DRILL_ENVIRONMENT:?Set DRILL_ENVIRONMENT=non-production; production drills require a separate approved procedure}"
: "${DRILL_ACKNOWLEDGEMENT:?Set DRILL_ACKNOWLEDGEMENT=restore-temporary-database}"
: "${AWS_REGION:?Set AWS_REGION to the recovery Region}"
: "${SOURCE_AUTOMATED_BACKUP_ARN:?Set SOURCE_AUTOMATED_BACKUP_ARN to the recovery Region backup ARN}"
: "${DRILL_DB_SUBNET_GROUP:?Set DRILL_DB_SUBNET_GROUP to a non-production recovery subnet group}"
: "${DRILL_DB_SECURITY_GROUP_ID:?Set DRILL_DB_SECURITY_GROUP_ID to a non-production recovery security group}"
: "${DRILL_INSTANCE_CLASS:?Set DRILL_INSTANCE_CLASS for the temporary restore}"
: "${DRILL_DATABASE_NAME:?Set DRILL_DATABASE_NAME for the application smoke check}"
: "${DRILL_SMOKE_COMMAND:?Set DRILL_SMOKE_COMMAND to an executable that checks migrated schema and a known recovery marker}"

[[ "${DRILL_ENVIRONMENT}" == "non-production" ]] || { echo "Refusing: this script only runs in non-production." >&2; exit 2; }
[[ "${DRILL_ACKNOWLEDGEMENT}" == "restore-temporary-database" ]] || { echo "Refusing: explicit temporary-restore acknowledgement is required." >&2; exit 2; }
[[ "${DRILL_SMOKE_COMMAND}" == /* && -x "${DRILL_SMOKE_COMMAND}" ]] || { echo "DRILL_SMOKE_COMMAND must be an executable absolute path." >&2; exit 2; }
[[ "${DRILL_DB_SECURITY_GROUP_ID}" == sg-* ]] || { echo "A security-group ID is required." >&2; exit 2; }
[[ "${SOURCE_AUTOMATED_BACKUP_ARN}" =~ ^arn:[^:]+:rds:([^:]+):[0-9]{12}:auto-backup: ]] || {
  echo "SOURCE_AUTOMATED_BACKUP_ARN must identify an RDS instance automated backup." >&2
  exit 2
}
[[ "${BASH_REMATCH[1]}" == "${AWS_REGION}" ]] || {
  echo "The source backup ARN must be in the recovery Region selected by AWS_REGION." >&2
  exit 2
}
if [[ -n "${DRILL_RPO_OBSERVED_SECONDS:-}" || -n "${DRILL_RPO_MARKER_ID:-}" ]]; then
  [[ "${DRILL_RPO_OBSERVED_SECONDS:-}" =~ ^[0-9]+$ && -n "${DRILL_RPO_MARKER_ID:-}" ]] || {
    echo "A verified non-negative DRILL_RPO_OBSERVED_SECONDS and DRILL_RPO_MARKER_ID are both required." >&2
    exit 2
  }
fi

mkdir -p "${DRILL_EVIDENCE_DIR:-recovery-evidence}"
DRILL_INSTANCE_ID="cs-drill-$(date -u +%Y%m%d%H%M%S)-$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')"
DRILL_EVIDENCE_FILE="${DRILL_EVIDENCE_DIR:-recovery-evidence}/${DRILL_INSTANCE_ID}.json"
DRILL_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DRILL_STARTED_EPOCH="$(date +%s)"
DRILL_STATUS="failed"
DRILL_DB_CREATED="false"
DRILL_RPO_OBSERVED_SECONDS="${DRILL_RPO_OBSERVED_SECONDS:-}"
DRILL_RPO_MARKER_ID="${DRILL_RPO_MARKER_ID:-}"
AWS_ACCOUNT_ID="unknown"

write_evidence() {
  local ended_at ended_epoch elapsed
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ended_epoch="$(date +%s)"
  elapsed="$((ended_epoch - DRILL_STARTED_EPOCH))"
  DRILL_ENDED_AT="${ended_at}" DRILL_ELAPSED_SECONDS="${elapsed}" python3 - "${DRILL_EVIDENCE_FILE}" <<'PY'
import json
import os
import sys

def optional_int(value):
    return int(value) if value.isdigit() else None

record = {
    "drill": "rds-cross-region-restore",
    "status": os.environ["DRILL_STATUS"],
    "scope": "temporary-database-restore-and-smoke-check",
    "account_id": os.environ["AWS_ACCOUNT_ID"],
    "region": os.environ["AWS_REGION"],
    "source_backup_arn": os.environ["SOURCE_AUTOMATED_BACKUP_ARN"],
    "rpo_marker_id": os.environ.get("DRILL_RPO_MARKER_ID") or None,
    "temporary_database_id": os.environ["DRILL_INSTANCE_ID"],
    "started_at": os.environ["DRILL_STARTED_AT"],
    "ended_at": os.environ["DRILL_ENDED_AT"],
    "elapsed_seconds": int(os.environ["DRILL_ELAPSED_SECONDS"]),
    "rto_target_seconds": 14400,
    "rto_target_met_for_database_scope": (
        os.environ["DRILL_STATUS"] == "passed"
        and int(os.environ["DRILL_ELAPSED_SECONDS"]) <= 14400
    ),
    "rpo_observed_seconds": optional_int(os.environ.get("DRILL_RPO_OBSERVED_SECONDS", "")),
    "rpo_target_met": (
        int(os.environ["DRILL_RPO_OBSERVED_SECONDS"]) <= 300
        if os.environ.get("DRILL_RPO_OBSERVED_SECONDS", "").isdigit()
        else None
    ),
    "application_rto_verified": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as evidence:
    json.dump(record, evidence, indent=2, sort_keys=True)
    evidence.write("\n")
PY
}

cleanup() {
  local exit_status=$?
  write_evidence
  if [[ "${DRILL_CLEANUP:-false}" == "true" && "${DRILL_DB_CREATED}" == "true" ]]; then
    aws rds delete-db-instance \
      --region "${AWS_REGION}" \
      --db-instance-identifier "${DRILL_INSTANCE_ID}" \
      --skip-final-snapshot \
      --delete-automated-backups >/dev/null
  fi
  if [[ "${exit_status}" -ne 0 ]]; then
    echo "Restore drill failed; evidence: ${DRILL_EVIDENCE_FILE}" >&2
  else
    echo "Restore drill evidence: ${DRILL_EVIDENCE_FILE}"
  fi
  return "${exit_status}"
}
trap cleanup EXIT

AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

aws rds restore-db-instance-to-point-in-time \
  --region "${AWS_REGION}" \
  --source-db-instance-automated-backups-arn "${SOURCE_AUTOMATED_BACKUP_ARN}" \
  --target-db-instance-identifier "${DRILL_INSTANCE_ID}" \
  --use-latest-restorable-time \
  --db-instance-class "${DRILL_INSTANCE_CLASS}" \
  --db-subnet-group-name "${DRILL_DB_SUBNET_GROUP}" \
  --vpc-security-group-ids "${DRILL_DB_SECURITY_GROUP_ID}" \
  --no-publicly-accessible \
  --tags Key=Application,Value=CloudSentinel Key=RecoveryDrill,Value=true >/dev/null
DRILL_DB_CREATED="true"
aws rds wait db-instance-available --region "${AWS_REGION}" --db-instance-identifier "${DRILL_INSTANCE_ID}"

DRILL_RESTORED_ENDPOINT="$(aws rds describe-db-instances \
  --region "${AWS_REGION}" \
  --db-instance-identifier "${DRILL_INSTANCE_ID}" \
  --query 'DBInstances[0].Endpoint.Address' --output text)"
DRILL_RESTORED_PORT="$(aws rds describe-db-instances \
  --region "${AWS_REGION}" \
  --db-instance-identifier "${DRILL_INSTANCE_ID}" \
  --query 'DBInstances[0].Endpoint.Port' --output text)"
export DRILL_INSTANCE_ID DRILL_RESTORED_ENDPOINT DRILL_RESTORED_PORT DRILL_DATABASE_NAME AWS_ACCOUNT_ID DRILL_RPO_OBSERVED_SECONDS DRILL_RPO_MARKER_ID
"${DRILL_SMOKE_COMMAND}"
DRILL_STATUS="passed"
