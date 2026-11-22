#!/usr/bin/env bash
set -euo pipefail

: "${DRILL_ENVIRONMENT:?Set DRILL_ENVIRONMENT=non-production}"
: "${DRILL_ACKNOWLEDGEMENT:?Set DRILL_ACKNOWLEDGEMENT=restore-s3-replica}"
: "${AWS_REGION:?Set AWS_REGION to the source Region}"
: "${DR_AWS_REGION:?Set DR_AWS_REGION to the recovery Region}"
: "${SOURCE_BUCKET:?Set SOURCE_BUCKET to the non-production versioned source bucket}"
: "${RECOVERY_BUCKET:?Set RECOVERY_BUCKET to the non-production versioned replica bucket}"
: "${DRILL_SCAN_PREFIX:?Set DRILL_SCAN_PREFIX to the non-production customer-scan prefix}"
: "${SOURCE_KMS_KEY_ARN:?Set SOURCE_KMS_KEY_ARN}"
: "${RECOVERY_KMS_KEY_ARN:?Set RECOVERY_KMS_KEY_ARN}"
: "${DRILL_EVIDENCE_DIR:?Set DRILL_EVIDENCE_DIR for the drill record}"

[[ "${DRILL_ENVIRONMENT}" == "non-production" ]] || { echo "Refusing: S3 deletion drills are restricted to non-production." >&2; exit 2; }
[[ "${DRILL_ACKNOWLEDGEMENT}" == "restore-s3-replica" ]] || { echo "Refusing: explicit S3 recovery acknowledgement is required." >&2; exit 2; }
[[ "${AWS_REGION}" != "${DR_AWS_REGION}" ]] || { echo "Source and recovery Regions must differ." >&2; exit 2; }
[[ "${SOURCE_BUCKET}" != "${RECOVERY_BUCKET}" ]] || { echo "Source and recovery buckets must differ." >&2; exit 2; }
[[ "${SOURCE_KMS_KEY_ARN}" == arn:*:kms:* ]] || { echo "A source KMS key ARN is required." >&2; exit 2; }
[[ "${RECOVERY_KMS_KEY_ARN}" == arn:*:kms:* ]] || { echo "A recovery KMS key ARN is required." >&2; exit 2; }
normalized_scan_prefix="${DRILL_SCAN_PREFIX%/}"
[[ "${normalized_scan_prefix}" == */customer-scans && "${normalized_scan_prefix,,}" != *production* ]] || { echo "DRILL_SCAN_PREFIX must be a non-production customer-scan prefix." >&2; exit 2; }

mkdir -p "${DRILL_EVIDENCE_DIR}"
drill_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
key="${normalized_scan_prefix}/recovery-drill/${drill_id}/marker.txt"
evidence_file="${DRILL_EVIDENCE_DIR}/s3-restore-${drill_id}.json"
work_dir="$(mktemp -d)"
payload="${work_dir}/marker.txt"
restored="${work_dir}/restored.txt"
printf 'CloudSentinel S3 recovery drill %s\n' "${drill_id}" > "${payload}"
payload_sha256="$(sha256sum "${payload}" | cut -d ' ' -f 1)"
payload_checksum="$(python3 - "${payload}" <<'PY'
import base64
import hashlib
import sys
from pathlib import Path

print(base64.b64encode(hashlib.sha256(Path(sys.argv[1]).read_bytes()).digest()).decode())
PY
)"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date +%s)"
replication_seconds=""
restore_seconds=""
status="failed"
source_version_id=""
replica_version_id=""
restored_version_id=""
account_id="unknown"

write_evidence() {
  local exit_status=$?
  trap - EXIT
  [[ "${exit_status}" -eq 0 ]] && status="passed" || status="failed"
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  elapsed_seconds="$(( $(date +%s) - started_epoch ))"
  DRILL_STATUS="${status}" \
    DRILL_STARTED_AT="${started_at}" \
    DRILL_ENDED_AT="${ended_at}" \
    DRILL_ELAPSED_SECONDS="${elapsed_seconds}" \
    DRILL_ACCOUNT_ID="${account_id}" \
    DRILL_REPLICATION_SECONDS="${replication_seconds}" \
    DRILL_RESTORE_SECONDS="${restore_seconds}" \
    DRILL_OBJECT_KEY="${key}" \
    DRILL_RECOVERY_KMS_KEY_ARN="${RECOVERY_KMS_KEY_ARN}" \
    DRILL_SOURCE_VERSION_ID="${source_version_id}" \
    DRILL_REPLICA_VERSION_ID="${replica_version_id}" \
    DRILL_RESTORED_VERSION_ID="${restored_version_id}" \
    DRILL_PAYLOAD_SHA256="${payload_sha256}" \
    python3 - "${evidence_file}" <<'PY'
import json
import os
import sys

def optional_int(name):
    value = os.environ.get(name, "")
    return int(value) if value.isdigit() else None

replication_seconds = optional_int("DRILL_REPLICATION_SECONDS")
record = {
    "drill": "cross-region-s3-object-restore",
    "status": os.environ["DRILL_STATUS"],
    "scope": "synthetic-object-replication-and-restore",
    "account_id": os.environ["DRILL_ACCOUNT_ID"],
    "source_region": os.environ["AWS_REGION"],
    "recovery_region": os.environ["DR_AWS_REGION"],
    "source_bucket": os.environ["SOURCE_BUCKET"],
    "recovery_bucket": os.environ["RECOVERY_BUCKET"],
    "recovery_kms_key_arn": os.environ["DRILL_RECOVERY_KMS_KEY_ARN"],
    "object_key": os.environ["DRILL_OBJECT_KEY"],
    "sha256": os.environ["DRILL_PAYLOAD_SHA256"],
    "source_version_id": os.environ.get("DRILL_SOURCE_VERSION_ID") or None,
    "replica_version_id": os.environ.get("DRILL_REPLICA_VERSION_ID") or None,
    "restored_version_id": os.environ.get("DRILL_RESTORED_VERSION_ID") or None,
    "replication_seconds": replication_seconds,
    "restore_seconds": optional_int("DRILL_RESTORE_SECONDS"),
    "elapsed_seconds": int(os.environ["DRILL_ELAPSED_SECONDS"]),
    "rpo_target_seconds": 300,
    "rpo_target_met_for_synthetic_object": replication_seconds is not None and replication_seconds <= 300,
    "application_rto_verified": False,
    "started_at": os.environ["DRILL_STARTED_AT"],
    "ended_at": os.environ["DRILL_ENDED_AT"],
}
with open(sys.argv[1], "w", encoding="utf-8") as evidence:
    json.dump(record, evidence, indent=2, sort_keys=True)
    evidence.write("\n")
PY
  rm -rf "${work_dir}"
  echo "S3 replica restore drill evidence: ${evidence_file}"
  return "${exit_status}"
}
trap write_evidence EXIT

account_id="$(aws sts get-caller-identity --query Account --output text)"
put_response="$(aws s3api put-object \
  --region "${AWS_REGION}" \
  --bucket "${SOURCE_BUCKET}" \
  --key "${key}" \
  --body "${payload}" \
  --server-side-encryption aws:kms \
  --ssekms-key-id "${SOURCE_KMS_KEY_ARN}" \
  --checksum-algorithm SHA256 \
  --checksum-sha256 "${payload_checksum}" \
  --output json)"
source_version_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["VersionId"])' <<<"${put_response}")"
replication_started="$(date +%s)"

replica_ready=false
for _ in $(seq 1 300); do
  head_response="$(aws s3api head-object --region "${DR_AWS_REGION}" --bucket "${RECOVERY_BUCKET}" --key "${key}" --checksum-mode ENABLED --output json 2>/dev/null || true)"
  if [[ -n "${head_response}" ]] && python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ReplicationStatus")=="REPLICA" else 1)' <<<"${head_response}"; then
    replica_version_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("VersionId", ""))' <<<"${head_response}")"
    observed_checksum="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("ChecksumSHA256", ""))' <<<"${head_response}")"
    [[ "${observed_checksum}" == "${payload_checksum}" ]] || { echo "Replicated checksum does not match the source object." >&2; exit 1; }
    replica_ready=true
    break
  fi
  sleep 10
done
[[ "${replica_ready}" == true && -n "${replica_version_id}" ]] || { echo "Replica was not ready within the 50-minute drill window." >&2; exit 1; }
replication_seconds="$(( $(date +%s) - replication_started ))"

aws s3api delete-object --region "${AWS_REGION}" --bucket "${SOURCE_BUCKET}" --key "${key}" >/dev/null
restore_started="$(date +%s)"
aws s3api get-object \
  --region "${DR_AWS_REGION}" \
  --bucket "${RECOVERY_BUCKET}" \
  --key "${key}" \
  --version-id "${replica_version_id}" \
  "${restored}" >/dev/null
[[ "$(sha256sum "${restored}" | cut -d ' ' -f 1)" == "${payload_sha256}" ]] || { echo "Recovered object checksum does not match." >&2; exit 1; }
restore_response="$(aws s3api put-object \
  --region "${AWS_REGION}" \
  --bucket "${SOURCE_BUCKET}" \
  --key "${key}" \
  --body "${restored}" \
  --server-side-encryption aws:kms \
  --ssekms-key-id "${SOURCE_KMS_KEY_ARN}" \
  --checksum-algorithm SHA256 \
  --checksum-sha256 "${payload_checksum}" \
  --output json)"
restored_version_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["VersionId"])' <<<"${restore_response}")"
restore_seconds="$(( $(date +%s) - restore_started ))"
verified_current="$(aws s3api head-object --region "${AWS_REGION}" --bucket "${SOURCE_BUCKET}" --key "${key}" --checksum-mode ENABLED --output json)"
python3 - "${verified_current}" "${payload_checksum}" <<'PY'
import json
import sys

head = json.loads(sys.argv[1])
if head.get("ChecksumSHA256") != sys.argv[2]:
    raise SystemExit("Restored source object is not the current matching version.")
PY
status="passed"
