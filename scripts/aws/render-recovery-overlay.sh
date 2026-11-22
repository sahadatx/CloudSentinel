#!/usr/bin/env bash
set -euo pipefail

: "${DR_AWS_REGION:?Set DR_AWS_REGION}"
: "${DR_VPC_CIDR:?Set DR_VPC_CIDR to the recovery VPC CIDR}"
: "${DR_DOMAIN_NAME:?Set DR_DOMAIN_NAME for the recovery hostname}"
: "${DR_ACM_CERTIFICATE_ARN:?Set DR_ACM_CERTIFICATE_ARN issued in the recovery Region}"
: "${DR_WAF_WEB_ACL_ARN:?Set DR_WAF_WEB_ACL_ARN from the recovery Region}"
: "${DR_BACKEND_REPOSITORY_URI:?Set DR_BACKEND_REPOSITORY_URI from Terraform output}"
: "${DR_FRONTEND_REPOSITORY_URI:?Set DR_FRONTEND_REPOSITORY_URI from Terraform output}"
: "${DR_RELEASE_TAG:?Set DR_RELEASE_TAG to the mirrored immutable release tag (for example v1.2.3)}"
: "${RECOVERY_OVERLAY_OUTPUT:?Set RECOVERY_OVERLAY_OUTPUT to a new output directory}"

[[ "${DR_BACKEND_REPOSITORY_URI}" != *:* && "${DR_FRONTEND_REPOSITORY_URI}" != *:* ]] || {
  echo "Repository URIs must not include an image tag; use the separate DR_RELEASE_TAG." >&2
  exit 2
}
[[ "${DR_RELEASE_TAG}" =~ ^v[0-9][A-Za-z0-9._+-]*$ ]] || {
  echo "DR_RELEASE_TAG must be an immutable version tag beginning with v and a digit." >&2
  exit 2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
source_dir="${repo_root}/infrastructure/kubernetes/overlays/production"
overlay_root="${repo_root}/infrastructure/kubernetes/overlays/"
case "${RECOVERY_OVERLAY_OUTPUT}" in
  "${overlay_root}"*) ;;
  *) echo "RECOVERY_OVERLAY_OUTPUT must be inside ${overlay_root} so Kustomize keeps the repository base path." >&2; exit 2 ;;
esac
[[ ! -e "${RECOVERY_OVERLAY_OUTPUT}" ]] || {
  echo "Refusing to overwrite ${RECOVERY_OVERLAY_OUTPUT}." >&2
  exit 2
}
mkdir -p "$(dirname "${RECOVERY_OVERLAY_OUTPUT}")"
cp -R "${source_dir}" "${RECOVERY_OVERLAY_OUTPUT}"

export DR_AWS_REGION DR_VPC_CIDR DR_DOMAIN_NAME DR_ACM_CERTIFICATE_ARN DR_WAF_WEB_ACL_ARN
export DR_BACKEND_REPOSITORY_URI DR_FRONTEND_REPOSITORY_URI DR_RELEASE_TAG
python3 - "${RECOVERY_OVERLAY_OUTPUT}" <<'PY'
from pathlib import Path
import os
import sys

root = Path(sys.argv[1])
replacements = {
    "REPLACE_WITH_AWS_REGION": os.environ["DR_AWS_REGION"],
    "REPLACE_WITH_VPC_CIDR": os.environ["DR_VPC_CIDR"],
    "REPLACE_WITH_DOMAIN_NAME": os.environ["DR_DOMAIN_NAME"],
    "REPLACE_WITH_ACM_CERTIFICATE_ARN": os.environ["DR_ACM_CERTIFICATE_ARN"],
    "REPLACE_WITH_WAF_WEB_ACL_ARN": os.environ["DR_WAF_WEB_ACL_ARN"],
}
for path in root.glob("*.yaml"):
    text = path.read_text(encoding="utf-8")
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = text.replace("Environment=production", "Environment=production-dr")
    path.write_text(text, encoding="utf-8")

kustomization = root / "kustomization.yaml"
kustomization.write_text(
    kustomization.read_text(encoding="utf-8").rstrip()
    + "\nimages:\n"
    + "  - name: cloudsentinel/backend\n"
    + f"    newName: {os.environ['DR_BACKEND_REPOSITORY_URI']}\n"
    + f"    newTag: {os.environ['DR_RELEASE_TAG']}\n"
    + "  - name: cloudsentinel/frontend\n"
    + f"    newName: {os.environ['DR_FRONTEND_REPOSITORY_URI']}\n"
    + f"    newTag: {os.environ['DR_RELEASE_TAG']}\n"
    + "patches:\n"
    + "  - path: dr-otel-region-patch.yaml\n",
    encoding="utf-8",
)

(root / "dr-otel-region-patch.yaml").write_text(
    "apiVersion: apps/v1\n"
    "kind: Deployment\n"
    "metadata:\n"
    "  name: cloudsentinel-otel-collector\n"
    "  namespace: cloudsentinel\n"
    "spec:\n"
    "  template:\n"
    "    spec:\n"
    "      containers:\n"
    "        - name: collector\n"
    "          env:\n"
    "            - name: AWS_REGION\n"
    f"              value: {os.environ['DR_AWS_REGION']}\n",
    encoding="utf-8",
)
PY

echo "Recovery overlay rendered at ${RECOVERY_OVERLAY_OUTPUT}. Review it before applying with kubectl."
