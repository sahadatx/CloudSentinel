#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "Usage: $0 <aws-profile-name>" >&2
  exit 2
fi

aws_profile="$1"
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
aws_config_dir="${AWS_CONFIG_DIR:-$HOME/.aws}"

if ! command -v aws >/dev/null 2>&1; then
  echo "AWS CLI v2 is required. Install it, configure IAM Identity Center, and retry." >&2
  exit 1
fi
if [[ ! -d "$aws_config_dir" ]]; then
  echo "AWS config directory not found: $aws_config_dir" >&2
  echo "Configure a short-lived AWS IAM Identity Center profile first." >&2
  exit 1
fi

echo "Checking AWS profile '$aws_profile' without displaying account details…"
if ! aws sts get-caller-identity --profile "$aws_profile" --output json >/dev/null; then
  echo "The profile is not authenticated. Run: aws sso login --profile '$aws_profile'" >&2
  exit 1
fi

export AWS_CONFIG_DIR="$aws_config_dir"
export AWS_PROFILE="$aws_profile"
export AWS_CONTAINER_UID="$(id -u)"
export AWS_CONTAINER_GID="$(id -g)"

compose=(docker compose -f "$project_root/docker-compose.yml" -f "$project_root/docker-compose.aws-profile.yml")
"${compose[@]}" up -d --build backend worker

echo "Checking the AWS credential chain inside API and worker containers…"
for service in backend worker; do
  "${compose[@]}" exec -T "$service" python -c 'import boto3; boto3.client("sts").get_caller_identity(); print("AWS workload identity is available")'
done

echo "CloudSentinel API and worker can now call AWS STS with the selected profile."
