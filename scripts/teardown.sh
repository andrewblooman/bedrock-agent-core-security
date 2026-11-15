#!/usr/bin/env bash
# Destroy the bedrock-guard dev stack. Buckets use force_destroy in dev.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
terraform -chdir="$root/terraform/envs/dev" destroy -input=false "$@"
rm -f "$root/outputs.json"
