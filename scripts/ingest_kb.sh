#!/usr/bin/env bash
# Start a Bedrock KB ingestion job and wait for it to finish.
# Usage: ingest_kb.sh <knowledge_base_id> <data_source_id> <region>
set -euo pipefail
kb_id="$1"; ds_id="$2"; region="$3"

job_id=$(aws bedrock-agent start-ingestion-job --region "$region" \
  --knowledge-base-id "$kb_id" --data-source-id "$ds_id" \
  --query 'ingestionJob.ingestionJobId' --output text)
echo "ingestion job $job_id started"

for _ in $(seq 1 60); do
  status=$(aws bedrock-agent get-ingestion-job --region "$region" \
    --knowledge-base-id "$kb_id" --data-source-id "$ds_id" --ingestion-job-id "$job_id" \
    --query 'ingestionJob.status' --output text)
  case "$status" in
    COMPLETE) echo "ingestion complete"; exit 0 ;;
    FAILED|STOPPED)
      aws bedrock-agent get-ingestion-job --region "$region" \
        --knowledge-base-id "$kb_id" --data-source-id "$ds_id" --ingestion-job-id "$job_id" \
        --query 'ingestionJob.failureReasons' >&2
      exit 1 ;;
  esac
  sleep 10
done
echo "ingestion timed out" >&2
exit 1
