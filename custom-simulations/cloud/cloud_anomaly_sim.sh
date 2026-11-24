#!/usr/bin/env bash
# ==============================================================================
# cloud_anomaly_sim.sh - Simulates Cloud & Identity Anomaly Audit Telemetry
# Usage: cloud_anomaly_sim.sh <aws_root_login | aws_stop_trail | azure_risky_login | gcp_set_iam>
# ==============================================================================
set -eu

SCENARIO="${1:-aws_root_login}"
TARGET_LOG="/var/ossec/logs/alerts/cloud_sim.json"

case "$SCENARIO" in
  aws_root_login)
    EVENT='{"aws":{"eventName":"ConsoleLogin","userIdentity":{"type":"Root"},"additionalEventData":{"MFAUsed":"No"}},"event_source":"aws.cloudtrail"}'
    ;;
  aws_stop_trail)
    EVENT='{"aws":{"eventName":"StopLogging","userIdentity":{"type":"IAMUser","userName":"attacker"}},"event_source":"aws.cloudtrail"}'
    ;;
  azure_risky_login)
    EVENT='{"azure":{"operationName":"Sign-in activity","properties":{"riskState":"atRisk","userPrincipalName":"compromised@lab.domain"}},"event_source":"azure.signin"}'
    ;;
  gcp_set_iam)
    EVENT='{"gcp":{"methodName":"SetIamPolicy","resource":{"type":"project"},"policyDelta":{"bindingDeltas":[{"action":"ADD","role":"roles/owner"}]}},"event_source":"gcp.audit"}'
    ;;
  *)
    echo "Unknown scenario: $SCENARIO" >&2
    exit 2
    ;;
esac

# If running on manager or lab host with local logging enabled
if [ -w "$(dirname "$TARGET_LOG" 2>/dev/null || true)" ]; then
  echo "$EVENT" >> "$TARGET_LOG"
fi

echo "cloud_anomaly_sim: simulated event for $SCENARIO"

