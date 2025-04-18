#!/bin/bash

# Description: This script submits a Splunk app package to the Splunk AppInspect API for validation.
# Usage: ./splunk_appinspect.sh "<SPLUNKBASE_USERNAME>" "<SPLUNKBASE_PASSWORD>"
# Example: ./splunk_appinspect.sh "myusername" "mypassword"

USERNAME="$1"
PASSWORD="$2"
APP_PACKAGE="crowdsec-splunk-app.tar.gz"
REPORT_PATH="./appinspect-output.json"

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
  echo "Usage: $0 <USERNAME> <PASSWORD>"
  exit 1
fi

echo "🔐 Authenticating to Splunk AppInspect API..."
TOKEN=$(curl -s -u "$USERNAME:$PASSWORD" \
  --url 'https://api.splunk.com/2.0/rest/login/splunk' | jq -r .data.token)

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "❌ Error: Failed to retrieve token."
  exit 1
fi

echo "✅ Token retrieved successfully. Submitting app for validation..."
RESPONSE=$(curl -s -X POST \
  -H "Authorization: bearer $TOKEN" \
  -F "app_package=@$APP_PACKAGE" \
  "https://appinspect.splunk.com/v1/app/validate")

REQUEST_ID=$(echo "$RESPONSE" | jq -r '.request_id')

if [[ -z "$REQUEST_ID" || "$REQUEST_ID" == "null" ]]; then
  echo "❌ Error: Failed to submit app or retrieve request ID."
  echo "$RESPONSE"
  exit 1
fi

STATUS_URL="https://appinspect.splunk.com/v1/app/validate/status/$REQUEST_ID"
REPORT_URL="https://appinspect.splunk.com/v1/app/report/$REQUEST_ID"

echo "📤 App submitted. Request ID: $REQUEST_ID"
echo "⏳ Polling validation status..."

for i in {1..10}; do
  STATUS_RESPONSE=$(curl -s -H "Authorization: bearer $TOKEN" "$STATUS_URL")
  STATUS=$(echo "$STATUS_RESPONSE" | jq -r .status)

  echo "🔄 Status check #$i: $STATUS"

  if [[ "$STATUS" == "SUCCESS" ]]; then
    echo "✅ Validation succeeded!"
    break
  elif [[ "$STATUS" == "FAILURE" ]]; then
    echo "❌ Validation failed."
    echo "$STATUS_RESPONSE"
    exit 1
  fi

  sleep 5
done

if [[ "$STATUS" != "SUCCESS" ]]; then
  echo "❌ Timeout: Validation did not complete within expected time."
  exit 1
fi

echo "📥 Downloading validation report..."
curl -s -H "Authorization: bearer $TOKEN" "$REPORT_URL" > "$REPORT_PATH"

echo "📄 Report saved to $REPORT_PATH"
