#!/usr/bin/env bash
set -Eeuo pipefail

RG="${RG:-rg-policy-security-lab}"
LOCATION="${LOCATION:-centralus}"
ASSIGNMENT="${ASSIGNMENT:-deny-public-blob-access}"
POLICY_ID="/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751"

suffix="${SUFFIX:-$(date +%s)}"
suffix="${suffix: -6}"
BAD_STORAGE="${BAD_STORAGE:-stinsecure${suffix}}"
GOOD_STORAGE="${GOOD_STORAGE:-stsecure${suffix}}"

require_value() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    echo "ERROR: $name must not be empty." >&2
    exit 1
  fi
}

validate_storage_name() {
  local value="$1"
  if [[ ! "$value" =~ ^[a-z0-9]{3,24}$ ]]; then
    echo "ERROR: Storage name '$value' must contain 3-24 lowercase letters or numbers." >&2
    exit 1
  fi
}

for command in az grep; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "ERROR: Required command '$command' was not found." >&2
    exit 1
  }
done

require_value RG "$RG"
require_value LOCATION "$LOCATION"
require_value ASSIGNMENT "$ASSIGNMENT"
validate_storage_name "$BAD_STORAGE"
validate_storage_name "$GOOD_STORAGE"

az account show >/dev/null

echo "Creating isolated lab resource group: $RG"
az group create \
  --name "$RG" \
  --location "$LOCATION" \
  --tags purpose=security-lab managed-by=azure-cli \
  --output none

RG_ID="$(az group show --name "$RG" --query id --output tsv)"
require_value RG_ID "$RG_ID"

echo "Assigning the built-in deny policy at resource-group scope"
az policy assignment create \
  --name "$ASSIGNMENT" \
  --display-name "Deny storage accounts permitting public blob access" \
  --scope "$RG_ID" \
  --policy "$POLICY_ID" \
  --params '{"effect":{"value":"Deny"}}' \
  --non-compliance-messages '[{"message":"Public blob access is prohibited by the security baseline."}]' \
  --output none

az policy assignment show \
  --name "$ASSIGNMENT" \
  --scope "$RG_ID" \
  --query '{name:name,effect:parameters.effect.value,enforcementMode:enforcementMode,scope:scope}' \
  --output table

echo "Negative test 1: requesting an insecure storage account (expected denial)"
set +e
negative_create_output="$(az storage account create \
  --name "$BAD_STORAGE" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --allow-blob-public-access true \
  --https-only true \
  --min-tls-version TLS1_2 2>&1)"
negative_create_rc=$?
set -e

if [[ $negative_create_rc -eq 0 ]] || ! grep -q 'RequestDisallowedByPolicy' <<<"$negative_create_output"; then
  echo "ERROR: The insecure create request was not denied as expected." >&2
  echo "$negative_create_output" >&2
  exit 1
fi
echo "PASS: Azure Policy denied the insecure create request."

echo "Positive test: creating a compliant storage account"
az storage account create \
  --name "$GOOD_STORAGE" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --allow-blob-public-access false \
  --https-only true \
  --min-tls-version TLS1_2 \
  --query '{name:name,state:provisioningState,publicBlobAccess:allowBlobPublicAccess,httpsOnly:enableHttpsTrafficOnly,minimumTLS:minimumTlsVersion}' \
  --output table

echo "Negative test 2: attempting configuration drift (expected denial)"
set +e
negative_update_output="$(az storage account update \
  --name "$GOOD_STORAGE" \
  --resource-group "$RG" \
  --allow-blob-public-access true 2>&1)"
negative_update_rc=$?
set -e

if [[ $negative_update_rc -eq 0 ]] || ! grep -q 'RequestDisallowedByPolicy' <<<"$negative_update_output"; then
  echo "ERROR: The insecure update was not denied as expected." >&2
  echo "$negative_update_output" >&2
  exit 1
fi
echo "PASS: Azure Policy denied the insecure update."

actual_public_access="$(az storage account show \
  --name "$GOOD_STORAGE" \
  --resource-group "$RG" \
  --query allowBlobPublicAccess \
  --output tsv)"

if [[ "$actual_public_access" != "false" ]]; then
  echo "ERROR: Expected allowBlobPublicAccess=false; received '$actual_public_access'." >&2
  exit 1
fi

echo "PASS: The secure value remained false after the denied update."
echo "Lab complete. Run scripts/cleanup.sh when finished."

