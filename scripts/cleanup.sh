#!/usr/bin/env bash
set -Eeuo pipefail

RG="${RG:-rg-policy-security-lab}"

if ! az group exists --name "$RG" | grep -q true; then
  echo "Nothing to delete: resource group '$RG' does not exist."
  exit 0
fi

echo "This will delete resource group '$RG' and every resource inside it."
if [[ "${CONFIRM_DELETE:-}" != "yes" ]]; then
  read -r -p "Type the exact resource-group name to continue: " confirmation
  if [[ "$confirmation" != "$RG" ]]; then
    echo "Cleanup cancelled."
    exit 1
  fi
fi

az group delete --name "$RG" --yes --no-wait
echo "Deletion requested for '$RG'. Check status with: az group exists --name '$RG'"

