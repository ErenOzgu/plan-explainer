#!/usr/bin/env bash
# Records a real plan with Terraform or OpenTofu, using only the built-in terraform_data resource,
# so it needs no provider download and no credentials.
#
#   tests/real/record.sh lifecycle|structure WORKDIR      (TF=tofu to use OpenTofu)
#
# Applies scenarios/<name>/1, swaps in scenarios/<name>/2, and writes WORKDIR/plan.json from the plan.
set -euo pipefail
tf=${TF:-terraform}
here=$(cd "$(dirname "$0")" && pwd)
scenario=$1
work=$2
mkdir -p "$work"
cp -r "$here/scenarios/$scenario/1/." "$work/"
cd "$work"
"$tf" init -input=false -no-color > /dev/null
"$tf" apply -auto-approve -input=false -no-color > /dev/null
cp -r "$here/scenarios/$scenario/2/." "$work/"
"$tf" plan -input=false -no-color -out=p.tfplan > /dev/null
"$tf" show -json p.tfplan > plan.json
echo "recorded $work/plan.json"
