#!/usr/bin/env bash
# Checks that CD builds release/<major>.<minor> branches as release-<major>.<minor>-<sha7> (EXC-791)
# and that nothing but a successful push to this repository publishes an image.
set -uo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd_yml="$root/.github/workflows/cd.yml"
ci_yml="$root/.github/workflows/ci.yml"
failures=0

check() {
  local name=$1 expected=$2 actual=$3
  if [[ $expected == "$actual" ]]; then echo "ok   $name"; else echo "FAIL $name: expected '$expected', got '$actual'"; failures=$((failures + 1)); fi
}

job_condition() { awk -v job="  $1:" '$0 == job {f=1; next} f && /^    if:/ {sub(/^    if: */, ""); print; exit}' "$cd_yml" | tr -s ' '; }
job_body() { awk -v job="  $1:" '$0 == job {f=1; next} /^  [a-z-]+:$/ {f=0} f' "$cd_yml"; }

grep -qF '"release/**"' "$cd_yml"; check "cd.yml listens to release branches" "0" "$?"
grep -qF '"release/**"' "$ci_yml"; check "ci.yml runs on release branches" "0" "$?"
grep -qF "'^release/(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\$'" "$cd_yml"; check "cd.yml accepts only release/<major>.<minor>" "0" "$?"

own_push="github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push' && github.event.workflow_run.head_repository.full_name == github.repository"
for job in docker docker-release; do
  [[ $(job_condition "$job") == *"$own_push"* ]]; check "$job runs only for a successful push to this repository" "0" "$?"
done
[[ $(job_condition docker) == *"github.event.workflow_run.head_branch == 'main'"* ]]; check "the main build skips release branches" "0" "$?"

job_body docker-release | grep -qF 'ref: ${{ github.event.workflow_run.head_sha }}'; check "release builds check out the tested commit" "0" "$?"
job_body docker-release | grep -qE 'type=raw,value=(latest|[0-9]|main)'; check "release builds publish no latest, version or main tag" "1" "$?"
job_body docker-release | grep -qF 'imagetools inspect'; check "an existing release tag is refused" "0" "$?"

exit "$failures"
