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

# The token goes on disk only after the checked-out trivy action has run, in both jobs (EXC-791).
step_line() { job_body "$1" | grep -nF -- "- name: $2" | head -1 | cut -d: -f1; }
for job in docker docker-release; do
  login=$(step_line "$job" "Login to DockerHub"); scan=$(step_line "$job" "Trivy"); push=$(step_line "$job" "Build and push")
  [[ -n $login && -n $scan && $scan -lt $login ]]; check "$job logs in to Docker Hub only after the scan" "0" "$?"
  [[ -n $push && $login -lt $push && $((push - login)) -le 8 ]]; check "$job logs in just before the push" "0" "$?"
done

# The floating and main tags move only while the commit is still the branch tip, read again right before the push.
for job in docker docker-release; do
  tip=$(step_line "$job" "Check the branch tip again"); meta=$(step_line "$job" "Extract metadata"); push=$(step_line "$job" "Build and push")
  [[ -n $tip && -n $meta && $tip -lt $meta && $meta -lt $push ]]; check "$job re-reads the branch tip before it tags" "0" "$?"
  job_body "$job" | grep -qF "steps.tip.outputs.current == 'true'"; check "$job moves its floating tag only from that re-check" "0" "$?"
done
job_body docker-release | grep -qF "needs.release-plan.outputs.floating"; check "the plan's early tip reading no longer moves the floating tag" "1" "$?"

# The main build packages the tested commit, not whatever main is by now.
job_body docker | grep -qF 'ref: ${{ github.event.workflow_run.head_sha }}'; check "the main build checks out the tested commit" "0" "$?"
job_body docker | grep -qE 'type=ref|type=sha'; check "the main tags do not come from the default branch" "1" "$?"
job_body docker | grep -qF 'type=raw,value=main-${{ steps.commit.outputs.short }}'; check "main-<sha7> comes from the tested commit" "0" "$?"

exit "$failures"
