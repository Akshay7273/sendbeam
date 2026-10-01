#!/usr/bin/env bash
# Tests for the promote-wait CI polling logic (audit F03 follow-up):
# pending->success, pending->failure, missing runs, permission errors,
# reruns (latest attempt wins), and timeout -- without calling GitHub.
set -uo pipefail

PASS=0
FAIL=0
ok()  { echo "PASS [$1]"; PASS=$((PASS + 1)); }
bad() { echo "FAIL [$1]"; FAIL=$((FAIL + 1)); }

TMPBIN="$(mktemp -d)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY3="$(command -v python3)"
trap 'rm -rf "${TMPBIN}"' EXIT

GH_TEMPLATE='#!/usr/bin/env bash
if [ "$GH_STATUS" = "permerror" ]; then
  echo "gh: API permission denied" >&2
  exit 4
fi
printf "%s" "$GH_RUNS_JSON"'

WAIT_TEMPLATE='#!/usr/bin/env bash
set -uo pipefail
attempt=1
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  ROW="$(GH_RUNS_JSON="$GH_RUNS_JSON" GH_STATUS="$GH_STATUS" "$PY3" "$FIXTURE")"
  if [ "$ROW" = "PERM_ERROR" ]; then
    echo "PERM_ERROR" >&2
    exit 1
  fi
  if [ -z "$ROW" ]; then
    echo "  attempt $attempt/$MAX_ATTEMPTS: no CI run yet for $SHA"
  else
    echo "  attempt $attempt/$MAX_ATTEMPTS: $ROW"
    set -- $ROW
    STATUS="$2"
    CONC="$3"
    if [ "$STATUS" = "completed" ]; then
      if [ "$CONC" = "success" ]; then
        echo "[+] CI completed successfully on $SHA (promotion allowed)."
        exit 0
      fi
      echo "[-] CI completed on $SHA with conclusion $CONC; refusing to promote." >&2
      exit 1
    fi
  fi
  sleep "$INTERVAL"
  attempt=$((attempt + 1))
done
echo "[-] Timed out waiting for completed CI on $SHA; refusing to promote." >&2
exit 1'

run_scenario() {
  local name="$1" expect="$2" runs_json="$3" gh_status="$4"
  printf '%s' "${GH_TEMPLATE}" > "${TMPBIN}/gh"
  chmod +x "${TMPBIN}/gh"
  printf '%s' "${WAIT_TEMPLATE}" > "${TMPBIN}/wait.sh"
  chmod +x "${TMPBIN}/wait.sh"
  PY3="$(command -v python3)"
  FIXTURE="${SCRIPT_DIR}/promote-poll-fixture.py"
  OUT="$(MAX_ATTEMPTS=3 INTERVAL=0 GH_STATUS="${gh_status}" GH_RUNS_JSON="${runs_json}" \
    REPO=o/r SHA=deadbeefbeefbeefbeefbeefbeefbeef PATH="${TMPBIN}:/usr/bin:/bin" \
    FIXTURE="${SCRIPT_DIR}/promote-poll-fixture.py" PY3="${PY3}" \
    "${TMPBIN}/wait.sh" 2>&1)"
  RC=$?
  case "${expect}" in
    promote)
      if [ ${RC} -eq 0 ] && echo "${OUT}" | grep -q "promotion allowed"; then ok "${name}"; else bad "${name}: expected promote, got rc=${RC}: ${OUT}"; fi ;;
    refuse)
      if [ ${RC} -ne 0 ]; then ok "${name}"; else bad "${name}: expected refusal, got rc=0"; fi ;;
    perm)
      if [ ${RC} -ne 0 ] && echo "${OUT}" | grep -q "PERM_ERROR"; then ok "${name}"; else bad "${name}: expected PERM_ERROR, got rc=${RC}: ${OUT}"; fi ;;
  esac
}

run_scenario "pending -> success: waits then promotes" promote '{"workflow_runs":[{"id":1,"name":"CI","status":"in_progress","conclusion":null},{"id":2,"name":"CI","status":"completed","conclusion":"success"}]}' ok
run_scenario "pending -> failure: refuses promotion" refuse '{"workflow_runs":[{"id":3,"name":"CI","status":"completed","conclusion":"failure"}]}' ok
run_scenario "missing runs: bounded timeout refuses" refuse '{"workflow_runs":[]}' ok
run_scenario "permission error: fails closed" perm '' permerror
run_scenario "reruns: latest attempt (success) wins" promote '{"workflow_runs":[{"id":7,"name":"CI","status":"completed","conclusion":"failure"},{"id":9,"name":"CI","status":"completed","conclusion":"success"}]}' ok
run_scenario "reruns: newest failure governs" refuse '{"workflow_runs":[{"id":11,"name":"CI","status":"completed","conclusion":"success"},{"id":12,"name":"CI","status":"completed","conclusion":"failure"}]}' ok

echo ""
if [ ${FAIL} -gt 0 ]; then
  echo "=== ${FAIL} TEST(S) FAILED (${PASS} passed) ==="
  exit 1
fi
echo "=== ALL ${PASS} PROMOTE-POLL TESTS PASSED ==="
