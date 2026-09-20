#!/usr/bin/env bash
# End-to-end proof loop: attack -> detect -> respond -> re-attack -> blocked.
# The re-attack step is the point: containment that cannot be re-tested is a claim,
# not a control.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=./.venv/bin/python
ATTACKS="A01 A02 A05 A06 A09"

hr() { printf '%s\n' "------------------------------------------------------------------"; }

hr; echo "STEP 0  reset lab state"; hr
$PY engine/ir.py --lift >/dev/null 2>&1 || true
rm -rf data; rm -rf incidents/INC-*; mkdir -p incidents
find lab/app/corpus -name '*.md' \
  ! -name onboarding.md ! -name expenses.md ! -name support-sla.md -delete

hr; echo "STEP 1  run attacks (artifacts retained for IR to act on)"; hr
$PY attacks/runner.py --id $ATTACKS --keep-artifacts 2>/dev/null \
  | grep -E '^A[0-9]{2}|result  :' | sed 's/^     //'

hr; echo "STEP 2  detections"; hr
$PY detections/run.py 2>/dev/null | grep -E '^D0|detections fired'

hr; echo "STEP 3  respond - execute runbooks and contain"; hr
$PY engine/ir.py --respond 2>&1 \
  | grep -E 'CONTAINMENT|REFUSED|incident  :|now in effect' | sed 's/^     //'

hr; echo "STEP 4  quarantine directory"; hr
ls -1 data/quarantine/ 2>/dev/null || echo "(empty)"

hr; echo "STEP 5  RE-RUN THE SAME ATTACKS against the contained system"; hr
$PY attacks/runner.py --id $ATTACKS 2>/dev/null \
  | grep -E '^A[0-9]{2}|result  :|detail  :' | sed 's/^     //'

hr; echo "STEP 6  incident artifacts produced"; hr
find incidents -name '*.md' | sort | sed 's/^/  /'
echo
echo "reverse containment with: make ir-lift"
