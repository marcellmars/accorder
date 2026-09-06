import json
import sys

root = "TestFastBuildDarwinAPFSMechanisms"
expected = {root}
for group in ["provenance-policy", "closed-file-operations", "change-time-precision", "unavailable-change-time"]:
    expected.add(f"{root}/{group}")
for case in ["machine", "root-path", "root-id", "file-id", "filesystem", "missing-machine", "missing-root-id", "missing-file-id", "missing-capability", "missing-change-time"]:
    expected.add(f"{root}/provenance-policy/{case}")
for case in ["rewrite-restored-mtime", "atomic-replacement", "timestamp-only", "copied-root"]:
    expected.add(f"{root}/closed-file-operations/{case}")
with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.strip()]
passed = {e.get("Test") for e in events if e.get("Action") == "pass" and e.get("Test")}
bad = [e for e in events if e.get("Action") in {"fail", "skip"}]
if bad or passed != expected:
    raise SystemExit(f"Invalid test evidence: missing={sorted(expected-passed)} extra={sorted(passed-expected)} failures/skips={bad}")
if not any(e.get("Action") == "pass" and "Test" not in e for e in events):
    raise SystemExit("Missing package success event")
print(f"Verified {len(expected)} named passes, no skips or failures.")
