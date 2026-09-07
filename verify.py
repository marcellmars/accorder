"""Prepare/publish an isolated source-only native acceptance snapshot.

Run prepare first, inspect its manifest, then publish explicitly. No credentials,
git history, checked-in book fixtures, or operator configuration are included.
"""
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SOURCE = "7a50dfbbebcb6fe7ca7602d4e763483b50eca166"
REPO = "marcellmars/accorder"
BRANCH = "validation/fastbuild-commands-20260907"
HERE = Path(__file__).resolve().parent
TEST_FILES = [
    "cmd/fast_build_commands_test.go", "cmd/fast_build_acceptance_test.go",
    "cmd/fast_build_review_regression_test.go", "cmd/libraryPrivateCleanup_test.go",
    "cmd/libraryPrivateCleanupReview_test.go",
]


def command(*args, **kwargs):
    return subprocess.check_output(args, **kwargs)


def prepare(out):
    out.mkdir(parents=True, exist_ok=False)
    paths = command("git", "ls-tree", "-r", "--name-only", SOURCE, "--", "cmd", "pkg", "go.mod", "go.sum").decode().splitlines()
    paths = [p for p in paths if p.endswith(".go") or p in {"go.mod", "go.sum"} or p.startswith("pkg/calibre/embResources/")]
    assert not any("testdata/" in p or p.endswith((".epub", ".pdf", ".mobi", ".azw3")) for p in paths)
    archive = gzip.compress(command("git", "archive", "--format=tar", SOURCE, "--", *paths), mtime=0)
    (out / "source.tar.gz").write_bytes(archive)
    tests = []
    for path in TEST_FILES:
        raw = command("git", "show", f"{SOURCE}:{path}").decode()
        tests += re.findall(r"^func (Test\w+)\(t \*testing.T\)", raw, re.M)
    assert len(tests) == len(set(tests)) and len(tests) >= 25
    (out / "test-pattern.txt").write_text("^(" + "|".join(sorted(tests)) + ")$\n")
    (out / "expected-roots.json").write_text(json.dumps(sorted(tests), indent=2) + "\n")
    (out / "SOURCE.json").write_text(json.dumps({
        "git_commit": SOURCE, "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "files": paths, "archive_bytes": len(archive), "test_roots": len(tests),
        "exclusions": "git history, .sit, operator data/configuration and checked-in book/testdata fixtures",
    }, indent=2) + "\n")
    print(json.dumps({"directory": str(out), "files": len(paths), "bytes": len(archive), "test_roots": len(tests)}))


def verify(events_path, expected_path):
    events = [json.loads(line) for line in Path(events_path).read_text().splitlines() if line.strip()]
    expected = set(json.loads(Path(expected_path).read_text()))
    passed = {e["Test"] for e in events if e.get("Action") == "pass" and e.get("Test")}
    roots = {name for name in passed if "/" not in name}
    bad = [e for e in events if e.get("Action") in {"fail", "skip"}]
    if bad or expected - passed or roots != {n for n in expected if "/" not in n}:
        raise SystemExit(f"FAILED: missing={sorted(expected-passed)}, unexpected_roots={sorted(roots-expected)}, failures/skips={bad}")
    if not any(e.get("Action") == "pass" and not e.get("Test") for e in events):
        raise SystemExit("Missing package success")
    print(f"Verified {len(roots)} top-level and {len(passed)-len(roots)} nested passes; no skips or failures.")


def api(endpoint, data):
    return json.loads(command("gh", "api", "--method", "POST", f"repos/{REPO}/{endpoint}", "--input", "-", input=json.dumps(data).encode()))


def publish(out):
    import base64
    source = json.loads((out / "SOURCE.json").read_text())
    archive = (out / "source.tar.gz").read_bytes()
    assert hashlib.sha256(archive).hexdigest() == source["archive_sha256"]
    blob = api("git/blobs", {"encoding": "base64", "content": base64.b64encode(archive).decode()})
    entries = [{"path": "source.tar.gz", "type": "blob", "mode": "100644", "sha": blob["sha"]}]
    files = {
        "SOURCE.json": out / "SOURCE.json", "test-pattern.txt": out / "test-pattern.txt",
        "expected-tests.json": out / "expected-tests.json",
        "verify.py": HERE / "native-command-validation.py",
        ".github/workflows/native-commands.yml": HERE / "github-native-commands.yml",
    }
    for path, local in files.items():
        entries.append({"path": path, "type": "blob", "mode": "100644", "content": local.read_text()})
    tree = api("git/trees", {"tree": entries})
    commit = api("git/commits", {"message": "Validate fast-build commands on native macOS from 7a50dfb", "tree": tree["sha"], "parents": []})
    ref = api("git/refs", {"ref": "refs/heads/" + BRANCH, "sha": commit["sha"]})
    result = {"repository": REPO, "branch": BRANCH, "commit": commit["sha"], "ref": ref["ref"], "source": SOURCE}
    (out / "github-publication.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "prepare": prepare(Path(sys.argv[2]))
    elif action == "publish": publish(Path(sys.argv[2]))
    elif action == "verify": verify(sys.argv[2], sys.argv[3])
    elif action == "record-expected":
        verify(sys.argv[2], sys.argv[3])
        events = [json.loads(line) for line in Path(sys.argv[2]).read_text().splitlines() if line.strip()]
        passed = sorted({e["Test"] for e in events if e.get("Action") == "pass" and e.get("Test")})
        Path(sys.argv[4]).write_text(json.dumps(passed, indent=2) + "\n")
    else: raise SystemExit("Unknown action")
