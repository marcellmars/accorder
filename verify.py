"""Prepare/publish an isolated source-only native acceptance snapshot.

Run prepare first, inspect its manifest, then publish explicitly. No credentials,
git history, checked-in book fixtures, or operator configuration are included.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = os.environ.get("ACCORDER_NATIVE_SOURCE", "7a50dfbbebcb6fe7ca7602d4e763483b50eca166")
REPO = "marcellmars/accorder"
BRANCH = os.environ.get("ACCORDER_NATIVE_BRANCH", "validation/fastbuild-commands-20260907")
HERE = Path(__file__).resolve().parent
TEST_FILES = [
    "cmd/fast_build_commands_test.go", "cmd/fast_build_acceptance_test.go",
    "cmd/fast_build_review_regression_test.go", "cmd/libraryPrivateCleanup_test.go",
    "cmd/libraryPrivateCleanupReview_test.go",
]


def command(*args, **kwargs):
    return subprocess.check_output(args, **kwargs)


def prepare(out, working=False):
    out.mkdir(parents=True, exist_ok=False)
    if working:
        assert command("git", "rev-parse", "HEAD").decode().strip() == SOURCE
        paths = command("git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "cmd", "pkg", "go.mod", "go.sum").decode().splitlines()
    else:
        paths = command("git", "ls-tree", "-r", "--name-only", SOURCE, "--", "cmd", "pkg", "go.mod", "go.sum").decode().splitlines()
    paths = [p for p in paths if p.endswith(".go") or p in {"go.mod", "go.sum"} or p.startswith("pkg/calibre/embResources/")]
    assert not any("testdata/" in p or p.endswith((".epub", ".pdf", ".mobi", ".azw3")) for p in paths)
    if working:
        import io
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive_file:
            for path in sorted(paths):
                assert Path(path).is_file() and not Path(path).is_symlink()
                archive_file.add(path, arcname=path, recursive=False)
        archive = gzip.compress(buffer.getvalue(), mtime=0)
    else:
        archive = gzip.compress(command("git", "archive", "--format=tar", SOURCE, "--", *paths), mtime=0)
    (out / "source.tar.gz").write_bytes(archive)
    tests = []
    for path in TEST_FILES + (["cmd/buildOutput_test.go", "cmd/generation_change_immutable_test.go", "cmd/libraryInventory_test.go", "cmd/libraryObservation_test.go"] if working else []):
        raw = Path(path).read_text() if working else command("git", "show", f"{SOURCE}:{path}").decode()
        tests += re.findall(r"^func (Test\w+)\(t \*testing.T\)", raw, re.M)
    tests = [name for name in tests if name != "TestParallelInventoryRejectsSymlinks"]
    assert len(tests) == len(set(tests)) and len(tests) >= 25
    (out / "test-pattern.txt").write_text("^(" + "|".join(sorted(tests)) + ")$\n")
    (out / "expected-roots.json").write_text(json.dumps(sorted(tests), indent=2) + "\n")
    (out / "SOURCE.json").write_text(json.dumps({
        "git_commit": SOURCE, "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "working_tree_snapshot": working,
        "file_sha256": {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths} if working else {},
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
        "expected-mechanisms.json": out / "expected-mechanisms.json",
        "verify.py": HERE / "native-command-validation.py",
        ".github/workflows/native-commands.yml": HERE / "github-native-commands.yml",
    }
    for path, local in files.items():
        content = local.read_text()
        if path.endswith("native-commands.yml"):
            content = content.replace("validation/fastbuild-commands-20260907", BRANCH)
        entries.append({"path": path, "type": "blob", "mode": "100644", "content": content})
    tree = api("git/trees", {"tree": entries})
    commit = api("git/commits", {"message": f"Validate fast-build commands on native macOS from {SOURCE[:7]}", "tree": tree["sha"], "parents": []})
    ref = api("git/refs", {"ref": "refs/heads/" + BRANCH, "sha": commit["sha"]})
    result = {"repository": REPO, "branch": BRANCH, "commit": commit["sha"], "ref": ref["ref"], "source": SOURCE}
    (out / "github-publication.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


def update_workflow(out):
    previous = json.loads((out / "github-publication.json").read_text())
    current = json.loads(command("gh", "api", f"repos/{REPO}/git/ref/heads/{BRANCH}"))
    assert current["object"]["sha"] == previous["commit"]
    commit = json.loads(command("gh", "api", f"repos/{REPO}/git/commits/{previous['commit']}"))
    entries = [{
        "path": ".github/workflows/native-commands.yml", "type": "blob", "mode": "100644",
        "content": (HERE / "github-native-commands.yml").read_text(),
    }]
    if (out / "expected-mechanisms.json").exists():
        entries.append({"path": "expected-mechanisms.json", "type": "blob", "mode": "100644", "content": (out / "expected-mechanisms.json").read_text()})
    tree = api("git/trees", {"base_tree": commit["tree"]["sha"], "tree": entries})
    new = api("git/commits", {"message": "Update native validation harness without changing source snapshot", "tree": tree["sha"], "parents": [previous["commit"]]})
    command("gh", "api", "--method", "PATCH", f"repos/{REPO}/git/refs/heads/{BRANCH}", "--input", "-", input=json.dumps({"sha": new["sha"], "force": False}).encode())
    previous.setdefault("prior_commits", []).append(previous["commit"])
    previous["commit"] = new["sha"]
    (out / "github-publication.json").write_text(json.dumps(previous, indent=2) + "\n")
    print(json.dumps(previous))


def retain_evidence(out):
    import shutil
    destination = HERE / os.environ.get("ACCORDER_NATIVE_EVIDENCE_DIR", "native-command-results")
    assert destination.parent == HERE
    destination.mkdir(exist_ok=True)
    for name in ["SOURCE.json", "expected-tests.json", "expected-windows.json", "expected-mechanisms.json", "test-pattern.txt", "windows-pattern.txt", "github-publication.json", "gce-resources.json", "gce-guest-attributes.json", "local-tests.jsonl", "local-mechanisms.jsonl", "local-serve-components.jsonl"]:
        path = out / name
        if path.exists():
            shutil.copy2(path, destination / name)
    for name in ["macos-results", "windows-results"]:
        if (out / name).exists():
            shutil.copytree(out / name, destination / name, dirs_exist_ok=True)
    print(destination)


def verify_windows_supplement(out, results):
    events = [json.loads(line) for line in (out / "local-mechanisms.jsonl").read_text().splitlines()]
    names = sorted({e["Test"] for e in events if e.get("Action") == "pass" and e.get("Test")} | {"TestNewLocalObjectAtReadsWindowsChangeTime"})
    (results / "expected-mechanisms.json").write_text(json.dumps(names, indent=2) + "\n")
    (results / "expected-legacy.json").write_text(json.dumps(["TestWindowsLegacyLibraryUpgradeWithNewBookAndNonEmptyRemote"]) + "\n")
    complete = (results / "result.json").exists()
    if complete:
        state = json.loads((results / "result.json").read_text(encoding="utf-8-sig"))
    else:
        attributes = json.loads((out / "gce-guest-attributes.json").read_text())
        state = json.loads(next(row["value"] for row in attributes if row["key"] == "supplemental"))
    for name, package, expected in [("mechanisms", "accorder/pkg/libraryflow", results / "expected-mechanisms.json"), ("legacy", "accorder/cmd", results / "expected-legacy.json"), ("commands", "accorder/cmd", out / "expected-tests.json")]:
        if not complete and name == "commands":
            print("Duplicate command run interrupted; no acceptance result")
            continue
        stdout = (results / f"{name}-stdout.txt").read_bytes()
        raw = command("go", "tool", "test2json", "-p", package, input=stdout)
        path = results / f"{name}.jsonl"
        path.write_bytes(raw)
        if not complete and name == "legacy":
            assert state["legacy_exit_code"] == 2
            assert "panic: test timed out after 2m0s" in (results / "legacy-stderr.txt").read_text()
            print("Verified retained legacy timeout evidence; Windows command acceptance FAILED")
        else:
            verify(path, expected)
            assert state[f"{name}_exit_code"] == 0
    assert state["filesystem"] == "NTFS"
    if complete:
        assert state["status"] == "passed"


def prepare_mechanisms(out):
    events = [json.loads(line) for line in (HERE / "github-apfs-results/macos-15/tests.jsonl").read_text().splitlines()]
    expected = sorted({e["Test"] for e in events if e.get("Action") == "pass" and e.get("Test")})
    assert len(expected) == 19
    if "pkg/libraryflow/local_observation_test.go" in json.loads((out / "SOURCE.json").read_text())["files"]:
        expected.append("TestLocalObservationMatchesIndependentProbes")
        expected.sort()
    (out / "expected-mechanisms.json").write_text(json.dumps(expected, indent=2) + "\n")


def prepare_windows_pattern(out):
    names = sorted(set(json.loads((out / "expected-tests.json").read_text())) | {"TestWindowsLegacyLibraryUpgradeWithNewBookAndNonEmptyRemote"})
    (out / "expected-windows.json").write_text(json.dumps(names, indent=2) + "\n")
    (out / "windows-pattern.txt").write_text("^(" + "|".join(n for n in names if "/" not in n) + ")$\n")


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "prepare": prepare(Path(sys.argv[2]))
    elif action == "prepare-working": prepare(Path(sys.argv[2]), working=True)
    elif action == "publish": publish(Path(sys.argv[2]))
    elif action == "update-workflow": update_workflow(Path(sys.argv[2]))
    elif action == "retain-evidence": retain_evidence(Path(sys.argv[2]))
    elif action == "prepare-mechanisms": prepare_mechanisms(Path(sys.argv[2]))
    elif action == "prepare-windows-pattern": prepare_windows_pattern(Path(sys.argv[2]))
    elif action == "verify-windows-supplement": verify_windows_supplement(Path(sys.argv[2]), Path(sys.argv[3]))
    elif action == "verify": verify(sys.argv[2], sys.argv[3])
    elif action == "record-expected":
        verify(sys.argv[2], sys.argv[3])
        events = [json.loads(line) for line in Path(sys.argv[2]).read_text().splitlines() if line.strip()]
        passed = sorted({e["Test"] for e in events if e.get("Action") == "pass" and e.get("Test")})
        Path(sys.argv[4]).write_text(json.dumps(passed, indent=2) + "\n")
    else: raise SystemExit("Unknown action")
