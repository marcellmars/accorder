//go:build linux || windows || (darwin && fastbuild_apfs_validation)

package libraryflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Test-only policy experiment, not a production state format. Machine is an
// injected installation identity: obtaining and persisting it is not validated
// here. Neither this tuple nor native IDs detect a full filesystem rollback.
type spikeInventoryStamp struct {
	Machine, RootPath, RootID, FileID, Filesystem string
	Object                                        Object
}

func spikeInventoryReusable(a, b spikeInventoryStamp) bool {
	return a.Machine != "" && a.RootPath != "" && a.RootID != "" &&
		a.FileID != "" && a.Filesystem != "" &&
		a.Machine == b.Machine && a.RootPath == b.RootPath &&
		a.RootID == b.RootID && a.FileID == b.FileID && a.Filesystem == b.Filesystem &&
		a.Object.Path == b.Object.Path && a.Object.Size == b.Object.Size &&
		!a.Object.ModTime.IsZero() && a.Object.ModTime.Equal(b.Object.ModTime) &&
		a.Object.ChangeTime > 0 && a.Object.ChangeTime == b.Object.ChangeTime
}

func spikeCaptureInventory(t *testing.T, root string) spikeInventoryStamp {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "book.epub")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	rootID, filesystem := spikeNativeIdentity(t, root)
	fileID, fileFilesystem := spikeNativeIdentity(t, path)
	if filesystem != fileFilesystem {
		t.Fatal("fixture crosses filesystems")
	}
	stamp := spikeInventoryStamp{
		Machine: "test-installation-A", RootPath: canonical, RootID: rootID,
		FileID: fileID, Filesystem: filesystem,
		Object: NewLocalObjectAt("book.epub", path, info),
	}
	if !spikeInventoryReusable(stamp, stamp) {
		t.Fatal("native fixture has unavailable evidence")
	}
	return stamp
}

func TestSpikeInventoryProvenancePolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "book.epub")
	if err := os.WriteFile(path, []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := spikeCaptureInventory(t, root)
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var saved spikeInventoryStamp
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if !spikeInventoryReusable(saved, spikeCaptureInventory(t, root)) {
		t.Fatal("persisted/reopened identity failed unchanged control")
	}
	for _, field := range []string{"machine", "root-path", "root-id", "file-id", "filesystem", "missing-machine", "missing-root-id", "missing-file-id", "missing-capability", "missing-change-time"} {
		t.Run(field, func(t *testing.T) {
			current := saved // All payload metadata remains identical in identity controls.
			switch field {
			case "machine":
				current.Machine = "test-installation-B"
			case "root-path":
				current.RootPath += "-copied"
			case "root-id":
				current.RootID += "-replaced"
			case "file-id":
				current.FileID += "-replaced"
			case "filesystem":
				current.Filesystem += "-different"
			case "missing-machine":
				current.Machine = ""
			case "missing-root-id":
				current.RootID = ""
			case "missing-file-id":
				current.FileID = ""
			case "missing-capability":
				current.Filesystem = ""
			case "missing-change-time":
				current.Object.ChangeTime = 0
			}
			if spikeInventoryReusable(saved, current) {
				t.Fatal("mismatched/unavailable provenance trusted")
			}
		})
	}
	t.Logf("native identity round-trip passed; filesystem=%s; policy controls use injected installation identity", before.Filesystem)
}

func TestSpikeInventoryClosedFileOperations(t *testing.T) {
	for _, operation := range []string{"rewrite-restored-mtime", "atomic-replacement", "timestamp-only", "copied-root"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "book.epub")
			stamp := time.Unix(1700000000, 0)
			if err := os.WriteFile(path, []byte("old!"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			before := spikeCaptureInventory(t, root)
			time.Sleep(20 * time.Millisecond)
			want := "new!"
			switch operation {
			case "rewrite-restored-mtime":
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := f.WriteAt([]byte(want), 0)
				syncErr := f.Sync()
				closeErr := f.Close()
				if writeErr != nil || syncErr != nil || closeErr != nil {
					t.Fatalf("write=%v sync=%v close=%v", writeErr, syncErr, closeErr)
				}
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			case "atomic-replacement":
				replacement := filepath.Join(root, "replacement.epub")
				if err := os.WriteFile(replacement, []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(replacement, stamp, stamp); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			case "timestamp-only":
				want = "old!"
				if err := os.Chtimes(path, stamp.Add(time.Hour), stamp.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "copied-root":
				want = "old!"
				root = t.TempDir()
				path = filepath.Join(root, "book.epub")
				if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			after := spikeCaptureInventory(t, root)
			if spikeInventoryReusable(before, after) {
				t.Fatal("operation escaped metadata/identity detector")
			}
			data, err := os.ReadFile(path) // Independent byte oracle; never part of the detector.
			if err != nil || string(data) != want {
				t.Fatalf("byte oracle=%q err=%v", data, err)
			}
			if operation == "rewrite-restored-mtime" {
				if before.FileID != after.FileID || before.Object.Size != after.Object.Size || !before.Object.ModTime.Equal(after.Object.ModTime) || before.Object.ChangeTime == after.Object.ChangeTime {
					t.Fatal("in-place control must retain file ID/size/mtime and change ChangeTime")
				}
			}
			if operation == "atomic-replacement" && before.FileID == after.FileID {
				t.Fatal("replacement retained native file ID")
			}
			if operation == "copied-root" {
				if before.RootID == after.RootID {
					t.Fatal("copied root retained native root ID")
				}
				after.Object = before.Object // Prove rejection independent of incidental timestamp differences.
				if spikeInventoryReusable(before, after) {
					t.Fatal("copied root trusted after matching every payload timestamp")
				}
			}
			t.Logf("%s detected; filesystem=%s", operation, before.Filesystem)
		})
	}
}
