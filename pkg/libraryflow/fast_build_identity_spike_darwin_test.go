//go:build darwin && fastbuild_apfs_validation

package libraryflow

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This is an opt-in native mechanism experiment, not an APFS capability grant
// for production. Keep non-APFS developer machines out of the default suite.
func spikeNativeIdentity(t *testing.T, path string) (string, string) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		t.Fatal(err)
	}
	name := unix.ByteSliceToString(fs.Fstypename[:])
	if name != "apfs" || fs.Flags&unix.MNT_LOCAL == 0 {
		t.Fatalf("experiment requires local APFS; found filesystem=%q flags=%x (not validated, not a skip)", name, fs.Flags)
	}
	if stat.Ino == 0 {
		t.Fatal("missing native inode")
	}
	return fmt.Sprintf("%x:%x", stat.Dev, stat.Ino), "darwin:apfs"
}

func TestFastBuildDarwinAPFSMechanisms(t *testing.T) {
	t.Logf("native mechanism experiment: os=%s arch=%s go=%s", runtime.GOOS, runtime.GOARCH, runtime.Version())
	t.Run("provenance-policy", TestSpikeInventoryProvenancePolicy)
	t.Run("closed-file-operations", TestSpikeInventoryClosedFileOperations)
	t.Run("change-time-precision", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "book.epub")
		stamp := time.Unix(1700000000, 0)
		var before spikeInventoryStamp
		for i := 0; i < 10; i++ {
			if i > 0 {
				time.Sleep(2 * time.Millisecond)
			}
			data := []byte{byte(i), 1, 2, 3}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			after := spikeCaptureInventory(t, root)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			native, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatalf("unexpected native stat type %T", info.Sys())
			}
			want := native.Ctimespec.Sec*int64(time.Second) + native.Ctimespec.Nsec
			if after.Object.ChangeTime != want {
				t.Fatalf("probe lost native timestamp precision: got %d want %d", after.Object.ChangeTime, want)
			}
			if i > 0 {
				if before.FileID != after.FileID || before.Object.Size != after.Object.Size || !before.Object.ModTime.Equal(after.Object.ModTime) {
					t.Fatal("rewrite must retain file ID, size and mtime")
				}
				if spikeInventoryReusable(before, after) {
					t.Fatal("closed same-size rewrite escaped native timestamp detection")
				}
				t.Logf("rewrite=%d change_time_delta_ns=%d", i, after.Object.ChangeTime-before.Object.ChangeTime)
			}
			before = after
		}
	})
	t.Run("unavailable-change-time", func(t *testing.T) {
		for _, sys := range []any{nil, (*syscall.Stat_t)(nil), struct{}{}, &syscall.Stat_t{}} {
			if got := fileChangeTimeUnixNano("unused", sys); got != 0 {
				t.Fatalf("unavailable timestamp must remain unavailable: type=%T got=%d", sys, got)
			}
		}
	})
}
