package libraryflow

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

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
	if stat.Ino == 0 {
		t.Fatal("missing native inode")
	}
	return fmt.Sprintf("%x:%x", stat.Dev, stat.Ino), fmt.Sprintf("linux-fstype:%x", fs.Type)
}
