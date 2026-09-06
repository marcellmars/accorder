//go:build windows

package libraryflow

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLocalObjectAtReadsWindowsChangeTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "book.epub")
	stamp := time.Now().Add(-time.Hour).Round(time.Second)
	if err := os.WriteFile(path, []byte("old!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	before := NewLocalObjectAt("book.epub", path, beforeInfo)
	if before.ChangeTime <= 0 {
		t.Fatal("GetFileInformationByHandleEx returned no Windows ChangeTime")
	}

	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("new!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	after := NewLocalObjectAt("book.epub", path, afterInfo)
	if !after.ModTime.Equal(before.ModTime) || after.Size != before.Size {
		t.Fatalf("test rewrite did not preserve portable stat identity: before=%+v after=%+v", before, after)
	}
	if after.ChangeTime == before.ChangeTime {
		t.Fatalf("same-size/same-mtime rewrite did not advance Windows ChangeTime: %d", after.ChangeTime)
	}
}
