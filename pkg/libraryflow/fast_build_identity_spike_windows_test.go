package libraryflow

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func spikeNativeIdentity(t *testing.T, path string) (string, string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		t.Fatal(err)
	}
	var fsName [64]uint16
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName))); err != nil {
		t.Fatal(err)
	}
	fs := windows.UTF16ToString(fsName[:])
	if !strings.EqualFold(fs, "NTFS") {
		t.Fatalf("this experiment requires a local NTFS temporary directory; found %s (not validated, not a skip)", fs)
	}
	if info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
		t.Fatal("missing native file ID")
	}
	return fmt.Sprintf("%x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), "windows:NTFS"
}
