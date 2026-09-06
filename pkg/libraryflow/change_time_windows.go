//go:build windows

package libraryflow

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileBasicInfo mirrors FILE_BASIC_INFO. The final field makes the struct's
// size match Windows' 8-byte alignment after FileAttributes.
type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

func fileChangeTimeUnixNano(path string, _ any) int64 {
	if path == "" {
		return 0
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)

	var info fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil || info.ChangeTime <= 0 {
		return 0
	}
	filetime := windows.Filetime{
		LowDateTime:  uint32(info.ChangeTime),
		HighDateTime: uint32(uint64(info.ChangeTime) >> 32),
	}
	return filetime.Nanoseconds()
}
