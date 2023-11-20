package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procGetUserNameW = advapi32.NewProc("GetUserNameW")
)

func getUserName() (string, error) {
	var size uint32
	success, _, err := syscall.Syscall(procGetUserNameW.Addr(), 2, uintptr(0), uintptr(unsafe.Pointer(&size)), 0)
	if success == 0 {
		if err != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", fmt.Errorf("GetUserNameW failed: %v", err)
		}
	}

	buffer := make([]uint16, size)
	success, _, err = syscall.Syscall(procGetUserNameW.Addr(), 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
	if success == 0 {
		return "", fmt.Errorf("GetUserNameW failed: %v", err)
	}

	return syscall.UTF16ToString(buffer), nil
}

func main() {
	username, err := getUserName()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Current running username: %s\n", username)
}