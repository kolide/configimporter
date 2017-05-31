package main

/*
#cgo darwin LDFLAGS: -lcrypto -L/usr/local/opt/openssl/lib
#cgo darwin CFLAGS: -Wno-deprecated-declarations -I/usr/local/opt/openssl/include
#cgo linux windows LDFLAGS: -lcrypto
#cgo linux windows CFLAGS: -Wno-deprecated-declarations
#include <stdio.h>
#include <openssl/ui.h>
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func getPass() (string, error) {
	if password := os.Getenv("CONFIGIMPORTER_PASSWORD"); password != "" {
		return password, nil
	}
	prompt := C.CString("Password: ")
	defer C.free(unsafe.Pointer(prompt))
	const passwordLength = 64
	buff := make([]byte, passwordLength)
	pwBuff := C.CString(string(buff))
	defer C.free(unsafe.Pointer(pwBuff))
	// Use openssl to supply getpass functionality, as it's not available on Windows
	rc, _ := C.UI_UTIL_read_pw_string(pwBuff, C.int(passwordLength), prompt, C.int(0))
	if rc != 0 {
		return "", fmt.Errorf("Password read error %d", rc)
	}

	password := C.GoString(pwBuff)

	return password, nil
}
