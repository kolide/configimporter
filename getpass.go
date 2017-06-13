package main

import (
	"os"

	"github.com/howeyc/gopass"
)

func getPass() (string, error) {
	if password := os.Getenv("CONFIGIMPORTER_PASSWORD"); password != "" {
		return password, nil
	}
	buff, err := gopass.GetPasswdPrompt("Kolide Password: ", true, os.Stdin, os.Stdout)
	if err != nil {
		return "", err
	}
	return string(buff), nil
}
