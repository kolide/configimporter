package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type importStatus struct {
	Title       string              `json:"title"`
	ImportCount int                 `json:"import_count"`
	SkipCount   int                 `json:"skip_count"`
	Warnings    map[string][]string `json:"warnings"`
	Messages    []string            `json:"messages"`
}

type importConfigResponse struct {
	ImportStatus map[string]*importStatus `json:"import_status"`
}

type importResponse struct {
	Response *importConfigResponse `json:"response,omitempty"`
	Err      error                 `json:"error,omitempty"`
}

// Prints information about what the import process did if it
// succeeded
func printImportResults(resp *importConfigResponse) error {
	const lineSep = "========================================="
	if resp == nil {
		return errors.New("invalid config response")
	}
	for section, status := range resp.ImportStatus {
		fmt.Println(lineSep)
		fmt.Printf("CONFIGURATION SECTION: %s\n", section)
		fmt.Println(lineSep)
		fmt.Printf("Title:        %s\n", status.Title)
		fmt.Printf("Import Count: %d\n", status.ImportCount)
		fmt.Printf("Skip Count:   %d\n", status.SkipCount)
		if len(status.Warnings) > 0 {
			fmt.Println(lineSep)
			for _, msgs := range status.Warnings {
				for _, msg := range msgs {
					fmt.Printf("WARN: %s\n", msg)
				}
			}
		}
		if len(status.Messages) > 0 {
			fmt.Println(lineSep)
			for _, msg := range status.Messages {
				fmt.Printf("INFO: %s\n", msg)
			}
		}
	}
	return nil
}

type invalidError struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}
type invalidErrors struct {
	Message string         `json:"message"`
	Errors  []invalidError `json:"errors"`
}

func sendConfigToKolide(client *http.Client, host, token string, imp *importBody) error {
	body, err := json.Marshal(imp)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost,
		host+"/api/v1/kolide/osquery/config/import",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	fmt.Printf("\nResponse Status: %s\n\n", resp.Status)

	if resp.ContentLength == 0 {
		return errors.New("Empty response")
	}
	if resp.StatusCode == http.StatusOK {
		var result importResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return err
		}
		if result.Err != nil {
			return result.Err
		}
		err = printImportResults(result.Response)
		if err != nil {
			return err
		}
		return nil
	}

	if resp.StatusCode == http.StatusUnprocessableEntity {
		var invalid invalidErrors
		err = json.NewDecoder(resp.Body).Decode(&invalid)
		if err != nil {
			return err
		}
		fmt.Println(invalid.Message)
		fmt.Println(strings.Repeat("=", len(invalid.Message)))
		for _, errMsg := range invalid.Errors {
			fmt.Printf("%s - %s\n", errMsg.Name, errMsg.Reason)
		}
		fmt.Println("")
		return errors.New("invalid input file")
	}

	return fmt.Errorf("http response %s", resp.Status)
}
