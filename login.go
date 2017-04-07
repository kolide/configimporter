package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

type loginResult struct {
	Token string `json:"token,omitempty"`
	Err   error  `json:"error,omitempty"`
}

func loginToKolide(client *http.Client, userName, password, host string) (string, error) {
	passwordRequest := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: userName,
		Password: password,
	}
	body, err := json.Marshal(&passwordRequest)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequest(http.MethodPost,
		host+"/api/v1/kolide/login",
		bytes.NewBuffer(body))
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var result loginResult
		err = json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			return "", err
		}
		if result.Err != nil {
			return "", result.Err
		}
		return result.Token, nil
	}

	return "", errors.New(response.Status)
}
