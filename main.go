package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

var (
	userName = flag.String("user", "", "Kolide user name")
	password = flag.String("pwd", "", "Password for user")
	host     = flag.String("host", "https://localhost:8080", "Kolide host name")
	config   = flag.String("config", "", "Path to an Osquery configuration file")
	help     = flag.Bool("help", false, "Show usage")
)

func handleError(reason string, err error) {
	if err != nil {
		fmt.Printf("%s: %s\n", reason, err)
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	if *help {
		fmt.Printf("\nUsage: configimporter -host https://localhost:8080 -user bob -pwd secret -config somedir/osquery.cfg\n\n")
		flag.PrintDefaults()
		os.Exit(0)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	authToken, err := loginToKolide(httpClient, *userName, *password, *host)
	handleError("login failed", err)

	buffer, err := ioutil.ReadFile(*config)
	handleError("read config file failed", err)

	importBody, err := collectExternalPacks(buffer, &externalPackReader{})
	handleError("build import body failed", err)

	err = sendConfigToKolide(httpClient, *host, authToken, importBody)
	handleError("post import failed", err)

}
