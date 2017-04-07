package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type importBody struct {
	Config string `json:"config"`
}

type osqueryConfig struct {
	Options    map[string]interface{} `json:"options"`
	Schedule   map[string]interface{} `json:"schedule"`
	Packs      map[string]interface{} `json:"packs"`
	FilePaths  map[string]interface{} `json:"file_paths"`
	Yara       map[string]interface{} `json:"yara"`
	Prometheus map[string]interface{} `json:"prometheus_targets"`
	Decorators map[string]interface{} `json:"decorators"`
}

type externalReader interface {
	readFile(path string) (interface{}, error)
	globFiles(path string) ([]string, error)
}

type externalPackReader struct{}

func (pr *externalPackReader) readFile(path string) (interface{}, error) {
	buff, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(buff)
	result := make(map[string]interface{})
	err = json.NewDecoder(reader).Decode(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (pr *externalPackReader) globFiles(path string) ([]string, error) {
	matches, err := filepath.Glob(path)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			results = append(results, match)
		}
	}
	return results, nil
}

func collectExternalPacks(buffer []byte, rdr externalReader) (*importBody, error) {
	cfg, err := decodeConfig(buffer)
	if err != nil {
		return nil, err
	}
	newPackSection, err := packReplacer(cfg.Packs, rdr)
	if err != nil {
		return nil, err
	}
	cfg.Packs = newPackSection
	var writer bytes.Buffer
	err = json.NewEncoder(&writer).Encode(cfg)
	if err != nil {
		return nil, err
	}
	body := &importBody{
		Config: writer.String(),
	}
	return body, nil
}

func decodeConfig(buff []byte) (*osqueryConfig, error) {
	reader := bytes.NewReader(buff)
	var cfg osqueryConfig
	err := json.NewDecoder(reader).Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func handleGlob(glob interface{}, reader externalReader, packMap map[string]interface{}) error {
	str, ok := glob.(string)
	if !ok {
		return errors.New("glob expression is not a string")
	}
	paths, err := reader.globFiles(str)
	if err != nil {
		return err
	}
	for _, path := range paths {
		packName := strings.TrimRight(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), ".")
		pack, err := reader.readFile(path)
		if err != nil {
			return err
		}
		packMap[packName] = pack
	}
	return nil
}

// finds file references to external packs, reads packs from files, and add them
// to pack
func packReplacer(packs map[string]interface{}, reader externalReader) (map[string]interface{}, error) {
	replaced := make(map[string]interface{})
	for k, v := range packs {
		if k == "*" {
			err := handleGlob(v, reader, replaced)
			if err != nil {
				return nil, err
			}
			continue
		}
		switch path := v.(type) {
		case string:
			pack, err := reader.readFile(path)
			if err != nil {
				return nil, err
			}
			replaced[k] = pack
		default:
			replaced[k] = v
		}
	}
	return replaced, nil
}
