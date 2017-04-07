package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var testConfig = `
{
"options": {
  "read_max": 100000,
  "events_max": 100000,
  "enable_monitor": true,
  "host_identifier": "uuid"
},
"schedule": {
  "users_browser_plugins": {
    "query": "SELECT * FROM users JOIN browser_plugins USING (uid)",
    "interval": 60
  },
  "hashes_of_bin": {
    "query": "SELECT path, hash.sha256 FROM file JOIN hash USING (path) WHERE file.directory = '/bin/';",
    "interval": 3600,
    "removed": false,
    "platform": "darwin",
    "version": "1.4.5",
    "shard": 1
  }
},
"packs": {
    "*": "/globpath/*",
    "external_pack": "/some/osquery.cfg",
    "internal_stuff": {
      "discovery": [
        "select pid from processes where name = 'ldap';"
      ],
      "platform": "linux",
      "version": "1.5.2",
      "queries": {
        "active_directory": {
          "query": "select * from ad_config;",
          "interval": "1200",
          "description": "Check each user's active directory cached settings."
        }
      }
    },
    "testing": {
      "shard": "10",
      "queries": {
        "suid_bins": {
          "query": "select * from suid_bins;",
          "interval": "3600"
        }
      }
    }
  },
  "yara": {
     "signatures": {
       "signature_group_1": [
         "/path/to/signature.sig"
       ]
     },
     "file_paths": {
       "custom_category": [
         "signature_group_1"
       ]
     }
   },
   "decorators": {
    "load": [
      "SELECT version FROM osquery_info",
      "SELECT uuid AS host_uuid FROM system_info"
    ],
    "always": [
      "SELECT user AS username FROM logged_in_users WHERE user <> '' ORDER BY time LIMIT 1;"
    ],
    "interval": {
      "3600": [
        "SELECT total_seconds AS uptime FROM uptime;"
      ]
    }
  }
}
`

func TestConfigDecoder(t *testing.T) {
	cfg, err := decodeConfig([]byte(testConfig))
	require.Nil(t, err)

	packs := []string{"testing", "*", "internal_stuff", "external_pack"}
	for _, p := range packs {
		_, ok := cfg.Packs[p]
		assert.True(t, ok)
	}
	_, ok := cfg.Packs["internal_stuff"].(map[string]interface{})
	require.True(t, ok)
	_, ok = cfg.Packs["external_pack"].(string)
	require.True(t, ok)
	_, ok = cfg.Packs["*"].(string)
	require.True(t, ok)
}

type mockPackReader struct {
	mock.Mock
}

func (m *mockPackReader) readFile(path string) (interface{}, error) {
	args := m.Called(path)
	return args.Get(0).(interface{}), args.Error(1)
}

func (m *mockPackReader) globFiles(path string) ([]string, error) {
	args := m.Called(path)
	return args.Get(0).([]string), args.Error(1)
}

func TestPackReplacer(t *testing.T) {
	pr := new(mockPackReader)
	pr.On("globFiles", "/globpath/*").Return(
		[]string{"path/file1.cfg", "path/file2.cfg"},
		nil,
	)
	cfg, err := decodeConfig([]byte(testConfig))
	require.Nil(t, err)
	require.NotNil(t, cfg)
	pr.On("readFile", "path/file1.cfg").Return(cfg.Packs["internal_stuff"], nil)
	pr.On("readFile", "path/file2.cfg").Return(cfg.Packs["internal_stuff"], nil)
	pr.On("readFile", "/some/osquery.cfg").Return(cfg.Packs["internal_stuff"], nil)

	rep, err := packReplacer(cfg.Packs, pr)
	assert.Nil(t, err)
	// pack names for glob packs are the base name of the file
	_, ok := rep["file1"]
	assert.True(t, ok)
	_, ok = rep["file2"]
	assert.True(t, ok)
	_, ok = rep["external_pack"]
	assert.True(t, ok)
}

func TestBuildImportBody(t *testing.T) {
	pr := new(mockPackReader)
	pr.On("globFiles", "/globpath/*").Return(
		[]string{"path/file1.cfg", "path/file2.cfg"},
		nil,
	)
	cfg, err := decodeConfig([]byte(testConfig))
	require.Nil(t, err)
	require.NotNil(t, cfg)
	pr.On("readFile", "path/file1.cfg").Return(cfg.Packs["internal_stuff"], nil)
	pr.On("readFile", "path/file2.cfg").Return(cfg.Packs["internal_stuff"], nil)
	pr.On("readFile", "/some/osquery.cfg").Return(cfg.Packs["internal_stuff"], nil)
	impBody, err := collectExternalPacks([]byte(testConfig), pr)
	assert.Nil(t, err)
	assert.NotNil(t, impBody)
}
