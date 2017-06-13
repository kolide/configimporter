### Osquery Configuration Importer

Import an Osquery configuration file into [Kolide](https://github.com/kolide/kolide). The
configimporter application will take an Osquery configuration file, consolidate any external packs found in the file and then post it to Kolide where it is validated and imported.  

#### Installation
```
go get -u github.com/kolide/configimporter
```

#### Usage
```
Usage: configimporter -host https://localhost:8080 -user 'bob' -config /somedir/osquery.cfg

  -config string
        Path to an Osquery configuration file
  -dry-run
        Run import but don't make any changes to Kolide
  -help
        Show usage
  -host string
        Kolide host name (default "https://localhost:8080")
  -user string
        Kolide user name

```
The user will be prompted for their Kolide password; alternatively, the password may
be supplied by setting an environment variable.
```
export CONFIGIMPORTER_PASSWORD=supersecret
```
