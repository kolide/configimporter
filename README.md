### Osquery Configuration Importer

Import an Osquery configuration file into [Kolide](https://github.com/kolide/kolide). The
configimporter application will take an Osquery configuration file, consolidate any external packs found in the file and then post it to Kolide where it is validated and imported.  

#### Installation
```
go get github.com/kolide/configimporter
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
The user will be prompted for their Kolide password; however, the password may
be supplied by setting an environment variable.
```
export CONFIGIMPORTER_PASSWORD=supersecret
```
### Dependencies

The openssl library and header files must be installed on the host system.

_Ubuntu Installation_
```
sudo apt-get install libssl-dev
```
_Mac OSX Installation_
```
brew install openssl
```
