### Osquery Configuration Importer

Import an Osquery configuration file into [Kolide](https://github.com/kolide/kolide). The
configimporter application will take an Osquery configuration file, consolidate any external packs found in the file and then post it to Kolide where it is validated and imported.  

#### Installation
```
go get github.com/kolide/configimporter
```

#### Usage
```
Usage: configimporter -host https://localhost:8080 -user bob -pwd 'secret' -config /somedir/osquery.cfg

  -config string
        Path to an Osquery configuration file
  -help
        Show usage
  -host string
        Kolide host name (default "https://localhost:8080")
  -pwd string
        Password for user
  -user string
        Kolide user name

```
