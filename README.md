Looking to import osquery packs into [Kolide Fleet](https://github.com/kolide/kolide)? Your best bet is following the instructions in [this gist](https://gist.github.com/marpaia/9e061f81fa60b2825f4b6bb8e0cd2c77) as this repo has been deprecated.


### Osquery Configuration Importer [Deprecated]

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
