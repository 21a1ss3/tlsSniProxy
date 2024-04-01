# Introduction
This is lightweight TLS proxy sniffer written on go for traffice DSCP (ToS) marking based on SNI (tls server name). Main desire for this project was to let Mikrotik RouterOS be able to route TLS requests conditionally based on domain-name.

# How to build

Just install go and run `go build` or `GOOS=<OS> GOARCH=<CPUARCH> go build` for cross compilation

If you want to run it in Docker, use standrt procedure to build docker container (current version might require arch update and filename, but will be fixed in a future)

# How to run

After getting executable you need either:
 - Create file `config.json` next to executable file
 - Put config file somewhere on your disk and supply path through the first argument

Config file structure:

```json
{
    "defaultDscp": 20,
    "levels" :[
        {
            "patterns": [
                "regex-domain-name, like: googele\\.com",
                "next domain and etc..."
            ],
            "dscp": 30
        }
    ],
    "bindSocket": "<socket addr",
    "logLevel": "level"
}

```
`defaultDscp`, `bindSocket` and `logLevel` are not required. Defaults: `defaultDscp = 0`, `bindSocket = :443`, `logLevel = Info`.

Field description

- `bindSocket`: socket (IP and port) where tcp listenere binds to. Must be in format like `HOST:PORT`, where `HOST` might be ommited (see go tcp listener docs&examples).
- `defaultDscp` and `dscp`: represents desired DSCP value. Must be in a range `0..63`. `defaultDscp` is used if no specific rule has been hit.
- `logLevel`: verbosity of log output. See `logrus` package documentation for more infromation
- `patterns`: array of regex strings for given level. Be mindful that regex slightly different to just strings, and, for example, you must escape characters, like `.`: `google\\.com`.
- `levels`: array of object rules describing pattern and desired DSCP value. Programs scans levels in their natural presence order and hits first matching rule. This allows you to make complex behavior, including exlusions. Same `DSCP` value could be present as many times as required.


Launch cli (linux example)
```
./tlsSniProxy
```
or
```
./tlsSniProxy /path/to/config
```


## Mikrotik setup example

Coming soon