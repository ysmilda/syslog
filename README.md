# Syslog

The goal of this library is to provide a simple and efficient way to parse syslog messages.

## Supported RFCs

Currently, the library supports the following RFCs:
 - [RFC3164](https://datatracker.ietf.org/doc/html/rfc3164)
 - [RFC5424](https://datatracker.ietf.org/doc/html/rfc5424)

The implementation is close to feature complete for the RFC5424 format. The `SD-IDS` are not yet supported, however feel free to open an issue if you need them.

## Usage

The library has an interface similar to the json decoder/encoder interface. This allows for parsing in a streaming fashion as well as from memory. Depending on the RFC standard that you want to encode or decode, you can use the `rfc3164` or `rfc5424` package.

```go
message := []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")
msg, err := rfc3164.NewDecoder(bytes.NewReader(message)).Decode()
if err != nil {
    panic(err)
}
```

```go
message := []byte("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8'")
msg, err := rfc5424.NewDecoder(bytes.NewReader(message)).Decode()
if err != nil {
    panic(err)
}
```

```go
var (
    buf bytes.Buffer
    message rfc5424.Message
)
n, err := rfc5424.NewEncoder(&buf).Encode(message)
if err != nil {
    panic(err)
}
```

## TODO

- [ ] Allow for filtering/early return through parser options.