# Syslog

The goal of this library is to provide a simple and efficient way to parse syslog messages.

## Supported RFCs

Currently, the library supports the following RFCs:
 - [RFC5424](https://datatracker.ietf.org/doc/html/rfc5424)

The implementation is close to feature complete for the RFC5424 format. The `SD-IDS` are not yet supported, however feel free to open an issue if you need them.

## Usage

The library is designed around the `io.ByteScanner` interface. This allows for parsing in a streaming fashion as well as from memory.

```go
parser := rfc5424.NewParser()
message := []byte("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8'")
msg, err := parser.Parse(bytes.NewReader(message))
if err != nil {
    panic(err)
}
```

The parser will take options during initialisation to allow for customisation of the parsing process. The options are passed as variadic arguments to the `NewParser` function.

```go
// Parse the structured data into its elements instead of just the raw string.
parser := rfc5424.NewParser(rfc5424.WithParseStructuredDataElements())
```

## TODO

- [ ] Support the [RFC3164](https://datatracker.ietf.org/doc/html/rfc3164) format.
- [ ] Allow for filtering/early return through parser options.