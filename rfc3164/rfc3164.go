package rfc3164

import (
	"io"
	"strings"
	"time"
)

type Parser struct{}

// NewParser creates a new Parser.
func NewParser() Parser {
	return Parser{}
}

func (p Parser) Parse(input io.ByteScanner) (Message, error) {
	var m Message

	pri, err := parsePRI(input)
	if err != nil {
		return m, err
	}

	timestamp, err := parseTimestamp(input)
	if err != nil {
		return m, err
	}

	hostname, err := parseHostname(input)
	if err != nil {
		return m, err
	}

	tag, content := parseMessage(input)

	return Message{
		PRI:       PRI{pri},
		Timestamp: timestamp,
		Hostname:  hostname,
		Tag:       tag,
		Content:   content,
	}, nil
}

// parsePRI parses the PRI part of a syslog message.
func parsePRI(input io.ByteScanner) (byte, error) {
	b, err := input.ReadByte()
	if err != nil || b != '<' {
		return 0, ErrInvalidPRI
	}

	PRI := byte(0)
	for i := 0; i < 4; i++ {
		b, err = input.ReadByte()
		if err != nil {
			return 0, ErrInvalidPRI
		}
		if b == '>' {
			if PRI > 191 {
				return 0, ErrInvalidPRI
			}
			return PRI, nil
		}
		if b < '0' || b > '9' {
			return 0, ErrInvalidPRI
		}
		PRI = PRI*10 + (b - '0')
	}

	return 0, ErrInvalidPRI
}

func parseTimestamp(input io.ByteScanner) (time.Time, error) {
	b, err := input.ReadByte()
	if err != nil {
		return time.Time{}, ErrInvalidTimestamp
	}
	if b == ' ' {
		return time.Time{}, nil
	}

	builder := strings.Builder{}
	builder.WriteByte(b)
	for i := 0; i < 14; i++ {
		b, err := input.ReadByte()
		if err != nil {
			return time.Time{}, ErrInvalidTimestamp
		}
		builder.WriteByte(b)
	}

	space, err := input.ReadByte()
	if err != nil || space != ' ' {
		return time.Time{}, ErrInvalidTimestamp
	}

	timestamp, err := time.Parse(time.Stamp, builder.String())
	if err != nil {
		return time.Time{}, ErrInvalidTimestamp
	}
	return timestamp, nil
}

func parseHostname(input io.ByteScanner) (string, error) {
	builder := strings.Builder{}
	for {
		b, err := input.ReadByte()
		if err != nil {
			return "", ErrInvalidHostname
		}
		if b == ' ' {
			break
		}
		builder.WriteByte(b)
	}
	return builder.String(), nil
}

func parseMessage(input io.ByteScanner) (tag string, content string) {
	builder := strings.Builder{}
	tagFound := false
	for {
		b, err := input.ReadByte()
		if err != nil {
			break
		}
		if (b == '[' || b == ']' || b == ':') && !tagFound {
			tagFound = true
			tag = builder.String()
			builder.Reset()
		}
		builder.WriteByte(b)
	}
	content = builder.String()
	return
}
