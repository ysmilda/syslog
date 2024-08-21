package rfc5424

import (
	"io"
	"strings"
	"time"

	"github.com/ysmilda/syslog/pkg/characters"
)

type Parser struct {
	parseStructuredDataElements bool
}

// NewParser creates a new Parser with the provided options.
func NewParser(options ...parseOption) Parser {
	r := Parser{}
	for _, option := range options {
		option(&r)
	}
	return r
}

// Parse tries to parse a syslog message from the input. If the input is not a valid syslog message, an error is returned.
func (r Parser) Parse(input io.ByteScanner) (Message, error) {
	// Taken from https://datatracker.ietf.org/doc/html/rfc5424#section-6
	// The syslog message has the following ABNF [RFC5234] definition:
	// SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]
	// HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID

	var (
		m        Message
		elements *[]StructuredDataElement
	)

	pri, err := parsePRI(input)
	if err != nil {
		return m, err
	}

	version, err := parseVersion(input)
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

	appName, err := parseAppName(input)
	if err != nil {
		return m, err
	}

	procID, err := parseProcID(input)
	if err != nil {
		return m, err
	}

	msgID, err := parseMsgID(input)
	if err != nil {
		return m, err
	}

	structuredData, err := parseStructuredData(input)
	if err != nil {
		return m, err
	}

	if r.parseStructuredDataElements {
		elements, err = parseStructuredDataElements(structuredData)
		if err != nil {
			return m, err
		}
	}

	builder := strings.Builder{}
	for {
		b, err := input.ReadByte()
		if err != nil {
			break
		}
		builder.WriteByte(b)
	}

	return Message{
		PRI:                    PRI{pri},
		Version:                version,
		Timestamp:              timestamp,
		Hostname:               hostname,
		AppName:                appName,
		ProcID:                 procID,
		MsgID:                  msgID,
		StructuredData:         structuredData,
		StructuredDataElements: elements,
		Message:                builder.String(),
	}, nil
}

// parsePRI parses the PRI part of a syslog message according to the following rules.
// PRI             = "<" PRIVAL ">"
// PRIVAL          = 1*3DIGIT ; range 0 .. 191
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
		if !characters.IsDigit(b) {
			return 0, ErrInvalidPRI
		}
		PRI = PRI*10 + (b - '0')
	}

	return 0, ErrInvalidPRI
}

// parseVersion parses the VERSION part of a syslog message according to the following rules.
// VERSION         = NONZERO-DIGIT 0*2DIGIT
// NONZERO-DIGIT   = %d49-57         ; 1-9
func parseVersion(input io.ByteScanner) (byte, error) {
	b, err := input.ReadByte()
	if err != nil {
		return 0, ErrInvalidVersion
	}
	space, err := input.ReadByte()
	if err != nil || space != ' ' {
		return 0, ErrInvalidVersion
	}
	b -= '0'
	if b == 0 || b > 9 {
		return 0, ErrInvalidVersion
	}
	return b, nil
}

// parseTimestamp parses the TIMESTAMP part of a syslog message according to the following rules.
// The TIMESTAMP field is a formalized timestamp derived from [RFC3339]
// TIMESTAMP       = NILVALUE / FULL-DATE "T" FULL-TIME
// FULL-DATE       = DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
// DATE-FULLYEAR   = 4DIGIT
// DATE-MONTH      = 2DIGIT  ; 01-12
// DATE-MDAY       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on month/year
// FULL-TIME       = PARTIAL-TIME TIME-OFFSET
// PARTIAL-TIME    = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND [TIME-SECFRAC]
// TIME-HOUR       = 2DIGIT  ; 00-23
// TIME-MINUTE     = 2DIGIT  ; 00-59
// TIME-SECOND     = 2DIGIT  ; 00-59
// TIME-SECFRAC    = "." 1*6DIGIT
// TIME-OFFSET     = "Z" / TIME-NUMOFFSET
// TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE
func parseTimestamp(input io.ByteScanner) (time.Time, error) {
	isNil, err := checkNilValue(input)
	if err != nil {
		return time.Time{}, ErrInvalidTimestamp
	}

	if isNil {
		return time.Time{}, nil
	}

	builder := strings.Builder{}
	for {
		b, err := input.ReadByte()
		if err != nil {
			return time.Time{}, ErrInvalidTimestamp
		}
		if b == ' ' {
			break
		}
		builder.WriteByte(b)
	}
	return time.Parse(time.RFC3339, builder.String())
}

// parseHostname parses the HOSTNAME part of a syslog message according to the following rules.
// HOSTNAME        = NILVALUE / 1*255PRINTUSASCII
func parseHostname(input io.ByteScanner) (string, error) {
	return parseString(input, 255, ErrInvalidHostname)
}

// parseAppName parses the APP-NAME part of a syslog message according to the following rules.
// APP-NAME        = NILVALUE / 1*48PRINTUSASCII
func parseAppName(input io.ByteScanner) (string, error) {
	return parseString(input, 48, ErrInvalidAppName)
}

// parseProcID parses the PROCID part of a syslog message according to the following rules.
// PROCID          = NILVALUE / 1*128PRINTUSASCII
func parseProcID(input io.ByteScanner) (string, error) {
	return parseString(input, 128, ErrInvalidProcID)
}

// parseMsgID parses the MSGID part of a syslog message according to the following rules.
// MSGID           = NILVALUE / 1*32PRINTUSASCII
func parseMsgID(input io.ByteScanner) (string, error) {
	return parseString(input, 32, ErrInvalidMsgID)
}

// parseStructuredData parses the STRUCTURED-DATA part of a syslog message into a string according to the following rules.
// STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
// SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
func parseStructuredData(input io.ByteScanner) (string, error) {
	isNil, err := checkNilValue(input)
	if err != nil {
		return "", ErrInvalidStructuredData
	}
	if isNil {
		return "", nil
	}
	builder := strings.Builder{}
	for {
		b, err := input.ReadByte()
		if err != nil {
			return "", ErrInvalidStructuredData
		}
		if b == ']' {
			space, err := input.ReadByte()
			if err != nil || space == ' ' {
				builder.WriteByte(b)
				break
			}
			err = input.UnreadByte()
			if err != nil {
				return "", ErrInvalidStructuredData
			}
		}
		builder.WriteByte(b)
	}
	return builder.String(), nil
}

// parseStructuredDataElements parses the STRUCTURED-DATA part of a syslog message according to the following rules.
// SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
// SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
// SD-ID           = SD-NAME
// PARAM-NAME      = SD-NAME
// PARAM-VALUE     = UTF-8-STRING ; characters '"', '\' and ']' MUST be escaped.
// SD-NAME         = 1*32PRINTUSASCII except '=', SP, ']', %d34 (")
func parseStructuredDataElements(input string) (*[]StructuredDataElement, error) {
	// If the input is empty, return nil
	// The structured data is optional, and a nil value ('-') is parsed as an empty string.
	if input == "" {
		return nil, nil //nolint:nilnil
	}
	input = strings.TrimSpace(input)

	elements := []StructuredDataElement{}
	// Split the input by the indicator of a new element: '['
	for _, element := range strings.Split(input, "[") {
		if element == "" {
			continue
		}
		// Split the element on spaces, ignore the last character which is ']'
		parts := strings.Split(element[:len(element)-1], " ")
		id := parts[0]
		// Check if the ID is valid
		if len(id) < 1 || len(id) > 32 || strings.ContainsAny(id, "= ]\"") {
			return nil, ErrInvalidStructuredData
		}
		params := map[string]string{}
		for _, param := range parts[1:] {
			parts := strings.Split(param, "=")
			if len(parts) != 2 {
				return nil, ErrInvalidStructuredData
			}
			// Remove the quotes from the value and unescape the characters
			value := parts[1][1 : len(parts[1])-1]
			value = strings.ReplaceAll(value, "\\\"", "\"")
			value = strings.ReplaceAll(value, "\\\\", "\\")
			value = strings.ReplaceAll(value, "\\]", "]")
			params[parts[0]] = value
		}
		elements = append(elements, StructuredDataElement{
			ID:         id,
			Parameters: params,
		})
	}
	return &elements, nil
}

// parseString parses a string from the input with a maximum length according to the following rules.
// STRING = NILVALUE / 1*[max]PRINTUSASCII SP

func parseString(input io.ByteScanner, max int, e error) (string, error) {
	isNil, err := checkNilValue(input)
	if err != nil {
		return "", e
	}
	if isNil {
		return "", nil
	}
	builder := strings.Builder{}
	for {
		b, err := input.ReadByte()
		if err != nil {
			return "", e
		}
		if b == ' ' {
			break
		}
		builder.WriteByte(b)
	}
	if builder.Len() < 1 || builder.Len() > max {
		return "", e
	}
	return builder.String(), nil
}

// checkNilValue checks if the input is a nil value ('-') according to the following rules.
// NILVALUE        = "-"
func checkNilValue(input io.ByteScanner) (bool, error) {
	b, err := input.ReadByte()
	if err != nil {
		return false, ErrInvalidNilValue
	}
	if b == '-' {
		space, err := input.ReadByte()
		if err != nil || space != ' ' {
			return false, ErrInvalidNilValue
		}
		return true, nil
	}
	return false, input.UnreadByte()
}
