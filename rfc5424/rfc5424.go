package rfc5424

import (
	"io"
	"strings"
	"time"

	"github.com/ysmilda/syslog/pkg/characters"
)

const (
	nilValue = '-'
)

type RFC5424 struct {
	parseStructuredDataElements bool
}

func NewRFC5424(options ...parseOption) RFC5424 {
	r := RFC5424{}
	for _, option := range options {
		option(&r)
	}
	return r
}

func (r RFC5424) Parse(input io.ByteScanner) (Message, error) {
	// Taken from https://datatracker.ietf.org/doc/html/rfc5424#section-6
	// The syslog message has the following ABNF [RFC5234] definition:
	// SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]
	// HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID

	var (
		m        Message
		elements *[]StructuredDataElements
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

func parsePRI(input io.ByteScanner) (byte, error) {
	// PRI             = "<" PRIVAL ">"
	// PRIVAL          = 1*3DIGIT ; range 0 .. 191

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

func parseVersion(input io.ByteScanner) (byte, error) {
	// VERSION         = NONZERO-DIGIT 0*2DIGIT
	// NONZERO-DIGIT   = %d49-57         ; 1-9

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

func parseTimestamp(input io.ByteScanner) (time.Time, error) {
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

func parseHostname(input io.ByteScanner) (string, error) {
	// HOSTNAME        = NILVALUE / 1*255PRINTUSASCII

	return parseString(input, 255, ErrInvalidHostname)
}

func parseAppName(input io.ByteScanner) (string, error) {
	// APP-NAME        = NILVALUE / 1*48PRINTUSASCII

	return parseString(input, 48, ErrInvalidAppName)
}

func parseProcID(input io.ByteScanner) (string, error) {
	// PROCID          = NILVALUE / 1*128PRINTUSASCII

	return parseString(input, 128, ErrInvalidProcID)
}

func parseMsgID(input io.ByteScanner) (string, error) {
	// MSGID           = NILVALUE / 1*32PRINTUSASCII

	return parseString(input, 32, ErrInvalidMsgID)
}

func parseStructuredData(input io.ByteScanner) (string, error) {
	// STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
	// SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"

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

func parseStructuredDataElements(input string) (*[]StructuredDataElements, error) {
	// SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
	// SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
	// SD-ID           = SD-NAME
	// PARAM-NAME      = SD-NAME
	// PARAM-VALUE     = UTF-8-STRING ; characters '"', '\' and ']' MUST be escaped.
	// SD-NAME         = 1*32PRINTUSASCII except '=', SP, ']', %d34 (")

	// If the input is empty, return nil
	// The structured data is optional, and a nil value ('-') is parsed as an empty string.
	if input == "" {
		return nil, nil //nolint:nilnil
	}
	input = strings.TrimSpace(input)

	elements := []StructuredDataElements{}
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
		elements = append(elements, StructuredDataElements{
			ID:         id,
			Parameters: params,
		})
	}
	return &elements, nil
}

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

func checkNilValue(input io.ByteScanner) (bool, error) {
	b, err := input.ReadByte()
	if err != nil {
		return false, ErrInvalidNilValue
	}
	if b == nilValue {
		space, err := input.ReadByte()
		if err != nil || space != ' ' {
			return false, ErrInvalidNilValue
		}
		return true, nil
	}
	return false, input.UnreadByte()
}
